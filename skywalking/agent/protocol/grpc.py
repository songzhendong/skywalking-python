#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import logging
import traceback
from queue import Queue, Empty
from threading import Event, Thread, Lock
from time import monotonic
from typing import Optional

import grpc

from skywalking import config
from skywalking.agent.protocol import Protocol
from skywalking.agent.protocol.interceptors import header_adder_interceptor
from skywalking.client.grpc import GrpcServiceManagementClient, GrpcTraceSegmentReportService, \
    GrpcProfileTaskChannelService, GrpcLogDataReportService, GrpcMeterReportService
from skywalking.loggings import logger, logger_debug_enabled
from skywalking.utils.grpc_channel import (
    apply_connectivity_transition,
    create_sync_channel,
    dns_reresolve_join_timeout_sec,
    handle_rpc_error,
    is_channel_ready,
    resolve_collector_dial_plan,
)
from skywalking.utils.reporter_log import log_dropped_throttled
from skywalking.profile.profile_task import ProfileTask
from skywalking.profile.snapshot import TracingThreadSnapshot
from skywalking.protocol.common.Common_pb2 import KeyStringValuePair
from skywalking.protocol.language_agent.Tracing_pb2 import SegmentObject, SpanObject, Log, SegmentReference
from skywalking.protocol.logging.Logging_pb2 import LogData
from skywalking.protocol.language_agent.Meter_pb2 import MeterData
from skywalking.protocol.profile.Profile_pb2 import ThreadSnapshot, ThreadStack
from skywalking.trace.segment import Segment


def _queue_get_within_batch(queue: Queue, block: bool, batch_deadline: float, *, allow_immediate: bool = False):
    """
    Get one item within an absolute batch window (monotonic deadline).

    Avoids int(elapsed) truncation that could let queue waits approach
    agent_queue_timeout + 1s and collide with a tight RPC deadline.
    When allow_immediate is True (first generator iteration), still attempt
    Queue.get once so SW_AGENT_QUEUE_TIMEOUT=0 can drain an immediately
    available item via get(timeout=0).
    Returns None when the window is exhausted or the queue is empty.
    """
    remaining = batch_deadline - monotonic()
    if remaining <= 0 and not allow_immediate:
        return None
    try:
        if block:
            timeout = remaining if remaining > 0 else 0
            return queue.get(block=True, timeout=timeout)
        return queue.get(block=False)
    except Empty:
        return None


class GrpcProtocol(Protocol):
    def __init__(self):
        self.properties_sent = False
        self.state = None
        self._dns_fingerprint = None
        self._dial_plan = None  # type: Optional[tuple]
        self._dns_stop = Event()
        self._dns_thread = None
        self._channel_generation = 0
        self._active_cb = None
        self._channel_lock = Lock()

        # One channel for process lifetime; multi-address failover via gRPC pick_first.
        # Periodic DNS (when enabled) may rebuild this channel if the IP set changes.
        target, authority, fingerprint = resolve_collector_dial_plan()
        self._bind_channel(target, authority, fingerprint=fingerprint)
        self._start_dns_reresolve_thread()

    def _bind_channel(self, target: str, authority: str, fingerprint=None):
        # Build the new channel + clients fully before swapping self.* so a
        # constructor failure never leaves a half-bound protocol or invalidates
        # the still-live previous subscribe generation.
        channel = create_sync_channel(target=target, authority=authority)
        try:
            if config.agent_authentication:
                channel = grpc.intercept_channel(
                    channel, header_adder_interceptor('authentication', config.agent_authentication)
                )
            service_management = GrpcServiceManagementClient(channel)
            traces_reporter = GrpcTraceSegmentReportService(channel)
            profile_channel = GrpcProfileTaskChannelService(channel)
            log_reporter = GrpcLogDataReportService(channel)
            meter_reporter = GrpcMeterReportService(channel)
        except Exception:
            try:
                channel.close()
            except Exception:  # noqa: BLE001
                pass
            raise

        self._channel_generation += 1
        generation = self._channel_generation

        def _cb(state, _generation=generation):
            # Ignore connectivity events from a channel we already replaced.
            if _generation != self._channel_generation:
                return
            # Snapshot before mutating: a concurrent rebuild may bump generation
            # and swap service_management under us (narrow TOCTOU window).
            prev = self.state
            service_management_ref = self.service_management
            if logger_debug_enabled:
                logger.debug('grpc channel connectivity changed, [%s -> %s]', prev, state)
            try:
                apply_connectivity_transition(prev, state)
                if prev == grpc.ChannelConnectivity.READY and state != grpc.ChannelConnectivity.READY:
                    if _generation != self._channel_generation:
                        return
                    self.properties_sent = False
                    service_management_ref.sent_properties_counter = 0
            except Exception:  # noqa: BLE001 - never let grpc's connectivity thread die on us
                logger.exception('failed to handle grpc connectivity transition')
            if _generation != self._channel_generation:
                return
            self.state = state

        self.channel = channel
        self.service_management = service_management
        self.traces_reporter = traces_reporter
        self.profile_channel = profile_channel
        self.log_reporter = log_reporter
        self.meter_reporter = meter_reporter
        self._dns_fingerprint = fingerprint
        self._dial_plan = (target, authority, fingerprint)
        self.state = None
        self._active_cb = _cb

        # Subscribe last: _cb runs on a grpc thread and touches service_management.
        self.channel.subscribe(self._active_cb, try_to_connect=True)

    def _start_dns_reresolve_thread(self):
        if not config.agent_collector_is_resolve_dns_periodically:
            return
        interval = max(1, int(config.agent_collector_grpc_channel_check_interval))
        self._dns_thread = Thread(
            name='GrpcDnsReResolve',
            target=self._dns_reresolve_loop,
            args=(interval,),
            daemon=True,
        )
        self._dns_thread.start()
        logger.info(
            'Periodic collector DNS re-resolve enabled (interval=%ss)',
            interval,
        )

    def _dns_reresolve_loop(self, interval: int):
        while not self._dns_stop.wait(interval):
            try:
                self.maybe_reresolve_dns()
            except Exception:  # noqa: BLE001 - never kill the watcher thread
                logger.exception('Periodic collector DNS re-resolve failed')

    def maybe_reresolve_dns(self) -> bool:
        """
        Re-resolve collector DNS. Rebuild the pick_first channel when the dial
        plan fingerprint changes. Returns True if a rebuild happened.
        """
        if not config.agent_collector_is_resolve_dns_periodically:
            return False
        if self._dns_stop.is_set():
            return False
        # Resolve outside the channel lock so close()/on_error are not blocked
        # for the full DNS budget (up to ~5s per hostname).
        with self._channel_lock:
            if self._dns_stop.is_set():
                return False
            previous = self._dial_plan
        target, authority, fingerprint = resolve_collector_dial_plan(
            previous=previous,
        )
        old_to_close = None
        rebuilt = False
        try:
            with self._channel_lock:
                if self._dns_stop.is_set():
                    return False
                if fingerprint == self._dns_fingerprint:
                    return False
                logger.info(
                    'Collector DNS dial plan changed (%s -> %s); rebuilding gRPC channel',
                    self._dns_fingerprint,
                    fingerprint,
                )
                old = self.channel
                old_cb = self._active_cb
                # Snapshot so a post-commit failure (e.g. subscribe) can restore.
                prev_sm = self.service_management
                prev_traces = self.traces_reporter
                prev_profile = self.profile_channel
                prev_log = self.log_reporter
                prev_meter = self.meter_reporter
                prev_fp = self._dns_fingerprint
                prev_plan = self._dial_plan
                prev_state = self.state
                prev_props = self.properties_sent
                prev_gen = self._channel_generation
                try:
                    if old_cb is not None:
                        old.unsubscribe(old_cb)
                except Exception:  # noqa: BLE001
                    pass
                try:
                    self._bind_channel(target, authority, fingerprint=fingerprint)
                    self.properties_sent = False
                    self.service_management.sent_properties_counter = 0
                    old_to_close = old
                    rebuilt = True
                except Exception:
                    if self.channel is old:
                        # Create never swapped self.channel; re-subscribe previous.
                        if old_cb is not None and not self._dns_stop.is_set():
                            try:
                                old.subscribe(old_cb, try_to_connect=True)
                                self._active_cb = old_cb
                            except Exception:  # noqa: BLE001
                                pass
                    else:
                        # Swapped then failed (typically subscribe): restore prior
                        # channel/clients/fingerprint so DNS can retry later and
                        # reporting is not stuck on an unsubscribed channel.
                        broken = self.channel
                        broken_cb = self._active_cb
                        try:
                            if broken_cb is not None:
                                broken.unsubscribe(broken_cb)
                        except Exception:  # noqa: BLE001
                            pass
                        self.channel = old
                        self._active_cb = old_cb
                        self.service_management = prev_sm
                        self.traces_reporter = prev_traces
                        self.profile_channel = prev_profile
                        self.log_reporter = prev_log
                        self.meter_reporter = prev_meter
                        self._dns_fingerprint = prev_fp
                        self._dial_plan = prev_plan
                        self.state = prev_state
                        self.properties_sent = prev_props
                        self._channel_generation = prev_gen
                        if old_cb is not None and not self._dns_stop.is_set():
                            try:
                                old.subscribe(old_cb, try_to_connect=True)
                            except Exception:  # noqa: BLE001
                                pass
                        old_to_close = broken
                    raise
        finally:
            # Close outside the lock so a stuck C-core close cannot block
            # on_error()/agent close() from taking the lock.
            if old_to_close is not None:
                try:
                    old_to_close.close()
                except Exception:  # noqa: BLE001
                    pass
        return rebuilt

    def is_ready(self) -> bool:
        """
        Node CONNECTED ≈ subscribe-watched gRPC READY.

        Sync grpcio has no Channel.get_state(); check_connectivity_state can disagree
        with subscribe callbacks on some builds and permanently skipped all RPCs in
        E2E (channel already READY via subscribe, reporters still gated). Use the
        watched state as source of truth; only nudge C-core when IDLE.
        """
        if self.state == grpc.ChannelConnectivity.READY:
            return True
        if self.state == grpc.ChannelConnectivity.IDLE:
            # Side-effect nudge (ignore return); subscribe callback updates self.state.
            is_channel_ready(self.channel)
        return self.state == grpc.ChannelConnectivity.READY

    def query_profile_commands(self):
        if not self.is_ready():
            return
        if logger_debug_enabled:
            logger.debug('query profile commands')
        self.profile_channel.do_query()

    def notify_profile_task_finish(self, task: ProfileTask):
        if not self.is_ready():
            return
        self.profile_channel.finish(task)

    def heartbeat(self):
        if not self.is_ready():
            return
        if not self.properties_sent:
            try:
                self.service_management.send_instance_props()
                self.properties_sent = True
            except grpc.RpcError as e:
                handle_rpc_error(e, self.on_error)
        try:
            self.service_management.send_heart_beat()
        except grpc.RpcError as e:
            handle_rpc_error(e, self.on_error)
            raise

    def on_error(self):
        # Re-subscribe the same channel only — never rebuild or rotate backends here.
        # DEADLINE_EXCEEDED on READY is not a connectivity failure; see handle_rpc_error.
        traceback.print_exc() if logger.isEnabledFor(logging.DEBUG) else None
        with self._channel_lock:
            if self._dns_stop.is_set():
                return
            cb = self._active_cb
            channel = self.channel
            if cb is None:
                return
            try:
                channel.unsubscribe(cb)
            except Exception:  # noqa: BLE001
                pass
            # Rebuild may have swapped channel/cb while we unsubscribed.
            if cb is not self._active_cb or channel is not self.channel:
                return
            try:
                channel.subscribe(cb, try_to_connect=True)
            except Exception:  # noqa: BLE001
                pass

    def close(self):
        """Best-effort channel teardown on agent stop (Node shutdownNow parity)."""
        self._dns_stop.set()
        channel = None
        with self._channel_lock:
            # Invalidate in-flight subscribe callbacks before close.
            self._channel_generation += 1
            cb = self._active_cb
            channel = self.channel
            self._active_cb = None
            try:
                if cb is not None:
                    channel.unsubscribe(cb)
            except Exception:  # noqa: BLE001
                pass
        # Close outside the lock: C-core close can block; do not stall DNS/on_error.
        if channel is not None:
            try:
                channel.close()
            except Exception:  # noqa: BLE001
                pass
        # Join outside the lock: the DNS thread may be waiting on the same lock.
        thread = self._dns_thread
        if thread is not None and thread.is_alive():
            # After _dns_stop, the thread may still finish an in-flight resolve
            # (up to DNS_LOOKUP_TIMEOUT_SEC per configured backend hostname).
            thread.join(timeout=dns_reresolve_join_timeout_sec())

    def report_segment(self, queue: Queue, block: bool = True):
        # Gate before dequeue so disconnect windows keep segments in the queue (Node buffer parity).
        if not self.is_ready():
            return
        sent = 0

        def generator():
            nonlocal sent

            batch_deadline = monotonic() + float(config.agent_queue_timeout)
            first_get = True
            while True:
                segment = _queue_get_within_batch(queue, block, batch_deadline, allow_immediate=first_get)  # type: Segment
                first_get = False
                if segment is None:
                    return

                queue.task_done()
                sent += 1

                if logger_debug_enabled:
                    logger.debug('reporting segment %s', segment)

                s = SegmentObject(
                    traceId=str(segment.related_traces[0]),
                    traceSegmentId=str(segment.segment_id),
                    service=config.agent_name,
                    serviceInstance=config.agent_instance_name,
                    isSizeLimited=segment.is_size_limited,
                    spans=[SpanObject(
                        spanId=span.sid,
                        parentSpanId=span.pid,
                        startTime=span.start_time,
                        endTime=span.end_time,
                        operationName=span.op,
                        peer=span.peer,
                        spanType=span.kind.name,
                        spanLayer=span.layer.name,
                        componentId=span.component.value,
                        isError=span.error_occurred,
                        logs=[Log(
                            time=int(log.timestamp * 1000),
                            data=[KeyStringValuePair(key=item.key, value=item.val) for item in log.items],
                        ) for log in span.logs],
                        tags=[KeyStringValuePair(
                            key=tag.key,
                            value=tag.val,
                        ) for tag in span.iter_tags()],
                        refs=[SegmentReference(
                            refType=0 if ref.ref_type == 'CrossProcess' else 1,
                            traceId=ref.trace_id,
                            parentTraceSegmentId=ref.segment_id,
                            parentSpanId=ref.span_id,
                            parentService=ref.service,
                            parentServiceInstance=ref.service_instance,
                            parentEndpoint=ref.endpoint,
                            networkAddressUsedAtPeer=ref.client_address,
                        ) for ref in span.refs if ref.trace_id],
                    ) for span in segment.spans],
                )

                yield s

        try:
            self.traces_reporter.report(generator())
        except grpc.RpcError as e:
            if sent:
                log_dropped_throttled('segment', sent)
            handle_rpc_error(e, self.on_error)
            raise  # reraise so that incremental reconnect wait can process; failed batch discarded

    def report_log(self, queue: Queue, block: bool = True):
        if not self.is_ready():
            return
        sent = 0

        def generator():
            nonlocal sent

            batch_deadline = monotonic() + float(config.agent_queue_timeout)
            first_get = True
            while True:
                log_data = _queue_get_within_batch(queue, block, batch_deadline, allow_immediate=first_get)  # type: LogData
                first_get = False
                if log_data is None:
                    return

                queue.task_done()
                sent += 1

                if logger_debug_enabled:
                    logger.debug('Reporting Log')

                yield log_data

        try:
            self.log_reporter.report(generator())
        except grpc.RpcError as e:
            if sent:
                log_dropped_throttled('log', sent)
            handle_rpc_error(e, self.on_error)
            raise

    def report_meter(self, queue: Queue, block: bool = True):
        if not self.is_ready():
            return
        sent = 0

        def generator():
            nonlocal sent

            batch_deadline = monotonic() + float(config.agent_queue_timeout)
            first_get = True
            while True:
                meter_data = _queue_get_within_batch(queue, block, batch_deadline, allow_immediate=first_get)  # type: MeterData
                first_get = False
                if meter_data is None:
                    return

                queue.task_done()
                sent += 1

                yield meter_data

        try:
            if logger_debug_enabled:
                logger.debug('Reporting Meter')
            self.meter_reporter.report(generator())
        except grpc.RpcError as e:
            if sent:
                log_dropped_throttled('meter', sent)
            handle_rpc_error(e, self.on_error)
            raise

    def report_snapshot(self, queue: Queue, block: bool = True):
        if not self.is_ready():
            return
        sent = 0

        def generator():
            nonlocal sent

            batch_deadline = monotonic() + float(config.agent_queue_timeout)
            first_get = True
            while True:
                snapshot = _queue_get_within_batch(queue, block, batch_deadline, allow_immediate=first_get)  # type: TracingThreadSnapshot
                first_get = False
                if snapshot is None:
                    return

                queue.task_done()
                sent += 1

                transform_snapshot = ThreadSnapshot(
                    taskId=str(snapshot.task_id),
                    traceSegmentId=str(snapshot.trace_segment_id),
                    time=int(snapshot.time),
                    sequence=int(snapshot.sequence),
                    stack=ThreadStack(codeSignatures=snapshot.stack_list)
                )

                yield transform_snapshot

        try:
            self.profile_channel.report(generator())
        except grpc.RpcError as e:
            if sent:
                log_dropped_throttled('snapshot', sent)
            handle_rpc_error(e, self.on_error)
            raise
