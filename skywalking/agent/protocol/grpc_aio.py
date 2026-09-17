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
import asyncio
import contextlib
from asyncio import Queue, Event

import grpc

from skywalking import config
from skywalking.agent.protocol import ProtocolAsync
from skywalking.agent.protocol.interceptors_aio import header_adder_interceptor_async
from skywalking.client.grpc_aio import GrpcServiceManagementClientAsync, GrpcTraceSegmentReportServiceAsync, \
    GrpcProfileTaskChannelServiceAsync, GrpcLogReportServiceAsync, GrpcMeterReportServiceAsync
from skywalking.loggings import logger, logger_debug_enabled
from skywalking.utils.reporter_log import log_dropped_throttled
from skywalking.utils.grpc_channel import (
    apply_connectivity_transition,
    create_aio_channel,
    handle_rpc_error,
    is_channel_ready,
    log_dns_reresolve_failure_throttled,
    resolve_collector_dial_plan,
)
from skywalking.profile.profile_task import ProfileTask
from skywalking.profile.snapshot import TracingThreadSnapshot
from skywalking.protocol.common.Common_pb2 import KeyStringValuePair
from skywalking.protocol.language_agent.Tracing_pb2 import SegmentObject, SpanObject, Log, SegmentReference
from skywalking.protocol.logging.Logging_pb2 import LogData
from skywalking.protocol.language_agent.Meter_pb2 import MeterData
from skywalking.protocol.profile.Profile_pb2 import ThreadSnapshot, ThreadStack
from skywalking.trace.segment import Segment


class GrpcProtocolAsync(ProtocolAsync):
    """
    grpc for asyncio
    """
    def __init__(self):
        self.properties_sent = Event()
        self.state = None
        self._dns_fingerprint = None
        self._dial_plan = None
        self._auth_interceptors = None
        self._channel_generation = 0
        self._closed = False
        # Wakes watch_connectivity when the channel is replaced even if old.close() fails.
        self._channel_changed = asyncio.Event()

        # grpc.aio has no Channel.subscribe(); watch_connectivity() mirrors Node
        # watchConnectivityState via wait_for_state_change (started by the agent loop).

        if config.agent_authentication:
            self._auth_interceptors = [
                header_adder_interceptor_async('authentication', config.agent_authentication)
            ]

        # One channel for process lifetime; multi-address failover via gRPC pick_first.
        target, authority, fingerprint = resolve_collector_dial_plan()
        self._bind_channel(target, authority, fingerprint=fingerprint)

    def _notify_channel_changed(self):
        try:
            self._channel_changed.set()
        except Exception:  # noqa: BLE001
            pass

    def _abandon_aio_channel(self, channel) -> None:
        """Best-effort close for a channel that never became self.channel."""
        try:
            result = channel.close()
            if not asyncio.iscoroutine(result):
                return
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                # Off the agent loop (failed construct during unusual init):
                # drain close so the channel is not leaked by dropping the coroutine.
                try:
                    asyncio.run(result)
                except Exception:  # noqa: BLE001
                    with contextlib.suppress(Exception):
                        result.close()
                return
            loop.create_task(result)
        except Exception:  # noqa: BLE001
            pass

    def _bind_channel(self, target: str, authority: str, fingerprint=None):
        # Construct channel + clients fully before swapping self.* so a
        # constructor failure does not orphan the previous live channel or
        # invalidate watch_connectivity's generation for it.
        channel = create_aio_channel(
            interceptors=self._auth_interceptors,
            target=target,
            authority=authority,
        )
        try:
            service_management = GrpcServiceManagementClientAsync(channel)
            traces_reporter = GrpcTraceSegmentReportServiceAsync(channel)
            log_reporter = GrpcLogReportServiceAsync(channel)
            meter_reporter = GrpcMeterReportServiceAsync(channel)
            profile_channel = GrpcProfileTaskChannelServiceAsync(channel)
        except Exception:
            self._abandon_aio_channel(channel)
            raise

        self._channel_generation += 1
        self.channel = channel
        self.service_management = service_management
        self.traces_reporter = traces_reporter
        self.log_reporter = log_reporter
        self.meter_reporter = meter_reporter
        self.profile_channel = profile_channel
        self._dns_fingerprint = fingerprint
        self._dial_plan = (target, authority, fingerprint)
        self.state = None
        self._notify_channel_changed()

    async def maybe_reresolve_dns(self) -> bool:
        """
        Rebuild the aio channel when periodic DNS sees a dial-plan change.

        DNS runs in ``asyncio.to_thread``. Bind is refused when ``_closed``;
        a successful bind closes the previous channel (best-effort). Cancel
        during ``old.close()`` still attempts to tear down the displaced channel.
        """
        if not config.agent_collector_is_resolve_dns_periodically:
            return False
        if self._closed:
            return False
        previous = self._dial_plan
        old = None
        # Offload blocking getaddrinfo waits so the agent asyncio loop stays responsive
        # (heartbeat / report / connectivity watch). Cancel does not interrupt the
        # worker thread, but we refuse to bind after cancel/close.
        try:
            target, authority, fingerprint = await asyncio.to_thread(
                resolve_collector_dial_plan, previous=previous,
            )
            if self._closed:
                return False
            if fingerprint == self._dns_fingerprint:
                return False
            logger.info(
                'Collector DNS dial plan changed (%s -> %s); rebuilding aio gRPC channel',
                self._dns_fingerprint,
                fingerprint,
            )
            # Re-check after logging: cross-thread begin_shutdown()/close() may have
            # flipped _closed (same-loop shutdown cancels at the next await).
            if self._closed:
                return False
            old = self.channel
            self._bind_channel(target, authority, fingerprint=fingerprint)
            self.properties_sent.clear()
            self.service_management.sent_properties_counter = 0
            try:
                # Unblocks watch_connectivity wait_for_state_change on the old channel.
                # _notify_channel_changed already ran in _bind_channel as a fallback if
                # close fails or never wakes the waiter.
                await old.close()
            except Exception:  # noqa: BLE001
                pass
            return True
        except asyncio.CancelledError:
            # If cancel hit during await old.close(), the new channel is already
            # bound; still try to tear down the previous channel.
            if old is not None and old is not self.channel:
                try:
                    await old.close()
                except Exception:  # noqa: BLE001
                    pass
            raise

    async def watch_dns_reresolve(self):
        """Background loop: Java grpc_channel_check_interval cadence, pick_first rebuild."""
        if not config.agent_collector_is_resolve_dns_periodically:
            return
        interval = max(1, int(config.agent_collector_grpc_channel_check_interval))
        logger.info(
            'Periodic collector DNS re-resolve enabled for aio (interval=%ss)',
            interval,
        )
        while not self._closed:
            try:
                await asyncio.sleep(interval)
                if self._closed:
                    return
                await self.maybe_reresolve_dns()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log_dns_reresolve_failure_throttled('Periodic aio collector DNS re-resolve failed')

    def is_ready(self) -> bool:
        """
        Prefer watch-maintained state as source of truth.

        When state is None or IDLE, peek+nudge via get_state(True) and apply the
        result under the channel generation captured for this peek so a concurrent
        DNS rebuild cannot publish a stale connectivity state.
        """
        if self.state == grpc.ChannelConnectivity.READY:
            return True
        if self.state in (None, grpc.ChannelConnectivity.IDLE):
            generation = self._channel_generation
            channel = self.channel
            try:
                peeked = channel.get_state(True)
                if peeked is not None:
                    self._on_connectivity(peeked, generation=generation)
            except Exception:  # noqa: BLE001
                is_channel_ready(channel)
        return self.state == grpc.ChannelConnectivity.READY

    def _on_connectivity(self, state, generation=None) -> None:
        if generation is not None and generation != self._channel_generation:
            return
        prev = self.state
        service_management = self.service_management
        if logger_debug_enabled:
            logger.debug('grpc aio channel connectivity changed, [%s -> %s]', prev, state)
        apply_connectivity_transition(prev, state)
        if prev == grpc.ChannelConnectivity.READY and state != grpc.ChannelConnectivity.READY:
            if generation is not None and generation != self._channel_generation:
                return
            self.properties_sent.clear()
            service_management.sent_properties_counter = 0
        if generation is not None and generation != self._channel_generation:
            return
        self.state = state

    async def watch_connectivity(self):
        """
        Background watch: aio equivalent of sync Channel.subscribe.
        get_state(True) nudges IDLE; wait_for_state_change blocks until transition.
        Rebinds to self.channel after DNS rebuild (generation + Event wake; old.close
        is best-effort and must not be the only wake path).
        """
        while not self._closed:
            generation = self._channel_generation
            channel = self.channel
            try:
                state = channel.get_state(try_to_connect=True)
                if generation != self._channel_generation or self._closed:
                    continue
                self._on_connectivity(state, generation=generation)
                self._channel_changed.clear()
                # Rebuild may have raced between clear() and wait().
                if generation != self._channel_generation or self._closed:
                    continue
                wait_state = asyncio.create_task(channel.wait_for_state_change(state))
                wait_wake = asyncio.create_task(self._channel_changed.wait())
                done, pending = await asyncio.wait(
                    {wait_state, wait_wake},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for task in pending:
                    task.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await task
                for task in done:
                    with contextlib.suppress(Exception):
                        task.result()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - keep watch alive across transient errors
                if generation != self._channel_generation or self._closed:
                    continue
                if logger_debug_enabled:
                    logger.debug('aio connectivity watch error', exc_info=True)
                await asyncio.sleep(1.0)

    async def query_profile_commands(self):
        if not self.is_ready():
            return
        if logger_debug_enabled:
            logger.debug('query profile commands')
        await self.profile_channel.do_query()

    async def notify_profile_task_finish(self, task: ProfileTask):
        if not self.is_ready():
            return
        await self.profile_channel.finish(task)

    async def heartbeat(self):
        if not self.is_ready():
            return
        if not self.properties_sent.is_set():
            try:
                await self.service_management.send_instance_props()
                self.properties_sent.set()
            except grpc.aio.AioRpcError as e:
                handle_rpc_error(e, self.on_error)
        try:
            await self.service_management.send_heart_beat()
        except grpc.aio.AioRpcError as e:
            handle_rpc_error(e, self.on_error)
            raise

    def on_error(self):
        if logger_debug_enabled:
            logger.debug('error occurred in grpc protocol (Async)')
        # Never rebuild / rotate the channel on RPC errors (auth or otherwise).
        # DEADLINE_EXCEEDED on READY is not a connectivity failure; see handle_rpc_error.
        traceback.print_exc() if logger.isEnabledFor(logging.DEBUG) else None

    def begin_shutdown(self) -> None:
        """
        Mark closed and wake watches before canceling background tasks.

        Call this from agent shutdown *before* cancelling watch_dns /
        watch_connectivity so in-flight to_thread DNS work refuses to bind,
        even if CancelledError is slow to deliver.
        """
        if self._closed:
            self._notify_channel_changed()
            return
        self._closed = True
        self._channel_generation += 1
        self._notify_channel_changed()

    def close(self):
        """Best-effort channel teardown on agent stop (Node shutdownNow parity)."""
        self.begin_shutdown()
        # grpc.aio.Channel.close is async; schedule on the running loop when possible.
        try:
            result = self.channel.close()
            if asyncio.iscoroutine(result):
                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    # Called off-loop (should not happen from __fini_async); drop.
                    result.close()
                    return
                loop.create_task(result)
        except Exception:  # noqa: BLE001
            pass

    async def aclose(self):
        """Await channel close from the agent event loop."""
        self.begin_shutdown()
        try:
            await self.channel.close()
        except Exception:  # noqa: BLE001
            pass

    async def report_segment(self, queue: Queue):
        # Gate before dequeue so disconnect windows keep segments in the queue.
        if not self.is_ready():
            return

        sent = 0

        async def generator():
            nonlocal sent
            while True:
                # Let eventloop schedule blocking instead of user configuration: `config.agent_queue_timeout`
                segment = await queue.get()  # type: Segment

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
            await self.traces_reporter.report(generator())
        except grpc.RpcError as e:
            if sent:
                log_dropped_throttled('segment', sent)
            handle_rpc_error(e, self.on_error)
            raise  # reraise so that incremental reconnect wait can process; failed batch discarded

    async def report_log(self, queue: Queue):
        if not self.is_ready():
            return

        sent = 0

        async def generator():
            nonlocal sent
            while True:
                # Let eventloop schedule blocking instead of user configuration: `config.agent_queue_timeout`
                log_data = await queue.get()  # type: LogData

                queue.task_done()
                sent += 1

                if logger_debug_enabled:
                    logger.debug('Reporting Log %s', log_data.timestamp)

                yield log_data

        try:
            await self.log_reporter.report(generator())
        except grpc.RpcError as e:
            if sent:
                log_dropped_throttled('log', sent)
            handle_rpc_error(e, self.on_error)
            raise

    async def report_meter(self, queue: Queue):
        if not self.is_ready():
            return

        sent = 0

        async def generator():
            nonlocal sent
            while True:
                # Let eventloop schedule blocking instead of user configuration: `config.agent_queue_timeout`
                meter_data = await queue.get()  # type: MeterData

                queue.task_done()
                sent += 1

                if logger_debug_enabled:
                    logger.debug('Reporting Meter %s', meter_data.timestamp)

                yield meter_data

        try:
            await self.meter_reporter.report(generator())
        except grpc.RpcError as e:
            if sent:
                log_dropped_throttled('meter', sent)
            handle_rpc_error(e, self.on_error)
            raise

    async def report_snapshot(self, queue: Queue):
        if not self.is_ready():
            return

        sent = 0

        async def generator():
            nonlocal sent
            while True:
                # Let eventloop schedule blocking instead of user configuration: `config.agent_queue_timeout`
                snapshot = await queue.get()  # type: TracingThreadSnapshot

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
            await self.profile_channel.report(generator())
        except grpc.RpcError as e:
            if sent:
                log_dropped_throttled('snapshot', sent)
            handle_rpc_error(e, self.on_error)
            raise
