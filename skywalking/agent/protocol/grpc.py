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
from time import monotonic

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
    handle_rpc_error,
    is_channel_ready,
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


def _queue_get_within_batch(queue: Queue, block: bool, batch_deadline: float):
    """
    Get one item within an absolute batch window (monotonic deadline).

    Avoids int(elapsed) truncation that could let queue waits approach
    agent_queue_timeout + 1s and collide with a tight RPC deadline.
    Returns None when the window is exhausted or the queue is empty.
    """
    remaining = batch_deadline - monotonic()
    if remaining <= 0:
        return None
    try:
        if block:
            return queue.get(block=True, timeout=remaining)
        return queue.get(block=False)
    except Empty:
        return None


class GrpcProtocol(Protocol):
    def __init__(self):
        self.properties_sent = False
        self.state = None

        # One channel for process lifetime; multi-address failover via gRPC pick_first.
        self.channel = create_sync_channel()

        if config.agent_authentication:
            self.channel = grpc.intercept_channel(
                self.channel, header_adder_interceptor('authentication', config.agent_authentication)
            )

        self.service_management = GrpcServiceManagementClient(self.channel)
        self.traces_reporter = GrpcTraceSegmentReportService(self.channel)
        self.profile_channel = GrpcProfileTaskChannelService(self.channel)
        self.log_reporter = GrpcLogDataReportService(self.channel)
        self.meter_reporter = GrpcMeterReportService(self.channel)

        # Subscribe last: _cb runs on a grpc thread and touches service_management.
        self.channel.subscribe(self._cb, try_to_connect=True)

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

    def _cb(self, state):
        prev = self.state
        if logger_debug_enabled:
            logger.debug('grpc channel connectivity changed, [%s -> %s]', prev, state)
        try:
            apply_connectivity_transition(prev, state)
            # Independent OAPs need properties re-registered after failover.
            # Immediate send via properties_sent; periodic refresh covers silent READY switches.
            if prev == grpc.ChannelConnectivity.READY and state != grpc.ChannelConnectivity.READY:
                self.properties_sent = False
                self.service_management.sent_properties_counter = 0
        except Exception:  # noqa: BLE001 - never let grpc's connectivity thread die on us
            logger.exception('failed to handle grpc connectivity transition')
        self.state = state

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
        self.channel.unsubscribe(self._cb)
        self.channel.subscribe(self._cb, try_to_connect=True)

    def close(self):
        """Best-effort channel teardown on agent stop (Node shutdownNow parity)."""
        try:
            self.channel.unsubscribe(self._cb)
        except Exception:  # noqa: BLE001
            pass
        try:
            self.channel.close()
        except Exception:  # noqa: BLE001
            pass

    def report_segment(self, queue: Queue, block: bool = True):
        # Gate before dequeue so disconnect windows keep segments in the queue (Node buffer parity).
        if not self.is_ready():
            return
        sent = 0

        def generator():
            nonlocal sent

            batch_deadline = monotonic() + float(config.agent_queue_timeout)
            while True:
                segment = _queue_get_within_batch(queue, block, batch_deadline)  # type: Segment
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
            while True:
                log_data = _queue_get_within_batch(queue, block, batch_deadline)  # type: LogData
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
            while True:
                meter_data = _queue_get_within_batch(queue, block, batch_deadline)  # type: MeterData
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
            while True:
                snapshot = _queue_get_within_batch(queue, block, batch_deadline)  # type: TracingThreadSnapshot
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
