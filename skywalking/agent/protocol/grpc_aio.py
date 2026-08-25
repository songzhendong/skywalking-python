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
from asyncio import Queue, Event

import grpc

from skywalking import config
from skywalking.agent.protocol import ProtocolAsync
from skywalking.agent.protocol.interceptors_aio import header_adder_interceptor_async
from skywalking.client.grpc_aio import GrpcServiceManagementClientAsync, GrpcTraceSegmentReportServiceAsync, \
    GrpcProfileTaskChannelServiceAsync, GrpcLogReportServiceAsync, GrpcMeterReportServiceAsync
from skywalking.loggings import logger, logger_debug_enabled
from skywalking.utils.grpc_channel import (
    apply_connectivity_transition,
    create_aio_channel,
    handle_rpc_error,
    is_channel_ready,
    log_dropped_throttled,
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

        # grpc.aio has no Channel.subscribe(); watch_connectivity() mirrors Node
        # watchConnectivityState via wait_for_state_change (started by the agent loop).

        interceptors = None
        if config.agent_authentication:
            interceptors = [header_adder_interceptor_async('authentication', config.agent_authentication)]

        # One channel for process lifetime; multi-address failover via gRPC pick_first.
        self.channel = create_aio_channel(interceptors=interceptors)

        self.service_management = GrpcServiceManagementClientAsync(self.channel)
        self.traces_reporter = GrpcTraceSegmentReportServiceAsync(self.channel)
        self.log_reporter = GrpcLogReportServiceAsync(self.channel)
        self.meter_reporter = GrpcMeterReportServiceAsync(self.channel)
        self.profile_channel = GrpcProfileTaskChannelServiceAsync(self.channel)

    def is_ready(self) -> bool:
        """Prefer watch-maintained state; peek+nudge when IDLE/None before watch catches up."""
        if self.state == grpc.ChannelConnectivity.READY:
            return True
        if self.state in (None, grpc.ChannelConnectivity.IDLE):
            try:
                peeked = self.channel.get_state(True)
                if peeked is not None:
                    self._on_connectivity(peeked)
            except Exception:  # noqa: BLE001
                is_channel_ready(self.channel)
        return self.state == grpc.ChannelConnectivity.READY

    def _on_connectivity(self, state) -> None:
        prev = self.state
        if logger_debug_enabled:
            logger.debug('grpc aio channel connectivity changed, [%s -> %s]', prev, state)
        apply_connectivity_transition(prev, state)
        if prev == grpc.ChannelConnectivity.READY and state != grpc.ChannelConnectivity.READY:
            self.properties_sent.clear()
            self.service_management.sent_properties_counter = 0
        self.state = state

    async def watch_connectivity(self):
        """
        Background watch: aio equivalent of sync Channel.subscribe.
        get_state(True) nudges IDLE; wait_for_state_change blocks until transition.
        """
        while True:
            try:
                state = self.channel.get_state(try_to_connect=True)
                self._on_connectivity(state)
                await self.channel.wait_for_state_change(state)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - keep watch alive across transient errors
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

    def close(self):
        """Best-effort channel teardown on agent stop (Node shutdownNow parity)."""
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
