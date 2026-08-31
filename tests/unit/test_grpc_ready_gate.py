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

import unittest
from unittest.mock import MagicMock, patch

import grpc

from skywalking.agent.protocol.grpc import GrpcProtocol


class TestSyncGrpcReadyGate(unittest.TestCase):

    def _protocol(self) -> GrpcProtocol:
        channel = MagicMock()
        with patch('skywalking.agent.protocol.grpc.create_sync_channel', return_value=channel), \
             patch('skywalking.agent.protocol.grpc.GrpcServiceManagementClient'), \
             patch('skywalking.agent.protocol.grpc.GrpcTraceSegmentReportService'), \
             patch('skywalking.agent.protocol.grpc.GrpcProfileTaskChannelService'), \
             patch('skywalking.agent.protocol.grpc.GrpcLogDataReportService'), \
             patch('skywalking.agent.protocol.grpc.GrpcMeterReportService'):
            return GrpcProtocol()

    def test_is_ready_follows_subscribe_state(self):
        protocol = self._protocol()
        self.assertFalse(protocol.is_ready())

        protocol.state = grpc.ChannelConnectivity.CONNECTING
        self.assertFalse(protocol.is_ready())

        protocol.state = grpc.ChannelConnectivity.READY
        self.assertTrue(protocol.is_ready())

        protocol.properties_sent = True
        protocol.service_management.sent_properties_counter = 7
        protocol._cb(grpc.ChannelConnectivity.TRANSIENT_FAILURE)
        self.assertFalse(protocol.properties_sent)
        self.assertEqual(protocol.service_management.sent_properties_counter, 0)

        protocol.state = grpc.ChannelConnectivity.IDLE
        with patch('skywalking.agent.protocol.grpc.is_channel_ready') as nudge:
            nudge.return_value = False
            self.assertFalse(protocol.is_ready())
            nudge.assert_called_once_with(protocol.channel)

    def test_heartbeat_keep_alive_after_instance_props_failure(self):
        class FakeRpcError(grpc.RpcError):
            def code(self):
                return grpc.StatusCode.UNAVAILABLE

            def details(self):
                return 'props failed'

        protocol = self._protocol()
        protocol.state = grpc.ChannelConnectivity.READY
        protocol.properties_sent = False
        protocol.service_management.send_instance_props = MagicMock(side_effect=FakeRpcError())
        protocol.service_management.send_heart_beat = MagicMock()
        protocol.heartbeat()
        protocol.service_management.send_heart_beat.assert_called_once()
        self.assertFalse(protocol.properties_sent)

    def test_failed_segment_batch_counts_drops(self):
        from queue import Queue

        class FakeRpcError(grpc.RpcError):
            def code(self):
                return grpc.StatusCode.UNAVAILABLE

            def details(self):
                return 'collect failed'

        protocol = self._protocol()
        protocol.state = grpc.ChannelConnectivity.READY
        protocol.on_error = MagicMock()

        segment = MagicMock()
        segment.related_traces = ['trace']
        segment.segment_id = 'seg'
        segment.is_size_limited = False
        segment.spans = []

        queue = Queue()
        queue.put(segment)

        def _report(generator):
            list(generator)
            raise FakeRpcError()

        protocol.traces_reporter.report = _report
        with patch('skywalking.agent.protocol.grpc.log_dropped_throttled') as dropped, \
             patch('skywalking.agent.protocol.grpc.SegmentObject', return_value=object()), \
             patch('skywalking.agent.protocol.grpc.handle_rpc_error'):
            with self.assertRaises(FakeRpcError):
                protocol.report_segment(queue, block=False)
            dropped.assert_called_with('segment', 1)

    def test_properties_refresh_every_factor_heartbeats(self):
        """Java/Node cadence: reportInstanceProperties every N keepAlive ticks."""
        from skywalking import config
        from skywalking.client import ServiceManagementClient

        class _Client(ServiceManagementClient):
            def send_instance_props(self) -> None:
                pass

        client = _Client()
        client.send_instance_props = MagicMock()

        prev = config.agent_collector_properties_report_period_factor
        try:
            config.agent_collector_properties_report_period_factor = 3
            client.refresh_instance_props()  # 1
            client.refresh_instance_props()  # 2
            self.assertEqual(client.send_instance_props.call_count, 0)
            client.refresh_instance_props()  # 3
            self.assertEqual(client.send_instance_props.call_count, 1)
            client.refresh_instance_props()  # 4
            client.refresh_instance_props()  # 5
            client.refresh_instance_props()  # 6
            self.assertEqual(client.send_instance_props.call_count, 2)
        finally:
            config.agent_collector_properties_report_period_factor = prev


class TestAsyncGrpcReadyGate(unittest.TestCase):

    def test_aio_is_ready_follows_watched_state(self):
        from skywalking.agent.protocol.grpc_aio import GrpcProtocolAsync

        channel = MagicMock()
        channel.get_state.return_value = grpc.ChannelConnectivity.CONNECTING
        with patch('skywalking.agent.protocol.grpc_aio.create_aio_channel', return_value=channel), \
             patch('skywalking.agent.protocol.grpc_aio.GrpcServiceManagementClientAsync'), \
             patch('skywalking.agent.protocol.grpc_aio.GrpcTraceSegmentReportServiceAsync'), \
             patch('skywalking.agent.protocol.grpc_aio.GrpcProfileTaskChannelServiceAsync'), \
             patch('skywalking.agent.protocol.grpc_aio.GrpcLogReportServiceAsync'), \
             patch('skywalking.agent.protocol.grpc_aio.GrpcMeterReportServiceAsync'):
            protocol = GrpcProtocolAsync()

        protocol.state = grpc.ChannelConnectivity.READY
        self.assertTrue(protocol.is_ready())
        protocol.properties_sent.set()
        protocol.service_management.sent_properties_counter = 4
        protocol._on_connectivity(grpc.ChannelConnectivity.TRANSIENT_FAILURE)
        self.assertFalse(protocol.properties_sent.is_set())
        self.assertEqual(protocol.service_management.sent_properties_counter, 0)
        protocol.state = grpc.ChannelConnectivity.TRANSIENT_FAILURE
        self.assertFalse(protocol.is_ready())


if __name__ == '__main__':
    unittest.main()
