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

import queue
import unittest
from unittest.mock import MagicMock, patch

import grpc

from skywalking import config
from skywalking.client.grpc import GrpcConfigurationDiscoveryChannelService
from skywalking.command import command_service
from skywalking.command.command_service import command_executor_service
from skywalking.command.configuration_discovery_command import ConfigurationDiscoveryCommand
from skywalking.conf.dynamic import SAMPLE_N_PROPERTY_KEY, configuration_discovery_service
from skywalking.protocol.common.Command_pb2 import Command, Commands
from skywalking.protocol.common.Common_pb2 import KeyStringValuePair
from skywalking.sampling.sampling_service import SamplingService


def _reset_cds():
    configuration_discovery_service._uuid = None
    configuration_discovery_service._watchers.clear()


def _reset_command_queue():
    while True:
        try:
            command_service._commands.get_nowait()
        except queue.Empty:
            break
    command_service._command_serial_number_cache.queue.clear()


def _drain_and_execute_commands():
    """Execute commands queued by receive_command (dispatch thread is not running in unit tests)."""
    while True:
        try:
            cmd = command_service._commands.get_nowait()
        except queue.Empty:
            return
        command_executor_service.execute(cmd)
        command_service._command_serial_number_cache.add(cmd.serial_number)


def _cds_commands(uuid: str, rate: str, serial: str) -> Commands:
    command = Command(command=ConfigurationDiscoveryCommand.NAME)
    command.args.append(KeyStringValuePair(key='UUID', value=uuid))
    command.args.append(KeyStringValuePair(key='SerialNumber', value=serial))
    command.args.append(KeyStringValuePair(key=SAMPLE_N_PROPERTY_KEY, value=rate))
    return Commands(commands=[command])


class TestConfigurationDiscoverySampling(unittest.TestCase):
    """Java SamplingRateWatcherTest parity for agent.sample_n_per_3_secs."""

    def setUp(self):
        _reset_cds()
        self._prev_rate = config.sample_n_per_3_secs
        config.sample_n_per_3_secs = 0

    def tearDown(self):
        config.sample_n_per_3_secs = self._prev_rate
        _reset_cds()

    def _service_with_watcher(self) -> SamplingService:
        service = SamplingService()
        service.register_cds_watcher()
        return service

    def test_bootstrap_rate_zero_accepts_all(self):
        service = self._service_with_watcher()
        self.assertFalse(service._on)
        for _ in range(5):
            self.assertTrue(service.try_sampling())

    def test_modify_enables_sampling(self):
        service = self._service_with_watcher()
        configuration_discovery_service.handle_configuration_discovery_command(
            ConfigurationDiscoveryCommand(
                serial_number='1',
                uuid='u1',
                config=[(SAMPLE_N_PROPERTY_KEY, '2')],
            )
        )
        self.assertEqual(2, service.get_sampling_rate())
        self.assertTrue(service.try_sampling())
        self.assertTrue(service.try_sampling())
        self.assertFalse(service.try_sampling())

    def test_same_uuid_short_circuits(self):
        service = self._service_with_watcher()
        cmd = ConfigurationDiscoveryCommand(
            serial_number='1',
            uuid='same',
            config=[(SAMPLE_N_PROPERTY_KEY, '1')],
        )
        configuration_discovery_service.handle_configuration_discovery_command(cmd)
        self.assertEqual(1, service.get_sampling_rate())
        # Second apply with same UUID must not change rate even if payload differs.
        configuration_discovery_service.handle_configuration_discovery_command(
            ConfigurationDiscoveryCommand(
                serial_number='2',
                uuid='same',
                config=[(SAMPLE_N_PROPERTY_KEY, '99')],
            )
        )
        self.assertEqual(1, service.get_sampling_rate())
        self.assertEqual('same', configuration_discovery_service.peek_uuid())

    def test_delete_restores_bootstrap_default(self):
        config.sample_n_per_3_secs = 3
        service = self._service_with_watcher()
        configuration_discovery_service.handle_configuration_discovery_command(
            ConfigurationDiscoveryCommand(
                serial_number='1',
                uuid='u1',
                config=[(SAMPLE_N_PROPERTY_KEY, '1')],
            )
        )
        self.assertEqual(1, service.get_sampling_rate())
        # Omitted key => DELETE for registered watchers (Java readConfig).
        configuration_discovery_service.handle_configuration_discovery_command(
            ConfigurationDiscoveryCommand(serial_number='2', uuid='u2', config=[])
        )
        self.assertEqual(3, service.get_sampling_rate())
        self.assertTrue(service._on)

    def test_invalid_value_ignored(self):
        service = self._service_with_watcher()
        configuration_discovery_service.handle_configuration_discovery_command(
            ConfigurationDiscoveryCommand(
                serial_number='1',
                uuid='u1',
                config=[(SAMPLE_N_PROPERTY_KEY, 'not-int')],
            )
        )
        self.assertEqual(0, service.get_sampling_rate())
        self.assertFalse(service._on)

    def test_peek_uuid_resets_when_watcher_registered(self):
        self.assertIsNone(configuration_discovery_service.peek_uuid())
        configuration_discovery_service._uuid = 'cached'
        service = self._service_with_watcher()
        self.assertIsNotNone(service)
        # New watcher registration clears UUID so OAP pushes a full config.
        self.assertIsNone(configuration_discovery_service.peek_uuid())

    def test_deserialize_command(self):
        command = Command(command=ConfigurationDiscoveryCommand.NAME)
        command.args.append(KeyStringValuePair(key='UUID', value='abc'))
        command.args.append(KeyStringValuePair(key='SerialNumber', value='sn-1'))
        command.args.append(KeyStringValuePair(key=SAMPLE_N_PROPERTY_KEY, value='5'))
        parsed = ConfigurationDiscoveryCommand.deserialize(command)
        self.assertEqual('abc', parsed.uuid)
        self.assertEqual('sn-1', parsed.serial_number)
        self.assertEqual([(SAMPLE_N_PROPERTY_KEY, '5')], parsed.config)


class TestConfigurationDiscoveryPullPath(unittest.TestCase):
    """
    Mock gRPC fetchConfigurations pull path:
    sync -> stub.fetchConfigurations -> receive_command -> executor -> SamplingRateWatcher.
    """

    def setUp(self):
        _reset_cds()
        _reset_command_queue()
        self._prev_rate = config.sample_n_per_3_secs
        self._prev_name = config.agent_name
        config.sample_n_per_3_secs = 0
        config.agent_name = 'cds-pull-test-service'
        self.sampling = SamplingService()
        self.sampling.register_cds_watcher()

        with patch(
            'skywalking.client.grpc.ConfigurationDiscoveryServiceStub',
            return_value=MagicMock(),
        ):
            self.cds = GrpcConfigurationDiscoveryChannelService(MagicMock())
        self.captured_requests = []

    def tearDown(self):
        config.sample_n_per_3_secs = self._prev_rate
        config.agent_name = self._prev_name
        _reset_command_queue()
        _reset_cds()

    def _stub_responses(self, *responses):
        queue_responses = list(responses)

        def _fetch(request, timeout=None):
            self.captured_requests.append(request)
            if not queue_responses:
                raise AssertionError('unexpected extra fetchConfigurations call')
            item = queue_responses.pop(0)
            if isinstance(item, Exception):
                raise item
            return item

        self.cds._stub.fetchConfigurations = MagicMock(side_effect=_fetch)

    def test_pull_applies_rate_and_sends_uuid_on_next_poll(self):
        self._stub_responses(
            _cds_commands(uuid='uuid-1', rate='3', serial='sn-1'),
            Commands(),  # same config: OAP returns empty Commands when UUID matches
        )

        self.cds.sync()
        _drain_and_execute_commands()

        self.assertEqual(1, len(self.captured_requests))
        self.assertEqual('cds-pull-test-service', self.captured_requests[0].service)
        self.assertFalse(self.captured_requests[0].uuid)
        self.assertEqual(3, self.sampling.get_sampling_rate())
        self.assertEqual('uuid-1', configuration_discovery_service.peek_uuid())

        self.cds.sync()
        _drain_and_execute_commands()

        self.assertEqual(2, len(self.captured_requests))
        self.assertEqual('uuid-1', self.captured_requests[1].uuid)
        # Empty Commands must not change the applied rate.
        self.assertEqual(3, self.sampling.get_sampling_rate())

    def test_pull_same_uuid_empty_commands_keeps_rate(self):
        self._stub_responses(
            _cds_commands(uuid='same', rate='2', serial='sn-a'),
            Commands(),
            _cds_commands(uuid='same', rate='99', serial='sn-b'),  # should be ignored by CDS uuid short-circuit
        )

        self.cds.sync()
        _drain_and_execute_commands()
        self.assertEqual(2, self.sampling.get_sampling_rate())

        self.cds.sync()
        _drain_and_execute_commands()
        self.assertEqual(2, self.sampling.get_sampling_rate())

        # Even if a stale payload arrives with the same UUID, rate stays.
        self.cds.sync()
        _drain_and_execute_commands()
        self.assertEqual(2, self.sampling.get_sampling_rate())

    def test_pull_unimplemented_warns_once(self):
        class FakeUnimplemented(grpc.RpcError):
            def code(self):
                return grpc.StatusCode.UNIMPLEMENTED

        self._stub_responses(FakeUnimplemented(), FakeUnimplemented())

        with patch('skywalking.client.grpc.logger') as mock_logger:
            self.cds.sync()
            self.cds.sync()
            self.assertEqual(1, mock_logger.warning.call_count)
            self.assertIn(
                'ConfigurationDiscoveryService',
                mock_logger.warning.call_args[0][0],
            )

        self.assertTrue(self.cds._cds_unimplemented)
        self.assertEqual(0, self.sampling.get_sampling_rate())
        # Second call short-circuits before RPC.
        self.assertEqual(1, self.cds._stub.fetchConfigurations.call_count)


if __name__ == '__main__':
    unittest.main()
