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

from skywalking import config
from skywalking.command.configuration_discovery_command import ConfigurationDiscoveryCommand
from skywalking.conf.dynamic import SAMPLE_N_PROPERTY_KEY, configuration_discovery_service
from skywalking.protocol.common.Command_pb2 import Command
from skywalking.protocol.common.Common_pb2 import KeyStringValuePair
from skywalking.sampling.sampling_service import SamplingService


def _reset_cds():
    configuration_discovery_service._uuid = None
    configuration_discovery_service._watchers.clear()


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


if __name__ == '__main__':
    unittest.main()
