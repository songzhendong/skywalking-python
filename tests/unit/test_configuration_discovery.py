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
from skywalking.conf.dynamic import (
    IGNORE_PATH_KEY,
    IGNORE_SUFFIX_KEY,
    SAMPLE_N_PROPERTY_KEY,
    SPAN_LIMIT_KEY,
    SQL_PARAMETERS_KEY,
    configuration_discovery_service,
)
from skywalking.conf.dynamic.agent_watchers import (
    SpanLimitWatcher,
    TraceSqlParametersWatcher,
    register_agent_dynamic_watchers,
    reset_bootstrap_defaults_for_tests,
)
from skywalking.protocol.common.Command_pb2 import Command, Commands
from skywalking.protocol.common.Common_pb2 import KeyStringValuePair
from skywalking.sampling.sampling_service import SamplingService


def _reset_cds():
    configuration_discovery_service._uuid = None
    configuration_discovery_service._watchers.clear()
    reset_bootstrap_defaults_for_tests()


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
        # Mirror CommandService.dispatch: only remember serial when execute is not False.
        if command_executor_service.execute(cmd) is not False and cmd.serial_number:
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
        # Rejected value must not commit UUID, so a later correction is applied.
        self.assertIsNone(configuration_discovery_service.peek_uuid())
        configuration_discovery_service.handle_configuration_discovery_command(
            ConfigurationDiscoveryCommand(
                serial_number='2',
                uuid='u2',
                config=[(SAMPLE_N_PROPERTY_KEY, '4')],
            )
        )
        self.assertEqual(4, service.get_sampling_rate())
        self.assertEqual('u2', configuration_discovery_service.peek_uuid())

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

    def test_deserialize_uuid_only_keeps_empty_serial(self):
        command = Command(command=ConfigurationDiscoveryCommand.NAME)
        command.args.append(KeyStringValuePair(key='UUID', value='abc'))
        command.args.append(KeyStringValuePair(key=SAMPLE_N_PROPERTY_KEY, value='5'))
        parsed = ConfigurationDiscoveryCommand.deserialize(command)
        self.assertEqual('abc', parsed.uuid)
        self.assertEqual('', parsed.serial_number)


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

        self.assertTrue(self.cds._cds_unimplemented_warned)
        self.assertEqual(0, self.sampling.get_sampling_rate())
        # Later polls still call OAP so CDS can recover when the method appears.
        self.assertEqual(2, self.cds._stub.fetchConfigurations.call_count)

    def test_pull_reject_does_not_cache_serial(self):
        """Executor must propagate False so dispatch does not remember a bad serial."""
        self._stub_responses(
            _cds_commands(uuid='bad-uuid', rate='not-int', serial='sn-bad'),
            _cds_commands(uuid='good-uuid', rate='2', serial='sn-bad'),  # same serial, corrected value
        )

        self.cds.sync()
        _drain_and_execute_commands()
        self.assertEqual(0, self.sampling.get_sampling_rate())
        self.assertIsNone(configuration_discovery_service.peek_uuid())
        self.assertFalse(
            command_service._command_serial_number_cache.contains('sn-bad'),
        )

        # Same serial must still be accepted once the value is valid.
        self.cds.sync()
        _drain_and_execute_commands()
        self.assertEqual(2, self.sampling.get_sampling_rate())
        self.assertEqual('good-uuid', configuration_discovery_service.peek_uuid())
        self.assertTrue(
            command_service._command_serial_number_cache.contains('sn-bad'),
        )


class TestConfigurationDiscoveryHardening(unittest.TestCase):
    """Fork remount, empty serial cache, async command queue init."""

    def setUp(self):
        _reset_cds()
        _reset_command_queue()
        self._prev_rate = config.sample_n_per_3_secs
        config.sample_n_per_3_secs = 0

    def tearDown(self):
        config.sample_n_per_3_secs = self._prev_rate
        _reset_command_queue()
        _reset_cds()

    def test_force_remount_replaces_watcher(self):
        """Fork/force re-init must rebind CDS to the new SamplingService."""
        from skywalking import sampling as sampling_mod

        prev = sampling_mod.sampling_service
        try:
            sampling_mod.sampling_service = None
            sampling_mod.init(force=False)
            first = sampling_mod.sampling_service
            configuration_discovery_service._uuid = 'stale-parent-uuid'

            sampling_mod.init(force=True)
            second = sampling_mod.sampling_service
            self.assertIsNot(first, second)
            self.assertIsNone(configuration_discovery_service.peek_uuid())

            configuration_discovery_service.handle_configuration_discovery_command(
                ConfigurationDiscoveryCommand(
                    serial_number='sn-remount',
                    uuid='child-uuid',
                    config=[(SAMPLE_N_PROPERTY_KEY, '4')],
                )
            )
            self.assertEqual(4, second.get_sampling_rate())
            # Parent instance must not receive the CDS update.
            self.assertEqual(0, first.get_sampling_rate())
        finally:
            sampling_mod.sampling_service = prev

    def test_duplicate_register_ignored_without_replace(self):
        first = SamplingService()
        first.register_cds_watcher()
        second = SamplingService()
        second.register_cds_watcher(replace=False)
        configuration_discovery_service.handle_configuration_discovery_command(
            ConfigurationDiscoveryCommand(
                serial_number='sn-dup',
                uuid='u-dup',
                config=[(SAMPLE_N_PROPERTY_KEY, '7')],
            )
        )
        self.assertEqual(7, first.get_sampling_rate())
        self.assertEqual(0, second.get_sampling_rate())

    def test_duplicate_register_does_not_wipe_cds_config(self):
        """replace=False must not construct watchers that reset live config to bootstrap."""
        config.agent_ignore_suffix = '.jpg'
        config.agent_span_limit_per_segment = 300
        config.finalize_regex()
        first = SamplingService()
        first.register_cds_watcher()
        configuration_discovery_service.handle_configuration_discovery_command(
            ConfigurationDiscoveryCommand(
                serial_number='sn-wipe',
                uuid='u-wipe',
                config=[
                    (IGNORE_SUFFIX_KEY, '.txt'),
                    (SPAN_LIMIT_KEY, '1'),
                ],
            )
        )
        self.assertEqual('.txt', config.agent_ignore_suffix)
        self.assertEqual(1, config.agent_span_limit_per_segment)

        second = SamplingService()
        second.register_cds_watcher(replace=False)
        self.assertEqual('.txt', config.agent_ignore_suffix)
        self.assertEqual(1, config.agent_span_limit_per_segment)

    def test_empty_serial_does_not_poison_cache(self):
        _reset_command_queue()
        cmd1 = Command(command=ConfigurationDiscoveryCommand.NAME)
        cmd1.args.append(KeyStringValuePair(key=SAMPLE_N_PROPERTY_KEY, value='1'))
        cmd2 = Command(command=ConfigurationDiscoveryCommand.NAME)
        cmd2.args.append(KeyStringValuePair(key=SAMPLE_N_PROPERTY_KEY, value='2'))
        # No SerialNumber / UUID → empty serial after deserialize.
        command_service.receive_command(Commands(commands=[cmd1]))
        command_service.receive_command(Commands(commands=[cmd2]))
        queued = []
        while True:
            try:
                queued.append(command_service._commands.get_nowait())
            except queue.Empty:
                break
        self.assertEqual(2, len(queued))

    def test_uuid_only_serial_does_not_poison_cache(self):
        """UUID must not be copied into serial_number or the cache blocks re-dispatch."""
        _reset_command_queue()
        SamplingService().register_cds_watcher()
        cmd = Command(command=ConfigurationDiscoveryCommand.NAME)
        cmd.args.append(KeyStringValuePair(key='UUID', value='same-uuid'))
        cmd.args.append(KeyStringValuePair(key=SAMPLE_N_PROPERTY_KEY, value='1'))
        command_service.receive_command(Commands(commands=[cmd]))
        _drain_and_execute_commands()
        self.assertFalse(
            command_service._command_serial_number_cache.contains('same-uuid'),
        )
        # Same UUID-only payload can be queued again (dedupe is CDS uuid short-circuit).
        command_service.receive_command(Commands(commands=[cmd]))
        queued = []
        while True:
            try:
                queued.append(command_service._commands.get_nowait())
            except queue.Empty:
                break
        self.assertEqual(1, len(queued))
        self.assertEqual('', queued[0].serial_number)

    def test_async_command_queue_ready_before_dispatch(self):
        from skywalking.command.command_service import CommandServiceAsync

        svc = CommandServiceAsync()
        self.assertTrue(hasattr(svc, '_commands'))
        svc.receive_command(Commands())  # must not raise AttributeError


class TestAdditionalCdsKeys(unittest.TestCase):
    def setUp(self):
        _reset_cds()
        self._prev = (
            config.agent_ignore_suffix,
            config.agent_trace_ignore_path,
            config.agent_span_limit_per_segment,
            config.plugin_sql_parameters_max_length,
        )

    def tearDown(self):
        (
            config.agent_ignore_suffix,
            config.agent_trace_ignore_path,
            config.agent_span_limit_per_segment,
            config.plugin_sql_parameters_max_length,
        ) = self._prev
        config.finalize_regex()
        _reset_cds()

    def _apply(self, pairs):
        register_agent_dynamic_watchers()
        configuration_discovery_service.handle_configuration_discovery_command(
            ConfigurationDiscoveryCommand(serial_number='sn', uuid='u', config=pairs)
        )

    def test_ignore_suffix_and_path_rebuild_matcher(self):
        config.agent_ignore_suffix = '.jpg'
        config.agent_trace_ignore_path = ''
        config.finalize_regex()
        self._apply([
            (IGNORE_SUFFIX_KEY, '.txt'),
            (IGNORE_PATH_KEY, '/health/**'),
        ])
        self.assertTrue(config.RE_IGNORE_PATH.match('file.txt'))
        self.assertFalse(config.RE_IGNORE_PATH.match('file.jpg'))
        self.assertTrue(config.RE_IGNORE_PATH.match('/health/live'))
        # Omitted keys restore bootstrap.
        configuration_discovery_service.handle_configuration_discovery_command(
            ConfigurationDiscoveryCommand(serial_number='sn2', uuid='u2', config=[])
        )
        self.assertEqual('.jpg', config.agent_ignore_suffix)
        self.assertEqual('', config.agent_trace_ignore_path)
        self.assertTrue(config.RE_IGNORE_PATH.match('file.jpg'))
        self.assertFalse(config.RE_IGNORE_PATH.match('/health/live'))

    def test_span_limit_drops_extra_spans(self):
        from unittest.mock import patch

        from skywalking.trace.context import SpanContext
        from skywalking.trace.span import NoopSpan

        config.agent_span_limit_per_segment = 300
        self._apply([(SPAN_LIMIT_KEY, '1')])
        self.assertEqual(1, config.agent_span_limit_per_segment)
        with patch('skywalking.trace.context.agent.is_segment_queue_full', return_value=False):
            ctx = SpanContext()
            first = ctx.new_local_span('one')
            self.assertNotIsInstance(first, NoopSpan)
            ctx.start(first)
            second = ctx.new_local_span('two')
            self.assertIsInstance(second, NoopSpan)
            self.assertTrue(ctx.segment.is_size_limited)
        configuration_discovery_service.handle_configuration_discovery_command(
            ConfigurationDiscoveryCommand(serial_number='sn2', uuid='u2', config=[])
        )
        self.assertEqual(300, config.agent_span_limit_per_segment)

    def test_span_limit_invalid_keeps_previous(self):
        config.agent_span_limit_per_segment = 300
        watcher = SpanLimitWatcher()
        configuration_discovery_service.register_agent_config_change_watcher(watcher)
        configuration_discovery_service.handle_configuration_discovery_command(
            ConfigurationDiscoveryCommand(
                serial_number='sn', uuid='u', config=[(SPAN_LIMIT_KEY, 'nope')]
            )
        )
        self.assertEqual(300, config.agent_span_limit_per_segment)
        self.assertIsNone(configuration_discovery_service.peek_uuid())

    def test_sql_parameters_boolean(self):
        config.plugin_sql_parameters_max_length = 0
        watcher = TraceSqlParametersWatcher()
        configuration_discovery_service.register_agent_config_change_watcher(watcher)
        configuration_discovery_service.handle_configuration_discovery_command(
            ConfigurationDiscoveryCommand(
                serial_number='sn', uuid='u1', config=[(SQL_PARAMETERS_KEY, 'true')]
            )
        )
        self.assertEqual(512, config.plugin_sql_parameters_max_length)
        configuration_discovery_service.handle_configuration_discovery_command(
            ConfigurationDiscoveryCommand(
                serial_number='sn2', uuid='u2', config=[(SQL_PARAMETERS_KEY, 'false')]
            )
        )
        self.assertEqual(0, config.plugin_sql_parameters_max_length)
        configuration_discovery_service.handle_configuration_discovery_command(
            ConfigurationDiscoveryCommand(serial_number='sn3', uuid='u3', config=[])
        )
        self.assertEqual(0, config.plugin_sql_parameters_max_length)

    def test_sql_parameters_delete_restores_positive_bootstrap(self):
        config.plugin_sql_parameters_max_length = 100
        watcher = TraceSqlParametersWatcher()
        configuration_discovery_service.register_agent_config_change_watcher(watcher)
        configuration_discovery_service.handle_configuration_discovery_command(
            ConfigurationDiscoveryCommand(
                serial_number='sn', uuid='u1', config=[(SQL_PARAMETERS_KEY, 'false')]
            )
        )
        self.assertEqual(0, config.plugin_sql_parameters_max_length)
        configuration_discovery_service.handle_configuration_discovery_command(
            ConfigurationDiscoveryCommand(serial_number='sn2', uuid='u2', config=[])
        )
        self.assertEqual(100, config.plugin_sql_parameters_max_length)

    def test_unknown_oap_key_is_warned_and_ignored(self):
        register_agent_dynamic_watchers()
        with patch('skywalking.conf.dynamic.configuration_discovery_service.logger') as mock_logger:
            configuration_discovery_service.handle_configuration_discovery_command(
                ConfigurationDiscoveryCommand(
                    serial_number='sn',
                    uuid='u-unknown',
                    config=[('agent.unknown.cds.key', 'x'), (SPAN_LIMIT_KEY, '10')],
                )
            )
            self.assertTrue(
                any(
                    'agent.unknown.cds.key' in str(call)
                    for call in mock_logger.warning.call_args_list
                )
            )
        self.assertEqual(10, config.agent_span_limit_per_segment)
        self.assertEqual('u-unknown', configuration_discovery_service.peek_uuid())

    def test_remount_delete_restores_original_bootstrap(self):
        """replace=True must not capture the last CDS value as the new DELETE default."""
        config.agent_ignore_suffix = '.jpg'
        config.agent_trace_ignore_path = ''
        config.agent_span_limit_per_segment = 300
        config.plugin_sql_parameters_max_length = 100
        config.finalize_regex()
        register_agent_dynamic_watchers()
        configuration_discovery_service.handle_configuration_discovery_command(
            ConfigurationDiscoveryCommand(
                serial_number='sn1',
                uuid='u1',
                config=[
                    (IGNORE_SUFFIX_KEY, '.txt'),
                    (SPAN_LIMIT_KEY, '1'),
                    (SQL_PARAMETERS_KEY, 'false'),
                ],
            )
        )
        self.assertEqual('.txt', config.agent_ignore_suffix)
        self.assertEqual(1, config.agent_span_limit_per_segment)
        self.assertEqual(0, config.plugin_sql_parameters_max_length)

        register_agent_dynamic_watchers(replace=True)
        # Remount must restore bootstrap into live config immediately (not wait for DELETE).
        self.assertEqual('.jpg', config.agent_ignore_suffix)
        self.assertEqual(300, config.agent_span_limit_per_segment)
        self.assertEqual(100, config.plugin_sql_parameters_max_length)

        configuration_discovery_service.handle_configuration_discovery_command(
            ConfigurationDiscoveryCommand(serial_number='sn2', uuid='u2', config=[])
        )
        self.assertEqual('.jpg', config.agent_ignore_suffix)
        self.assertEqual(300, config.agent_span_limit_per_segment)
        self.assertEqual(100, config.plugin_sql_parameters_max_length)


if __name__ == '__main__':
    unittest.main()
