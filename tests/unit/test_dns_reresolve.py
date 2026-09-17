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

import socket
import unittest
from unittest.mock import patch

import grpc

from skywalking import config
from skywalking.utils.grpc_channel import (
    prepare_grpc_channel_endpoints,
    parse_backend_addresses,
    resolve_collector_dial_plan,
)
import skywalking.utils.grpc_channel as grpc_channel_mod


def _gai(host, port, type=0, *args, **kwargs):
    mapping = {
        'oap.svc': [('10.0.0.1', port)],
        'oap-a': [('10.0.0.1', port)],
        'oap-b': [('10.0.0.2', port)],
    }
    if host not in mapping:
        raise socket.gaierror(socket.EAI_NONAME, 'nodename nor servname provided')
    return [
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, p))
        for ip, p in mapping[host]
    ]


class TestPeriodicDnsResolve(unittest.TestCase):
    def setUp(self):
        self._saved = (
            config.agent_collector_backend_services,
            config.agent_collector_is_resolve_dns_periodically,
            config.agent_collector_grpc_channel_check_interval,
            config.agent_authentication,
            config.agent_force_tls,
        )
        config.agent_collector_is_resolve_dns_periodically = False
        config.agent_collector_grpc_channel_check_interval = 30
        config.agent_authentication = ''
        config.agent_force_tls = False
        grpc_channel_mod._last_dns_keep_previous_log_at = 0.0
        grpc_channel_mod._last_dns_reresolve_fail_log_at = 0.0

    def tearDown(self):
        (
            config.agent_collector_backend_services,
            config.agent_collector_is_resolve_dns_periodically,
            config.agent_collector_grpc_channel_check_interval,
            config.agent_authentication,
            config.agent_force_tls,
        ) = self._saved

    def test_single_hostname_stays_plain_when_periodic_off(self):
        config.agent_collector_backend_services = 'oap.svc:11800'
        config.agent_collector_is_resolve_dns_periodically = False
        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=_gai):
            target, authority, fp = resolve_collector_dial_plan()
        self.assertEqual(target, 'oap.svc:11800')
        self.assertEqual(authority, 'oap.svc:11800')
        self.assertEqual(fp, (target, authority))

    def test_single_hostname_expands_when_periodic_on(self):
        config.agent_collector_backend_services = 'oap.svc:11800'
        config.agent_collector_is_resolve_dns_periodically = True
        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=_gai):
            target, authority, fp = resolve_collector_dial_plan()
        self.assertEqual(target, 'ipv4:10.0.0.1:11800')
        self.assertEqual(authority, 'oap.svc:11800')
        self.assertEqual(fp, (target, authority))

    def test_force_static_ips_kwarg_expands_single_hostname(self):
        addrs = parse_backend_addresses('oap.svc:11800')
        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=_gai):
            target, authority = prepare_grpc_channel_endpoints(addrs, force_static_ips=True)
        self.assertEqual(target, 'ipv4:10.0.0.1:11800')
        self.assertEqual(authority, 'oap.svc:11800')

    def test_fingerprint_stable_when_getaddrinfo_order_changes(self):
        config.agent_collector_backend_services = 'oap-a:11800,oap-b:11800'
        config.agent_collector_is_resolve_dns_periodically = True

        def gai_ab(host, port, type=0, *args, **kwargs):
            mapping = {
                'oap-a': [('10.0.0.1', port), ('10.0.0.3', port)],
                'oap-b': [('10.0.0.2', port)],
            }
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, p))
                for ip, p in mapping[host]
            ]

        def gai_ba(host, port, type=0, *args, **kwargs):
            mapping = {
                'oap-a': [('10.0.0.3', port), ('10.0.0.1', port)],
                'oap-b': [('10.0.0.2', port)],
            }
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, p))
                for ip, p in mapping[host]
            ]

        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=gai_ab):
            fp1 = resolve_collector_dial_plan()[2]
        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=gai_ba):
            fp2 = resolve_collector_dial_plan()[2]
        self.assertEqual(fp1, fp2)

    def test_fingerprint_changes_when_ip_set_changes(self):
        config.agent_collector_backend_services = 'oap.svc:11800'
        config.agent_collector_is_resolve_dns_periodically = True

        def gai_v1(host, port, type=0, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.1', port))]

        def gai_v2(host, port, type=0, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.99', port))]

        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=gai_v1):
            fp1 = resolve_collector_dial_plan()[2]
        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=gai_v2):
            fp2 = resolve_collector_dial_plan()[2]
        self.assertNotEqual(fp1, fp2)
        self.assertEqual(fp1[1], 'oap.svc:11800')
        self.assertEqual(fp2[1], 'oap.svc:11800')

    def test_fingerprint_grows_and_shrinks_with_ip_set(self):
        config.agent_collector_backend_services = 'oap.svc:11800'
        config.agent_collector_is_resolve_dns_periodically = True

        def gai_one(host, port, type=0, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.1', port))]

        def gai_two(host, port, type=0, *args, **kwargs):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.1', port)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.2', port)),
            ]

        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=gai_one):
            fp_one = resolve_collector_dial_plan()[2]
        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=gai_two):
            fp_two = resolve_collector_dial_plan()[2]
        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=gai_one):
            fp_back = resolve_collector_dial_plan()[2]
        self.assertNotEqual(fp_one, fp_two)
        self.assertEqual(fp_one, fp_back)
        self.assertIn('10.0.0.1', fp_two[0])
        self.assertIn('10.0.0.2', fp_two[0])

    def test_dns_failure_keeps_previous_plan(self):
        config.agent_collector_backend_services = 'oap.svc:11800'
        config.agent_collector_is_resolve_dns_periodically = True

        def gai_ok(host, port, type=0, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.1', port))]

        def gai_fail(host, port, type=0, *args, **kwargs):
            raise socket.gaierror(socket.EAI_NONAME, 'Name or service not known')

        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=gai_ok):
            previous = resolve_collector_dial_plan()
        self.assertEqual(previous[0], 'ipv4:10.0.0.1:11800')

        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=gai_fail), \
                self.assertLogs('skywalking', level='WARNING') as logs:
            kept = resolve_collector_dial_plan(previous=previous)
        self.assertEqual(kept, previous)
        self.assertTrue(any('keeping previous dial plan' in line for line in logs.output))

    def test_dns_keep_previous_warning_is_throttled(self):
        config.agent_collector_backend_services = 'oap.svc:11800'
        config.agent_collector_is_resolve_dns_periodically = True

        def gai_ok(host, port, type=0, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.1', port))]

        def gai_fail(host, port, type=0, *args, **kwargs):
            raise socket.gaierror(socket.EAI_NONAME, 'Name or service not known')

        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=gai_ok):
            previous = resolve_collector_dial_plan()

        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=gai_fail), \
                self.assertLogs('skywalking', level='WARNING') as first:
            self.assertEqual(resolve_collector_dial_plan(previous=previous), previous)
        self.assertEqual(sum(1 for line in first.output if 'keeping previous dial plan' in line), 1)

        # Immediate retry must not warn again within the throttle window.
        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=gai_fail):
            # assertNoLogs is 3.10+; count WARNING records manually via a handler.
            import logging
            records = []

            class _H(logging.Handler):
                def emit(self, record):
                    records.append(record)

            handler = _H(level=logging.WARNING)
            logger = logging.getLogger('skywalking')
            logger.addHandler(handler)
            try:
                self.assertEqual(resolve_collector_dial_plan(previous=previous), previous)
            finally:
                logger.removeHandler(handler)
        self.assertFalse(any('keeping previous dial plan' in r.getMessage() for r in records))

    def test_reresolve_suppresses_per_host_lookup_error_logs(self):
        """Periodic keep-previous must not emit per-host ERROR every check tick."""
        config.agent_collector_backend_services = 'oap.svc:11800'
        config.agent_collector_is_resolve_dns_periodically = True

        def gai_ok(host, port, type=0, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.1', port))]

        def gai_fail(host, port, type=0, *args, **kwargs):
            raise socket.gaierror(socket.EAI_NONAME, 'Name or service not known')

        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=gai_ok):
            previous = resolve_collector_dial_plan()

        import logging
        records = []

        class _H(logging.Handler):
            def emit(self, record):
                records.append(record)

        handler = _H(level=logging.DEBUG)
        logger = logging.getLogger('skywalking')
        logger.addHandler(handler)
        try:
            with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=gai_fail):
                self.assertEqual(resolve_collector_dial_plan(previous=previous), previous)
        finally:
            logger.removeHandler(handler)

        errors = [r for r in records if r.levelno >= logging.ERROR]
        self.assertFalse(
            any('Failed to resolve collector hostname' in r.getMessage() for r in errors),
            msg=f'unexpected lookup errors: {[r.getMessage() for r in errors]}',
        )
        warnings = [r for r in records if r.levelno == logging.WARNING]
        self.assertTrue(any('keeping previous dial plan' in r.getMessage() for r in warnings))

    def test_partial_hostname_failure_keeps_previous_plan(self):
        config.agent_collector_backend_services = 'oap-a:11800,oap-b:11800'
        config.agent_collector_is_resolve_dns_periodically = True

        def gai_both(host, port, type=0, *args, **kwargs):
            mapping = {
                'oap-a': [('10.0.0.1', port)],
                'oap-b': [('10.0.0.2', port)],
            }
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, p))
                for ip, p in mapping[host]
            ]

        def gai_b_fail(host, port, type=0, *args, **kwargs):
            if host == 'oap-b':
                raise socket.gaierror(socket.EAI_NONAME, 'Name or service not known')
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.1', port))]

        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=gai_both):
            previous = resolve_collector_dial_plan()
        self.assertIn('10.0.0.1', previous[0])
        self.assertIn('10.0.0.2', previous[0])

        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=gai_b_fail), \
                self.assertLogs('skywalking', level='WARNING') as logs:
            kept = resolve_collector_dial_plan(previous=previous)
        self.assertEqual(kept, previous)
        self.assertTrue(any('keeping previous dial plan' in line for line in logs.output))

    def test_bootstrap_still_skips_failed_hostname(self):
        config.agent_collector_backend_services = 'oap-a:11800,oap-b:11800'
        config.agent_collector_is_resolve_dns_periodically = True

        def gai_b_fail(host, port, type=0, *args, **kwargs):
            if host == 'oap-b':
                raise socket.gaierror(socket.EAI_NONAME, 'Name or service not known')
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.1', port))]

        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=gai_b_fail):
            target, authority, _fp = resolve_collector_dial_plan()
        self.assertEqual(target, 'ipv4:10.0.0.1:11800')
        self.assertEqual(authority, 'oap-a:11800')

    def test_protocol_rebuilds_channel_on_dns_change(self):
        config.agent_collector_backend_services = 'oap.svc:11800'
        config.agent_collector_is_resolve_dns_periodically = True
        config.agent_collector_grpc_channel_check_interval = 3600

        ips = {'v': '10.0.0.1'}

        def gai(host, port, type=0, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ips['v'], port))]

        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=gai):
            from skywalking.agent.protocol.grpc import GrpcProtocol

            protocol = GrpcProtocol()
            try:
                self.assertFalse(protocol.maybe_reresolve_dns())
                old_channel = protocol.channel
                old_gen = protocol._channel_generation
                ips['v'] = '10.0.0.2'
                self.assertTrue(protocol.maybe_reresolve_dns())
                self.assertIsNot(protocol.channel, old_channel)
                self.assertGreater(protocol._channel_generation, old_gen)
                self.assertEqual(
                    protocol._dns_fingerprint[0],
                    'ipv4:10.0.0.2:11800',
                )
            finally:
                protocol.close()

    def test_protocol_dns_failure_does_not_rebuild(self):
        config.agent_collector_backend_services = 'oap.svc:11800'
        config.agent_collector_is_resolve_dns_periodically = True
        config.agent_collector_grpc_channel_check_interval = 3600

        ips = {'ok': True}

        def gai(host, port, type=0, *args, **kwargs):
            if not ips['ok']:
                raise socket.gaierror(socket.EAI_NONAME, 'Name or service not known')
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.1', port))]

        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=gai):
            from skywalking.agent.protocol.grpc import GrpcProtocol

            protocol = GrpcProtocol()
            try:
                old_channel = protocol.channel
                old_fp = protocol._dns_fingerprint
                ips['ok'] = False
                with self.assertLogs('skywalking', level='WARNING'):
                    self.assertFalse(protocol.maybe_reresolve_dns())
                self.assertIs(protocol.channel, old_channel)
                self.assertEqual(protocol._dns_fingerprint, old_fp)
            finally:
                protocol.close()

    def test_stale_subscribe_callback_ignored(self):
        config.agent_collector_backend_services = 'oap.svc:11800'
        config.agent_collector_is_resolve_dns_periodically = True
        config.agent_collector_grpc_channel_check_interval = 3600

        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=_gai):
            from skywalking.agent.protocol.grpc import GrpcProtocol

            protocol = GrpcProtocol()
            try:
                old_cb = protocol._active_cb
                protocol.state = grpc.ChannelConnectivity.READY
                # Simulate generation bump as if channel was replaced.
                protocol._channel_generation += 1
                old_cb(grpc.ChannelConnectivity.SHUTDOWN)
                # Stale callback must not overwrite state after generation change.
                self.assertEqual(protocol.state, grpc.ChannelConnectivity.READY)
            finally:
                protocol.close()

    def test_on_error_skips_resubscribe_after_rebuild(self):
        from unittest.mock import MagicMock

        config.agent_collector_backend_services = 'oap.svc:11800'
        config.agent_collector_is_resolve_dns_periodically = True
        config.agent_collector_grpc_channel_check_interval = 3600

        ips = {'v': '10.0.0.1'}

        def gai(host, port, type=0, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ips['v'], port))]

        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=gai):
            from skywalking.agent.protocol.grpc import GrpcProtocol

            protocol = GrpcProtocol()
            try:
                old_cb = protocol._active_cb
                ips['v'] = '10.0.0.2'
                self.assertTrue(protocol.maybe_reresolve_dns())
                new_channel = protocol.channel
                new_cb = protocol._active_cb
                self.assertIsNot(old_cb, new_cb)

                new_channel.unsubscribe = MagicMock()
                new_channel.subscribe = MagicMock()
                protocol.on_error()
                new_channel.unsubscribe.assert_called_once_with(new_cb)
                new_channel.subscribe.assert_called_once_with(new_cb, try_to_connect=True)

                # Identity mismatch after unsubscribe: skip subscribe of stale cb.
                new_channel.unsubscribe.reset_mock()
                new_channel.subscribe.reset_mock()

                def _race_stale_cb():
                    with protocol._channel_lock:
                        cb = old_cb
                        channel = new_channel
                        channel.unsubscribe(cb)
                        if cb is not protocol._active_cb or channel is not protocol.channel:
                            return 'skipped'
                        channel.subscribe(cb, try_to_connect=True)
                        return 'subscribed'

                self.assertEqual(_race_stale_cb(), 'skipped')
                new_channel.subscribe.assert_not_called()
            finally:
                protocol.close()

    def test_protocol_close_aborts_rebuild(self):
        config.agent_collector_backend_services = 'oap.svc:11800'
        config.agent_collector_is_resolve_dns_periodically = True
        config.agent_collector_grpc_channel_check_interval = 3600

        ips = {'v': '10.0.0.1'}

        def gai(host, port, type=0, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ips['v'], port))]

        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=gai):
            from skywalking.agent.protocol.grpc import GrpcProtocol

            protocol = GrpcProtocol()
            protocol.close()
            ips['v'] = '10.0.0.2'
            self.assertFalse(protocol.maybe_reresolve_dns())

    def test_protocol_bind_failure_keeps_previous_channel(self):
        from unittest.mock import patch as _patch

        config.agent_collector_backend_services = 'oap.svc:11800'
        config.agent_collector_is_resolve_dns_periodically = True
        config.agent_collector_grpc_channel_check_interval = 3600

        ips = {'v': '10.0.0.1'}

        def gai(host, port, type=0, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ips['v'], port))]

        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=gai):
            from skywalking.agent.protocol.grpc import GrpcProtocol

            protocol = GrpcProtocol()
            old = protocol.channel
            old_cb = protocol._active_cb
            old_gen = protocol._channel_generation
            ips['v'] = '10.0.0.2'
            with _patch.object(old, 'subscribe', wraps=old.subscribe) as sub_spy, \
                    _patch(
                        'skywalking.agent.protocol.grpc.create_sync_channel',
                        side_effect=RuntimeError('open failed'),
                    ):
                with self.assertRaises(RuntimeError):
                    protocol.maybe_reresolve_dns()
            self.assertIs(protocol.channel, old)
            self.assertEqual(protocol._channel_generation, old_gen)
            self.assertIs(protocol._active_cb, old_cb)
            sub_spy.assert_called()
            protocol.close()

    def test_protocol_subscribe_failure_restores_previous_channel(self):
        from unittest.mock import patch as _patch

        config.agent_collector_backend_services = 'oap.svc:11800'
        config.agent_collector_is_resolve_dns_periodically = True
        config.agent_collector_grpc_channel_check_interval = 3600

        ips = {'v': '10.0.0.1'}

        def gai(host, port, type=0, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ips['v'], port))]

        channels = []

        def fake_create(**kwargs):
            from unittest.mock import MagicMock
            ch = MagicMock()
            idx = len(channels)
            channels.append(ch)

            def subscribe(cb, try_to_connect=False):
                if idx >= 1:
                    raise RuntimeError('subscribe failed')
                return None

            ch.subscribe = MagicMock(side_effect=subscribe)
            ch.unsubscribe = MagicMock()
            ch.close = MagicMock()
            return ch

        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=gai), \
                _patch('skywalking.agent.protocol.grpc.create_sync_channel', side_effect=fake_create), \
                _patch('skywalking.agent.protocol.grpc.GrpcServiceManagementClient'), \
                _patch('skywalking.agent.protocol.grpc.GrpcTraceSegmentReportService'), \
                _patch('skywalking.agent.protocol.grpc.GrpcProfileTaskChannelService'), \
                _patch('skywalking.agent.protocol.grpc.GrpcLogDataReportService'), \
                _patch('skywalking.agent.protocol.grpc.GrpcMeterReportService'):
            from skywalking.agent.protocol.grpc import GrpcProtocol

            protocol = GrpcProtocol()
            old = protocol.channel
            old_cb = protocol._active_cb
            old_gen = protocol._channel_generation
            old_fp = protocol._dns_fingerprint
            ips['v'] = '10.0.0.2'
            with self.assertRaises(RuntimeError):
                protocol.maybe_reresolve_dns()
            self.assertIs(protocol.channel, old)
            self.assertIs(protocol._active_cb, old_cb)
            self.assertEqual(protocol._channel_generation, old_gen)
            self.assertEqual(protocol._dns_fingerprint, old_fp)
            old.subscribe.assert_called()
            self.assertEqual(len(channels), 2)
            channels[1].close.assert_called()
            protocol.close()

    def test_protocol_resubscribe_mints_fresh_callback_if_prefer_fails(self):
        from unittest.mock import MagicMock, patch as _patch

        config.agent_collector_backend_services = 'oap.svc:11800'
        config.agent_collector_is_resolve_dns_periodically = True
        config.agent_collector_grpc_channel_check_interval = 3600

        ips = {'v': '10.0.0.1'}

        def gai(host, port, type=0, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ips['v'], port))]

        channels = []
        # After init, the next subscribe on channel 0 should fail once (prefer_cb),
        # then succeed for the fresh callback.
        channel0_subs = {'n': 0}

        def fake_create(**kwargs):
            ch = MagicMock()
            idx = len(channels)
            channels.append(ch)

            def subscribe(cb, try_to_connect=False):
                if idx >= 1:
                    raise RuntimeError('subscribe failed')
                channel0_subs['n'] += 1
                # 1 = init success; 2 = prefer_cb fail; 3+ = fresh cb success
                if channel0_subs['n'] == 2:
                    raise RuntimeError('prefer cb failed')
                return None

            ch.subscribe = MagicMock(side_effect=subscribe)
            ch.unsubscribe = MagicMock()
            ch.close = MagicMock()
            return ch

        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=gai), \
                _patch('skywalking.agent.protocol.grpc.create_sync_channel', side_effect=fake_create), \
                _patch('skywalking.agent.protocol.grpc.GrpcServiceManagementClient'), \
                _patch('skywalking.agent.protocol.grpc.GrpcTraceSegmentReportService'), \
                _patch('skywalking.agent.protocol.grpc.GrpcProfileTaskChannelService'), \
                _patch('skywalking.agent.protocol.grpc.GrpcLogDataReportService'), \
                _patch('skywalking.agent.protocol.grpc.GrpcMeterReportService'):
            from skywalking.agent.protocol.grpc import GrpcProtocol

            protocol = GrpcProtocol()
            old = protocol.channel
            old_cb = protocol._active_cb
            ips['v'] = '10.0.0.2'
            with self.assertRaises(RuntimeError):
                protocol.maybe_reresolve_dns()
            self.assertIs(protocol.channel, old)
            # Prefer cb failed once; fresh callback was installed.
            self.assertIsNot(protocol._active_cb, old_cb)
            self.assertGreaterEqual(channel0_subs['n'], 3)
            channels[1].close.assert_called()
            protocol.close()

    def test_aio_abandon_closes_without_running_loop(self):
        from unittest.mock import MagicMock, patch as _patch

        config.agent_collector_backend_services = 'oap.svc:11800'
        config.agent_collector_is_resolve_dns_periodically = True

        closed = {'n': 0}

        def fake_create_aio_channel(**kwargs):
            ch = MagicMock()

            async def _close():
                closed['n'] += 1

            ch.close = MagicMock(side_effect=_close)
            return ch

        sm_calls = {'n': 0}

        def fake_sm(*args, **kwargs):
            sm_calls['n'] += 1
            if sm_calls['n'] == 1:
                raise RuntimeError('client init failed off-loop')
            return MagicMock()

        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=_gai), \
                _patch('skywalking.agent.protocol.grpc_aio.create_aio_channel',
                       side_effect=fake_create_aio_channel), \
                _patch('skywalking.agent.protocol.grpc_aio.GrpcServiceManagementClientAsync',
                       side_effect=fake_sm), \
                _patch('skywalking.agent.protocol.grpc_aio.GrpcTraceSegmentReportServiceAsync'), \
                _patch('skywalking.agent.protocol.grpc_aio.GrpcProfileTaskChannelServiceAsync'), \
                _patch('skywalking.agent.protocol.grpc_aio.GrpcLogReportServiceAsync'), \
                _patch('skywalking.agent.protocol.grpc_aio.GrpcMeterReportServiceAsync'):
            from skywalking.agent.protocol.grpc_aio import GrpcProtocolAsync

            with self.assertRaises(RuntimeError):
                GrpcProtocolAsync()
            self.assertEqual(closed['n'], 1)

    def test_aio_bind_client_failure_keeps_previous_channel(self):
        import asyncio
        from unittest.mock import MagicMock, patch as _patch

        config.agent_collector_backend_services = 'oap.svc:11800'
        config.agent_collector_is_resolve_dns_periodically = True

        ips = {'v': '10.0.0.1'}

        def gai(host, port, type=0, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ips['v'], port))]

        channels = []
        sm_calls = {'n': 0}

        def fake_create_aio_channel(**kwargs):
            ch = MagicMock()

            async def _close():
                return None

            ch.close = MagicMock(side_effect=_close)
            channels.append(ch)
            return ch

        def fake_sm(*args, **kwargs):
            sm_calls['n'] += 1
            if sm_calls['n'] > 1:
                raise RuntimeError('client init failed')
            return MagicMock()

        async def _run():
            with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=gai), \
                    _patch('skywalking.agent.protocol.grpc_aio.create_aio_channel',
                           side_effect=fake_create_aio_channel), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcServiceManagementClientAsync',
                           side_effect=fake_sm), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcTraceSegmentReportServiceAsync'), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcProfileTaskChannelServiceAsync'), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcLogReportServiceAsync'), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcMeterReportServiceAsync'):
                from skywalking.agent.protocol.grpc_aio import GrpcProtocolAsync

                protocol = GrpcProtocolAsync()
                old = protocol.channel
                old_gen = protocol._channel_generation
                ips['v'] = '10.0.0.2'
                with self.assertRaises(RuntimeError):
                    await protocol.maybe_reresolve_dns()
                self.assertIs(protocol.channel, old)
                self.assertEqual(protocol._channel_generation, old_gen)
                self.assertEqual(len(channels), 2)
                channels[1].close.assert_called()
                await protocol.aclose()

        asyncio.run(_run())

    def test_aio_rebuilds_channel_on_dns_change(self):
        import asyncio
        from unittest.mock import MagicMock, patch as _patch

        config.agent_collector_backend_services = 'oap.svc:11800'
        config.agent_collector_is_resolve_dns_periodically = True
        config.agent_collector_grpc_channel_check_interval = 3600

        ips = {'v': '10.0.0.1'}

        def gai(host, port, type=0, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ips['v'], port))]

        channels = []

        def fake_create_aio_channel(**kwargs):
            ch = MagicMock()

            async def _close():
                return None

            ch.close = MagicMock(side_effect=_close)
            channels.append(ch)
            return ch

        async def _run():
            with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=gai), \
                    _patch('skywalking.agent.protocol.grpc_aio.create_aio_channel',
                           side_effect=fake_create_aio_channel), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcServiceManagementClientAsync'), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcTraceSegmentReportServiceAsync'), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcProfileTaskChannelServiceAsync'), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcLogReportServiceAsync'), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcMeterReportServiceAsync'):
                from skywalking.agent.protocol.grpc_aio import GrpcProtocolAsync

                protocol = GrpcProtocolAsync()
                self.assertFalse(await protocol.maybe_reresolve_dns())
                old = protocol.channel
                old_gen = protocol._channel_generation
                ips['v'] = '10.0.0.2'
                self.assertTrue(await protocol.maybe_reresolve_dns())
                self.assertIsNot(protocol.channel, old)
                self.assertGreater(protocol._channel_generation, old_gen)
                self.assertEqual(protocol._dns_fingerprint[0], 'ipv4:10.0.0.2:11800')
                await protocol.aclose()

        asyncio.run(_run())

    def test_aio_closed_skips_bind_after_resolve(self):
        import asyncio
        from unittest.mock import MagicMock, patch as _patch

        config.agent_collector_backend_services = 'oap.svc:11800'
        config.agent_collector_is_resolve_dns_periodically = True

        def gai(host, port, type=0, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.1', port))]

        def fake_create_aio_channel(**kwargs):
            ch = MagicMock()

            async def _close():
                return None

            ch.close = MagicMock(side_effect=_close)
            return ch

        async def _run():
            with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=gai), \
                    _patch('skywalking.agent.protocol.grpc_aio.create_aio_channel',
                           side_effect=fake_create_aio_channel), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcServiceManagementClientAsync'), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcTraceSegmentReportServiceAsync'), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcProfileTaskChannelServiceAsync'), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcLogReportServiceAsync'), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcMeterReportServiceAsync'):
                from skywalking.agent.protocol.grpc_aio import GrpcProtocolAsync

                protocol = GrpcProtocolAsync()
                await protocol.aclose()
                self.assertFalse(await protocol.maybe_reresolve_dns())

        asyncio.run(_run())

    def test_aio_channel_changed_event_wakes_when_close_fails(self):
        import asyncio
        import contextlib
        from unittest.mock import MagicMock, patch as _patch

        config.agent_collector_backend_services = 'oap.svc:11800'
        config.agent_collector_is_resolve_dns_periodically = True
        config.agent_collector_grpc_channel_check_interval = 3600

        ips = {'v': '10.0.0.1'}

        def gai(host, port, type=0, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ips['v'], port))]

        def fake_create_aio_channel(**kwargs):
            ch = MagicMock()
            ch.get_state.return_value = grpc.ChannelConnectivity.READY

            async def _close():
                raise RuntimeError('close failed')

            async def _wait(_state):
                await asyncio.Event().wait()  # never completes unless cancelled

            ch.close = MagicMock(side_effect=_close)
            ch.wait_for_state_change = MagicMock(side_effect=_wait)
            return ch

        async def _run():
            with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=gai), \
                    _patch('skywalking.agent.protocol.grpc_aio.create_aio_channel',
                           side_effect=fake_create_aio_channel), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcServiceManagementClientAsync'), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcTraceSegmentReportServiceAsync'), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcProfileTaskChannelServiceAsync'), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcLogReportServiceAsync'), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcMeterReportServiceAsync'):
                from skywalking.agent.protocol.grpc_aio import GrpcProtocolAsync

                protocol = GrpcProtocolAsync()
                first = protocol.channel
                watch = asyncio.create_task(protocol.watch_connectivity())
                for _ in range(100):
                    await asyncio.sleep(0.01)
                    if first.wait_for_state_change.called:
                        break
                else:
                    self.fail('watch_connectivity did not start waiting on first channel')

                gen_before = protocol._channel_generation
                ips['v'] = '10.0.0.2'
                self.assertTrue(await protocol.maybe_reresolve_dns())
                self.assertGreater(protocol._channel_generation, gen_before)
                new_ch = protocol.channel
                self.assertIsNot(new_ch, first)

                for _ in range(100):
                    await asyncio.sleep(0.01)
                    if new_ch.get_state.called:
                        break
                else:
                    self.fail('watch did not rebind after rebuild when old.close failed')

                watch.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await watch
                await protocol.aclose()

        asyncio.run(_run())

    def test_dns_join_timeout_counts_hostnames_only(self):
        from skywalking.utils.grpc_channel import (
            DNS_LOOKUP_TIMEOUT_SEC,
            dns_reresolve_join_timeout_sec,
        )

        self.assertEqual(
            dns_reresolve_join_timeout_sec('oap.svc:11800,10.0.0.1:11800'),
            DNS_LOOKUP_TIMEOUT_SEC * 1 + 2.0,
        )
        self.assertEqual(
            dns_reresolve_join_timeout_sec('oap-a:11800,oap-b:11800'),
            DNS_LOOKUP_TIMEOUT_SEC * 2 + 2.0,
        )
        self.assertEqual(
            dns_reresolve_join_timeout_sec('10.0.0.1:11800,10.0.0.2:11800'),
            DNS_LOOKUP_TIMEOUT_SEC * 1 + 2.0,
        )

    def test_aio_begin_shutdown_blocks_bind_before_cancel(self):
        import asyncio
        from unittest.mock import MagicMock, patch as _patch

        config.agent_collector_backend_services = 'oap.svc:11800'
        config.agent_collector_is_resolve_dns_periodically = True

        def gai(host, port, type=0, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.1', port))]

        def fake_create_aio_channel(**kwargs):
            ch = MagicMock()

            async def _close():
                return None

            ch.close = MagicMock(side_effect=_close)
            return ch

        async def _run():
            with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=gai), \
                    _patch('skywalking.agent.protocol.grpc_aio.create_aio_channel',
                           side_effect=fake_create_aio_channel), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcServiceManagementClientAsync'), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcTraceSegmentReportServiceAsync'), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcProfileTaskChannelServiceAsync'), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcLogReportServiceAsync'), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcMeterReportServiceAsync'):
                from skywalking.agent.protocol.grpc_aio import GrpcProtocolAsync

                protocol = GrpcProtocolAsync()
                channel = protocol.channel
                protocol.begin_shutdown()
                self.assertTrue(protocol._closed)
                self.assertFalse(await protocol.maybe_reresolve_dns())
                self.assertIs(protocol.channel, channel)
                await protocol.aclose()

        asyncio.run(_run())

    def test_aio_is_ready_ignores_stale_peek_generation(self):
        import asyncio
        from unittest.mock import MagicMock, patch as _patch

        config.agent_collector_backend_services = 'oap.svc:11800'
        config.agent_collector_is_resolve_dns_periodically = True

        def gai(host, port, type=0, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.1', port))]

        def fake_create_aio_channel(**kwargs):
            ch = MagicMock()
            ch.get_state.return_value = grpc.ChannelConnectivity.READY

            async def _close():
                return None

            ch.close = MagicMock(side_effect=_close)
            return ch

        async def _run():
            with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=gai), \
                    _patch('skywalking.agent.protocol.grpc_aio.create_aio_channel',
                           side_effect=fake_create_aio_channel), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcServiceManagementClientAsync'), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcTraceSegmentReportServiceAsync'), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcProfileTaskChannelServiceAsync'), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcLogReportServiceAsync'), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcMeterReportServiceAsync'):
                from skywalking.agent.protocol.grpc_aio import GrpcProtocolAsync

                protocol = GrpcProtocolAsync()
                protocol.state = None
                stale_gen = protocol._channel_generation
                protocol._channel_generation = stale_gen + 1
                protocol.state = grpc.ChannelConnectivity.IDLE
                # Peek reports READY on the old generation identity; must not apply.
                protocol.channel.get_state.return_value = grpc.ChannelConnectivity.READY
                # Force is_ready to peek with captured generation that no longer matches
                # by temporarily restoring generation around get_state — simulate race:
                # capture gen=stale, then gen bumps, then get_state returns.
                real_get_state = protocol.channel.get_state

                def racing_get_state(try_to_connect=False):
                    protocol._channel_generation = stale_gen + 2
                    return grpc.ChannelConnectivity.READY

                protocol.channel.get_state = racing_get_state
                protocol._channel_generation = stale_gen + 1
                protocol.state = None
                self.assertFalse(protocol.is_ready())
                self.assertIsNone(protocol.state)
                protocol.channel.get_state = real_get_state
                await protocol.aclose()

        asyncio.run(_run())

    def test_aio_cancel_during_old_close_still_closes_old(self):
        import asyncio
        from unittest.mock import MagicMock, patch as _patch

        config.agent_collector_backend_services = 'oap.svc:11800'
        config.agent_collector_is_resolve_dns_periodically = True

        ips = {'v': '10.0.0.1'}

        def gai(host, port, type=0, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ips['v'], port))]

        channels = []

        def fake_create_aio_channel(**kwargs):
            ch = MagicMock()
            idx = len(channels)

            async def _close():
                # Only the pre-rebuild channel's first close simulates cancel mid-teardown.
                if idx == 0 and getattr(ch, '_closed_once', False) is False:
                    ch._closed_once = True
                    raise asyncio.CancelledError()
                ch._closed_once = True
                return None

            ch.close = MagicMock(side_effect=_close)
            ch._closed_once = False
            channels.append(ch)
            return ch

        async def _run():
            with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=gai), \
                    _patch('skywalking.agent.protocol.grpc_aio.create_aio_channel',
                           side_effect=fake_create_aio_channel), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcServiceManagementClientAsync'), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcTraceSegmentReportServiceAsync'), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcProfileTaskChannelServiceAsync'), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcLogReportServiceAsync'), \
                    _patch('skywalking.agent.protocol.grpc_aio.GrpcMeterReportServiceAsync'):
                from skywalking.agent.protocol.grpc_aio import GrpcProtocolAsync

                protocol = GrpcProtocolAsync()
                old = protocol.channel
                ips['v'] = '10.0.0.2'
                with self.assertRaises(asyncio.CancelledError):
                    await protocol.maybe_reresolve_dns()
                self.assertIsNot(protocol.channel, old)
                # First close raised CancelledError; except handler retries old.close.
                self.assertEqual(old.close.call_count, 2)
                await protocol.aclose()

        asyncio.run(_run())


if __name__ == '__main__':
    unittest.main()
