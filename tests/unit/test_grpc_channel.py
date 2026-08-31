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
import json
import unittest
import asyncio
from queue import Queue
from time import monotonic
from unittest.mock import MagicMock, patch

import grpc

from skywalking.utils.grpc_channel import (
    GRPC_CHANNEL_OPTIONS,
    _GRPC_RPC_TIMEOUT_MARGIN_SEC,
    AddressKind,
    BackendAddress,
    build_grpc_target,
    encode_sw_static_for_c_core,
    expand_backend_addresses,
    grpc_call_timeout,
    handle_rpc_error,
    is_auth_rpc_error,
    is_channel_ready,
    parse_backend_address,
    parse_backend_addresses,
    prepare_grpc_channel_endpoints,
    resolve_grpc_target,
    sw_static_endpoints,
)


class TestGrpcBackendAddress(unittest.TestCase):

    def test_parse_ipv4_and_hostname(self):
        v4 = parse_backend_address('127.0.0.1:11800')
        self.assertEqual(v4.host, '127.0.0.1')
        self.assertEqual(v4.port, 11800)
        self.assertEqual(v4.kind.value, 'ipv4')

        host = parse_backend_address('oap.example.com:11800')
        self.assertEqual(host.host, 'oap.example.com')
        self.assertEqual(host.kind.value, 'hostname')

    def test_parse_ipv6_requires_brackets(self):
        v6 = parse_backend_address('[::1]:11800')
        self.assertEqual(v6.host, '::1')
        self.assertEqual(v6.port, 11800)
        self.assertEqual(v6.kind.value, 'ipv6')
        self.assertIsNone(parse_backend_address('::1:11800'))

    def test_parse_invalid_logged_and_skipped(self):
        with self.assertLogs('skywalking', level='ERROR') as cm:
            addrs = parse_backend_addresses('127.0.0.1:11800,bad-entry,10.0.0.2:11800')
        self.assertEqual(len(addrs), 2)
        self.assertTrue(any('bad-entry' in line for line in cm.output))

    def test_single_target_plain(self):
        self.assertEqual(
            build_grpc_target(parse_backend_addresses('oap.svc:11800')),
            'oap.svc:11800',
        )
        self.assertEqual(
            build_grpc_target(parse_backend_addresses('127.0.0.1:11800')),
            '127.0.0.1:11800',
        )

    def test_multi_ipv4_static_target(self):
        target = build_grpc_target(parse_backend_addresses('10.0.0.1:11800,10.0.0.2:11800'))
        self.assertEqual(target, 'ipv4:10.0.0.1:11800,10.0.0.2:11800')

    def test_multi_ipv6_static_target(self):
        target = build_grpc_target(parse_backend_addresses('[::1]:11800,[::2]:11800'))
        self.assertEqual(target, 'ipv6:[::1]:11800,[::2]:11800')

    def test_multi_hostname_expands_to_ipv4_static(self):
        def fake_getaddrinfo(host, port, type=0, *args, **kwargs):
            mapping = {
                'oap-a': [('10.0.0.1', port)],
                'oap-b': [('10.0.0.2', port)],
            }
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, p))
                for ip, p in mapping[host]
            ]

        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=fake_getaddrinfo):
            target = build_grpc_target(parse_backend_addresses('oap-a:11800,oap-b:11800'))
        self.assertEqual(target, 'ipv4:10.0.0.1:11800,10.0.0.2:11800')

    def test_mixed_hostname_and_ip_expands(self):
        def fake_getaddrinfo(host, port, type=0, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.9', port))]

        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=fake_getaddrinfo):
            target = build_grpc_target(
                parse_backend_addresses('10.0.0.1:11800,oap-b:11800')
            )
        self.assertEqual(target, 'ipv4:10.0.0.1:11800,10.0.0.9:11800')

    def test_mixed_families_encoded_as_ipv4_mapped(self):
        addrs = [
            BackendAddress('10.0.0.1', 11800, AddressKind.IPV4),
            BackendAddress('::1', 11800, AddressKind.IPV6),
        ]
        target = build_grpc_target(addrs)
        self.assertEqual(target, 'ipv6:[::ffff:10.0.0.1]:11800,[::1]:11800')
        self.assertEqual(
            sw_static_endpoints(addrs),
            [
                {'addresses': [{'host': '10.0.0.1', 'port': 11800}]},
                {'addresses': [{'host': '::1', 'port': 11800}]},
            ],
        )

    def test_hostname_dual_stack_keeps_both_families(self):
        def fake_getaddrinfo(host, port, type=0, *args, **kwargs):
            if host == 'oap-a':
                return [
                    (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.1', port)),
                    (socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('2001:db8::1', port)),
                ]
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.2', port))]

        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=fake_getaddrinfo):
            target = build_grpc_target(parse_backend_addresses('oap-a:11800,oap-b:11800'))
        self.assertEqual(
            target,
            'ipv6:[::ffff:10.0.0.1]:11800,[2001:db8::1]:11800,[::ffff:10.0.0.2]:11800',
        )

    def test_encode_rejects_hostname(self):
        with self.assertRaises(ValueError):
            encode_sw_static_for_c_core([
                BackendAddress('oap.svc', 11800, AddressKind.HOSTNAME),
            ])

    def test_expand_skips_failed_hostname(self):
        def fake_getaddrinfo(host, port, type=0, *args, **kwargs):
            if host == 'bad.host':
                raise socket.gaierror(socket.EAI_NONAME, 'Name or service not known')
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.3', port))]

        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=fake_getaddrinfo):
            with self.assertLogs('skywalking', level='ERROR'):
                expanded = expand_backend_addresses(
                    parse_backend_addresses('bad.host:11800,ok.host:11800')
                )
        self.assertEqual([a.endpoint() for a in expanded], ['10.0.0.3:11800'])

    def test_authority_skips_failed_first_hostname(self):
        def fake_getaddrinfo(host, port, type=0, *args, **kwargs):
            if host == 'bad.host':
                raise socket.gaierror(socket.EAI_NONAME, 'Name or service not known')
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.2', port))]

        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=fake_getaddrinfo):
            with self.assertLogs('skywalking', level='ERROR'):
                target, authority = prepare_grpc_channel_endpoints(
                    parse_backend_addresses('bad.host:11800,good.host:11800')
                )
        self.assertEqual(target, 'ipv4:10.0.0.2:11800')
        self.assertEqual(authority, 'good.host:11800')

    def test_rejects_ipv6_zone_and_control_chars(self):
        self.assertIsNone(parse_backend_address('[fe80::1%eth0]:11800'))
        self.assertIsNone(parse_backend_address('bad\nhost:11800'))
        self.assertIsNone(parse_backend_address('has space:11800'))

    def test_dns_timeout_returns_quickly_without_joining_worker(self):
        import threading
        import time
        from skywalking.utils import grpc_channel as mod

        def hang_getaddrinfo(*_args, **_kwargs):
            time.sleep(30)
            return []

        previous = mod._DNS_LOOKUP_TIMEOUT_SEC
        try:
            mod._DNS_LOOKUP_TIMEOUT_SEC = 0.3
            before = {t.ident for t in threading.enumerate()}
            t0 = time.monotonic()
            with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=hang_getaddrinfo):
                with self.assertLogs('skywalking', level='ERROR'):
                    result = mod._lookup_hostname('slow.host', 11800)
            elapsed = time.monotonic() - t0
            leftover = [
                t for t in threading.enumerate()
                if t.ident not in before and t.is_alive()
            ]
        finally:
            mod._DNS_LOOKUP_TIMEOUT_SEC = previous

        self.assertEqual(result, [])
        self.assertLess(elapsed, 2.0)
        # Hung lookup may still be running, but must be daemon so exit is not blocked.
        for t in leftover:
            self.assertTrue(t.daemon, msg=f'non-daemon leftover thread: {t.name}')

    def test_all_hostname_resolve_fail_raises(self):
        def fake_getaddrinfo(host, port, type=0, *args, **kwargs):
            raise socket.gaierror(socket.EAI_NONAME, 'Name or service not known')

        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=fake_getaddrinfo):
            with self.assertLogs('skywalking', level='ERROR'):
                with self.assertRaises(ValueError):
                    build_grpc_target(parse_backend_addresses('a.host:11800,b.host:11800'))

    def test_empty_raises(self):
        with self.assertRaises(ValueError):
            build_grpc_target([])

    def test_channel_options_disable_proxy_no_keepalive(self):
        keys = {k for k, _ in GRPC_CHANNEL_OPTIONS}
        self.assertIn('grpc.enable_http_proxy', keys)
        self.assertNotIn('grpc.lb_policy_name', keys)
        self.assertEqual(dict(GRPC_CHANNEL_OPTIONS)['grpc.enable_http_proxy'], 0)
        self.assertEqual(dict(GRPC_CHANNEL_OPTIONS)['grpc.max_reconnect_backoff_ms'], 30000)
        self.assertFalse(any('keepalive' in k for k in keys))

    def test_channel_options_properties_retry_service_config(self):
        opts = dict(GRPC_CHANNEL_OPTIONS)
        self.assertEqual(opts['grpc.enable_retries'], 1)
        cfg = json.loads(opts['grpc.service_config'])
        methods = cfg['methodConfig']
        self.assertEqual(len(methods), 1)
        names = methods[0]['name']
        self.assertEqual(names, [{
            'service': 'skywalking.v3.ManagementService',
            'method': 'reportInstanceProperties',
        }])
        policy = methods[0]['retryPolicy']
        self.assertEqual(policy['maxAttempts'], 3)
        self.assertEqual(policy['retryableStatusCodes'], ['UNAVAILABLE'])
        # Streaming collect must not appear — retries would duplicate segments.
        blob = opts['grpc.service_config']
        self.assertNotIn('collect', blob)
        self.assertNotIn('keepAlive', blob)
        lb = cfg['loadBalancingConfig']
        self.assertEqual(lb, [{'pick_first': {'shuffleAddressList': True}}])

    def test_resolve_uses_config(self):
        from skywalking import config

        previous = config.agent_collector_backend_services
        try:
            config.agent_collector_backend_services = '1.1.1.1:11800,1.1.1.2:11800'
            self.assertEqual(resolve_grpc_target(), 'ipv4:1.1.1.1:11800,1.1.1.2:11800')
        finally:
            config.agent_collector_backend_services = previous

    def test_create_sync_channel_tls_passes_authority(self):
        from skywalking import config
        from skywalking.utils.grpc_channel import create_sync_channel

        previous = config.agent_collector_backend_services
        previous_tls = config.agent_force_tls
        try:
            config.agent_collector_backend_services = 'oap.example:11800,10.0.0.2:11800'
            config.agent_force_tls = True

            def fake_getaddrinfo(host, port, type=0, *args, **kwargs):
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.1', port))]

            with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=fake_getaddrinfo), \
                 patch('skywalking.utils.grpc_channel.grpc.secure_channel') as secure, \
                 patch('skywalking.utils.grpc_channel.grpc.ssl_channel_credentials', return_value='creds'):
                create_sync_channel()
            args, kwargs = secure.call_args
            self.assertEqual(args[0], 'ipv4:10.0.0.1:11800,10.0.0.2:11800')
            opts = dict(kwargs['options'])
            self.assertEqual(opts['grpc.default_authority'], 'oap.example:11800')
        finally:
            config.agent_collector_backend_services = previous
            config.agent_force_tls = previous_tls


class TestAuthRpcHandling(unittest.TestCase):

    def _rpc_error(self, status):
        err = MagicMock()
        err.code = MagicMock(return_value=status)
        return err

    def test_auth_errors_detected(self):
        self.assertTrue(is_auth_rpc_error(self._rpc_error(grpc.StatusCode.UNAUTHENTICATED)))
        self.assertTrue(is_auth_rpc_error(self._rpc_error(grpc.StatusCode.PERMISSION_DENIED)))
        self.assertFalse(is_auth_rpc_error(self._rpc_error(grpc.StatusCode.UNAVAILABLE)))

    def test_auth_does_not_invoke_connectivity_hook(self):
        hook = MagicMock()
        with patch('skywalking.utils.grpc_channel._last_auth_log_at', 0):
            handle_rpc_error(self._rpc_error(grpc.StatusCode.UNAUTHENTICATED), hook)
        hook.assert_not_called()

    def test_unavailable_invokes_connectivity_hook(self):
        hook = MagicMock()
        handle_rpc_error(self._rpc_error(grpc.StatusCode.UNAVAILABLE), hook)
        hook.assert_called_once()


class TestReadyGate(unittest.TestCase):

    def test_ready_true_only_for_ready_state(self):
        channel = MagicMock()
        channel.get_state.return_value = grpc.ChannelConnectivity.READY
        # Ensure unwrap prefers public get_state (aio path).
        channel._channel = MagicMock()
        self.assertTrue(is_channel_ready(channel))
        channel.get_state.assert_called_with(True)

    def test_non_ready_states_skip(self):
        channel = MagicMock()
        for state in (
            grpc.ChannelConnectivity.IDLE,
            grpc.ChannelConnectivity.CONNECTING,
            grpc.ChannelConnectivity.TRANSIENT_FAILURE,
            grpc.ChannelConnectivity.SHUTDOWN,
        ):
            channel.get_state.return_value = state
            self.assertFalse(is_channel_ready(channel), msg=str(state))

    def test_sync_channel_without_get_state_uses_cython_check(self):
        # grpcio sync Channel has subscribe but no get_state — must not fail-closed forever.
        class SyncLikeChannel:
            pass

        channel = SyncLikeChannel()
        cython = MagicMock()
        cython.check_connectivity_state.return_value = grpc.ChannelConnectivity.READY.value[0]
        channel._channel = cython
        self.assertTrue(is_channel_ready(channel))
        cython.check_connectivity_state.assert_called_with(True)

        cython.check_connectivity_state.return_value = grpc.ChannelConnectivity.IDLE.value[0]
        self.assertFalse(is_channel_ready(channel))

    def test_intercept_channel_unwraps_to_cython_check(self):
        class InterceptLike:
            pass

        class SyncLike:
            pass

        intercept = InterceptLike()
        sync = SyncLike()
        cython = MagicMock()
        cython.check_connectivity_state.return_value = grpc.ChannelConnectivity.READY.value[0]
        sync._channel = cython
        intercept._channel = sync
        self.assertTrue(is_channel_ready(intercept))
        cython.check_connectivity_state.assert_called_with(True)

    def test_unknown_channel_fail_open(self):
        # Cannot read connectivity → do not permanently silence reporters.
        self.assertTrue(is_channel_ready(object()))


class TestLogThrottle(unittest.TestCase):

    def test_reporter_exception_throttled(self):
        from skywalking.utils import reporter_log as mod

        # patch replaces the module dict for this test only (auto-restored);
        # do not .clear() the shared throttle state — that leaks across tests.
        with patch.object(mod, '_last_reporter_log_at', {}):
            with self.assertLogs('skywalking', level='ERROR') as cm:
                try:
                    raise RuntimeError('boom')
                except RuntimeError:
                    mod.log_reporter_exception_throttled('segment', 1)
                    mod.log_reporter_exception_throttled('segment', 2)
            self.assertEqual(len(cm.records), 1)

    def test_connectivity_event_throttled(self):
        from skywalking.utils import grpc_channel as mod

        with patch.object(mod, '_last_connectivity_log_at', {}):
            with self.assertLogs('skywalking', level='WARNING') as cm:
                mod.log_connectivity_event('transient_failure', 'down1')
                mod.log_connectivity_event('transient_failure', 'down2')
            self.assertEqual(len(cm.records), 1)

    def test_dropped_throttled_includes_delta_and_total(self):
        from skywalking.utils import reporter_log as mod

        with patch.object(mod, '_last_drop_log_at', {}), \
             patch.object(mod, '_drop_totals', {}), \
             patch.object(mod, '_drop_logged_totals', {}):
            with self.assertLogs('skywalking', level='WARNING') as cm:
                mod.log_dropped_throttled('segment', 2)
                mod.log_dropped_throttled('segment', 3)
            self.assertEqual(len(cm.records), 1)
            self.assertIn('+2 since last log', cm.records[0].getMessage())
            self.assertIn('2 total', cm.records[0].getMessage())


class TestCreateChannelDoesNotRaise(unittest.TestCase):

    def _assert_factory_degrades(self, services: str):
        from skywalking import config
        from skywalking.utils.grpc_channel import create_sync_channel

        previous = config.agent_collector_backend_services
        channel = MagicMock()
        channel.get_state.return_value = grpc.ChannelConnectivity.IDLE
        try:
            config.agent_collector_backend_services = services
            with patch('skywalking.utils.grpc_channel.grpc.insecure_channel', return_value=channel) as insecure:
                with self.assertLogs('skywalking', level='ERROR'):
                    got = create_sync_channel()
            self.assertIs(got, channel)
            insecure.assert_called()
            self.assertNotEqual(got.get_state(), grpc.ChannelConnectivity.READY)
        finally:
            config.agent_collector_backend_services = previous

    def test_empty_config_does_not_raise(self):
        self._assert_factory_degrades('')

    def test_garbage_config_does_not_raise(self):
        self._assert_factory_degrades('not-an-address,also bad')

    def test_unresolvable_hostnames_do_not_raise(self):
        def fake_getaddrinfo(host, port, type=0, *args, **kwargs):
            raise socket.gaierror(socket.EAI_NONAME, 'Name or service not known')

        with patch('skywalking.utils.grpc_channel.socket.getaddrinfo', side_effect=fake_getaddrinfo):
            self._assert_factory_degrades('no.such.host.invalid:11800,also.invalid:11800')


class TestProfilingSnapshotNonBlocking(unittest.TestCase):

    def test_full_snapshot_queue_does_not_block(self):
        from queue import Queue
        from threading import Event, Thread

        from skywalking.agent import SkyWalkingAgent

        agent = SkyWalkingAgent.__new__(SkyWalkingAgent)
        agent._SkyWalkingAgent__reporting = True
        q = Queue(maxsize=1)
        q.put('full')
        agent._SkyWalkingAgent__snapshot_queue = q

        done = Event()

        def _put():
            agent.add_profiling_snapshot('next')
            done.set()

        Thread(target=_put, daemon=True).start()
        self.assertTrue(done.wait(1.0), 'add_profiling_snapshot blocked on a full queue')
        self.assertEqual(q.qsize(), 1)


class TestGrpcCallTimeoutAndKeepAlive(unittest.TestCase):

    def test_rpc_timeout_exceeds_queue_window(self):
        from skywalking import config

        prev = config.agent_queue_timeout
        try:
            config.agent_queue_timeout = 1
            self.assertEqual(grpc_call_timeout(), 10.0)
            config.agent_queue_timeout = 20
            self.assertEqual(grpc_call_timeout(), 25.0)
        finally:
            config.agent_queue_timeout = prev

    def test_sync_collect_passes_timeout(self):
        from skywalking.client.grpc import GrpcTraceSegmentReportService

        stub = MagicMock()
        svc = GrpcTraceSegmentReportService.__new__(GrpcTraceSegmentReportService)
        svc.report_stub = stub
        svc.report(iter(()))
        self.assertEqual(stub.collect.call_args.kwargs.get('timeout'), grpc_call_timeout())

    def test_keep_alive_after_properties_refresh_failure(self):
        from skywalking.client.grpc import GrpcServiceManagementClient

        class FakeRpcError(grpc.RpcError):
            def code(self):
                return grpc.StatusCode.UNAVAILABLE

            def details(self):
                return 'props failed'

        client = GrpcServiceManagementClient.__new__(GrpcServiceManagementClient)
        client.service_stub = MagicMock()
        client.refresh_instance_props = MagicMock(side_effect=FakeRpcError())
        client.send_heart_beat()
        client.service_stub.keepAlive.assert_called_once()
        self.assertEqual(
            client.service_stub.keepAlive.call_args.kwargs.get('timeout'),
            grpc_call_timeout(),
        )


class TestAioStreamingOmitsDeadline(unittest.IsolatedAsyncioTestCase):

    async def test_aio_collect_omits_timeout(self):
        from unittest.mock import AsyncMock

        from skywalking.client.grpc_aio import (
            GrpcLogReportServiceAsync,
            GrpcMeterReportServiceAsync,
            GrpcProfileTaskChannelServiceAsync,
            GrpcTraceSegmentReportServiceAsync,
        )

        traces = MagicMock()
        traces.collect = AsyncMock()
        svc = GrpcTraceSegmentReportServiceAsync.__new__(GrpcTraceSegmentReportServiceAsync)
        svc.report_stub = traces
        await svc.report(object())
        self.assertNotIn('timeout', traces.collect.call_args.kwargs)

        meters = MagicMock()
        meters.collect = AsyncMock()
        meters.collectBatch = AsyncMock()
        meter_svc = GrpcMeterReportServiceAsync.__new__(GrpcMeterReportServiceAsync)
        meter_svc.report_stub = meters
        await meter_svc.report(object())
        await meter_svc.report_batch(object())
        self.assertNotIn('timeout', meters.collect.call_args.kwargs)
        self.assertNotIn('timeout', meters.collectBatch.call_args.kwargs)

        logs = MagicMock()
        logs.collect = AsyncMock()
        log_svc = GrpcLogReportServiceAsync.__new__(GrpcLogReportServiceAsync)
        log_svc.report_stub = logs
        await log_svc.report(object())
        self.assertNotIn('timeout', logs.collect.call_args.kwargs)

        profile = MagicMock()
        profile.collectSnapshot = AsyncMock()
        profile_svc = GrpcProfileTaskChannelServiceAsync.__new__(GrpcProfileTaskChannelServiceAsync)
        profile_svc.profile_stub = profile
        await profile_svc.report(object())
        self.assertNotIn('timeout', profile.collectSnapshot.call_args.kwargs)

    async def test_aio_unary_keeps_timeout(self):
        from unittest.mock import AsyncMock

        from skywalking.client.grpc_aio import GrpcServiceManagementClientAsync

        client = GrpcServiceManagementClientAsync.__new__(GrpcServiceManagementClientAsync)
        client.service_stub = MagicMock()
        client.service_stub.keepAlive = AsyncMock()
        client.refresh_instance_props = AsyncMock()
        await client.send_heart_beat()
        self.assertEqual(
            client.service_stub.keepAlive.call_args.kwargs.get('timeout'),
            grpc_call_timeout(),
        )


class TestClosePreviousProtocol(unittest.IsolatedAsyncioTestCase):

    def test_sync_close_never_blocks_on_aclose(self):
        from skywalking.agent import _close_previous_protocol

        proto = MagicMock()
        proto.close = MagicMock()
        proto.aclose = MagicMock()
        _close_previous_protocol(proto)
        proto.close.assert_called_once()
        proto.aclose.assert_not_called()
        _close_previous_protocol(None)

    async def test_aclose_awaited_on_running_loop(self):
        from skywalking.agent import _aclose_previous_protocol

        called = []
        loop = asyncio.get_running_loop()

        class _Proto:
            async def aclose(self):
                called.append(loop)

            def close(self):
                called.append('close')

        await _aclose_previous_protocol(_Proto())
        self.assertEqual(called, [loop])
        await _aclose_previous_protocol(None)

    async def test_aclose_falls_back_to_close(self):
        from skywalking.agent import _aclose_previous_protocol

        proto = MagicMock()
        proto.aclose = None
        proto.close = MagicMock()
        await _aclose_previous_protocol(proto)
        proto.close.assert_called_once()



class TestRpcTimeoutVsQueueWindow(unittest.TestCase):

    def test_timeout_has_margin_over_worst_case_batch(self):
        """RPC timeout must exceed absolute batch window + encode/RTT margin."""
        from skywalking import config

        prev = config.agent_queue_timeout
        try:
            config.agent_queue_timeout = 20
            timeout = grpc_call_timeout()
            self.assertEqual(timeout, 20 + _GRPC_RPC_TIMEOUT_MARGIN_SEC)
            self.assertGreater(timeout, float(config.agent_queue_timeout) + 1.0)
        finally:
            config.agent_queue_timeout = prev

    def test_sync_report_uses_timeout_with_margin(self):
        from skywalking import config
        from skywalking.client.grpc import GrpcTraceSegmentReportService

        prev = config.agent_queue_timeout
        try:
            config.agent_queue_timeout = 20
            stub = MagicMock()
            svc = GrpcTraceSegmentReportService.__new__(GrpcTraceSegmentReportService)
            svc.report_stub = stub
            svc.report(iter(()))
            self.assertEqual(
                stub.collect.call_args.kwargs.get('timeout'),
                20 + _GRPC_RPC_TIMEOUT_MARGIN_SEC,
            )
        finally:
            config.agent_queue_timeout = prev


class TestQueueGetWithinBatch(unittest.TestCase):

    def test_queue_timeout_zero_drains_immediately_available_item(self):
        from skywalking.agent.protocol.grpc import _queue_get_within_batch

        q = Queue()
        q.put('segment')
        batch_deadline = monotonic()
        item = _queue_get_within_batch(q, True, batch_deadline, allow_immediate=True)
        self.assertEqual(item, 'segment')
        self.assertTrue(q.empty())

    def test_queue_timeout_zero_skips_when_empty(self):
        from skywalking.agent.protocol.grpc import _queue_get_within_batch

        q = Queue()
        batch_deadline = monotonic()
        self.assertIsNone(
            _queue_get_within_batch(q, True, batch_deadline, allow_immediate=True),
        )


class TestCollectorChannelNotInstrumented(unittest.TestCase):

    def test_multi_address_collector_channel_skips_sw_interceptor(self):
        """Regression: ipv4: multi targets must not get sw_grpc client interceptors."""
        import grpc

        from skywalking import config
        from skywalking.plugins import sw_grpc
        from skywalking.utils.grpc_channel import (
            create_sync_channel,
            is_agent_collector_channel,
        )

        prev = config.agent_collector_backend_services
        sw_grpc.install_sync()
        try:
            config.agent_collector_backend_services = '10.0.0.1:11800,10.0.0.2:11800'
            with patch('grpc.intercept_channel') as intercept:
                channel = create_sync_channel()
                intercept.assert_not_called()
            self.assertTrue(is_agent_collector_channel(channel))
            with patch('grpc.intercept_channel',
                       side_effect=lambda c, *a, **k: c) as intercept:
                grpc.insecure_channel('business.example:50051')
                intercept.assert_called()
        finally:
            config.agent_collector_backend_services = prev

    def test_aio_multi_address_uses_collector_scope(self):
        from skywalking import config
        from skywalking.plugins import sw_grpc
        from skywalking.utils.grpc_channel import (
            create_aio_channel,
            is_agent_collector_channel,
            is_building_agent_collector_channel,
        )

        prev = config.agent_collector_backend_services
        sw_grpc.install_async()
        seen_building = []

        class _Probe:
            def __init__(self, *args, **kwargs):
                seen_building.append(is_building_agent_collector_channel())
                # Minimal stand-in; create_aio_channel only needs a return object.
                self._sw_agent_collector_channel = False

        try:
            config.agent_collector_backend_services = '10.0.0.1:11800,10.0.0.2:11800'
            with patch('skywalking.utils.grpc_channel.grpc.aio.insecure_channel', side_effect=_Probe):
                channel = create_aio_channel()
            self.assertEqual(seen_building, [True])
            self.assertTrue(is_agent_collector_channel(channel))
            self.assertFalse(is_building_agent_collector_channel())
        finally:
            config.agent_collector_backend_services = prev


if __name__ == '__main__':
    unittest.main()
