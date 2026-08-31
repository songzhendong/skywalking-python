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

"""
Shared gRPC channel target / options helpers for sync and aio reporters.

Multi-backend design (aligned with skywalking-nodejs native failover):
- One channel for the process lifetime; no hand-rolled poll/reselect manager.
- Single address → plain host:port (DNS for hostnames, with re-resolve).
- Multiple addresses are assembled like Node sw-static endpoints
  ({host, port} list, IPv4 / IPv6 / hostname can coexist).
- grpcio cannot register a custom scheme; the endpoint list is encoded for
  C-core: homogeneous ipv4:/ipv6:, mixed families via ipv6: + IPv4-mapped
  (::ffff:a.b.c.d) so pick_first can try both families.
- Hostnames in a multi list are resolved once at channel build (grpcio cannot
  keep a literal hostname in ipv4:/ipv6:). No periodic DNS re-resolve for multi.
- pick_first shuffleAddressList is on (per-process random preferred backend).
  Channel target / grpc.default_authority still follow config order (TLS SAN).
- Invalid entries are logged and dropped; never silently ignored without a log.
- HTTP proxy disabled; keepalive channel options intentionally omitted (OAP conflict).
- Unary and sync streaming RPCs use a deadline (Node 10s floor, always >
  agent_queue_timeout + margin so sync collect is not cut off by the batching window).
  Aio client-streaming collect/collectBatch/collectSnapshot omit timeout=
  (generators await empty queues). DEADLINE_EXCEEDED / RESOURCE_EXHAUSTED on a
  READY backend do not rotate or rebuild; failover is for unreachable backends,
  not a slow but connected one.
- READY gate (application-level): skip report RPCs unless channel connectivity is READY;
  nudge IDLE via get_state(True) so gating does not starve reconnect (Node watch parity).
- Reconnect backoff max 30s (Node multi-backend parity).
- service_config retries only ManagementService.reportInstanceProperties on UNAVAILABLE
  (max 3); never retry client-streaming collect.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Sequence, Tuple

import grpc

from skywalking.loggings import logger

# Retry only unary idempotent reportInstanceProperties (Node service_config parity).
# Client-streaming collect must NOT be retried — replay would duplicate segments.
# keepAlive relies on the next heartbeat tick instead.
_PROPERTIES_RETRY_SERVICE_CONFIG = json.dumps({
    # Shuffle is LB-layer (Node parity): target string stays config-order so
    # grpc.default_authority / TLS SNI remain the first configured endpoint.
    'loadBalancingConfig': [{'pick_first': {'shuffleAddressList': True}}],
    'methodConfig': [{
        'name': [{
            'service': 'skywalking.v3.ManagementService',
            'method': 'reportInstanceProperties',
        }],
        'retryPolicy': {
            'maxAttempts': 3,
            'initialBackoff': '1s',
            'maxBackoff': '10s',
            'backoffMultiplier': 2,
            'retryableStatusCodes': ['UNAVAILABLE'],
        },
    }],
})

# Channel options shared by sync + aio. Do NOT add keepalive_* options here.
# pick_first + shuffle lives in grpc.service_config (not grpc.lb_policy_name).
GRPC_CHANNEL_OPTIONS: Tuple[Tuple[str, int | str], ...] = (
    ('grpc.enable_http_proxy', 0),
    ('grpc.enable_retries', 1),
    ('grpc.service_config', _PROPERTIES_RETRY_SERVICE_CONFIG),
    ('grpc.initial_reconnect_backoff_ms', 1000),
    ('grpc.min_reconnect_backoff_ms', 1000),
    # Cap aligns with Node multi-backend (~30s); shorter caps reconnect too aggressively.
    ('grpc.max_reconnect_backoff_ms', 30000),
)

# Node default RPC deadline is 10s. Sync streaming collect must outlive the queue
# batch window with room for protobuf encode + RTT + server handling.
# Sync generators may spend nearly the full queue window on the final queue.get
# (absolute batch deadline); margin keeps healthy sends off DEADLINE_EXCEEDED.
# Do not apply this to aio client-streaming: those generators await queue.get() forever.
_GRPC_RPC_TIMEOUT_FLOOR_SEC = 10.0
_GRPC_RPC_TIMEOUT_MARGIN_SEC = 5.0


def grpc_call_timeout() -> float:
    """Seconds for unary / sync-streaming stub timeout=. Always > agent_queue_timeout + margin."""
    from skywalking import config

    return max(
        _GRPC_RPC_TIMEOUT_FLOOR_SEC,
        float(config.agent_queue_timeout) + _GRPC_RPC_TIMEOUT_MARGIN_SEC,
    )


_AUTH_LOG_INTERVAL_SEC = 60.0
_last_auth_log_at = 0.0
_CONNECTIVITY_LOG_INTERVAL_SEC = 30.0
_last_connectivity_log_at: Dict[str, float] = {}
_DNS_LOOKUP_TIMEOUT_SEC = 5.0

# Thread-local: set while create_*_channel builds the agent→OAP channel so sw_grpc
# does not attach client interceptors (multi-address targets no longer match config).
_building_agent_collector = threading.local()
_SW_AGENT_COLLECTOR_ATTR = '_sw_agent_collector_channel'


@contextmanager
def agent_collector_channel_scope():
    _building_agent_collector.active = True
    try:
        yield
    finally:
        _building_agent_collector.active = False


def is_building_agent_collector_channel() -> bool:
    return bool(getattr(_building_agent_collector, 'active', False))


def mark_agent_collector_channel(channel):
    try:
        setattr(channel, _SW_AGENT_COLLECTOR_ATTR, True)
    except Exception:  # noqa: BLE001 - exotic channel wrappers
        pass
    return channel


def is_agent_collector_channel(channel) -> bool:
    return bool(getattr(channel, _SW_AGENT_COLLECTOR_ATTR, False))


class AddressKind(Enum):
    IPV4 = 'ipv4'
    IPV6 = 'ipv6'
    HOSTNAME = 'hostname'


@dataclass(frozen=True)
class BackendAddress:
    host: str
    port: int
    kind: AddressKind

    def endpoint(self) -> str:
        if self.kind == AddressKind.IPV6:
            return f'[{self.host}]:{self.port}'
        return f'{self.host}:{self.port}'


def _classify_host(host: str) -> Optional[AddressKind]:
    if not host or any(c.isspace() or ord(c) < 32 for c in host) or '/' in host:
        return None
    # Zone indices (fe80::1%eth0) are not usable in static ipv6: targets.
    if '%' in host:
        return None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return AddressKind.HOSTNAME
    if isinstance(ip, ipaddress.IPv4Address):
        return AddressKind.IPV4
    return AddressKind.IPV6


def parse_backend_address(raw: str) -> Optional[BackendAddress]:
    """Parse a single host:port (IPv6 requires [host]:port). Returns None if invalid."""
    text = (raw or '').strip()
    if not text:
        return None

    host: str
    port_str: str
    if text.startswith('['):
        # [ipv6]:port
        closing = text.find(']')
        if closing <= 1 or closing + 1 >= len(text) or text[closing + 1] != ':':
            return None
        host = text[1:closing]
        port_str = text[closing + 2:]
    else:
        if text.count(':') != 1:
            # Ambiguous IPv6 without brackets, or missing port.
            return None
        host, port_str = text.rsplit(':', 1)

    host = host.strip()
    port_str = port_str.strip()
    if not host or not port_str:
        return None
    try:
        port = int(port_str)
    except ValueError:
        return None
    if port < 1 or port > 65535:
        return None

    kind = _classify_host(host)
    if kind is None:
        return None
    return BackendAddress(host=host, port=port, kind=kind)


def parse_backend_addresses(services: str) -> List[BackendAddress]:
    """
    Split SW_AGENT_COLLECTOR_BACKEND_SERVICES on commas.
    Invalid entries are skipped with an error log (never silent).
    """
    parts = [p.strip() for p in (services or '').split(',') if p.strip()]
    addresses: List[BackendAddress] = []
    for part in parts:
        addr = parse_backend_address(part)
        if addr is None:
            logger.error(
                'Invalid collector backend address %r in SW_AGENT_COLLECTOR_BACKEND_SERVICES; '
                'expected host:port or [ipv6]:port',
                part,
            )
            continue
        addresses.append(addr)
    return addresses


def sw_static_endpoints(addresses: Sequence[BackendAddress]) -> List[Dict]:
    """
    Node sw-static resolver output shape: a list of endpoints, each with
    addresses: [{host, port}]. IPv4, IPv6, and hostnames can share one list.
    """
    return [
        {'addresses': [{'host': addr.host, 'port': addr.port}]}
        for addr in addresses
    ]


def _lookup_hostname(host: str, port: int) -> List[BackendAddress]:
    """
    Resolve hostname to BackendAddress IPs (order preserved, duplicates dropped).

    Multi-address targets require literal IPs for ipv4:/ipv6:. A hung DNS lookup
    must not block agent startup or process exit — bound the wait and run the
    lookup on a daemon thread (ThreadPoolExecutor workers are non-daemon and
    would keep the process alive after timeout).
    """
    import threading
    from concurrent.futures import Future, TimeoutError as FuturesTimeout

    fut: Future = Future()

    def _run() -> None:
        try:
            fut.set_result(socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM))
        except Exception as exc:  # noqa: BLE001 - forward any lookup failure to waiter
            if not fut.done():
                fut.set_exception(exc)

    threading.Thread(target=_run, name=f'sw-dns-{host}', daemon=True).start()
    try:
        infos = fut.result(timeout=_DNS_LOOKUP_TIMEOUT_SEC)
    except FuturesTimeout:
        logger.error(
            'Timed out resolving collector hostname %r:%s after %.1fs; skipping this backend',
            host,
            port,
            _DNS_LOOKUP_TIMEOUT_SEC,
        )
        return []
    except socket.gaierror as exc:
        logger.error(
            'Failed to resolve collector hostname %r:%s (%s); skipping this backend',
            host,
            port,
            exc,
        )
        return []
    except Exception as exc:  # noqa: BLE001 - never crash agent init on DNS oddities
        logger.error(
            'Unexpected error resolving collector hostname %r:%s (%s); skipping this backend',
            host,
            port,
            exc,
        )
        return []

    resolved: List[BackendAddress] = []
    seen = set()
    for family, _type, _proto, _canon, sockaddr in infos:
        if family == socket.AF_INET:
            ip = sockaddr[0]
            kind = AddressKind.IPV4
        elif family == socket.AF_INET6:
            ip = sockaddr[0]
            if '%' in ip:
                ip = ip.split('%', 1)[0]
            # Skip IPv4-mapped IPv6; the AF_INET result already covers that backend.
            try:
                packed = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if packed.ipv4_mapped is not None:
                continue
            kind = AddressKind.IPV6
        else:
            continue
        key = (kind, ip, port)
        if key in seen:
            continue
        seen.add(key)
        resolved.append(BackendAddress(host=ip, port=port, kind=kind))
    if not resolved:
        logger.error(
            'Collector hostname %r:%s resolved to no usable IPv4/IPv6 address; skipping',
            host,
            port,
        )
    return resolved


def expand_backend_addresses(addresses: Sequence[BackendAddress]) -> List[BackendAddress]:
    """
    Expand hostnames to literal IPs for C-core static targets.
    Literal IP entries are kept as-is. Failed hostname lookups are skipped with error logs.
    """
    expanded: List[BackendAddress] = []
    seen = set()
    for addr in addresses:
        candidates: Sequence[BackendAddress]
        if addr.kind == AddressKind.HOSTNAME:
            candidates = _lookup_hostname(addr.host, addr.port)
        else:
            candidates = (addr,)
        for item in candidates:
            key = (item.kind, item.host, item.port)
            if key in seen:
                continue
            seen.add(key)
            expanded.append(item)
    return expanded


def _ipv4_mapped_v6(ipv4: str) -> str:
    return f'::ffff:{ipv4}'


def encode_sw_static_for_c_core(addresses: Sequence[BackendAddress]) -> str:
    """
    Encode a Node-style mixed endpoint list for grpcio/C-core.

    Homogeneous lists use ipv4:/ipv6:. Mixed IPv4+IPv6 uses the ipv6 resolver
    with IPv4-mapped addresses so pick_first can try both families.
    """
    if not addresses:
        raise ValueError(
            'No valid collector backend address in SW_AGENT_COLLECTOR_BACKEND_SERVICES'
        )
    if any(a.kind == AddressKind.HOSTNAME for a in addresses):
        raise ValueError('encode_sw_static_for_c_core requires literal IP endpoints')

    kinds = {a.kind for a in addresses}
    if kinds == {AddressKind.IPV4}:
        return 'ipv4:' + ','.join(f'{a.host}:{a.port}' for a in addresses)
    if kinds == {AddressKind.IPV6}:
        return 'ipv6:' + ','.join(f'[{a.host}]:{a.port}' for a in addresses)

    parts = []
    for addr in addresses:
        if addr.kind == AddressKind.IPV4:
            parts.append(f'[{_ipv4_mapped_v6(addr.host)}]:{addr.port}')
        else:
            parts.append(f'[{addr.host}]:{addr.port}')
    logger.info(
        'Encoding mixed-family sw-static endpoints for grpcio via ipv6 IPv4-mapped list: %s',
        parts,
    )
    return 'ipv6:' + ','.join(parts)


def prepare_grpc_channel_endpoints(
    addresses: Sequence[BackendAddress],
) -> Tuple[str, str]:
    """
    Build (channel_target, default_authority) from parsed backends.

    Authority prefers the first *usable* original entry's host:port (hostname kept
    for TLS SAN when that name resolved). Never points at a hostname that DNS skipped.
    """
    if not addresses:
        raise ValueError(
            'No valid collector backend address in SW_AGENT_COLLECTOR_BACKEND_SERVICES'
        )

    if len(addresses) == 1:
        ep = addresses[0].endpoint()
        return ep, ep

    to_encode: List[BackendAddress] = []
    seen = set()
    authority: Optional[str] = None

    for orig in addresses:
        if orig.kind == AddressKind.HOSTNAME:
            candidates = _lookup_hostname(orig.host, orig.port)
            if not candidates:
                continue
            if authority is None:
                # Prefer original hostname for :authority / SNI (Node sw-static style).
                authority = orig.endpoint()
        else:
            candidates = (orig,)
            if authority is None:
                authority = orig.endpoint()
        for item in candidates:
            key = (item.kind, item.host, item.port)
            if key in seen:
                continue
            seen.add(key)
            to_encode.append(item)

    if not to_encode:
        raise ValueError(
            'No usable collector backend address after DNS expansion of '
            'SW_AGENT_COLLECTOR_BACKEND_SERVICES'
        )
    if authority is None:
        authority = to_encode[0].endpoint()

    if any(a.kind == AddressKind.HOSTNAME for a in addresses):
        logger.info(
            'Expanded multi-backend collector addresses %s -> %s (authority=%s)',
            [a.endpoint() for a in addresses],
            [a.endpoint() for a in to_encode],
            authority,
        )
    return encode_sw_static_for_c_core(to_encode), authority


def _resolve_channel_target_and_authority() -> Tuple[str, str]:
    """
    Never raise into the host app. prepare_grpc_channel_endpoints stays strict;
    factories degrade so the agent can idle behind the READY gate.
    """
    from skywalking import config

    raw = config.agent_collector_backend_services
    addresses = parse_backend_addresses(raw)
    try:
        return prepare_grpc_channel_endpoints(addresses)
    except ValueError:
        if addresses:
            target = addresses[0].endpoint()
            logger.error(
                'No usable collector backend after DNS expansion of %r; '
                'falling back to plain target %s so grpcio can re-resolve',
                raw,
                target,
            )
            return target, target
        fallback = (raw or '').strip() or 'localhost:1'
        logger.error(
            'No valid collector backend address in %r; opening a channel to %s '
            '(agent stays up; READY gate skips reports)',
            raw,
            fallback,
        )
        return fallback, fallback


def build_grpc_target(addresses: Sequence[BackendAddress]) -> str:
    """Build a gRPC channel target string (see prepare_grpc_channel_endpoints)."""
    target, _authority = prepare_grpc_channel_endpoints(addresses)
    return target


def resolve_grpc_target(services: Optional[str] = None) -> str:
    from skywalking import config

    raw = config.agent_collector_backend_services if services is None else services
    return build_grpc_target(parse_backend_addresses(raw))


def _channel_options(default_authority: str) -> Tuple[Tuple[str, int | str], ...]:
    options = list(GRPC_CHANNEL_OPTIONS)
    # Align with Node sw-static getDefaultAuthority (first usable backend).
    options.append(('grpc.default_authority', default_authority))
    return tuple(options)


def create_sync_channel():
    """Create one sync gRPC channel (caller may wrap with auth interceptor)."""
    from skywalking import config

    target, authority = _resolve_channel_target_and_authority()
    options = _channel_options(authority)
    logger.info('Creating gRPC channel to collector target %s (authority=%s)', target, authority)
    with agent_collector_channel_scope():
        try:
            if config.agent_force_tls:
                channel = grpc.secure_channel(target, grpc.ssl_channel_credentials(), options=options)
            else:
                channel = grpc.insecure_channel(target, options=options)
        except Exception:  # noqa: BLE001 - never fail host process start
            logger.exception(
                'Failed to create gRPC channel to %s; using localhost:1 placeholder',
                target,
            )
            channel = grpc.insecure_channel('localhost:1', options=options)
        return mark_agent_collector_channel(channel)


def create_aio_channel(interceptors=None):
    """Create one aio gRPC channel with optional interceptors."""
    from skywalking import config

    target, authority = _resolve_channel_target_and_authority()
    options = _channel_options(authority)
    logger.info('Creating aio gRPC channel to collector target %s (authority=%s)', target, authority)
    with agent_collector_channel_scope():
        try:
            if config.agent_force_tls:
                channel = grpc.aio.secure_channel(
                    target,
                    grpc.ssl_channel_credentials(),
                    options=options,
                    interceptors=interceptors,
                )
            else:
                channel = grpc.aio.insecure_channel(target, options=options, interceptors=interceptors)
        except Exception:  # noqa: BLE001 - never fail host process start
            logger.exception(
                'Failed to create aio gRPC channel to %s; using localhost:1 placeholder',
                target,
            )
            channel = grpc.aio.insecure_channel('localhost:1', options=options, interceptors=interceptors)
        return mark_agent_collector_channel(channel)


def _unwrap_connectivity_state(channel, try_to_connect: bool):
    """
    Read channel connectivity for sync, aio, and intercept_channel wrappers.

    grpc.aio.Channel exposes get_state(). Sync grpc._channel.Channel does not
    (subscribe only); use C-core check_connectivity_state on the cython channel.
    Intercepted channels nest the real Channel on ``_channel``.
    """
    get_state = getattr(channel, 'get_state', None)
    if callable(get_state):
        return get_state(try_to_connect)

    candidate = channel
    for _ in range(4):
        inner = getattr(candidate, '_channel', None)
        if inner is None:
            break
        check = getattr(inner, 'check_connectivity_state', None)
        if callable(check):
            code = check(try_to_connect)
            for state in grpc.ChannelConnectivity:
                if state.value[0] == code:
                    return state
            return None
        candidate = inner
    return None


def is_channel_ready(channel) -> bool:
    """
    Application-level READY gate (gRPC only exposes connectivity state).

    Returns True only when connectivity is READY. Uses try_to_connect=True so an
    IDLE channel is nudged into CONNECTING — otherwise skipping all RPCs would
    leave the channel idle forever (same role as Node watchConnectivityState
    with requestConnection=true). CONNECTING / TRANSIENT_FAILURE still return
    False so reporters skip until READY.

    If connectivity cannot be read, returns True (fail-open) so a missing API
    cannot permanently silence reporting.
    """
    try:
        state = _unwrap_connectivity_state(channel, True)
    except Exception:  # noqa: BLE001 - defensive for closed / exotic channels
        return True
    if state is None:
        return True
    return state == grpc.ChannelConnectivity.READY


def is_auth_rpc_error(error: BaseException) -> bool:
    code = getattr(error, 'code', None)
    if not callable(code):
        return False
    try:
        status = code()
    except Exception:  # noqa: BLE001 - defensive for non-grpc exceptions
        return False
    return status in (grpc.StatusCode.UNAUTHENTICATED, grpc.StatusCode.PERMISSION_DENIED)


def log_auth_failure_throttled(error: BaseException) -> None:
    """Auth failures must not rotate backends; same cluster shares one token."""
    global _last_auth_log_at
    now = time.monotonic()
    if now - _last_auth_log_at < _AUTH_LOG_INTERVAL_SEC:
        return
    _last_auth_log_at = now
    logger.error(
        'Collector rejected authentication (%s). Check SW_AGENT_AUTHENTICATION; '
        'the agent will not rotate backends for auth failures.',
        error,
    )


def log_connectivity_event(kind: str, message: str, *args) -> None:
    """Throttle disconnect warnings; recovery stays informative but rate-limited."""
    now = time.monotonic()
    last = _last_connectivity_log_at.get(kind, 0.0)
    if now - last < _CONNECTIVITY_LOG_INTERVAL_SEC:
        return
    _last_connectivity_log_at[kind] = now
    if kind == 'recovered':
        logger.info(message, *args)
    else:
        logger.warning(message, *args)


def apply_connectivity_transition(prev, state) -> None:
    """Shared INFO/WARN side-effects for sync subscribe and aio watch."""
    if state == grpc.ChannelConnectivity.TRANSIENT_FAILURE:
        log_connectivity_event(
            'transient_failure',
            'gRPC collector channel disconnected (TRANSIENT_FAILURE)',
        )
    elif state == grpc.ChannelConnectivity.IDLE and prev == grpc.ChannelConnectivity.READY:
        log_connectivity_event('idle', 'gRPC collector channel disconnected (IDLE)')
    elif state == grpc.ChannelConnectivity.READY and prev in (
        grpc.ChannelConnectivity.TRANSIENT_FAILURE,
        grpc.ChannelConnectivity.IDLE,
        grpc.ChannelConnectivity.CONNECTING,
        None,
    ):
        log_connectivity_event('recovered', 'gRPC collector channel recovered (READY)')


def handle_rpc_error(error: BaseException, on_connectivity_error) -> None:
    """
    Shared RpcError side-effects for sync/aio reporters.
    Auth: throttle log only (no channel rebuild / backend rotate).
    Other: invoke connectivity recovery hook (resubscribe / debug), never rebuild channel.

    Failover is for an unreachable backend, not functional health of a connected one.
    DEADLINE_EXCEEDED and RESOURCE_EXHAUSTED on a READY channel are intentionally
    left to the call site: pick_first will not move off a slow-but-READY backend,
    and this agent does not rotate or rebuild the channel for those codes.
    """
    if is_auth_rpc_error(error):
        log_auth_failure_throttled(error)
        return
    on_connectivity_error()
