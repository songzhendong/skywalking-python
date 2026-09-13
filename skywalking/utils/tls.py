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
Collector TLS / mTLS helpers for gRPC and HTTP reporters.

Rules:
- TLS when FORCE_TLS is set or the trusted CA file exists.
- Custom CA is used only when that file exists *and* parses as a CA PEM
  (otherwise system trust with FORCE_TLS, or plaintext without it).
- mTLS (client cert + key) is enabled only when a usable custom CA was loaded
  *and* both cert-chain and key files exist and parse. Missing / invalid
  cert/key logs a warning and stays one-way TLS — it does not fail agent start.
- A non-empty CA / cert / key path that cannot be resolved logs a warning
  (misconfig must not look like "TLS off by design").
- Invalid PEM content, SSLContext build failures, and temp-file I/O errors
  never raise into the host process: warn and degrade (see degrade table in
  ``ssl_context_for_collector`` / ``requests_tls_settings``).
- HTTP mTLS temp PEMs are process-local: after ``os.fork()`` the child rebinds
  its temp-file list so exiting the child cannot unlink the parent's files.
"""

from __future__ import annotations

import atexit
import base64
import os
import ssl
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple

from skywalking.loggings import logger

# Align with Node TlsMaterialCache: refuse oversized PEMs (DoS / misconfig).
_MAX_PEM_BYTES = 256 * 1024
# Avoid repeating the same misconfig warning on every reporter call.
_warned_keys: set = set()


def _warn_once(key: str, message: str, *args) -> None:
    if key in _warned_keys:
        return
    _warned_keys.add(key)
    logger.warning(message, *args)


def _configured_path(value: str) -> str:
    return (value or '').strip()


def ssl_file_path(value: str) -> Optional[Path]:
    """
    Return a readable regular file path, or None.

    Paths are cwd-relative or absolute. Symlinks are followed (Kubernetes
    secret mounts are typically ``ca.crt -> ..data/ca.crt``); the resolved
    target must be a regular file.

    Never raises: ``expanduser`` / ``resolve`` failures (including symlink
    loops and unresolvable ``~user`` → ``RuntimeError``) degrade to None so
    TLS misconfig cannot abort agent start.
    """
    text = _configured_path(value)
    if not text:
        return None
    try:
        path = Path(text).expanduser()
        resolved = path.resolve(strict=True)
        if resolved.is_file():
            return resolved
    except (OSError, ValueError, RuntimeError):
        # OSError: missing path / I/O. ValueError: embedded NUL. RuntimeError:
        # expanduser ~user miss or symlink-loop resolve on some platforms.
        return None
    return None


def collector_uses_tls() -> bool:
    from skywalking import config

    force = bool(config.agent_force_tls)
    ca_cfg = _configured_path(config.agent_ssl_trusted_ca_path)
    ca_path = ssl_file_path(ca_cfg) if ca_cfg else None
    if ca_cfg and ca_path is None:
        if force:
            _warn_once(
                f'ca-missing:{ca_cfg}',
                'SW_AGENT_SSL_TRUSTED_CA_PATH is set (%r) but is not a readable regular '
                'file; custom CA is ignored. FORCE_TLS remains on with the process trust store.',
                ca_cfg,
            )
        else:
            _warn_once(
                f'ca-missing:{ca_cfg}',
                'SW_AGENT_SSL_TRUSTED_CA_PATH is set (%r) but is not a readable regular '
                'file; TLS via custom CA is disabled and the collector stays plaintext '
                '(set SW_AGENT_FORCE_TLS to use the process trust store).',
                ca_cfg,
            )
    return force or ca_path is not None


def _read_bytes(path: Path) -> bytes:
    size = os.path.getsize(path)
    if size > _MAX_PEM_BYTES:
        raise ValueError(
            f'SSL PEM file exceeds {_MAX_PEM_BYTES} bytes: {path} ({size} bytes)'
        )
    return path.read_bytes()


def _load_trusted_ca(path: Path) -> bytes:
    """
    Read and parse a trusted CA PEM.

    Raises OSError / ValueError when the file is unreadable, oversized, or not
    a CA bundle OpenSSL can load — callers degrade instead of handing garbage
    to gRPC / requests (which may only fail at connect time).

    Returns ASCII PEM with ``CERTIFICATE`` and/or ``TRUSTED CERTIFICATE`` blocks
    extracted (labels and trust attributes preserved). UTF-8 BOM / preamble
    accepted by ``cafile`` stay usable for ``cadata`` and temp verify files.
    """
    data = _read_bytes(path)
    try:
        ssl.create_default_context(cafile=str(path))
    except OSError as exc:
        # ssl.SSLError subclasses OSError on CPython.
        raise ValueError(f'Invalid trusted CA PEM {path}: {exc}') from exc
    return _extract_ca_pem_blocks(data)


def _validate_client_cert_key(cert_pem: bytes, key_pem: bytes) -> None:
    """Raise OSError / ValueError when cert+key cannot load as a client identity."""
    cert_path = key_path = None
    try:
        fd, cert_path = tempfile.mkstemp(suffix='.crt')
        try:
            os.write(fd, cert_pem)
        finally:
            os.close(fd)
        fd, key_path = tempfile.mkstemp(suffix='.pem')
        try:
            os.write(fd, key_pem)
        finally:
            os.close(fd)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_cert_chain(cert_path, key_path)
    finally:
        for path in (cert_path, key_path):
            if path is None:
                continue
            try:
                os.unlink(path)
            except OSError:
                pass


# OpenSSL PKCS#1 PEM → PKCS#8 PEM for stacks that only accept PKCS#8.
# grpcio/BoringSSL and CPython ssl both accept PKCS#1 RSA PEMs directly; this
# wrap exists for HTTP stacks / older OpenSSL bindings that reject
# ``BEGIN RSA PRIVATE KEY`` and only load PKCS#8 ``BEGIN PRIVATE KEY``.
_PKCS1_PEM_HEADER = '-----BEGIN RSA PRIVATE KEY-----'
_PKCS1_PEM_FOOTER = '-----END RSA PRIVATE KEY-----'
_PKCS8_PEM_HEADER = '-----BEGIN PRIVATE KEY-----'
_PKCS8_PEM_FOOTER = '-----END PRIVATE KEY-----'
_ENCRYPTED_PEM_HEADER = '-----BEGIN ENCRYPTED PRIVATE KEY-----'


def normalize_private_key_pem(key_pem: bytes) -> bytes:
    """
    Return PKCS#8 PEM bytes. PKCS#1 (`BEGIN RSA PRIVATE KEY`) is wrapped into
    an unencrypted PKCS#8 PEM; other PEM/DER forms pass through.

    Passphrase-encrypted PEMs (PKCS#8 encrypted or legacy OpenSSL Proc-Type)
    are rejected with a clear error (not supported).

    Only the bytes between the matching PKCS#1 BEGIN/END delimiters are
    decoded — comments or ``openssl rsa -text`` preamble outside the block
    must not corrupt the key (OpenSSL accepts such files).
    """
    text = key_pem.decode('utf-8', errors='ignore')
    if _ENCRYPTED_PEM_HEADER in text:
        raise ValueError(
            'Passphrase-encrypted private keys are not supported; '
            'use an unencrypted PEM (PKCS#8 or PKCS#1 RSA)'
        )
    # Legacy OpenSSL ``openssl genrsa -aes256`` / ``rsa -des3`` output.
    if 'Proc-Type:' in text and 'ENCRYPTED' in text.upper():
        raise ValueError(
            'Passphrase-encrypted private keys are not supported; '
            'use an unencrypted PEM (PKCS#8 or PKCS#1 RSA)'
        )
    if _PKCS1_PEM_HEADER not in text:
        return key_pem

    start = text.find(_PKCS1_PEM_HEADER)
    end = text.find(_PKCS1_PEM_FOOTER, start)
    if start < 0 or end < 0:
        raise ValueError('Invalid PKCS#1 private key PEM: missing BEGIN/END delimiters')
    body = text[start + len(_PKCS1_PEM_HEADER):end]
    body = body.replace('\r', '').replace('\n', '').replace(' ', '')
    try:
        pkcs1 = base64.b64decode(body, validate=False)
    except ValueError as exc:
        raise ValueError(f'Invalid PKCS#1 private key PEM: {exc}') from exc

    pkcs1_length = len(pkcs1)
    total_length = pkcs1_length + 22
    # Fixed 2-byte length form (keys up to ~64KiB DER).
    if total_length > 0xFFFF or pkcs1_length > 0xFFFF:
        raise ValueError('PKCS#1 private key too large for PKCS#8 wrap')

    # Hand-rolled PKCS#8 PrivateKeyInfo wrapping RSA PKCS#1 (AlgorithmIdentifier
    # rsaEncryption). Verified byte-identical to cryptography for 2048/4096 RSA.
    pkcs8_header = bytes([
        0x30, 0x82, (total_length >> 8) & 0xFF, total_length & 0xFF,
        0x02, 0x01, 0x00,
        0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00,
        0x04, 0x82, (pkcs1_length >> 8) & 0xFF, pkcs1_length & 0xFF,
    ])
    encoded = base64.b64encode(pkcs8_header + pkcs1).decode('ascii')
    # 64-char lines, matching typical PEM layout.
    lines = [encoded[i:i + 64] for i in range(0, len(encoded), 64)]
    pem = _PKCS8_PEM_HEADER + '\n' + '\n'.join(lines) + '\n' + _PKCS8_PEM_FOOTER + '\n'
    return pem.encode('ascii')


def _extract_pem_blocks(data: bytes, label: str) -> bytes:
    """
    Return ASCII PEM containing only ``BEGIN/END {label}`` blocks.

    Strips UTF-8 BOM and ignores preamble/comments outside PEM delimiters so
    OpenSSL-accepted files (BOM, UTF-8 comments) stay usable for ``cadata`` and
    temp-file verify paths that require clean ASCII PEM.
    """
    text = data.decode('utf-8', errors='ignore').lstrip('\ufeff')
    header = f'-----BEGIN {label}-----'
    footer = f'-----END {label}-----'
    blocks: List[str] = []
    pos = 0
    while True:
        start = text.find(header, pos)
        if start < 0:
            break
        end = text.find(footer, start)
        if end < 0:
            break
        end += len(footer)
        blocks.append(text[start:end].strip() + '\n')
        pos = end
    if not blocks:
        raise ValueError(f'No {label} PEM block found')
    return ''.join(blocks).encode('ascii')


# OpenSSL ``openssl x509 -trustout`` emits TRUSTED CERTIFICATE (with trust
# auxiliary). Keep that label — do not relabel as CERTIFICATE.
_CA_PEM_LABELS = ('TRUSTED CERTIFICATE', 'CERTIFICATE')


def _extract_ca_pem_blocks(data: bytes) -> bytes:
    """
    Return ASCII PEM with ``CERTIFICATE`` / ``TRUSTED CERTIFICATE`` blocks only.

    Preserves each block's PEM label and trust attributes. Strips UTF-8 BOM and
    ignores preamble outside delimiters. ``TRUSTED CERTIFICATE`` is searched
    first so its header is not confused with plain ``CERTIFICATE``.
    """
    text = data.decode('utf-8', errors='ignore').lstrip('\ufeff')
    found: List[Tuple[int, str]] = []
    for label in _CA_PEM_LABELS:
        header = f'-----BEGIN {label}-----'
        footer = f'-----END {label}-----'
        pos = 0
        while True:
            start = text.find(header, pos)
            if start < 0:
                break
            end = text.find(footer, start)
            if end < 0:
                break
            end += len(footer)
            found.append((start, text[start:end].strip() + '\n'))
            pos = end
    if not found:
        raise ValueError('No CERTIFICATE or TRUSTED CERTIFICATE PEM block found')
    found.sort(key=lambda item: item[0])
    return ''.join(block for _, block in found).encode('ascii')


def _mtls_material(*, ca_usable: bool) -> Tuple[Optional[bytes], Optional[bytes]]:
    """
    Client certificate_chain and private_key PEM bytes, or (None, None).

    mTLS is considered only when a custom CA was successfully loaded and parsed
    (``ca_usable``). A CA path that exists but failed to load must not unlock
    client certs for FORCE_TLS / system-trust fallback.
    Private keys are normalized to PKCS#8 when the file is PKCS#1.
    """
    from skywalking import config

    cert_cfg = _configured_path(config.agent_ssl_cert_chain_path)
    key_cfg = _configured_path(config.agent_ssl_key_path)

    if not ca_usable:
        # Client material without a usable CA cannot enable mTLS (by design).
        if cert_cfg or key_cfg:
            _warn_once(
                f'mtls-without-ca:{cert_cfg}|{key_cfg}',
                'Client SSL cert/key is configured but SW_AGENT_SSL_TRUSTED_CA_PATH '
                'is missing, unreadable, or not a valid CA PEM; mTLS is disabled. '
                'Provide a readable CA PEM to enable mTLS (FORCE_TLS alone uses '
                'system trust for one-way TLS).',
            )
        return None, None

    if bool(cert_cfg) ^ bool(key_cfg):
        _warn_once(
            f'mtls-partial:{cert_cfg}|{key_cfg}',
            'Only one of SW_AGENT_SSL_CERT_CHAIN_PATH / SW_AGENT_SSL_KEY_PATH is set; '
            'mTLS requires both. Staying on one-way TLS.',
        )
        return None, None

    if not cert_cfg or not key_cfg:
        return None, None

    cert_path = ssl_file_path(cert_cfg)
    key_path = ssl_file_path(key_cfg)
    if cert_path is None or key_path is None:
        logger.warning('Failed to enable mTLS caused by cert or key cannot be found.')
        return None, None

    try:
        cert_pem = _read_bytes(cert_path)
        key_pem = normalize_private_key_pem(_read_bytes(key_path))
        _validate_client_cert_key(cert_pem, key_pem)
        return cert_pem, key_pem
    except (OSError, ValueError) as exc:
        logger.warning('Failed to enable mTLS caused by cert or key read error: %s', exc)
        return None, None


# Keep mTLS / CA temp PEM paths alive for the process (requests/ssl need file paths).
_mtls_temp_files: List[str] = []
_mtls_file_cache_key: Optional[Tuple[bytes, bytes]] = None
_mtls_file_cache: Optional[Tuple[str, str]] = None
_ca_file_cache_key: Optional[bytes] = None
_ca_file_cache: Optional[str] = None
_atexit_registered = False


def _cleanup_mtls_temp_files() -> None:
    global _ca_file_cache, _ca_file_cache_key, _mtls_file_cache, _mtls_file_cache_key
    for path in list(_mtls_temp_files):
        try:
            os.unlink(path)
        except OSError:
            pass
    _mtls_temp_files.clear()
    _mtls_file_cache = None
    _mtls_file_cache_key = None
    _ca_file_cache = None
    _ca_file_cache_key = None


def _after_fork_in_child() -> None:
    """
    Drop inherited temp-path bookkeeping without unlinking.

    Parent-created PEM temps must stay on disk for the parent reporter. Clearing
    the list in-place would also empty the parent's list (same object); rebind
    instead so the child's atexit handler cannot delete the parent's files.
    """
    global _mtls_temp_files, _mtls_file_cache, _mtls_file_cache_key
    global _ca_file_cache, _ca_file_cache_key
    _mtls_temp_files = []
    _mtls_file_cache = None
    _mtls_file_cache_key = None
    _ca_file_cache = None
    _ca_file_cache_key = None


if hasattr(os, 'register_at_fork'):
    os.register_at_fork(after_in_child=_after_fork_in_child)


def _ensure_atexit() -> None:
    global _atexit_registered
    if not _atexit_registered:
        atexit.register(_cleanup_mtls_temp_files)
        _atexit_registered = True


def _pem_bytes_to_temp_file(data: bytes, suffix: str) -> str:
    _ensure_atexit()
    handle, path = tempfile.mkstemp(suffix=suffix)
    try:
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            written = os.write(handle, view[offset:])
            if written <= 0:
                raise OSError(f'Failed to write SSL PEM temp file {path}')
            offset += written
    except Exception:
        os.close(handle)
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    else:
        os.close(handle)
    _mtls_temp_files.append(path)
    return path


def _mtls_cert_key_files(
    certificate_chain: bytes,
    private_key: bytes,
) -> Optional[Tuple[str, str]]:
    """
    Write normalized PEM bytes to temp files (cached per material).

    Returns None when temp files cannot be created (caller stays one-way TLS).
    """
    global _mtls_file_cache_key, _mtls_file_cache

    cache_key = (certificate_chain, private_key)
    if _mtls_file_cache is not None and _mtls_file_cache_key == cache_key:
        return _mtls_file_cache

    try:
        paths = (
            _pem_bytes_to_temp_file(certificate_chain, '.crt'),
            _pem_bytes_to_temp_file(private_key, '.pem'),
        )
    except OSError as exc:
        _warn_once(
            f'mtls-temp:{exc}',
            'Failed to write mTLS cert/key temp files (%s); staying on one-way TLS.',
            exc,
        )
        return None

    _mtls_file_cache_key = cache_key
    _mtls_file_cache = paths
    return paths


def tls_pem_material() -> Optional[Tuple[Optional[bytes], Optional[bytes], Optional[bytes]]]:
    """
    PEM bytes for (root_certificates, private_key, certificate_chain).

    None means plaintext (no TLS). Tuple members may still be None when using
    FORCE_TLS with the process trust store and/or one-way TLS.

    CA / client PEMs are parsed before return so invalid content degrades here
    (plaintext or system-trust one-way TLS) instead of only failing at connect.

    Enable decision uses the *current* CA load result (not a prior existence
    check alone): if the CA path races away between resolve and read without
    FORCE_TLS, returns None (plaintext) rather than a system-trust HTTPS tuple.
    """
    from skywalking import config

    # Emit configured-but-unusable CA path warnings (warn_once dedupes).
    collector_uses_tls()

    force = bool(config.agent_force_tls)
    ca_path = ssl_file_path(config.agent_ssl_trusted_ca_path)
    root_certificates = None
    ca_usable = False
    if ca_path is not None:
        try:
            root_certificates = _load_trusted_ca(ca_path)
            ca_usable = True
        except (OSError, ValueError) as exc:
            if force:
                logger.warning(
                    'Failed to load trusted CA file (%s); continuing with FORCE_TLS '
                    'and the process trust store (custom CA ignored, mTLS disabled).',
                    exc,
                )
            else:
                logger.warning(
                    'Failed to load trusted CA file (%s); collector stays plaintext '
                    '(set SW_AGENT_FORCE_TLS to use the process trust store instead).',
                    exc,
                )
                # Still surface mTLS-without-CA diagnostics when client PEMs are set.
                _mtls_material(ca_usable=False)
                return None

    if not force and not ca_usable:
        # No TLS without FORCE or a usable CA — including CA that vanished after
        # collector_uses_tls() saw it (TOCTOU). Warn if client cert/key are set.
        _mtls_material(ca_usable=False)
        return None

    certificate_chain, private_key = _mtls_material(ca_usable=ca_usable)
    return root_certificates, private_key, certificate_chain


def grpc_ssl_credentials():
    """
    grpc.ChannelCredentials for TLS/mTLS, or None for plaintext.

    FORCE_TLS without a CA file uses the process trust store
    (grpc.ssl_channel_credentials() with no roots).

    If credential construction ultimately fails (including process-trust
    FORCE_TLS fallback), returns None so the channel stays plaintext with a
    warning — never raises into agent start.
    """
    import grpc

    material = tls_pem_material()
    if material is None:
        return None

    root_certificates, private_key, certificate_chain = material
    try:
        return grpc.ssl_channel_credentials(
            root_certificates=root_certificates,
            private_key=private_key,
            certificate_chain=certificate_chain,
        )
    except Exception as exc:  # noqa: BLE001 - never fail host process start
        from skywalking import config

        if private_key is not None or certificate_chain is not None:
            _warn_once(
                f'grpc-creds-mtls:{exc}',
                'Failed to build gRPC mTLS credentials (%s); retrying one-way TLS.',
                exc,
            )
            try:
                return grpc.ssl_channel_credentials(root_certificates=root_certificates)
            except Exception as one_way_exc:  # noqa: BLE001
                _warn_once(
                    f'grpc-creds-oneway:{one_way_exc}',
                    'Failed to build gRPC TLS credentials (%s); collector stays plaintext.',
                    one_way_exc,
                )
                return None
        if config.agent_force_tls:
            _warn_once(
                f'grpc-creds-force:{exc}',
                'Failed to build gRPC TLS credentials with custom CA (%s); '
                'continuing with FORCE_TLS and the process trust store.',
                exc,
            )
            try:
                return grpc.ssl_channel_credentials()
            except Exception as force_exc:  # noqa: BLE001
                _warn_once(
                    f'grpc-creds-force-fail:{force_exc}',
                    'Failed to build gRPC TLS credentials (%s); collector stays plaintext.',
                    force_exc,
                )
                return None
        _warn_once(
            f'grpc-creds:{exc}',
            'Failed to build gRPC TLS credentials (%s); collector stays plaintext.',
            exc,
        )
        return None


def collector_http_scheme() -> str:
    """
    ``https://`` when TLS material is enabled, else ``http://``.

    Never raises into reporter ``__init__`` (HTTP clients call this before
    other TLS helpers that may wrap failures).
    """
    try:
        return 'https://' if tls_pem_material() is not None else 'http://'
    except Exception as exc:  # noqa: BLE001 - never fail host process start
        from skywalking import config

        _warn_once(
            f'http-scheme:{exc}',
            'Failed to decide collector HTTP scheme (%s); falling back.',
            exc,
        )
        return 'https://' if config.agent_force_tls else 'http://'


def _ca_verify_temp_file(root_certificates: bytes) -> str:
    """Process-lifetime temp path for trusted CA bytes (survives K8s secret rotation)."""
    global _ca_file_cache_key, _ca_file_cache
    if (
        _ca_file_cache is not None
        and _ca_file_cache_key == root_certificates
        and os.path.exists(_ca_file_cache)
    ):
        return _ca_file_cache
    path = _pem_bytes_to_temp_file(root_certificates, '.crt')
    _ca_file_cache_key = root_certificates
    _ca_file_cache = path
    return path


def requests_tls_settings() -> Tuple[object, Optional[Tuple[str, str]]]:
    """
    (verify, cert) for requests.Session.

    verify is True (system CAs), a CA file path, or unused for plaintext callers.
    cert is (cert_path, key_path) when mTLS files are present.

    Keeps the same enable/disable decision as grpc_ssl_credentials / tls_pem_material
    so an unreadable or oversized CA cannot leave HTTP on https:// with a bad verify path.

    Custom CA prefers a process-lifetime temp snapshot of the validated PEM bytes
    (never the resolved symlink target), so Kubernetes secret rotation that
    removes the old ``..data`` version cannot invalidate an already-configured
    session. If the snapshot cannot be written (e.g. read-only temp dir), fall
    back to the still-readable configured CA path rather than discarding the
    private CA for Requests' default trust store.

    Client-cert temp-file failures drop mTLS only (one-way TLS), with a warning.
    """
    from skywalking import config

    material = tls_pem_material()
    if material is None:
        return True, None

    root_certificates, private_key, certificate_chain = material
    if root_certificates is not None:
        try:
            verify: object = _ca_verify_temp_file(root_certificates)
        except OSError as exc:
            ca_path = ssl_file_path(config.agent_ssl_trusted_ca_path)
            if ca_path is not None:
                _warn_once(
                    f'requests-ca-temp:{exc}',
                    'Failed to persist trusted CA temp file (%s); '
                    'falling back to configured CA path for HTTP verify.',
                    exc,
                )
                verify = str(ca_path)
            else:
                _warn_once(
                    f'requests-ca-temp:{exc}',
                    'Failed to persist trusted CA temp file (%s); '
                    'using process trust store for HTTP verify.',
                    exc,
                )
                verify = True
    else:
        verify = True

    if private_key is None or certificate_chain is None:
        return verify, None

    pair = _mtls_cert_key_files(certificate_chain, private_key)
    return verify, pair


def configure_requests_session(session) -> None:
    try:
        verify, cert = requests_tls_settings()
    except Exception as exc:  # noqa: BLE001 - never fail host process start
        from skywalking import config

        _warn_once(
            f'requests-tls:{exc}',
            'Failed to configure HTTP reporter TLS (%s); falling back.',
            exc,
        )
        if config.agent_force_tls or ssl_file_path(config.agent_ssl_trusted_ca_path):
            # Prefer system-trust https over aborting agent start.
            session.verify = True
            session.cert = None
        return
    session.verify = verify
    if cert is not None:
        session.cert = cert


def ssl_context_for_collector() -> Optional[ssl.SSLContext]:
    """
    stdlib SSLContext for aiohttp, or None when the collector stays plaintext.

    Degrade on SSLError / OSError (never raise into agent bootstrap):
    - bad / unparsable custom CA + FORCE_TLS → process trust store, no client cert
    - bad / unparsable custom CA without FORCE_TLS → plaintext (None)
    - bad client cert/key or temp-file failure → one-way TLS (CA or system trust)

    Custom CA is loaded from normalized in-memory PEM bytes (``cadata``) when
    present so path races and UTF-8 BOM/preamble cannot drop the custom trust
    store after ``tls_pem_material`` already accepted the CA.
    """
    from skywalking import config

    material = tls_pem_material()
    if material is None:
        return None

    root_certificates, private_key, certificate_chain = material

    def _system_trust_context() -> ssl.SSLContext:
        return ssl.create_default_context()

    ctx: Optional[ssl.SSLContext]
    if root_certificates is not None:
        load_exc: Optional[BaseException] = None
        try:
            # Normalized ASCII PEM from _load_trusted_ca (BOM/preamble stripped).
            # Plain CERTIFICATE works via cadata; TRUSTED CERTIFICATE often needs cafile.
            ctx = ssl.create_default_context(
                cadata=root_certificates.decode('ascii'),
            )
        except (OSError, ValueError) as exc:
            load_exc = exc
            ctx = None
            try:
                cafile = _ca_verify_temp_file(root_certificates)
                ctx = ssl.create_default_context(cafile=cafile)
                load_exc = None
            except OSError as temp_exc:
                load_exc = temp_exc
                ca_path = ssl_file_path(config.agent_ssl_trusted_ca_path)
                if ca_path is not None:
                    try:
                        ctx = ssl.create_default_context(cafile=str(ca_path))
                        load_exc = None
                    except OSError as path_exc:
                        load_exc = path_exc
                        ctx = None
        if load_exc is not None:
            # ssl.SSLError subclasses OSError; ValueError: non-ASCII PEM bytes.
            if config.agent_force_tls:
                _warn_once(
                    f'ssl-ctx-ca:{load_exc}',
                    'Failed to load trusted CA into SSLContext (%s); continuing with '
                    'FORCE_TLS and the process trust store (mTLS disabled).',
                    load_exc,
                )
                try:
                    ctx = _system_trust_context()
                except OSError as sys_exc:
                    _warn_once(
                        f'ssl-ctx-system:{sys_exc}',
                        'Failed to create SSLContext from process trust store (%s); '
                        'collector stays plaintext.',
                        sys_exc,
                    )
                    return None
                private_key = None
                certificate_chain = None
            else:
                _warn_once(
                    f'ssl-ctx-ca-plain:{load_exc}',
                    'Failed to load trusted CA into SSLContext (%s); collector stays '
                    'plaintext (set SW_AGENT_FORCE_TLS to use the process trust store).',
                    load_exc,
                )
                return None
    else:
        # FORCE_TLS without usable CA → process trust store.
        try:
            ctx = _system_trust_context()
        except OSError as exc:
            _warn_once(
                f'ssl-ctx-system:{exc}',
                'Failed to create SSLContext from process trust store (%s); '
                'collector stays plaintext.',
                exc,
            )
            return None

    if private_key is not None and certificate_chain is not None:
        pair = _mtls_cert_key_files(certificate_chain, private_key)
        if pair is None:
            return ctx
        cert_file, key_file = pair
        try:
            ctx.load_cert_chain(cert_file, key_file)
        except OSError as exc:
            _warn_once(
                f'ssl-ctx-mtls:{exc}',
                'Failed to load client cert/key into SSLContext (%s); staying on one-way TLS.',
                exc,
            )
    return ctx
