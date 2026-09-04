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
Collector TLS / mTLS helpers aligned with Java TLSChannelBuilder.

Java rules (apm-agent-core TLSChannelBuilder):
- TLS when FORCE_TLS is set or the trusted CA file exists.
- Custom CA is used only when that file exists (otherwise system trust).
- mTLS (client cert + key) is enabled only when the CA file exists *and*
  both cert-chain and key files exist. Missing cert/key logs a warning and
  stays one-way TLS — it does not fail agent start.
"""

from __future__ import annotations

import base64
import binascii
import os
import ssl
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple

from skywalking.loggings import logger

# Align with Node TlsMaterialCache: refuse oversized PEMs (DoS / misconfig).
_MAX_PEM_BYTES = 256 * 1024


def _configured_path(value: str) -> str:
    return (value or '').strip()


def ssl_file_path(value: str) -> Optional[Path]:
    """
    Return a readable regular file path, or None.

    Paths are cwd-relative or absolute. Symlinks are rejected (Node
    TlsMaterialCache parity) so a mis-set env cannot follow attacker-controlled
    links into unexpected files.
    """
    text = _configured_path(value)
    if not text:
        return None
    path = Path(text).expanduser()
    try:
        if path.is_symlink():
            logger.warning('Ignoring SSL path that is a symlink: %s', path)
            return None
        if path.is_file():
            return path
    except OSError:
        return None
    return None


def collector_uses_tls() -> bool:
    from skywalking import config

    return bool(config.agent_force_tls or ssl_file_path(config.agent_ssl_trusted_ca_path))


def _read_bytes(path: Path) -> bytes:
    size = os.path.getsize(path)
    if size > _MAX_PEM_BYTES:
        raise ValueError(
            f'SSL PEM file exceeds {_MAX_PEM_BYTES} bytes: {path} ({size} bytes)'
        )
    return path.read_bytes()


# Java PrivateKeyUtil: OpenSSL PKCS#1 PEM → PKCS#8 PEM for stacks that only accept PKCS#8.
_PKCS1_PEM_HEADER = '-----BEGIN RSA PRIVATE KEY-----'
_PKCS1_PEM_FOOTER = '-----END RSA PRIVATE KEY-----'
_PKCS8_PEM_HEADER = '-----BEGIN PRIVATE KEY-----'
_PKCS8_PEM_FOOTER = '-----END PRIVATE KEY-----'


def normalize_private_key_pem(key_pem: bytes) -> bytes:
    """
    Return PKCS#8 PEM bytes. PKCS#1 (`BEGIN RSA PRIVATE KEY`) is wrapped like
    Java ``PrivateKeyUtil.loadDecryptionKey``; other PEM/DER forms pass through.
    """
    text = key_pem.decode('utf-8', errors='ignore')
    if _PKCS1_PEM_HEADER not in text:
        return key_pem

    body = text.replace(_PKCS1_PEM_HEADER, '').replace(_PKCS1_PEM_FOOTER, '')
    body = body.replace('\r', '').replace('\n', '').replace(' ', '')
    try:
        pkcs1 = base64.b64decode(body)
    except (ValueError, binascii.Error) as exc:
        raise ValueError(f'Invalid PKCS#1 private key PEM: {exc}') from exc

    pkcs1_length = len(pkcs1)
    total_length = pkcs1_length + 22
    # Same fixed 2-byte length form as Java PrivateKeyUtil (keys up to ~64KiB DER).
    if total_length > 0xFFFF or pkcs1_length > 0xFFFF:
        raise ValueError('PKCS#1 private key too large for Java-compatible PKCS#8 wrap')

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


def _mtls_material() -> Tuple[Optional[bytes], Optional[bytes]]:
    """
    Client certificate_chain and private_key PEM bytes, or (None, None).

    Matches Java: mTLS is considered only after the CA file exists.
    Private keys are normalized to PKCS#8 when the file is PKCS#1.
    """
    from skywalking import config

    if ssl_file_path(config.agent_ssl_trusted_ca_path) is None:
        return None, None

    cert_cfg = _configured_path(config.agent_ssl_cert_chain_path)
    key_cfg = _configured_path(config.agent_ssl_key_path)
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
        return cert_pem, key_pem
    except (OSError, ValueError) as exc:
        logger.warning('Failed to enable mTLS caused by cert or key read error: %s', exc)
        return None, None


# Keep mTLS temp PEM paths alive for the process (requests/ssl need file paths).
_mtls_temp_files: List[str] = []
_mtls_file_cache_key: Optional[Tuple[bytes, bytes]] = None
_mtls_file_cache: Optional[Tuple[str, str]] = None


def _pem_bytes_to_temp_file(data: bytes, suffix: str) -> str:
    handle, path = tempfile.mkstemp(suffix=suffix)
    try:
        os.write(handle, data)
    finally:
        os.close(handle)
    _mtls_temp_files.append(path)
    return path


def _mtls_cert_key_files(
    certificate_chain: bytes,
    private_key: bytes,
) -> Tuple[str, str]:
    """Write normalized PEM bytes to temp files (cached per material)."""
    global _mtls_file_cache_key, _mtls_file_cache

    cache_key = (certificate_chain, private_key)
    if _mtls_file_cache is not None and _mtls_file_cache_key == cache_key:
        return _mtls_file_cache

    paths = (
        _pem_bytes_to_temp_file(certificate_chain, '.crt'),
        _pem_bytes_to_temp_file(private_key, '.pem'),
    )
    _mtls_file_cache_key = cache_key
    _mtls_file_cache = paths
    return paths


def tls_pem_material() -> Optional[Tuple[Optional[bytes], Optional[bytes], Optional[bytes]]]:
    """
    PEM bytes for (root_certificates, private_key, certificate_chain).

    None means plaintext (no TLS). Tuple members may still be None when using
    FORCE_TLS with the process trust store and/or one-way TLS.
    """
    from skywalking import config

    if not collector_uses_tls():
        return None

    ca_path = ssl_file_path(config.agent_ssl_trusted_ca_path)
    root_certificates = None
    if ca_path is not None:
        try:
            root_certificates = _read_bytes(ca_path)
        except (OSError, ValueError) as exc:
            logger.warning('Failed to read trusted CA file (%s); falling back to system trust.', exc)
            # FORCE_TLS may still apply with system trust; CA-only TLS needs the file.
            if not config.agent_force_tls:
                return None

    certificate_chain, private_key = _mtls_material()
    return root_certificates, private_key, certificate_chain


def grpc_ssl_credentials():
    """
    grpc.ChannelCredentials for TLS/mTLS, or None for plaintext.

    FORCE_TLS without a CA file uses the process trust store
    (grpc.ssl_channel_credentials() with no roots).
    """
    import grpc

    material = tls_pem_material()
    if material is None:
        return None

    root_certificates, private_key, certificate_chain = material
    return grpc.ssl_channel_credentials(
        root_certificates=root_certificates,
        private_key=private_key,
        certificate_chain=certificate_chain,
    )


def collector_http_scheme() -> str:
    return 'https://' if tls_pem_material() is not None else 'http://'


def requests_tls_settings() -> Tuple[object, Optional[Tuple[str, str]]]:
    """
    (verify, cert) for requests.Session.

    verify is True (system CAs), a CA file path, or unused for plaintext callers.
    cert is (cert_path, key_path) when mTLS files are present.

    Keeps the same enable/disable decision as grpc_ssl_credentials / tls_pem_material
    so an unreadable or oversized CA cannot leave HTTP on https:// with a bad verify path.
    """
    from skywalking import config

    material = tls_pem_material()
    if material is None:
        return True, None

    root_certificates, private_key, certificate_chain = material
    ca_path = ssl_file_path(config.agent_ssl_trusted_ca_path)
    # Prefer the CA file when it was successfully loaded into material.
    if root_certificates is not None and ca_path is not None:
        verify: object = str(ca_path)
    else:
        verify = True

    if private_key is None or certificate_chain is None:
        return verify, None

    # Temp files hold PKCS#8-normalized key bytes (same material as gRPC).
    return verify, _mtls_cert_key_files(certificate_chain, private_key)


def configure_requests_session(session) -> None:
    verify, cert = requests_tls_settings()
    session.verify = verify
    if cert is not None:
        session.cert = cert


def ssl_context_for_collector() -> Optional[ssl.SSLContext]:
    """stdlib SSLContext for aiohttp, or None when the collector stays plaintext."""
    from skywalking import config

    material = tls_pem_material()
    if material is None:
        return None

    root_certificates, private_key, certificate_chain = material
    ca_path = ssl_file_path(config.agent_ssl_trusted_ca_path)
    if root_certificates is not None and ca_path is not None:
        ctx = ssl.create_default_context(cafile=str(ca_path))
    else:
        # FORCE_TLS without usable CA → process trust store (Java FORCE_TLS path).
        ctx = ssl.create_default_context()

    if private_key is not None and certificate_chain is not None:
        cert_file, key_file = _mtls_cert_key_files(certificate_chain, private_key)
        ctx.load_cert_chain(cert_file, key_file)
    return ctx
