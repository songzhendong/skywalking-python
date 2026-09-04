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

import os
import ssl
from pathlib import Path
from typing import Optional, Tuple

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


def _mtls_material() -> Tuple[Optional[bytes], Optional[bytes]]:
    """
    Client certificate_chain and private_key PEM bytes, or (None, None).

    Matches Java: mTLS is considered only after the CA file exists.
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
        return _read_bytes(cert_path), _read_bytes(key_path)
    except (OSError, ValueError) as exc:
        logger.warning('Failed to enable mTLS caused by cert or key read error: %s', exc)
        return None, None


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
    """
    from skywalking import config

    if not collector_uses_tls():
        return True, None

    ca_path = ssl_file_path(config.agent_ssl_trusted_ca_path)
    verify: object = str(ca_path) if ca_path is not None else True

    chain, key = _mtls_material()
    if chain is None or key is None:
        return verify, None

    return verify, (
        str(ssl_file_path(config.agent_ssl_cert_chain_path)),
        str(ssl_file_path(config.agent_ssl_key_path)),
    )


def configure_requests_session(session) -> None:
    verify, cert = requests_tls_settings()
    session.verify = verify
    if cert is not None:
        session.cert = cert


def ssl_context_for_collector() -> Optional[ssl.SSLContext]:
    """stdlib SSLContext for aiohttp, or None when the collector stays plaintext."""
    from skywalking import config

    if not collector_uses_tls():
        return None

    ca_path = ssl_file_path(config.agent_ssl_trusted_ca_path)
    if ca_path is not None:
        ctx = ssl.create_default_context(cafile=str(ca_path))
    else:
        ctx = ssl.create_default_context()

    chain, key = _mtls_material()
    if chain is not None and key is not None:
        ctx.load_cert_chain(
            str(ssl_file_path(config.agent_ssl_cert_chain_path)),
            str(ssl_file_path(config.agent_ssl_key_path)),
        )
    return ctx
