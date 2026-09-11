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

import base64
import os
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from skywalking import config
from skywalking.utils import tls as tls_mod
from skywalking.utils.tls import (
    collector_http_scheme,
    collector_uses_tls,
    normalize_private_key_pem,
    requests_tls_settings,
    ssl_context_for_collector,
    tls_pem_material,
)

# Self-signed PEMs for unit tests (loadable by OpenSSL; not for production).
_TEST_CA_CERT = b"""-----BEGIN CERTIFICATE-----
MIICxjCCAa6gAwIBAgIUF4Oln8syl8F84oLaGDfp2Y34WNIwDQYJKoZIhvcNAQEL
BQAwHTEbMBkGA1UEAwwSc2t5d2Fsa2luZy10ZXN0LWNhMB4XDTI2MDkxMDIzNTkx
NVoXDTM2MDkwODIzNTkxNVowHTEbMBkGA1UEAwwSc2t5d2Fsa2luZy10ZXN0LWNh
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3kWpwJ4D/b7osNRM6khH
22cU4/HMvVZsMqEMl966iDxhOjBsTiY9kUFHdQqqxfyEcSf5cZ9bGgOq+qFE+0ES
O7/xm7mPehMtBfrOIryOLwGru7a09Nt4EzsyNr8Pfa3uUMRGqMjg5BwWL/1/Fl+N
yWNcoe+DzQ1nMu1mOXDgRk+T/Kv4sVrUMUAxbEVr0pYIOBwmksKd1/vgDoZirKD/
I4natV4RJUkiaDbovE/iUb7D9RqTvKj+xUe9IOY/zRhwZAS9mX3+xSYCS5eik/uP
J0sRt8TBbehtGlbqtfKDqlL75dJxR9noOX69Q4s/xw1bupFvrtkAjfhTTiABC/tJ
4QIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBuLlOFq8oN6aymQ6mlaeXIXc+Hs87V
jKxeMkQuEIz5oTqykfz4od7CJHTqaSsJC5o/M7F8KuYHjT9CFxM+bbkCyUkQXPRC
ZEibp8qiqJeUiWnU7bTtoBcY/so5V1DNrer56jajJ3iltnOnw3reiH3BKIjr20hq
jzECpayEsoEFyXUViVsJtd+0A0owJy2h2z9dB6c+C/H5BAuo/M7dbQAIOyQiBXeY
gLcAZ/zj9tMNTxOAcFHppHZS1TVF/Wt5c/shLDxC0XVvutVG8s3q+cqZ/xQyMs9y
wlTT55CMucIIw0KTLNyNCB12fALoaf0AzZbHBCEvTsi4Qf34NW2C7V2s
-----END CERTIFICATE-----
"""

_TEST_CLIENT_CERT = b"""-----BEGIN CERTIFICATE-----
MIICzjCCAbagAwIBAgIUCipZSsMD9Tl7eGdHHlEujKB/mF8wDQYJKoZIhvcNAQEL
BQAwITEfMB0GA1UEAwwWc2t5d2Fsa2luZy10ZXN0LWNsaWVudDAeFw0yNjA5MTAy
MzU5MTVaFw0zNjA5MDgyMzU5MTVaMCExHzAdBgNVBAMMFnNreXdhbGtpbmctdGVz
dC1jbGllbnQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDNyXYhjEpM
5H+gOWuEzLQh5cwJtjbLDpCo6756AtffkGxGZI96HFzpBshl8e1AcXWSIdia9P1M
xckVeTgreYHe5YxfYRuhXsOfAYVxM8nb3v1iwieHhetmIHlzNzpGLXluqkwNyBuY
xo3y+AApv6Otxf+v/60Uj6kEjMhJM8O/BEoNwagvl1KA7FknTyJWnQmpHwZpovmP
TNogsjHn1a79MioUq8n1QOCQlfXqssoLllCjQXblv8TiBuaijAXfa66stdoxsQ8+
GKv+WIC5zQyjhcoKhur37hGlSwSbOKng4MI9zfHMNvPvhRdDachGZ9vl0f+61OLf
aphVI1xn0u1/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAEptwm4EAQuVUdqTNrPF
47e3E5iZtkBjF2TDFiLJfvjvGZJFj7PbtrFR9UVRxP5l6Y/8GHmLtIvni1C+7HjV
tuW2JpId+miVvM0vHm3FPtjil5JapSDVlNrtkOxGxizOtuf4vx0s1bUlxbDstarx
ASVBFRxdG+XBhAyCC3Jgui2li/mw2oJEk50b37cD9vE8jSuA5qHNLRRqMhRPs+Y4
CPh4r/MnvhJChhEPzzbUoxejbrccpVBBA2hlwM363tRNr7E3i6tsDFfnChhXlKIH
ypuoPrg+L1WWdF4gkCWhCYdZN7dM0ph1Z+2XZjGZYmk6/US9HOvVImOw39AAr9Ev
bAs=
-----END CERTIFICATE-----
"""

_TEST_CLIENT_KEY_PKCS1 = b"""-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAzcl2IYxKTOR/oDlrhMy0IeXMCbY2yw6QqOu+egLX35BsRmSP
ehxc6QbIZfHtQHF1kiHYmvT9TMXJFXk4K3mB3uWMX2EboV7DnwGFcTPJ2979YsIn
h4XrZiB5czc6Ri15bqpMDcgbmMaN8vgAKb+jrcX/r/+tFI+pBIzISTPDvwRKDcGo
L5dSgOxZJ08iVp0JqR8GaaL5j0zaILIx59Wu/TIqFKvJ9UDgkJX16rLKC5ZQo0F2
5b/E4gbmoowF32uurLXaMbEPPhir/liAuc0Mo4XKCobq9+4RpUsEmzip4ODCPc3x
zDbz74UXQ2nIRmfb5dH/utTi32qYVSNcZ9LtfwIDAQABAoIBADGuZ5Sl1/JEYAOA
mVKQURS189KMaSIQvB/r+ipesVtJ9Lnx4Smr20pu1sa1539dZPMItNCEQPrd7TP/
9e2ZAh+b742/VfpZdITYyyyPQjaQ2T+UfBKd5DzdrjSAqtLye5SaDI5vNyplFTQJ
Z5CssYlsedQ1t8V1AWsVyezSUHm20iAPFzldYwyhsS9jz0H8EBtMuMU2uo7I6e4a
4WlQAQtzcBNzplcwdAQ9qvba3UFlA62gIsH39Va+QckXROgnISaJMsq1H/RSx12Y
rht8SOxF7GXvjfnesZ6Gfc7gek/8E65ny+CS0xv8xj2HV8W+IrlQFE4pqX8VQ/Qg
OJWdCpECgYEA+rURpz+IAP7aYcGgogKhATJOOJGHqg2grXWUZr6J/NrMI4/ohJg3
rMoiEJBDb0q/tUxsvuT8aH+UxuZ3gWwcMci5PvldKlrFC+sVpJTlLB+MWbNPWBs/
dr7riyy/0ZJ5OTt3h/ZsSy2RczFOKWXXNS/r/WvXFtfvV40+McGQ4S0CgYEA0iGf
m9Z0BBpHlwL3sGsZvPI5KflhgMx3D2YDwGonk4fW31k+NcCYR1d+0Ghq0oNyb2qS
09z+ZZA94uiO3t+mtZc5IWLZoJW/dDBiam2tVManluqFRX+i3d2JcJuDNpiI76Wz
Be8NrpG8uOfaO3tovmgwaS1WZ3mBe1R21wBi/NsCgYBRq0x95BdE48B2GeJfBGY4
go+yo83C2r+d4fCe67D9urTHXOjM0N1KH2qrZKNjDMGYqLXAFc4XqH/pr0f81B/3
I8Ecv5TW6EzKTiF1xL9G+Vv6GIxfUjkBUL5gTwqJlaKBv1p34xFyB/0avlQM7k0F
2X+RxWCC44LnTW6WPM0aXQKBgQCaGrySLlmRNLCyCCQchr8ueboAlXqzWcArU9aG
g5OYt7OWwz1DcIZ9M6a2Mw28a1g+a7tYkyci1wD76y/0NbNuU4Q7fuI5yfjJvj4+
7UaD+Nipbj7k9DE+Yx1Lr1EwdfdfQXckb+fp0cnFFYxPuTbdBU4TpINMiaizCQPK
s+bkpwKBgQC0WurqUUJ6EZc6ahUwxeGKVgJcBt4+9Nz+61t0j9mwrga7iIHmOBp/
hnGpvSFjYbsX7zIPELCZs4GTkpAvyrDLSD1x/ZTLf+cXyX/c/7vF3KtOoKAQT9N0
VunQSXwz7Gln1ZemLrcAn9XQwovDZGAkT+NrCRda9sFfD8GN3AedUg==
-----END RSA PRIVATE KEY-----
"""


class TestCollectorTls(unittest.TestCase):
    def setUp(self):
        self._saved = (
            config.agent_force_tls,
            config.agent_ssl_trusted_ca_path,
            config.agent_ssl_cert_chain_path,
            config.agent_ssl_key_path,
        )
        config.agent_force_tls = False
        config.agent_ssl_trusted_ca_path = ''
        config.agent_ssl_cert_chain_path = ''
        config.agent_ssl_key_path = ''
        tls_mod._warned_keys.clear()
        tls_mod._cleanup_mtls_temp_files()
        tls_mod._mtls_file_cache_key = None
        tls_mod._mtls_file_cache = None

    def tearDown(self):
        (
            config.agent_force_tls,
            config.agent_ssl_trusted_ca_path,
            config.agent_ssl_cert_chain_path,
            config.agent_ssl_key_path,
        ) = self._saved
        tls_mod._cleanup_mtls_temp_files()
        tls_mod._mtls_file_cache_key = None
        tls_mod._mtls_file_cache = None
        tls_mod._warned_keys.clear()

    def _write_pem(self, directory: str, name: str, data: bytes) -> Path:
        path = Path(directory) / name
        path.write_bytes(data)
        return path

    def test_plaintext_when_tls_off_and_no_ca(self):
        self.assertFalse(collector_uses_tls())
        self.assertIsNone(tls_pem_material())
        self.assertEqual(collector_http_scheme(), 'http://')

    def test_force_tls_uses_system_trust_without_ca(self):
        config.agent_force_tls = True
        self.assertTrue(collector_uses_tls())
        self.assertEqual(collector_http_scheme(), 'https://')
        self.assertEqual(tls_pem_material(), (None, None, None))
        verify, cert = requests_tls_settings()
        self.assertTrue(verify)
        self.assertIsNone(cert)

    def test_ca_file_enables_tls_without_force_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            ca = self._write_pem(tmp, 'ca.crt', _TEST_CA_CERT)
            config.agent_ssl_trusted_ca_path = str(ca)
            self.assertTrue(collector_uses_tls())
            self.assertEqual(tls_pem_material(), (_TEST_CA_CERT, None, None))
            verify, cert = requests_tls_settings()
            self.assertTrue(Path(verify).samefile(ca))
            self.assertIsNone(cert)

    def test_missing_ca_path_warns_and_stays_plaintext(self):
        config.agent_ssl_trusted_ca_path = '/nonexistent/skywalking-ca.crt'
        with self.assertLogs('skywalking', level='WARNING') as logs:
            self.assertFalse(collector_uses_tls())
            self.assertIsNone(tls_pem_material())
            self.assertEqual(collector_http_scheme(), 'http://')
        self.assertTrue(any('SW_AGENT_SSL_TRUSTED_CA_PATH' in line for line in logs.output))
        self.assertTrue(any('plaintext' in line for line in logs.output))

    def test_mtls_when_ca_cert_and_key_exist(self):
        with tempfile.TemporaryDirectory() as tmp:
            ca = self._write_pem(tmp, 'ca.crt', _TEST_CA_CERT)
            crt = self._write_pem(tmp, 'client.crt', _TEST_CLIENT_CERT)
            key = self._write_pem(tmp, 'client.pem', _TEST_CLIENT_KEY_PKCS1)
            config.agent_ssl_trusted_ca_path = str(ca)
            config.agent_ssl_cert_chain_path = str(crt)
            config.agent_ssl_key_path = str(key)
            roots, private_key, chain = tls_pem_material()
            self.assertEqual(roots, _TEST_CA_CERT)
            self.assertEqual(chain, _TEST_CLIENT_CERT)
            self.assertIn(b'BEGIN PRIVATE KEY', private_key)
            verify, pair = requests_tls_settings()
            self.assertTrue(Path(verify).samefile(ca))
            self.assertIsNotNone(pair)
            cert_file, key_file = pair
            self.assertEqual(Path(cert_file).read_bytes(), _TEST_CLIENT_CERT)
            self.assertEqual(Path(key_file).read_bytes(), private_key)
            self.assertTrue(all(os.path.exists(p) for p in tls_mod._mtls_temp_files))
            tls_mod._cleanup_mtls_temp_files()
            self.assertEqual(tls_mod._mtls_temp_files, [])

    def test_normalize_pkcs1_to_pkcs8(self):
        der = b'\x30' + b'\x00' * 31
        body = base64.b64encode(der).decode('ascii')
        pkcs1 = (
            '-----BEGIN RSA PRIVATE KEY-----\n'
            f'{body}\n'
            '-----END RSA PRIVATE KEY-----\n'
        ).encode('ascii')
        out = normalize_private_key_pem(pkcs1)
        text = out.decode('ascii')
        self.assertIn('-----BEGIN PRIVATE KEY-----', text)
        self.assertIn('-----END PRIVATE KEY-----', text)
        self.assertNotIn('BEGIN RSA PRIVATE KEY', text)

        pkcs8 = b'-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n'
        self.assertEqual(normalize_private_key_pem(pkcs8), pkcs8)

    def test_normalize_rejects_encrypted_private_key(self):
        encrypted = (
            b'-----BEGIN ENCRYPTED PRIVATE KEY-----\n'
            b'abc\n'
            b'-----END ENCRYPTED PRIVATE KEY-----\n'
        )
        with self.assertRaises(ValueError) as ctx:
            normalize_private_key_pem(encrypted)
        self.assertIn('Passphrase-encrypted', str(ctx.exception))

    def test_normalize_rejects_legacy_proc_type_encrypted(self):
        legacy = (
            b'-----BEGIN RSA PRIVATE KEY-----\n'
            b'Proc-Type: 4,ENCRYPTED\n'
            b'DEK-Info: AES-256-CBC,0123456789ABCDEF0123456789ABCDEF\n'
            b'\n'
            b'AAAA\n'
            b'-----END RSA PRIVATE KEY-----\n'
        )
        with self.assertRaises(ValueError) as ctx:
            normalize_private_key_pem(legacy)
        self.assertIn('Passphrase-encrypted', str(ctx.exception))

    def test_mtls_converts_pkcs1_key_for_grpc_and_http(self):
        with tempfile.TemporaryDirectory() as tmp:
            ca = self._write_pem(tmp, 'ca.crt', _TEST_CA_CERT)
            crt = self._write_pem(tmp, 'client.crt', _TEST_CLIENT_CERT)
            key = self._write_pem(tmp, 'client.pem', _TEST_CLIENT_KEY_PKCS1)
            config.agent_ssl_trusted_ca_path = str(ca)
            config.agent_ssl_cert_chain_path = str(crt)
            config.agent_ssl_key_path = str(key)

            roots, private_key, chain = tls_pem_material()
            self.assertEqual(roots, _TEST_CA_CERT)
            self.assertEqual(chain, _TEST_CLIENT_CERT)
            self.assertIn(b'BEGIN PRIVATE KEY', private_key)
            self.assertNotIn(b'BEGIN RSA PRIVATE KEY', private_key)

            verify, pair = requests_tls_settings()
            self.assertTrue(Path(verify).samefile(ca))
            self.assertEqual(Path(pair[1]).read_bytes(), private_key)

    def test_missing_key_stays_one_way_tls(self):
        with tempfile.TemporaryDirectory() as tmp:
            ca = self._write_pem(tmp, 'ca.crt', _TEST_CA_CERT)
            crt = self._write_pem(tmp, 'client.crt', _TEST_CLIENT_CERT)
            config.agent_ssl_trusted_ca_path = str(ca)
            config.agent_ssl_cert_chain_path = str(crt)
            config.agent_ssl_key_path = str(Path(tmp) / 'missing.pem')
            with self.assertLogs('skywalking', level='WARNING') as logs:
                self.assertEqual(tls_pem_material(), (_TEST_CA_CERT, None, None))
            self.assertTrue(any('mTLS' in line for line in logs.output))

    def test_only_cert_configured_warns(self):
        with tempfile.TemporaryDirectory() as tmp:
            ca = self._write_pem(tmp, 'ca.crt', _TEST_CA_CERT)
            crt = self._write_pem(tmp, 'client.crt', _TEST_CLIENT_CERT)
            config.agent_ssl_trusted_ca_path = str(ca)
            config.agent_ssl_cert_chain_path = str(crt)
            config.agent_ssl_key_path = ''
            with self.assertLogs('skywalking', level='WARNING') as logs:
                self.assertEqual(tls_pem_material(), (_TEST_CA_CERT, None, None))
            self.assertTrue(any('Only one of' in line for line in logs.output))

    def test_client_certs_ignored_without_ca_file_warns(self):
        with tempfile.TemporaryDirectory() as tmp:
            crt = self._write_pem(tmp, 'client.crt', _TEST_CLIENT_CERT)
            key = self._write_pem(tmp, 'client.pem', _TEST_CLIENT_KEY_PKCS1)
            config.agent_force_tls = True
            config.agent_ssl_cert_chain_path = str(crt)
            config.agent_ssl_key_path = str(key)
            with self.assertLogs('skywalking', level='WARNING') as logs:
                self.assertEqual(tls_pem_material(), (None, None, None))
            self.assertTrue(any('mTLS is disabled' in line for line in logs.output))

    def test_symlink_ca_to_file_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            real = self._write_pem(tmp, 'ca.crt', _TEST_CA_CERT)
            link = Path(tmp) / 'ca-link.crt'
            try:
                link.symlink_to(real)
            except OSError:
                self.skipTest('symlinks not available')
            config.agent_ssl_trusted_ca_path = str(link)
            self.assertTrue(collector_uses_tls())
            self.assertEqual(tls_pem_material(), (_TEST_CA_CERT, None, None))

    def test_oversized_pem_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            ca = Path(tmp) / 'ca.crt'
            ca.write_bytes(b'X' * (tls_mod._MAX_PEM_BYTES + 1))
            config.agent_ssl_trusted_ca_path = str(ca)
            self.assertTrue(collector_uses_tls())
            with self.assertLogs('skywalking', level='WARNING') as logs:
                self.assertIsNone(tls_pem_material())
            self.assertTrue(any('plaintext' in line for line in logs.output))
            self.assertFalse(any('system trust' in line for line in logs.output))
            self.assertEqual(collector_http_scheme(), 'http://')
            verify, cert = requests_tls_settings()
            self.assertTrue(verify)
            self.assertIsNone(cert)
            self.assertIsNone(ssl_context_for_collector())

    def test_oversized_pem_with_force_tls_uses_system_trust(self):
        with tempfile.TemporaryDirectory() as tmp:
            ca = Path(tmp) / 'ca.crt'
            ca.write_bytes(b'X' * (tls_mod._MAX_PEM_BYTES + 1))
            config.agent_force_tls = True
            config.agent_ssl_trusted_ca_path = str(ca)
            with self.assertLogs('skywalking', level='WARNING') as logs:
                self.assertEqual(tls_pem_material(), (None, None, None))
            self.assertTrue(any('process trust store' in line for line in logs.output))
            self.assertEqual(collector_http_scheme(), 'https://')

    def test_bad_ca_content_degrades_to_plaintext(self):
        with tempfile.TemporaryDirectory() as tmp:
            ca = Path(tmp) / 'ca.crt'
            ca.write_text('not-a-pem')
            config.agent_ssl_trusted_ca_path = str(ca)
            with self.assertLogs('skywalking', level='WARNING') as logs:
                self.assertIsNone(tls_pem_material())
                self.assertEqual(collector_http_scheme(), 'http://')
                self.assertIsNone(ssl_context_for_collector())
            self.assertTrue(any('plaintext' in line for line in logs.output))
            verify, cert = requests_tls_settings()
            # Material is None → callers that still ask for settings get defaults,
            # but HTTP reporter uses scheme from tls_pem_material() → http://.
            self.assertTrue(verify)
            self.assertIsNone(cert)

    def test_bad_ca_content_with_force_tls_degrades_to_system_trust(self):
        with tempfile.TemporaryDirectory() as tmp:
            ca = Path(tmp) / 'ca.crt'
            ca.write_text('not-a-pem')
            config.agent_force_tls = True
            config.agent_ssl_trusted_ca_path = str(ca)
            with self.assertLogs('skywalking', level='WARNING') as logs:
                self.assertEqual(tls_pem_material(), (None, None, None))
                ctx = ssl_context_for_collector()
            self.assertIsInstance(ctx, ssl.SSLContext)
            self.assertTrue(any('process trust store' in line for line in logs.output))
            verify, cert = requests_tls_settings()
            self.assertTrue(verify)
            self.assertIsNone(cert)

    def test_bad_ca_with_force_and_client_certs_drops_mtls(self):
        with tempfile.TemporaryDirectory() as tmp:
            ca = Path(tmp) / 'ca.crt'
            ca.write_bytes(b'bad')
            crt = self._write_pem(tmp, 'client.crt', _TEST_CLIENT_CERT)
            key = self._write_pem(tmp, 'client.pem', _TEST_CLIENT_KEY_PKCS1)
            config.agent_force_tls = True
            config.agent_ssl_trusted_ca_path = str(ca)
            config.agent_ssl_cert_chain_path = str(crt)
            config.agent_ssl_key_path = str(key)
            with self.assertLogs('skywalking', level='WARNING') as logs:
                self.assertEqual(tls_pem_material(), (None, None, None))
            self.assertTrue(any('mTLS is disabled' in line for line in logs.output))
            verify, pair = requests_tls_settings()
            self.assertTrue(verify)
            self.assertIsNone(pair)

    def test_oversized_ca_with_force_and_client_certs_drops_mtls(self):
        with tempfile.TemporaryDirectory() as tmp:
            ca = Path(tmp) / 'ca.crt'
            ca.write_bytes(b'X' * (tls_mod._MAX_PEM_BYTES + 1))
            crt = self._write_pem(tmp, 'client.crt', _TEST_CLIENT_CERT)
            key = self._write_pem(tmp, 'client.pem', _TEST_CLIENT_KEY_PKCS1)
            config.agent_force_tls = True
            config.agent_ssl_trusted_ca_path = str(ca)
            config.agent_ssl_cert_chain_path = str(crt)
            config.agent_ssl_key_path = str(key)
            with self.assertLogs('skywalking', level='WARNING'):
                self.assertEqual(tls_pem_material(), (None, None, None))
            verify, pair = requests_tls_settings()
            self.assertTrue(verify)
            self.assertIsNone(pair)

    def test_invalid_client_material_stays_one_way_tls(self):
        with tempfile.TemporaryDirectory() as tmp:
            ca = self._write_pem(tmp, 'ca.crt', _TEST_CA_CERT)
            crt = Path(tmp) / 'client.crt'
            key = Path(tmp) / 'client.pem'
            crt.write_bytes(b'not-a-cert')
            key.write_bytes(b'not-a-key')
            config.agent_ssl_trusted_ca_path = str(ca)
            config.agent_ssl_cert_chain_path = str(crt)
            config.agent_ssl_key_path = str(key)
            with self.assertLogs('skywalking', level='WARNING') as logs:
                self.assertEqual(tls_pem_material(), (_TEST_CA_CERT, None, None))
            self.assertTrue(any('mTLS' in line for line in logs.output))

    def test_temp_file_failure_stays_one_way_for_requests(self):
        with tempfile.TemporaryDirectory() as tmp:
            ca = self._write_pem(tmp, 'ca.crt', _TEST_CA_CERT)
            crt = self._write_pem(tmp, 'client.crt', _TEST_CLIENT_CERT)
            key = self._write_pem(tmp, 'client.pem', _TEST_CLIENT_KEY_PKCS1)
            config.agent_ssl_trusted_ca_path = str(ca)
            config.agent_ssl_cert_chain_path = str(crt)
            config.agent_ssl_key_path = str(key)

            def boom(*_a, **_k):
                raise OSError(30, 'Read-only file system')

            with patch('tempfile.mkstemp', side_effect=boom), \
                    self.assertLogs('skywalking', level='WARNING') as logs:
                # Validation also uses mkstemp; either path must stay one-way TLS.
                material = tls_pem_material()
                if material is not None and material[1] is not None:
                    verify, pair = requests_tls_settings()
                    self.assertTrue(Path(verify).samefile(ca))
                    self.assertIsNone(pair)
                else:
                    self.assertEqual(material, (_TEST_CA_CERT, None, None))
            self.assertTrue(any('mTLS' in line or 'temp files' in line for line in logs.output))

    def test_configure_requests_session_never_raises(self):
        config.agent_force_tls = True
        session = MagicMock()
        with patch('skywalking.utils.tls.requests_tls_settings', side_effect=RuntimeError('boom')), \
                self.assertLogs('skywalking', level='WARNING'):
            tls_mod.configure_requests_session(session)
        self.assertIs(session.verify, True)
        self.assertIsNone(session.cert)

    def test_ssl_file_path_rejects_invalid_path(self):
        self.assertIsNone(tls_mod.ssl_file_path('a\x00b'))
        self.assertIsNone(tls_mod.ssl_file_path('/nonexistent/ca.crt'))

    def test_ssl_file_path_swallows_expanduser_and_resolve_errors(self):
        with patch.object(Path, 'expanduser', side_effect=RuntimeError('no home')):
            self.assertIsNone(tls_mod.ssl_file_path('~/missing-user-ca.crt'))

        with patch.object(Path, 'resolve', side_effect=RuntimeError('symlink loop')):
            self.assertIsNone(tls_mod.ssl_file_path('ca.crt'))

        # HTTP scheme is chosen before configure_requests_session's try/except.
        config.agent_ssl_trusted_ca_path = '~/missing-user-ca.crt'
        with patch.object(Path, 'expanduser', side_effect=RuntimeError('no home')):
            self.assertEqual(collector_http_scheme(), 'http://')

    def test_ca_vanishes_after_exists_check_stays_plaintext_without_force(self):
        # Simulate TOCTOU: existence probe said TLS-on, but the CA path is gone
        # before material load — without FORCE_TLS must stay plaintext.
        config.agent_ssl_trusted_ca_path = '/tmp/vanished-ca.crt'
        with patch.object(tls_mod, 'collector_uses_tls', return_value=True), \
                patch.object(tls_mod, 'ssl_file_path', return_value=None):
            self.assertIsNone(tls_pem_material())
            self.assertEqual(collector_http_scheme(), 'http://')

        with tempfile.TemporaryDirectory() as tmp:
            crt = self._write_pem(tmp, 'client.crt', _TEST_CLIENT_CERT)
            key = self._write_pem(tmp, 'client.pem', _TEST_CLIENT_KEY_PKCS1)
            config.agent_ssl_cert_chain_path = str(crt)
            config.agent_ssl_key_path = str(key)
            tls_mod._warned_keys.clear()
            with patch.object(tls_mod, 'collector_uses_tls', return_value=True), \
                    patch.object(tls_mod, 'ssl_file_path', return_value=None), \
                    self.assertLogs('skywalking', level='WARNING') as logs:
                self.assertIsNone(tls_pem_material())
            self.assertTrue(any('mTLS is disabled' in line for line in logs.output))
            self.assertEqual(collector_http_scheme(), 'http://')

    def test_client_certs_without_ca_warn_when_force_tls_off(self):
        with tempfile.TemporaryDirectory() as tmp:
            crt = self._write_pem(tmp, 'client.crt', _TEST_CLIENT_CERT)
            key = self._write_pem(tmp, 'client.pem', _TEST_CLIENT_KEY_PKCS1)
            config.agent_force_tls = False
            config.agent_ssl_cert_chain_path = str(crt)
            config.agent_ssl_key_path = str(key)
            with self.assertLogs('skywalking', level='WARNING') as logs:
                self.assertIsNone(tls_pem_material())
            self.assertTrue(any('mTLS is disabled' in line for line in logs.output))
            self.assertEqual(collector_http_scheme(), 'http://')

    def test_create_default_context_oserror_degrades(self):
        with tempfile.TemporaryDirectory() as tmp:
            ca = self._write_pem(tmp, 'ca.crt', _TEST_CA_CERT)
            config.agent_ssl_trusted_ca_path = str(ca)

            with patch('ssl.create_default_context', side_effect=PermissionError(13, 'Permission denied')), \
                    self.assertLogs('skywalking', level='WARNING') as logs:
                # Validation and SSLContext build both call create_default_context.
                self.assertIsNone(tls_pem_material())
            self.assertTrue(any('plaintext' in line for line in logs.output))

            config.agent_force_tls = True
            tls_mod._warned_keys.clear()

            call_count = {'n': 0}

            def _ctx(*_a, **kwargs):
                call_count['n'] += 1
                if kwargs.get('cadata') or kwargs.get('cafile'):
                    raise PermissionError(13, 'Permission denied')
                return ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

            with patch('ssl.create_default_context', side_effect=_ctx), \
                    self.assertLogs('skywalking', level='WARNING') as logs:
                material = tls_pem_material()
                self.assertEqual(material, (None, None, None))
                ctx = ssl_context_for_collector()
            self.assertIsInstance(ctx, ssl.SSLContext)
            self.assertTrue(any('process trust store' in line for line in logs.output))

    def test_system_trust_failure_after_bad_cadata_does_not_raise(self):
        with tempfile.TemporaryDirectory() as tmp:
            ca = self._write_pem(tmp, 'ca.crt', _TEST_CA_CERT)
            config.agent_force_tls = True
            config.agent_ssl_trusted_ca_path = str(ca)

            def _ctx(*_a, **kwargs):
                if kwargs.get('cadata') or kwargs.get('cafile'):
                    raise PermissionError(13, 'Permission denied')
                raise PermissionError(13, 'system trust boom')

            # Bypass early CA validation so we exercise ssl_context_for_collector's
            # FORCE + cadata-fail → system-trust path.
            with patch.object(tls_mod, 'tls_pem_material', return_value=(_TEST_CA_CERT, None, None)), \
                    patch('ssl.create_default_context', side_effect=_ctx), \
                    self.assertLogs('skywalking', level='WARNING') as logs:
                self.assertIsNone(ssl_context_for_collector())
            self.assertTrue(any('plaintext' in line for line in logs.output))

    def test_after_fork_rebind_clears_child_bookkeeping_without_unlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            ca = self._write_pem(tmp, 'ca.crt', _TEST_CA_CERT)
            crt = self._write_pem(tmp, 'client.crt', _TEST_CLIENT_CERT)
            key = self._write_pem(tmp, 'client.pem', _TEST_CLIENT_KEY_PKCS1)
            config.agent_ssl_trusted_ca_path = str(ca)
            config.agent_ssl_cert_chain_path = str(crt)
            config.agent_ssl_key_path = str(key)
            _verify, pair = requests_tls_settings()
            self.assertIsNotNone(pair)
            parent_list = tls_mod._mtls_temp_files
            cert_file, key_file = pair
            self.assertTrue(parent_list)
            self.assertTrue(os.path.exists(cert_file))

            tls_mod._after_fork_in_child()
            self.assertIsNot(tls_mod._mtls_temp_files, parent_list)
            self.assertEqual(tls_mod._mtls_temp_files, [])
            self.assertIsNone(tls_mod._mtls_file_cache)
            # Simulate child atexit against the rebound empty list.
            tls_mod._cleanup_mtls_temp_files()
            self.assertTrue(os.path.exists(cert_file))
            self.assertTrue(os.path.exists(key_file))
            # Parent still holds the original list object with live paths.
            self.assertEqual(parent_list, list(pair))
            # Restore parent bookkeeping so tearDown can unlink temps.
            tls_mod._mtls_temp_files = parent_list
            tls_mod._mtls_file_cache = pair
            tls_mod._mtls_file_cache_key = (
                Path(cert_file).read_bytes(),
                Path(key_file).read_bytes(),
            )

    @unittest.skipUnless(hasattr(os, 'fork'), 'os.fork required')
    def test_fork_child_exit_does_not_delete_parent_mtls_temps(self):
        with tempfile.TemporaryDirectory() as tmp:
            ca = self._write_pem(tmp, 'ca.crt', _TEST_CA_CERT)
            crt = self._write_pem(tmp, 'client.crt', _TEST_CLIENT_CERT)
            key = self._write_pem(tmp, 'client.pem', _TEST_CLIENT_KEY_PKCS1)
            config.agent_ssl_trusted_ca_path = str(ca)
            config.agent_ssl_cert_chain_path = str(crt)
            config.agent_ssl_key_path = str(key)
            verify, pair = requests_tls_settings()
            self.assertIsNotNone(pair)
            cert_file, key_file = pair
            self.assertTrue(os.path.exists(cert_file))
            self.assertTrue(os.path.exists(key_file))

            pid = os.fork()
            if pid == 0:
                # Run atexit like a normal shutdown, then hard-exit. Raising
                # SystemExit under pytest in a forked child is unreliable
                # (non-zero wait status / parent sees the exception).
                import atexit
                atexit._run_exitfuncs()
                os._exit(0)
            _pid, status = os.waitpid(pid, 0)
            self.assertTrue(os.WIFEXITED(status), status)
            self.assertEqual(os.WEXITSTATUS(status), 0)
            self.assertTrue(os.path.exists(cert_file), 'parent cert temp deleted by child')
            self.assertTrue(os.path.exists(key_file), 'parent key temp deleted by child')
            self.assertEqual(tls_mod._mtls_file_cache, pair)


if __name__ == '__main__':
    unittest.main()
