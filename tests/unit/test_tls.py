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

import tempfile
import unittest
from pathlib import Path

from skywalking import config
from skywalking.utils.tls import (
    collector_http_scheme,
    collector_uses_tls,
    requests_tls_settings,
    tls_pem_material,
)


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

    def tearDown(self):
        (
            config.agent_force_tls,
            config.agent_ssl_trusted_ca_path,
            config.agent_ssl_cert_chain_path,
            config.agent_ssl_key_path,
        ) = self._saved

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
            ca = Path(tmp) / 'ca.crt'
            ca.write_bytes(b'CA-PEM')
            config.agent_ssl_trusted_ca_path = str(ca)
            self.assertTrue(collector_uses_tls())
            self.assertEqual(tls_pem_material(), (b'CA-PEM', None, None))
            verify, cert = requests_tls_settings()
            self.assertEqual(verify, str(ca))
            self.assertIsNone(cert)

    def test_mtls_when_ca_cert_and_key_exist(self):
        with tempfile.TemporaryDirectory() as tmp:
            ca = Path(tmp) / 'ca.crt'
            crt = Path(tmp) / 'client.crt'
            key = Path(tmp) / 'client.pem'
            ca.write_bytes(b'CA-PEM')
            crt.write_bytes(b'CERT-PEM')
            key.write_bytes(b'KEY-PEM')
            config.agent_ssl_trusted_ca_path = str(ca)
            config.agent_ssl_cert_chain_path = str(crt)
            config.agent_ssl_key_path = str(key)
            self.assertEqual(tls_pem_material(), (b'CA-PEM', b'KEY-PEM', b'CERT-PEM'))
            verify, pair = requests_tls_settings()
            self.assertEqual(verify, str(ca))
            self.assertEqual(pair, (str(crt), str(key)))

    def test_missing_key_stays_one_way_tls(self):
        with tempfile.TemporaryDirectory() as tmp:
            ca = Path(tmp) / 'ca.crt'
            crt = Path(tmp) / 'client.crt'
            ca.write_bytes(b'CA-PEM')
            crt.write_bytes(b'CERT-PEM')
            config.agent_ssl_trusted_ca_path = str(ca)
            config.agent_ssl_cert_chain_path = str(crt)
            config.agent_ssl_key_path = str(Path(tmp) / 'missing.pem')
            with self.assertLogs('skywalking', level='WARNING') as logs:
                self.assertEqual(tls_pem_material(), (b'CA-PEM', None, None))
            self.assertTrue(any('mTLS' in line for line in logs.output))

    def test_client_certs_ignored_without_ca_file(self):
        """Java only loads keyManager inside the CA-file branch."""
        with tempfile.TemporaryDirectory() as tmp:
            crt = Path(tmp) / 'client.crt'
            key = Path(tmp) / 'client.pem'
            crt.write_bytes(b'CERT-PEM')
            key.write_bytes(b'KEY-PEM')
            config.agent_force_tls = True
            config.agent_ssl_cert_chain_path = str(crt)
            config.agent_ssl_key_path = str(key)
            self.assertEqual(tls_pem_material(), (None, None, None))

    def test_symlink_ca_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            real = Path(tmp) / 'ca.crt'
            link = Path(tmp) / 'ca-link.crt'
            real.write_bytes(b'CA-PEM')
            try:
                link.symlink_to(real)
            except OSError:
                self.skipTest('symlinks not available')
            config.agent_ssl_trusted_ca_path = str(link)
            with self.assertLogs('skywalking', level='WARNING') as logs:
                self.assertFalse(collector_uses_tls())
            self.assertTrue(any('symlink' in line for line in logs.output))

    def test_oversized_pem_is_rejected(self):
        from skywalking.utils import tls as tls_mod

        with tempfile.TemporaryDirectory() as tmp:
            ca = Path(tmp) / 'ca.crt'
            ca.write_bytes(b'X' * (tls_mod._MAX_PEM_BYTES + 1))
            config.agent_ssl_trusted_ca_path = str(ca)
            self.assertTrue(collector_uses_tls())
            with self.assertLogs('skywalking', level='WARNING') as logs:
                self.assertIsNone(tls_pem_material())
            self.assertTrue(any('trusted CA' in line or 'exceeds' in line for line in logs.output))


if __name__ == '__main__':
    unittest.main()
