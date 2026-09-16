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

import asyncio
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from skywalking import config


class _OkHandler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa
        length = int(self.headers.get('Content-Length') or 0)
        self.rfile.read(length)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{}')

    def log_message(self, *_args):
        pass


def _start_http_server():
    server = HTTPServer(('127.0.0.1', 0), _OkHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


class TestAsyncHttpClientSession(unittest.TestCase):
    def setUp(self):
        self._saved = (
            config.agent_collector_backend_services,
            config.agent_protocol,
            config.agent_name,
            config.agent_instance_name,
        )
        config.agent_protocol = 'http'
        config.agent_name = 'test-service'
        config.agent_instance_name = 'test-instance'

    def tearDown(self):
        (
            config.agent_collector_backend_services,
            config.agent_protocol,
            config.agent_name,
            config.agent_instance_name,
        ) = self._saved

    def test_async_http_session_survives_repeated_posts(self):
        """async with session.post closes the response, not the long-lived session."""
        server, port = _start_http_server()
        config.agent_collector_backend_services = f'127.0.0.1:{port}'
        try:
            from skywalking.client.http_aio import HttpServiceManagementClientAsync

            async def run():
                client = HttpServiceManagementClientAsync()
                self.assertFalse(client.client.closed)
                await client.send_instance_props()
                self.assertFalse(
                    client.client.closed,
                    'ClientSession must stay open after the first request',
                )
                await client.send_heart_beat()
                self.assertFalse(client.client.closed)
                await client.aclose()
                self.assertTrue(client.client.closed)

            asyncio.run(run())
        finally:
            server.shutdown()

    def test_async_http_segment_reporter_reuses_session(self):
        server, port = _start_http_server()
        config.agent_collector_backend_services = f'127.0.0.1:{port}'
        try:
            from skywalking.client.http_aio import HttpTraceSegmentReportServiceAsync

            class _Seg:
                related_traces = ['t1']
                segment_id = 's1'
                is_size_limited = False
                spans = []

            async def gen():
                yield _Seg()
                yield _Seg()

            async def run():
                reporter = HttpTraceSegmentReportServiceAsync()
                await reporter.report(gen())
                self.assertFalse(reporter.client.closed)
                await reporter.aclose()

            asyncio.run(run())
        finally:
            server.shutdown()


if __name__ == '__main__':
    unittest.main()
