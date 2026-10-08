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
import unittest
from concurrent import futures

import grpc

from skywalking.plugins import sw_grpc


class TestGrpcServerUnimplemented(unittest.TestCase):
    def test_sync_server_unregistered_method_returns_unimplemented(self):
        """continuation() is None for unknown methods; interceptor must not AttributeError."""
        sw_grpc.install_sync()

        server = grpc.server(futures.ThreadPoolExecutor(max_workers=1))
        port = server.add_insecure_port('127.0.0.1:0')
        server.start()
        try:
            channel = grpc.insecure_channel(f'127.0.0.1:{port}')
            stub = channel.unary_unary(
                '/skywalking.test.NoService/NoMethod',
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            with self.assertRaises(grpc.RpcError) as ctx:
                stub(b'', timeout=5)
            self.assertEqual(ctx.exception.code(), grpc.StatusCode.UNIMPLEMENTED)
        finally:
            server.stop(grace=0)

    def test_aio_server_unregistered_method_returns_unimplemented(self):
        sw_grpc.install_async()

        async def run():
            server = grpc.aio.server()
            port = server.add_insecure_port('127.0.0.1:0')
            await server.start()
            try:
                async with grpc.aio.insecure_channel(f'127.0.0.1:{port}') as channel:
                    stub = channel.unary_unary(
                        '/skywalking.test.NoService/NoMethod',
                        request_serializer=lambda x: x,
                        response_deserializer=lambda x: x,
                    )
                    with self.assertRaises(grpc.aio.AioRpcError) as ctx:
                        await stub(b'', timeout=5)
                    self.assertEqual(ctx.exception.code(), grpc.StatusCode.UNIMPLEMENTED)
            finally:
                await server.stop(grace=0)

        asyncio.run(run())


if __name__ == '__main__':
    unittest.main()
