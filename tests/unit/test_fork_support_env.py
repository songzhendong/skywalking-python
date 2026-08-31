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

import os
import subprocess
import sys
import unittest


class TestForkSupportEnvBeforeGrpcImport(unittest.TestCase):

    def test_import_agent_does_not_load_grpc(self):
        code = r"""
import sys
import os
os.environ["SW_AGENT_ASYNCIO_ENHANCEMENT"] = "false"
os.environ["SW_AGENT_EXPERIMENTAL_FORK_SUPPORT"] = "true"
os.environ["SW_AGENT_PROTOCOL"] = "grpc"
os.environ["SW_AGENT_COLLECTOR_BACKEND_SERVICES"] = "127.0.0.1:11800"
import skywalking.agent  # noqa: F401
assert "grpc" not in sys.modules, sorted(m for m in sys.modules if m == "grpc" or m.startswith("grpc."))
print("OK_NO_GRPC")
"""
        r = subprocess.run(
            [sys.executable, '-c', code],
            cwd=os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(r.returncode, 0, msg=r.stdout + r.stderr)
        self.assertIn('OK_NO_GRPC', r.stdout)

    def test_prefork_master_enables_fork_support(self):
        code = r"""
import sys
import os
os.environ["SW_AGENT_ASYNCIO_ENHANCEMENT"] = "false"
os.environ["SW_AGENT_EXPERIMENTAL_FORK_SUPPORT"] = "true"
os.environ["SW_AGENT_PROTOCOL"] = "grpc"
os.environ["SW_AGENT_COLLECTOR_BACKEND_SERVICES"] = "127.0.0.1:11800"
os.environ["SW_AGENT_NAME"] = "fork-env-test"
os.environ["SW_AGENT_INSTANCE_NAME"] = "i1"
# Avoid plugin side effects that need a live collector.
os.environ["SW_AGENT_DISABLE_PLUGINS"] = ".*"
from skywalking.agent import agent
assert "grpc" not in sys.modules
agent.start_prefork_master()
import grpc  # noqa: F401
from grpc._cython import cygrpc
assert cygrpc.is_fork_support_enabled(), "GRPC_ENABLE_FORK_SUPPORT must be set before import grpc"
print("OK_FORK_SUPPORT")
"""
        r = subprocess.run(
            [sys.executable, '-c', code],
            cwd=os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(r.returncode, 0, msg=r.stdout + r.stderr)
        self.assertIn('OK_FORK_SUPPORT', r.stdout)


if __name__ == '__main__':
    unittest.main()
