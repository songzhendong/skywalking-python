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

from typing import List, Optional, Tuple

from skywalking.protocol.common.Command_pb2 import Command

from skywalking.command.base_command import BaseCommand
from skywalking.utils.lang import tostring

ConfigPair = Tuple[str, str]


@tostring
class ConfigurationDiscoveryCommand(BaseCommand):
    """OAP CDS response command (Java ConfigurationDiscoveryCommand)."""

    NAME = 'ConfigurationDiscoveryCommand'
    UUID_KEY = 'UUID'
    SERIAL_NUMBER_KEY = 'SerialNumber'

    def __init__(
        self,
        serial_number: str = '',
        uuid: Optional[str] = None,
        config: Optional[List[ConfigPair]] = None,
    ):
        BaseCommand.__init__(self, self.NAME, serial_number or '')
        self.uuid = uuid
        self.config = config or []  # type: List[ConfigPair]

    @staticmethod
    def deserialize(command: Command) -> 'ConfigurationDiscoveryCommand':
        serial_number = ''
        uuid = None
        config: List[ConfigPair] = []

        for pair in command.args:
            if pair.key == ConfigurationDiscoveryCommand.SERIAL_NUMBER_KEY:
                serial_number = pair.value
            elif pair.key == ConfigurationDiscoveryCommand.UUID_KEY:
                uuid = pair.value
            else:
                config.append((pair.key, pair.value))

        return ConfigurationDiscoveryCommand(
            serial_number=serial_number or (uuid or ''),
            uuid=uuid,
            config=config,
        )
