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

from skywalking.command.base_command import BaseCommand
from skywalking.command.configuration_discovery_command import ConfigurationDiscoveryCommand
from skywalking.command.executors.command_executor import CommandExecutor
from skywalking.conf.dynamic import configuration_discovery_service
from skywalking.loggings import logger


class ConfigurationDiscoveryCommandExecutor(CommandExecutor):

    def execute(self, command: BaseCommand) -> bool:
        try:
            cds_command = command  # type: ConfigurationDiscoveryCommand
            return configuration_discovery_service.handle_configuration_discovery_command(cds_command)
        except Exception:  # noqa: BLE001 - never fail the command dispatcher
            logger.exception('Handle ConfigurationDiscoveryCommand error, command=%s', command)
            return False
