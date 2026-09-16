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

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from skywalking.command.configuration_discovery_command import ConfigurationDiscoveryCommand
from skywalking.conf.dynamic.watcher import AgentConfigChangeWatcher, ConfigChangeEvent, EventType
from skywalking.loggings import logger

# (key, value) pairs from OAP; blank value means DELETE for that registered key.
ConfigPair = Tuple[str, str]


class ConfigurationDiscoveryService:
    """
    Agent-side CDS center (Java ConfigurationDiscoveryService parity).

    Watchers register by property key. Sync responses are applied through
    ConfigurationDiscoveryCommand; UUID short-circuits unchanged configs.
    """

    def __init__(self):
        self._uuid: Optional[str] = None
        self._watchers: Dict[str, AgentConfigChangeWatcher] = {}

    def register_agent_config_change_watcher(self, watcher: AgentConfigChangeWatcher) -> None:
        key = watcher.get_property_key()
        if key in self._watchers and type(self._watchers[key]) is type(watcher):
            logger.debug('Duplicate CDS watcher register ignored, watcher=%s', watcher)
            return
        self._watchers[key] = watcher
        # New watcher must force a full OAP config push (Java watcher-size reset).
        self._uuid = None

    def peek_uuid(self) -> Optional[str]:
        """UUID to send on the next fetchConfigurations (None resets OAP cache)."""
        return self._uuid

    def handle_configuration_discovery_command(self, command: ConfigurationDiscoveryCommand) -> None:
        response_uuid = command.uuid
        if response_uuid is not None and response_uuid == self._uuid:
            return

        for key, value in self._read_config(command):
            watcher = self._watchers.get(key)
            if watcher is None:
                logger.warning('Config %s from OAP does not match any watcher; ignore.', key)
                continue
            if value is None or value == '':
                if watcher.value() is not None:
                    watcher.notify(ConfigChangeEvent(None, EventType.DELETE))
            elif value != watcher.value():
                watcher.notify(ConfigChangeEvent(value, EventType.MODIFY))

        self._uuid = response_uuid
        logger.debug('CDS applied; uuid=%s watchers=%s', self._uuid, list(self._watchers.keys()))

    def _read_config(self, command: ConfigurationDiscoveryCommand) -> List[ConfigPair]:
        """
        For every registered key, take OAP's value or an empty value (DELETE).

        Matches Java readConfig(): OAP may omit keys that were removed dynamically.
        """
        command_configs = {pair[0]: pair[1] for pair in command.config}
        result: List[ConfigPair] = []
        for name in self._watchers.keys():
            result.append((name, command_configs.get(name, '')))
        return result


configuration_discovery_service = ConfigurationDiscoveryService()
