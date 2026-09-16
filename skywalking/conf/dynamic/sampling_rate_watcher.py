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

from typing import TYPE_CHECKING

from skywalking.conf.dynamic.watcher import AgentConfigChangeWatcher, ConfigChangeEvent, EventType
from skywalking.loggings import logger

if TYPE_CHECKING:
    from skywalking.sampling.sampling_service import SamplingServiceBase

PROPERTY_KEY = 'agent.sample_n_per_3_secs'


class SamplingRateWatcher(AgentConfigChangeWatcher):
    """
    Dynamic watcher for ``agent.sample_n_per_3_secs`` (Java SamplingRateWatcher).

    Keeps an effective rate separate from bootstrap ``config.sample_n_per_3_secs``.
    DELETE restores the bootstrap default captured at construction time.
    """

    def __init__(self, sampling_service: SamplingServiceBase, default_value: int):
        super().__init__(PROPERTY_KEY)
        self._sampling_service = sampling_service
        self._default_value = int(default_value)
        self._sampling_rate = self._default_value
        self._sampling_service.handle_sampling_rate_changed(self._sampling_rate)

    def notify(self, event: ConfigChangeEvent) -> None:
        if event.event_type == EventType.DELETE:
            self._active_setting(str(self._default_value))
        else:
            self._active_setting(event.new_value)

    def value(self) -> str:
        return str(self._sampling_rate)

    def get_sampling_rate(self) -> int:
        return self._sampling_rate

    def _active_setting(self, config_value: str | None) -> None:
        if config_value is None:
            logger.error('Cannot load %s from: %r', self.get_property_key(), config_value)
            return
        try:
            rate = int(config_value)
        except (TypeError, ValueError):
            logger.error('Cannot load %s from: %r', self.get_property_key(), config_value)
            return
        self._sampling_rate = rate
        self._sampling_service.handle_sampling_rate_changed(rate)
        logger.debug('Updated %s to %s', self.get_property_key(), rate)
