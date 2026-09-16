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

from enum import Enum
from typing import Optional


class EventType(Enum):
    ADD = 'ADD'
    MODIFY = 'MODIFY'
    DELETE = 'DELETE'


class ConfigChangeEvent:
    def __init__(self, new_value: Optional[str], event_type: EventType):
        self.new_value = new_value
        self.event_type = event_type


class AgentConfigChangeWatcher:
    """Java AgentConfigChangeWatcher parity for CDS-driven keys."""

    def __init__(self, property_key: str):
        self._property_key = property_key

    def get_property_key(self) -> str:
        return self._property_key

    def notify(self, event: ConfigChangeEvent) -> None:
        raise NotImplementedError

    def value(self) -> Optional[str]:
        raise NotImplementedError
