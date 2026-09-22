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

"""CDS watchers for the Java dynamic keys besides sampling."""

from skywalking import config
from skywalking.conf.dynamic.configuration_discovery_service import configuration_discovery_service
from skywalking.conf.dynamic.watcher import AgentConfigChangeWatcher, ConfigChangeEvent, EventType
from skywalking.loggings import logger

IGNORE_SUFFIX_KEY = 'agent.ignore_suffix'
IGNORE_PATH_KEY = 'agent.trace.ignore_path'
SPAN_LIMIT_KEY = 'agent.span_limit_per_segment'
SQL_PARAMETERS_KEY = 'plugin.jdbc.trace_sql_parameters'

# Java Plugin.JDBC.SQL_PARAMETERS_MAX_LENGTH default, used when CDS turns collection on
# and the Python bootstrap length is 0 (which means off).
_SQL_LENGTH_WHEN_ENABLED = 512

# Captured once from env/bootstrap config. Remount (fork/force) must DELETE back to
# these values, not to whatever CDS last wrote into the live config globals.
_bootstrap_defaults: dict | None = None


def _bootstrap() -> dict:
    global _bootstrap_defaults
    if _bootstrap_defaults is None:
        _bootstrap_defaults = {
            'agent_ignore_suffix': str(config.agent_ignore_suffix),
            'agent_trace_ignore_path': str(config.agent_trace_ignore_path),
            'agent_span_limit_per_segment': int(config.agent_span_limit_per_segment),
            'plugin_sql_parameters_max_length': int(config.plugin_sql_parameters_max_length),
        }
    return _bootstrap_defaults


def reset_bootstrap_defaults_for_tests() -> None:
    """Clear the process bootstrap snapshot so unit tests can re-seed it."""
    global _bootstrap_defaults
    _bootstrap_defaults = None


class _StringConfigWatcher(AgentConfigChangeWatcher):
    def __init__(self, property_key: str, config_attr: str, *, rebuild_ignore: bool):
        super().__init__(property_key)
        self._config_attr = config_attr
        self._rebuild_ignore = rebuild_ignore
        self._default = str(_bootstrap()[config_attr])
        # Push bootstrap into live config so fork/force remount does not leave
        # the previous CDS value in globals while watcher.value() reports default.
        self._apply(self._default)

    def notify(self, event: ConfigChangeEvent) -> bool:
        if event.event_type == EventType.DELETE:
            return self._apply(self._default)
        return self._apply(event.new_value)

    def value(self) -> str:
        return self._value

    def _apply(self, new_value: str | None) -> bool:
        if new_value is None:
            logger.error('Cannot load %s from: %r', self.get_property_key(), new_value)
            return False
        self._value = new_value
        setattr(config, self._config_attr, new_value)
        if self._rebuild_ignore:
            config.finalize_regex()
        logger.debug('Updated %s to %s', self.get_property_key(), new_value)
        return True


class SpanLimitWatcher(AgentConfigChangeWatcher):
    def __init__(self):
        super().__init__(SPAN_LIMIT_KEY)
        self._default = int(_bootstrap()['agent_span_limit_per_segment'])
        self._apply(str(self._default))

    def notify(self, event: ConfigChangeEvent) -> bool:
        if event.event_type == EventType.DELETE:
            return self._apply(str(self._default))
        return self._apply(event.new_value)

    def value(self) -> str:
        return str(self._limit)

    def _apply(self, raw: str | None) -> bool:
        if raw is None:
            logger.error('Cannot load %s from: %r', self.get_property_key(), raw)
            return False
        try:
            limit = int(raw)
        except (TypeError, ValueError):
            logger.error('Cannot load %s from: %r', self.get_property_key(), raw)
            return False
        self._limit = limit
        config.agent_span_limit_per_segment = limit
        logger.debug('Updated %s to %s', self.get_property_key(), limit)
        return True


class TraceSqlParametersWatcher(AgentConfigChangeWatcher):
    """
    Java ``plugin.jdbc.trace_sql_parameters`` is a boolean.

    Python collection is ``plugin_sql_parameters_max_length`` (0 = off).
    ``true`` keeps a positive bootstrap length, or 512 when bootstrap is off.
    ``false`` sets the length to 0. DELETE restores the bootstrap length.
    """

    def __init__(self):
        super().__init__(SQL_PARAMETERS_KEY)
        self._default_length = int(_bootstrap()['plugin_sql_parameters_max_length'])
        self._enabled_length = self._default_length if self._default_length > 0 else _SQL_LENGTH_WHEN_ENABLED
        self._apply_length(self._default_length)

    def notify(self, event: ConfigChangeEvent) -> bool:
        if event.event_type == EventType.DELETE:
            self._apply_length(self._default_length)
            return True
        parsed = _parse_bool(event.new_value)
        if parsed is None:
            logger.error('Cannot load %s from: %r', self.get_property_key(), event.new_value)
            return False
        self._apply_length(self._enabled_length if parsed else 0)
        return True

    def value(self) -> str:
        return 'true' if config.plugin_sql_parameters_max_length > 0 else 'false'

    def _apply_length(self, length: int) -> None:
        config.plugin_sql_parameters_max_length = length
        logger.debug('Updated %s to %s (max_length=%s)', self.get_property_key(), self.value(), length)


def _parse_bool(raw: str | None) -> bool | None:
    if raw is None:
        return None
    text = raw.strip().lower()
    if text == 'true':
        return True
    if text == 'false':
        return False
    return None


def register_agent_dynamic_watchers(*, replace: bool = False) -> None:
    """Register the non-sampling CDS watchers. Safe to call more than once."""
    # Construct only when registering or replacing. Watcher __init__ writes bootstrap
    # into live config; building throwaways on a duplicate register would wipe CDS.
    factories = (
        (IGNORE_SUFFIX_KEY, lambda: _StringConfigWatcher(
            IGNORE_SUFFIX_KEY, 'agent_ignore_suffix', rebuild_ignore=True,
        )),
        (IGNORE_PATH_KEY, lambda: _StringConfigWatcher(
            IGNORE_PATH_KEY, 'agent_trace_ignore_path', rebuild_ignore=True,
        )),
        (SPAN_LIMIT_KEY, SpanLimitWatcher),
        (SQL_PARAMETERS_KEY, TraceSqlParametersWatcher),
    )
    for key, factory in factories:
        if not replace and key in configuration_discovery_service._watchers:
            continue
        configuration_discovery_service.register_agent_config_change_watcher(
            factory(),
            replace=replace,
        )
