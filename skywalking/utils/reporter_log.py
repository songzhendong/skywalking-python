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
"""Throttled reporter logs that must not import grpc.

agent/__init__.py imports these helpers at module load. Keeping them out of
grpc_channel.py ensures GRPC_ENABLE_FORK_SUPPORT can be set before the first
`import grpc` (see start / start_prefork_master).
"""

from __future__ import annotations

import os
import time
from typing import Dict

from skywalking.loggings import logger

_REPORTER_LOG_INTERVAL_SEC = 30.0
_last_reporter_log_at: Dict[str, float] = {}
_DROP_LOG_INTERVAL_SEC = 30.0
_last_drop_log_at: Dict[str, float] = {}
_drop_totals: Dict[str, int] = {}
_drop_logged_totals: Dict[str, int] = {}


def log_reporter_exception_throttled(reporter_name: str, wait: float) -> None:
    """
    Throttle reporter exception stacks during outages (otherwise every backoff tick floods logs).
    """
    now = time.monotonic()
    last = _last_reporter_log_at.get(reporter_name, 0.0)
    if now - last < _REPORTER_LOG_INTERVAL_SEC:
        return
    _last_reporter_log_at[reporter_name] = now
    logger.exception(
        'Exception in %s service in pid %s, retry in %s seconds',
        reporter_name,
        os.getpid(),
        wait,
    )


def log_dropped_throttled(kind: str, count: int = 1, *, force: bool = False) -> None:
    """
    Throttle drop warnings. ``count`` is added to a process-wide total for ``kind``.
    At most one line per 30s unless ``force`` (shutdown). Message includes this
    window's increment and the process total.
    """
    if count <= 0:
        return
    now = time.monotonic()
    total = _drop_totals.get(kind, 0) + count
    _drop_totals[kind] = total
    last = _last_drop_log_at.get(kind, 0.0)
    if not force and now - last < _DROP_LOG_INTERVAL_SEC:
        return
    logged = _drop_logged_totals.get(kind, 0)
    delta = total - logged
    _drop_logged_totals[kind] = total
    _last_drop_log_at[kind] = now
    logger.warning(
        'dropped %s: +%d since last log, %d total this process (best-effort; never retried)',
        kind,
        delta,
        total,
    )
