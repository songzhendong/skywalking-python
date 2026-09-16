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

from threading import Lock, Thread

import time
from typing import Set

from skywalking import config
from skywalking.conf.dynamic import SamplingRateWatcher, configuration_discovery_service
from skywalking.log import logger

import asyncio


class SamplingServiceBase:
    """
    Sampling limiter with Java SamplingService on/off semantics.

    rate <= 0: sampling off, every trace is accepted.
    rate > 0: accept at most ``rate`` new traces every 3 seconds.
    """

    def __init__(self):
        self.sampling_factor = 0
        self._on = False
        self._sample_n = 0
        self._rate_watcher: SamplingRateWatcher | None = None
        # Bootstrap from env/config; CDS watcher may override later.
        self.handle_sampling_rate_changed(config.sample_n_per_3_secs)

    @property
    def reset_sampling_factor_interval(self) -> int:
        return 3

    def register_cds_watcher(self) -> None:
        """Register CDS watcher once; bootstrap rate comes from config.sample_n_per_3_secs."""
        if self._rate_watcher is not None:
            return
        self._rate_watcher = SamplingRateWatcher(self, config.sample_n_per_3_secs)
        configuration_discovery_service.register_agent_config_change_watcher(self._rate_watcher)

    def handle_sampling_rate_changed(self, rate: int) -> None:
        rate = int(rate)
        self._sample_n = rate
        if rate > 0:
            if not self._on:
                self._on = True
                self._set_sampling_factor(0)
                logger.debug('Agent sampling started. Sample %s traces in 3 seconds.', rate)
        else:
            if self._on:
                self._on = False
                logger.debug('Agent sampling stopped (rate=%s).', rate)

    def get_sampling_rate(self) -> int:
        if self._rate_watcher is not None:
            return self._rate_watcher.get_sampling_rate()
        return self._sample_n

    @property
    def can_sampling(self):
        if not self._on:
            return True
        return self.sampling_factor < self._sample_n

    def _try_sampling(self) -> bool:
        if not self._on:
            return True
        if self.sampling_factor < self._sample_n:
            self._incr_sampling_factor()
            return True
        logger.debug(
            '%s try_sampling return false, sampling_factor: %d rate: %d',
            self.__class__.__name__,
            self.sampling_factor,
            self._sample_n,
        )
        return False

    def _set_sampling_factor(self, val: int):
        logger.debug('Set sampling factor to %d', val)
        self.sampling_factor = val

    def _incr_sampling_factor(self):
        self.sampling_factor += 1


class SamplingService(Thread, SamplingServiceBase):

    def __init__(self):
        Thread.__init__(self, name='SamplingService', daemon=True)
        self.lock = Lock()
        SamplingServiceBase.__init__(self)

    def run(self):
        logger.debug('Started sampling service sampling_n_per_3_secs: %d', self.get_sampling_rate())
        while True:
            self.reset_sampling_factor()
            time.sleep(self.reset_sampling_factor_interval)

    def try_sampling(self) -> bool:
        with self.lock:
            return super()._try_sampling()

    def force_sampled(self) -> None:
        with self.lock:
            if self._on:
                super()._incr_sampling_factor()

    def reset_sampling_factor(self) -> None:
        with self.lock:
            super()._set_sampling_factor(0)

    def handle_sampling_rate_changed(self, rate: int) -> None:
        with self.lock:
            super().handle_sampling_rate_changed(rate)


class SamplingServiceAsync(SamplingServiceBase):

    def __init__(self):
        super().__init__()
        self.strong_ref_set: Set[asyncio.Task[None]] = set()

    async def start(self):
        logger.debug('Started async sampling service sampling_n_per_3_secs: %d', self.get_sampling_rate())
        while True:
            await self.reset_sampling_factor()
            await asyncio.sleep(self.reset_sampling_factor_interval)

    def try_sampling(self) -> bool:
        return super()._try_sampling()

    def force_sampled(self):
        if self._on:
            super()._incr_sampling_factor()

    async def reset_sampling_factor(self):
        super()._set_sampling_factor(0)
