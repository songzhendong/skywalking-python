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
import time
import unittest
from queue import Queue
from threading import Event, Thread

from skywalking.agent import (
    _abandon_async_queue,
    _abandon_sync_queue,
    _cancel_pending_tasks,
    _join_sync_queue,
    _shutdown_async_queue,
    _shutdown_sync_queue,
)


class TestShutdownQueueHelpers(unittest.TestCase):

    def test_abandon_sync_queue_unblocks_join(self):
        q = Queue()
        q.put('a')
        q.put('b')
        self.assertEqual(q.unfinished_tasks, 2)

        hung = Event()

        def _join():
            q.join()
            hung.set()

        Thread(target=_join, daemon=True).start()
        time.sleep(0.05)
        self.assertFalse(hung.is_set())

        abandoned = _abandon_sync_queue(q)
        self.assertEqual(abandoned, 2)
        self.assertTrue(hung.wait(1.0))
        self.assertTrue(_join_sync_queue(q, 0.5))

    def test_shutdown_sync_skips_flush_when_not_ready(self):
        q = Queue()
        q.put('x')
        called = []

        def report():
            called.append(1)
            raise AssertionError('must not flush when may_send is False')

        _shutdown_sync_queue(report, q, 'test', may_send=False)
        self.assertEqual(called, [])
        self.assertTrue(q.empty())
        self.assertEqual(q.unfinished_tasks, 0)

    def test_shutdown_sync_flush_timeout_then_abandon(self):
        q = Queue()
        q.put('x')
        started = Event()

        def report():
            started.set()
            time.sleep(10)  # longer than flush budget

        # Temporarily shrink budget via monkeypatch on module constant
        import skywalking.agent as agent_mod

        previous = agent_mod._SHUTDOWN_FLUSH_TIMEOUT_SEC
        try:
            agent_mod._SHUTDOWN_FLUSH_TIMEOUT_SEC = 0.2
            t0 = time.monotonic()
            _shutdown_sync_queue(report, q, 'test', may_send=True)
            elapsed = time.monotonic() - t0
        finally:
            agent_mod._SHUTDOWN_FLUSH_TIMEOUT_SEC = previous

        self.assertTrue(started.wait(1.0))
        self.assertLess(elapsed, 2.0)
        self.assertTrue(q.empty())
        self.assertEqual(q.unfinished_tasks, 0)

    def test_abandon_async_queue_unblocks_join(self):
        async def _run():
            q = asyncio.Queue()
            await q.put('a')
            await q.put('b')
            join_task = asyncio.create_task(q.join())
            await asyncio.sleep(0.05)
            self.assertFalse(join_task.done())
            abandoned = await _abandon_async_queue(q)
            self.assertEqual(abandoned, 2)
            await asyncio.wait_for(join_task, timeout=1.0)

        asyncio.run(_run())

    def test_cancel_pending_tasks_excludes_caller(self):
        """Regression: gathering the caller's own task made shutdown hang until the outer budget."""
        loop = asyncio.new_event_loop()
        thread = Thread(target=loop.run_forever, daemon=True)
        thread.start()

        async def _forever():
            while True:
                await asyncio.sleep(0.05)

        try:
            async def _spawn():
                return [asyncio.create_task(_forever()) for _ in range(2)]

            reporter_tasks = asyncio.run_coroutine_threadsafe(_spawn(), loop).result(timeout=2.0)
            time.sleep(0.1)

            t0 = time.monotonic()
            future = asyncio.run_coroutine_threadsafe(_cancel_pending_tasks(reporter_tasks), loop)
            future.result(timeout=2.0)
            self.assertLess(time.monotonic() - t0, 2.0)
            for task in reporter_tasks:
                self.assertTrue(task.cancelled() or task.done())
        finally:
            loop.call_soon_threadsafe(loop.stop)
            thread.join(timeout=2.0)
            loop.close()

    def test_cancel_preserves_asyncio_run_root_so_fini_completes(self):
        """
        Production path uses asyncio.run(root). Cancelling the root tears down the Runner
        and cancels fini before aclose(). Only background tasks may be cancelled.
        """
        aclose_done = Event()
        loop_ready = Event()
        holder = {}

        async def root():
            holder['loop'] = asyncio.get_running_loop()
            holder['root'] = asyncio.current_task()

            async def reporter():
                while True:
                    await asyncio.sleep(0.05)

            holder['tasks'] = {asyncio.create_task(reporter()) for _ in range(2)}
            loop_ready.set()
            # return_exceptions: cancelled reporters must not surface as root CancelledError
            await asyncio.gather(*holder['tasks'], return_exceptions=True)
            holder['root_finished'] = True

        thread = Thread(target=lambda: asyncio.run(root()), daemon=True)
        thread.start()
        self.assertTrue(loop_ready.wait(3.0))

        async def fini():
            # Must not cancel holder["root"]; doing so would cancel this fini via Runner teardown.
            await _cancel_pending_tasks(holder['tasks'])
            aclose_done.set()
            return 'ok'

        result = asyncio.run_coroutine_threadsafe(fini(), holder['loop']).result(timeout=3.0)
        self.assertEqual(result, 'ok')
        self.assertTrue(aclose_done.wait(1.0))
        thread.join(timeout=3.0)
        self.assertTrue(holder.get('root_finished', False))


    def test_shutdown_async_queue_bounded(self):
        async def _run():
            q = asyncio.Queue()
            await q.put('a')
            t0 = time.monotonic()
            await _shutdown_async_queue(q, 'test')
            self.assertLess(time.monotonic() - t0, 2.0)
            self.assertTrue(q.empty())

        asyncio.run(_run())


if __name__ == '__main__':
    unittest.main()
