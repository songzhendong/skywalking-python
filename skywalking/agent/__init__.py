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
import atexit
import functools
import os
import sys
import time
from queue import Empty, Full, Queue
from threading import Event, Thread
from typing import TYPE_CHECKING, Callable, Optional

from skywalking import config, loggings, meter, plugins, profile, sampling
from skywalking.agent.protocol import Protocol, ProtocolAsync
from skywalking.command import command_service, command_service_async
from skywalking.loggings import logger
from skywalking.profile.profile_task import ProfileTask
from skywalking.profile.snapshot import TracingThreadSnapshot
from skywalking.protocol.language_agent.Meter_pb2 import MeterData
from skywalking.protocol.logging.Logging_pb2 import LogData
from skywalking.utils.reporter_log import log_dropped_throttled, log_reporter_exception_throttled
from skywalking.utils.singleton import Singleton

if TYPE_CHECKING:
    from skywalking.trace.context import Segment

if config.agent_asyncio_enhancement:
    import uvloop
    uvloop.install()

# Shutdown must never block the host indefinitely (Node flush budget parity).
_SHUTDOWN_FLUSH_TIMEOUT_SEC = 2.0
_SHUTDOWN_JOIN_TIMEOUT_SEC = 2.0
_SHUTDOWN_LOOP_JOIN_TIMEOUT_SEC = 3.0


def _abandon_sync_queue(q: Queue) -> int:
    """Drop queued items and balance unfinished_tasks so Queue.join() can finish."""
    abandoned = 0
    while True:
        try:
            q.get_nowait()
            q.task_done()
            abandoned += 1
        except Empty:
            break
    return abandoned


def _join_sync_queue(q: Queue, timeout: float) -> bool:
    """Return True if join completed within timeout."""
    done = Event()

    def _wait():
        q.join()
        done.set()

    Thread(target=_wait, name='sw-queue-join', daemon=True).start()
    return done.wait(timeout)


def _shutdown_sync_queue(
    report_fn: Optional[Callable[[], None]],
    q: Queue,
    label: str,
    *,
    may_send: bool,
) -> None:
    """
    Best-effort shutdown drain: optional timed flush when READY, then abandon + timed join.
    Never blocks longer than flush+join budgets (prevents atexit hang when not READY).
    """
    if may_send and report_fn is not None and not q.empty():
        done = Event()

        def _flush():
            try:
                report_fn()
            except Exception:  # noqa: BLE001 - shutdown must continue
                logger.exception('shutdown flush failed for %s queue', label)
            finally:
                done.set()

        Thread(target=_flush, name=f'sw-shutdown-flush-{label}', daemon=True).start()
        if not done.wait(_SHUTDOWN_FLUSH_TIMEOUT_SEC):
            logger.warning(
                'shutdown flush timed out after %.1fs for %s queue; abandoning remainder',
                _SHUTDOWN_FLUSH_TIMEOUT_SEC,
                label,
            )

    abandoned = _abandon_sync_queue(q)
    if abandoned:
        log_dropped_throttled(label, abandoned, force=True)

    if not _join_sync_queue(q, _SHUTDOWN_JOIN_TIMEOUT_SEC):
        logger.warning(
            'shutdown join timed out after %.1fs for %s queue (unfinished_tasks=%s)',
            _SHUTDOWN_JOIN_TIMEOUT_SEC,
            label,
            getattr(q, 'unfinished_tasks', '?'),
        )


async def _abandon_async_queue(q: asyncio.Queue) -> int:
    abandoned = 0
    while True:
        try:
            q.get_nowait()
            q.task_done()
            abandoned += 1
        except asyncio.QueueEmpty:
            break
    return abandoned


async def _shutdown_async_queue(q: asyncio.Queue, label: str) -> None:
    """
    Async reporters use unbounded queue.get() generators — do not await report() on
    shutdown (can hang forever). Abandon + timed join, then caller cancels tasks.
    """
    abandoned = await _abandon_async_queue(q)
    if abandoned:
        log_dropped_throttled(label, abandoned, force=True)
    try:
        await asyncio.wait_for(q.join(), timeout=_SHUTDOWN_JOIN_TIMEOUT_SEC)
    except asyncio.TimeoutError:
        logger.warning(
            'shutdown join timed out after %.1fs for async %s queue',
            _SHUTDOWN_JOIN_TIMEOUT_SEC,
            label,
        )


def _retrieve_background_task_outcome(
    task: asyncio.Task,
    *,
    report_unexpected_completion: bool = True,
    report_unexpected_cancellation: bool = False,
):
    """
    Return a completed background task's exception when it should be reported.

    Retrieves the exception so asyncio does not emit "never retrieved" warnings.
    Successful completion / cancellation are only converted to errors when the
    corresponding report_* flag is set (supervisor path before shutdown).
    """
    if task is None or not task.done():
        return None
    if task.cancelled():
        if report_unexpected_cancellation:
            return RuntimeError(
                'Python agent asyncio background task was cancelled unexpectedly'
            )
        return None
    exc = task.exception()
    if exc is not None:
        return exc
    if report_unexpected_completion:
        return RuntimeError('Python agent asyncio background task finished unexpectedly')
    return None


def _log_background_task_outcome(
    task: asyncio.Task,
    *,
    report_unexpected_completion: bool = True,
    report_unexpected_cancellation: bool = False,
) -> bool:
    """Log and retrieve a completed background task outcome. Returns True if logged."""
    if getattr(task, '_sw_outcome_handled', False):
        return False
    exc = _retrieve_background_task_outcome(
        task,
        report_unexpected_completion=report_unexpected_completion,
        report_unexpected_cancellation=report_unexpected_cancellation,
    )
    if exc is None:
        return False
    # Mark before logging so cleanup never re-logs a supervisor-handled outcome.
    setattr(task, '_sw_outcome_handled', True)
    logger.error('Error in Python agent asyncio event loop: %s', exc, exc_info=exc)
    return True


async def _await_shutdown_or_background_failure(
    finished: asyncio.Event,
    background_tasks,
) -> None:
    """
    Wait for shutdown or the first unexpected background-task completion.

    Background tasks are expected to run until shutdown. If one finishes or is
    cancelled early, retrieve/log its outcome and signal shutdown so the root
    can clean up.
    """
    shutdown_waiter = asyncio.create_task(finished.wait())
    pending = {task for task in background_tasks if task is not None}
    try:
        while not finished.is_set():
            if not pending:
                await finished.wait()
                return
            done, _ = await asyncio.wait(
                pending | {shutdown_waiter},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if shutdown_waiter in done or finished.is_set():
                return
            for task in done:
                pending.discard(task)
                # Before shutdown, both early success and unexpected cancel are errors.
                if _log_background_task_outcome(
                    task,
                    report_unexpected_completion=True,
                    report_unexpected_cancellation=True,
                ):
                    finished.set()
                    return
    finally:
        if not shutdown_waiter.done():
            shutdown_waiter.cancel()
            try:
                await shutdown_waiter
            except asyncio.CancelledError:
                pass


async def _cancel_pending_tasks(tasks) -> None:
    """
    Cancel agent-owned reporter / connectivity-watch tasks only.

    Cancel only the given reporter / watch tasks; never the asyncio.run root.
    The current task is excluded so we never await ourselves.

    During cleanup, normal completion and intentional cancellation are silent;
    only real exceptions that were not already handled by the supervisor are logged.
    """
    current = asyncio.current_task()
    for task in tasks:
        if task is None or task is current:
            continue
        if task.done():
            _log_background_task_outcome(
                task,
                report_unexpected_completion=False,
                report_unexpected_cancellation=False,
            )
    pending = [
        task for task in tasks
        if task is not None and task is not current and not task.done()
    ]
    if not pending:
        return
    for task in pending:
        task.cancel()
    try:
        await asyncio.wait_for(
            asyncio.gather(*pending, return_exceptions=True),
            timeout=_SHUTDOWN_JOIN_TIMEOUT_SEC,
        )
    except asyncio.TimeoutError:
        logger.warning(
            'shutdown task cancellation timed out after %.1fs; %d task(s) still pending',
            _SHUTDOWN_JOIN_TIMEOUT_SEC,
            sum(1 for task in pending if not task.done()),
        )
    for task in pending:
        _log_background_task_outcome(
            task,
            report_unexpected_completion=False,
            report_unexpected_cancellation=False,
        )


def _close_previous_protocol(protocol) -> None:
    """Close a replaced protocol channel (fork re-bootstrap / defensive re-open)."""
    if protocol is None:
        return
    close = getattr(protocol, 'close', None)
    if callable(close):
        try:
            close()
        except Exception:  # noqa: BLE001
            logger.exception('failed to close previous protocol channel')


async def _aclose_previous_protocol(protocol) -> None:
    """Await aclose on the running loop. Never run_coroutine_threadsafe().result() here."""
    if protocol is None:
        return
    aclose = getattr(protocol, 'aclose', None)
    if callable(aclose):
        try:
            await aclose()
            return
        except Exception:  # noqa: BLE001
            logger.exception('failed to aclose previous protocol channel')
    close = getattr(protocol, 'close', None)
    if callable(close):
        try:
            close()
        except Exception:  # noqa: BLE001
            logger.exception('failed to close previous protocol channel')


def report_with_backoff(reporter_name, init_wait):
    """
    An exponential backoff for retrying reporters.
    """

    def backoff_decorator(func):
        @functools.wraps(func)
        def backoff_wrapper(self, *args, **kwargs):
            wait = base = init_wait
            while not self._finished.is_set():
                try:
                    flag = func(self, *args, **kwargs)
                    # for segment/log reporter, if the queue not empty(return True), we should keep reporter working
                    # for other cases(return false or None), reset to base wait time on success
                    wait = 0 if flag else base
                except Exception:  # noqa
                    wait = min(60, wait * 2 or 1)  # double wait time with each consecutive error up to a maximum
                    log_reporter_exception_throttled(reporter_name, wait)
                self._finished.wait(wait)
            logger.info('finished reporter thread')

        return backoff_wrapper

    return backoff_decorator


def report_with_backoff_async(reporter_name, init_wait):
    """
    An exponential async backoff for retrying reporters.
    """

    def backoff_decorator(func):
        @functools.wraps(func)
        async def backoff_wrapper(self, *args, **kwargs):
            wait = base = init_wait
            while not self._finished.is_set():
                try:
                    flag = await func(self, *args, **kwargs)
                    # for segment/log reporter, if the queue not empty(return True), we should keep reporter working
                    # for other cases(return false or None), reset to base wait time on success
                    wait = 0 if flag else base
                except Exception:  # noqa
                    wait = min(60, wait * 2 or 1)  # double wait time with each consecutive error up to a maximum
                    log_reporter_exception_throttled(reporter_name, wait)
                # Prefer Event.wait so shutdown (_finished.set) wakes immediately;
                # plain sleep(wait) would otherwise block up to heartbeat/backoff period.
                if wait:
                    try:
                        await asyncio.wait_for(self._finished.wait(), timeout=wait)
                    except asyncio.TimeoutError:
                        pass
                else:
                    await asyncio.sleep(0)
            logger.info('finished reporter coroutine')

        return backoff_wrapper

    return backoff_decorator


class SkyWalkingAgent(Singleton):
    """
    The main singleton class and entrypoint of SkyWalking Python Agent.
    Upon fork(), original instance rebuild everything (queues, threads, instrumentation) by
    calling the fork handlers in the class instance.
    """
    __started: bool = False  # shared by all instances

    def __init__(self):
        """
        Protocol is one of gRPC, HTTP and Kafka that
        provides clients to reporters to communicate with OAP backend.
        """
        self.started_pid = None
        self.__protocol: Optional[Protocol] = None
        self._finished: Optional[Event] = None
        # True only after __bootstrap() in the current process; stays False in a pre-fork master
        self.__reporting: bool = False
        self.__at_fork_registered: bool = False
        self.__fini_registered: bool = False

    def __bootstrap(self):
        # when forking, already instrumented modules must not be instrumented again
        # otherwise it will cause double instrumentation! (we should provide an un-instrument method)

        # Initialize queues for segment, log, meter and profiling snapshots
        self.__init_queues()

        if config.agent_protocol == 'grpc':
            from skywalking.agent.protocol.grpc import GrpcProtocol
            _close_previous_protocol(self.__protocol)
            self.__protocol = GrpcProtocol()
        elif config.agent_protocol == 'http':
            from skywalking.agent.protocol.http import HttpProtocol
            _close_previous_protocol(self.__protocol)
            self.__protocol = HttpProtocol()
        elif config.agent_protocol == 'kafka':
            from skywalking.agent.protocol.kafka import KafkaProtocol
            _close_previous_protocol(self.__protocol)
            self.__protocol = KafkaProtocol()

        # Start reporter threads and register queues
        self.__init_threading()

        self.__reporting = True

    def __init_queues(self) -> None:
        """
        This method initializes all the queues for the agent and reporters.
        """
        self.__segment_queue = Queue(maxsize=config.agent_trace_reporter_max_buffer_size)
        self.__log_queue: Optional[Queue] = None
        self.__meter_queue: Optional[Queue] = None
        self.__snapshot_queue: Optional[Queue] = None

        if config.agent_meter_reporter_active:
            self.__meter_queue = Queue(maxsize=config.agent_meter_reporter_max_buffer_size)
        if config.agent_log_reporter_active:
            self.__log_queue = Queue(maxsize=config.agent_log_reporter_max_buffer_size)
        if config.agent_profile_active:
            self.__snapshot_queue = Queue(maxsize=config.agent_profile_snapshot_transport_buffer_size)


    def __init_threading(self) -> None:
        """
        This method initializes all the threads for the agent and reporters.
        Upon os.fork(), callback will reinitialize threads and queues by calling this method

        Heartbeat thread is started by default.
        Segment reporter thread and segment queue is created by default.
        All other queues and threads depends on user configuration.
        """
        self._finished = Event()

        __heartbeat_thread = Thread(name='HeartbeatThread', target=self.__heartbeat, daemon=True)
        __heartbeat_thread.start()

        __segment_report_thread = Thread(name='SegmentReportThread', target=self.__report_segment, daemon=True)
        __segment_report_thread.start()

        if config.agent_meter_reporter_active:
            __meter_report_thread = Thread(name='MeterReportThread', target=self.__report_meter, daemon=True)
            __meter_report_thread.start()

            if config.agent_pvm_meter_reporter_active:
                from skywalking.meter.pvm.cpu_usage import CPUUsageDataSource
                from skywalking.meter.pvm.gc_data import GCDataSource
                from skywalking.meter.pvm.mem_usage import MEMUsageDataSource
                from skywalking.meter.pvm.thread_data import ThreadDataSource

                MEMUsageDataSource().register()
                CPUUsageDataSource().register()
                GCDataSource().register()
                ThreadDataSource().register()

        if config.agent_log_reporter_active:
            __log_report_thread = Thread(name='LogReportThread', target=self.__report_log, daemon=True)
            __log_report_thread.start()

        if config.agent_profile_active:
            # Now only profiler receives commands from OAP
            __command_dispatch_thread = Thread(name='CommandDispatchThread', target=self.__command_dispatch,
                                               daemon=True)
            __command_dispatch_thread.start()

            __query_profile_thread = Thread(name='QueryProfileCommandThread', target=self.__query_profile_command,
                                            daemon=True)
            __query_profile_thread.start()

            __send_profile_thread = Thread(name='SendProfileSnapShotThread', target=self.__send_profile_snapshot,
                                           daemon=True)
            __send_profile_thread.start()

    @staticmethod  # for now
    def __fork_before() -> None:
        """
        This handles explicit fork() calls. The child process will not have a running thread, so we need to
        revive all of them. The parent process will continue to run as normal.

        This does not affect pre-forking server support, which are handled separately.
        """
        # possible deadlock would be introduced if some queue is in use when fork() is called and
        # therefore child process will inherit a locked queue. To avoid this and have side benefit
        # of a clean queue in child process (prevent duplicated reporting), we simply restart the agent and
        # reinitialize all queues and threads.
        logger.warning('SkyWalking Python agent fork support is currently experimental, '
                       'please report issues if you encounter any.')

    @staticmethod  # for now
    def __fork_after_in_parent() -> None:
        """
        Something to do after fork() in parent process
        """
        ...

    def __fork_after_in_child(self) -> None:
        """
        Simply restart the agent after we detect a fork() call
        """
        # This will be used by os.fork() called by application and also Gunicorn, not uWSGI
        # otherwise we assume a fork() happened, give it a new service instance name
        logger.info('New process detected, re-initializing SkyWalking Python agent')
        # Note: this is for experimental change, default config should never reach here
        # Fork support is controlled by config.agent_fork_support :default: False
        # Important: This does not impact pre-forking server support (uwsgi, gunicorn, etc...)
        # This is only for explicit long-running fork() calls.
        config.agent_instance_name = f'{config.agent_instance_name}-child({os.getpid()})'
        self.start()
        logger.info(f'Agent spawned as {config.agent_instance_name} for service {config.agent_name}.')

    def start(self) -> None:
        """
        Start would be called by user or os.register_at_fork() callback
        Start will proceed if and only if the agent is not started in the
        current process.

        When os.fork(), the service instance should be changed to a new one by appending pid.
        """
        loggings.init()

        if sys.version_info < (3, 7):
            # agent may or may not work for Python 3.6 and below
            # since 3.6 is EOL, we will not officially support it
            logger.warning('SkyWalking Python agent does not support Python 3.6 and below, '
                           'please upgrade to Python 3.7 or above.')
        # Required for grpcio to work with fork(), see grpc/grpc doc/fork_support.md.
        if config.agent_protocol == 'grpc' and config.agent_experimental_fork_support:
            python_major_version: tuple = sys.version_info[:2]
            if python_major_version == (3, 7):
                logger.warning('gRPC fork support may cause hanging on Python 3.7 '
                               'when used together with gRPC and subprocess lib'
                               'See: https://github.com/grpc/grpc/issues/18075.'
                               'Please consider upgrade to Python 3.8+, '
                               'or use HTTP/Kafka protocol, or disable experimental fork support '
                               'if your application did not start successfully.')

            # GRPC_POLL_STRATEGY=poll must NOT be set: the legacy poller is broken across
            # fork() on grpcio >= 1.80 (the agent requires >= 1.83),
            # see https://github.com/apache/skywalking/issues/13958
            os.environ['GRPC_ENABLE_FORK_SUPPORT'] = 'true'  # must precede `import grpc`

            if not os.getenv('prefork'):  # Gunicorn prefork creates channels only after fork() and is safe
                logger.warning('Explicit os.fork() with a live gRPC channel is unreliable on '
                               'grpcio >= 1.80 (see grpc/grpc#43055) and may silently break '
                               'reporting in either process; prefer SW_AGENT_PROTOCOL=http or '
                               'kafka for forking applications.')

        if not self.__started:
            # if not already started, start the agent
            logger.info(f'SkyWalking sync agent instance {config.agent_instance_name} starting in pid-{os.getpid()}.')
            self.__init_instrumentation()
        elif self.__started and os.getpid() == self.started_pid:
            # if already started, and this is the same process, raise an error
            raise RuntimeError('SkyWalking Python agent has already been started in this process, '
                               'did you call start more than once in your code + sw-python CLI? '
                               'If you already use sw-python CLI, you should remove the manual start(), vice versa.')
        # Else there's a new process (after fork()), we will restart the agent in the new process

        self.started_pid = os.getpid()

        flag = False
        try:
            from gevent import monkey
            flag = monkey.is_module_patched('socket')
        except ModuleNotFoundError:
            logger.debug("it was found that no gevent was used, if you don't use, please ignore.")
        if flag:
            import grpc.experimental.gevent as grpc_gevent
            grpc_gevent.init_gevent()

        if config.agent_profile_active:
            profile.init()
        if config.agent_meter_reporter_active:
            meter.init(force=True)  # force re-init after fork()
        if config.sample_n_per_3_secs > 0:
            sampling.init(force=True)

        self.__bootstrap()  # calls init_threading

        # atexit registrations are fork-inherited; register once per lineage so a
        # fork-restarted child does not stack a duplicate __fini
        if not self.__fini_registered:
            self.__fini_registered = True
            atexit.register(self.__fini)

        if config.agent_experimental_fork_support:
            self.__register_fork_hooks()

    def __init_instrumentation(self) -> None:
        """
        Install instrumentation once per process lineage; forked children inherit
        the patches and the __started flag, so they skip this.
        """
        config.finalize()  # Must be finalized exactly once

        self.__started = True

        # Install log reporter core
        if config.agent_log_reporter_active:
            from skywalking import log
            log.install()
        # Here we install all other lib plugins on first time start (parent process)
        plugins.install()

    def __register_fork_hooks(self) -> None:
        # at-fork registrations cannot be removed and are fork-inherited; never register twice
        if self.__at_fork_registered:
            return
        if hasattr(os, 'register_at_fork'):
            self.__at_fork_registered = True
            os.register_at_fork(before=self.__fork_before, after_in_parent=self.__fork_after_in_parent,
                                after_in_child=self.__fork_after_in_child)

    def start_prefork_master(self) -> None:
        """
        Prepare the agent in a pre-forking server master (Gunicorn): install instrumentation
        and arm the fork hooks only. The full agent — queues, gRPC channel, reporter threads —
        starts in each forked worker; a channel living across fork() is unsafe with
        grpcio >= 1.80, see https://github.com/apache/skywalking/issues/13958.
        """
        loggings.init()

        if config.agent_protocol == 'grpc' and config.agent_experimental_fork_support:
            # Must be exported before the first `import grpc`; plugins.install() below imports grpc
            os.environ['GRPC_ENABLE_FORK_SUPPORT'] = 'true'

        if not self.__started:
            self.__init_instrumentation()
            logger.info(f'SkyWalking Python agent instrumented pre-fork master pid-{os.getpid()}, '
                        f'reporters will start in forked worker processes.')

        self.started_pid = os.getpid()

        if config.agent_experimental_fork_support:
            self.__register_fork_hooks()

    def __fini(self):
        """
        This method is called when the agent is shutting down.
        Clean up all the queues and threads.

        Stop reporter loops first, then best-effort flush (timed) when READY, else
        abandon queued items so Queue.join() cannot hang forever (READY-gate gap).
        """
        if not self.__reporting:  # never bootstrapped in this process (e.g. pre-fork master)
            return

        # Wake backoff loops immediately; do not leave finished.set() until after joins.
        self._finished.set()
        may_send = self.__protocol.is_ready()

        _shutdown_sync_queue(
            (lambda: self.__protocol.report_segment(self.__segment_queue, False)) if may_send else None,
            self.__segment_queue,
            'segment',
            may_send=may_send,
        )

        if config.agent_log_reporter_active:
            _shutdown_sync_queue(
                (lambda: self.__protocol.report_log(self.__log_queue, False)) if may_send else None,
                self.__log_queue,
                'log',
                may_send=may_send,
            )

        if config.agent_profile_active:
            _shutdown_sync_queue(
                (lambda: self.__protocol.report_snapshot(self.__snapshot_queue, False)) if may_send else None,
                self.__snapshot_queue,
                'snapshot',
                may_send=may_send,
            )

        if config.agent_meter_reporter_active:
            _shutdown_sync_queue(
                (lambda: self.__protocol.report_meter(self.__meter_queue, False)) if may_send else None,
                self.__meter_queue,
                'meter',
                may_send=may_send,
            )

        close = getattr(self.__protocol, 'close', None)
        if callable(close):
            close()

    def stop(self) -> None:
        """
        Stops the agent and reset the started flag.
        """
        atexit.unregister(self.__fini)
        self.__fini_registered = False
        self.__fini()
        self.__reporting = False
        self.__started = False

    @report_with_backoff(reporter_name='heartbeat', init_wait=config.agent_collector_heartbeat_period)
    def __heartbeat(self) -> bool:
        # Until subscribe reports READY, retry soon (do not wait a full heartbeat period).
        if not self.__protocol.is_ready():
            time.sleep(0.5)
            return True
        self.__protocol.heartbeat()
        return False

    # segment/log init_wait is set to 0.02 to prevent threads from hogging the cpu too much
    # The value of 0.02(20 ms) is set to be consistent with the queue delay of the Java agent

    @report_with_backoff(reporter_name='segment', init_wait=0.02)
    def __report_segment(self) -> bool:
        """Returns True if the queue is not empty and a send was attempted."""
        # Not READY: sleep then wait=0 — avoid 20ms busy-loop + IDLE nudge thrash.
        if not self.__protocol.is_ready():
            time.sleep(0.5)
            return True
        queue_not_empty_flag = not self.__segment_queue.empty()
        if queue_not_empty_flag:
            self.__protocol.report_segment(self.__segment_queue)
        return queue_not_empty_flag

    @report_with_backoff(reporter_name='log', init_wait=0.02)
    def __report_log(self) -> bool:
        """Returns True if the queue is not empty and a send was attempted."""
        if not self.__protocol.is_ready():
            time.sleep(0.5)
            return True
        queue_not_empty_flag = not self.__log_queue.empty()
        if queue_not_empty_flag:
            self.__protocol.report_log(self.__log_queue)
        return queue_not_empty_flag

    @report_with_backoff(reporter_name='meter', init_wait=config.agent_meter_reporter_period)
    def __report_meter(self) -> None:
        if not self.__protocol.is_ready():
            time.sleep(0.5)
            return
        if not self.__meter_queue.empty():
            self.__protocol.report_meter(self.__meter_queue)

    @report_with_backoff(reporter_name='profile_snapshot', init_wait=0.5)
    def __send_profile_snapshot(self) -> None:
        if not self.__protocol.is_ready():
            time.sleep(0.5)
            return
        if not self.__snapshot_queue.empty():
            self.__protocol.report_snapshot(self.__snapshot_queue)

    @report_with_backoff(reporter_name='query_profile_command',
                         init_wait=config.agent_collector_get_profile_task_interval)
    def __query_profile_command(self) -> None:
        self.__protocol.query_profile_commands()

    @staticmethod
    def __command_dispatch() -> None:
        # command dispatch will stuck when there are no commands
        command_service.dispatch()

    def started(self) -> bool:
        """
        Whether reporting (queues, protocol clients, reporter threads) is active in this process.
        False in a pre-forking server master, where only instrumentation is installed.
        """
        return self.__reporting

    def is_segment_queue_full(self):
        if not self.__reporting:
            return True  # treated as full so span creation short-circuits to NoopSpan
        return self.__segment_queue.full()

    def archive_segment(self, segment: 'Segment'):
        if not self.__reporting:
            return
        try:  # unlike checking __queue.full() then inserting, this is atomic
            self.__segment_queue.put(segment, block=False)
        except Full:
            log_dropped_throttled('segment')

    def archive_log(self, log_data: 'LogData'):
        if not self.__reporting:
            return
        try:
            self.__log_queue.put(log_data, block=False)
        except Full:
            log_dropped_throttled('log')

    def archive_meter(self, meter_data: 'MeterData'):
        if not self.__reporting:
            return
        try:
            self.__meter_queue.put(meter_data, block=False)
        except Full:
            log_dropped_throttled('meter')

    def add_profiling_snapshot(self, snapshot: TracingThreadSnapshot):
        if not self.__reporting:
            return
        try:
            self.__snapshot_queue.put_nowait(snapshot)
        except Full:
            log_dropped_throttled('snapshot')

    def notify_profile_finish(self, task: ProfileTask):
        try:
            self.__protocol.notify_profile_task_finish(task)
        except Exception as e:
            logger.error(f'notify profile task finish to backend fail. {str(e)}')


class SkyWalkingAgentAsync(Singleton):
    __started: bool = False  # shared by all instances

    def __init__(self):
        """
        ProtocolAsync is one of gRPC, HTTP and Kafka that
        provides async clients to reporters to communicate with OAP backend.
        """
        self.started_pid = None
        self.__protocol: Optional[ProtocolAsync] = None
        self._finished: Optional[asyncio.Event] = None
        # Initialize asyncio queues for segment, log, meter and profiling snapshots
        self.__segment_queue: Optional[asyncio.Queue] = None
        self.__log_queue: Optional[asyncio.Queue] = None
        self.__meter_queue: Optional[asyncio.Queue] = None
        self.__snapshot_queue: Optional[asyncio.Queue] = None

        self.event_loop_thread: Optional[Thread] = None

    async def __bootstrap(self):
        await _aclose_previous_protocol(self.__protocol)
        if config.agent_protocol == 'grpc':
            from skywalking.agent.protocol.grpc_aio import GrpcProtocolAsync
            self.__protocol = GrpcProtocolAsync()
        elif config.agent_protocol == 'http':
            from skywalking.agent.protocol.http_aio import HttpProtocolAsync
            self.__protocol = HttpProtocolAsync()
        elif config.agent_protocol == 'kafka':
            from skywalking.agent.protocol.kafka_aio import KafkaProtocolAsync
            self.__protocol = KafkaProtocolAsync()
        else:
            raise ValueError(f'Unsupported protocol: {config.agent_protocol}')
        logger.info(f'You are using {config.agent_protocol} protocol to communicate with OAP backend')

        # Start reporter's asyncio coroutines and register queues
        self.__init_coroutine()

    def __init_coroutine(self) -> None:
        """
        This method initializes all asyncio coroutines for the agent and reporters.

        Heartbeat task is started by default.
        Segment reporter task and segment queue is created by default.
        All other queues and tasks depends on user configuration.
        """

        self.background_coroutines = set()

        watch = getattr(self.__protocol, 'watch_connectivity', None)
        if callable(watch):
            self.background_coroutines.add(watch())

        self.background_coroutines.add(self.__heartbeat())
        self.background_coroutines.add(self.__report_segment())

        if config.agent_meter_reporter_active:
            self.background_coroutines.add(self.__report_meter())

            if config.agent_pvm_meter_reporter_active:
                from skywalking.meter.pvm.cpu_usage import CPUUsageDataSource
                from skywalking.meter.pvm.gc_data import GCDataSource
                from skywalking.meter.pvm.mem_usage import MEMUsageDataSource
                from skywalking.meter.pvm.thread_data import ThreadDataSource

                MEMUsageDataSource().register()
                CPUUsageDataSource().register()
                GCDataSource().register()
                ThreadDataSource().register()

        if config.agent_log_reporter_active:
            self.background_coroutines.add(self.__report_log())

        if config.agent_profile_active:
            self.background_coroutines.add(self.__command_dispatch())
            self.background_coroutines.add(self.__query_profile_command())
            self.background_coroutines.add(self.__send_profile_snapshot())

    async def __start_event_loop_async(self) -> None:
        self.loop = asyncio.get_running_loop()  # always get the current running loop first
        # asyncio Queue should be created after the creation of event loop
        self.__segment_queue = asyncio.Queue(maxsize=config.agent_trace_reporter_max_buffer_size)
        if config.agent_meter_reporter_active:
            self.__meter_queue = asyncio.Queue(maxsize=config.agent_meter_reporter_max_buffer_size)
        if config.agent_log_reporter_active:
            self.__log_queue = asyncio.Queue(maxsize=config.agent_log_reporter_max_buffer_size)
        if config.agent_profile_active:
            self.__snapshot_queue = asyncio.Queue(maxsize=config.agent_profile_snapshot_transport_buffer_size)
        # initialize background coroutines
        self.background_coroutines = set()
        self.background_tasks = set()
        self._finished = asyncio.Event()

        # Install log reporter core
        if config.agent_log_reporter_active:
            from skywalking import log
            log.install()
        if config.agent_meter_reporter_active:
            # meter.init(force=True)
            await meter.init_async()
        if config.sample_n_per_3_secs > 0:
            await sampling.init_async()

        await self.__bootstrap()  # gather all coroutines

        self.background_tasks = {asyncio.create_task(coro) for coro in self.background_coroutines}
        logger.debug('All background coroutines started')
        # Wait for shutdown or unexpected background-task completion inside the
        # asyncio.run root, then clean up here so the Runner stays alive through
        # protocol aclose() before asyncio.run returns.
        await _await_shutdown_or_background_failure(self._finished, self.background_tasks)
        await self.__async_shutdown_cleanup()

    def __start_event_loop(self) -> None:
        try:
            asyncio.run(self.__start_event_loop_async())
        except asyncio.CancelledError:
            logger.info('Python agent asyncio event loop is closed')
        except Exception as e:
            logger.error(f'Error in Python agent asyncio event loop: {e}')
        finally:
            if self._finished is not None:
                self._finished.set()

    def start(self) -> None:
        loggings.init()

        if sys.version_info < (3, 7):
            # agent may or may not work for Python 3.6 and below
            # since 3.6 is EOL, we will not officially support it
            logger.warning('SkyWalking Python agent does not support Python 3.6 and below, '
                           'please upgrade to Python 3.7 or above.')

        if not self.__started:
            # if not already started, start the agent
            config.finalize()  # Must be finalized exactly once

            self.__started = True
            logger.info(f'SkyWalking async agent instance {config.agent_instance_name} starting in pid-{os.getpid()}.')

            # Here we install all other lib plugins on first time start (parent process)
            plugins.install()

        elif self.__started and os.getpid() == self.started_pid:
            # if already started, and this is the same process, raise an error
            raise RuntimeError('SkyWalking Python agent has already been started in this process, '
                               'did you call start more than once in your code + sw-python CLI? '
                               'If you already use sw-python CLI, you should remove the manual start(), vice versa.')

        self.started_pid = os.getpid()
        atexit.register(self.__fini)

        # still init profile here, since it is using threading rather than asyncio
        if config.agent_profile_active:
            profile.init()

        self.event_loop_thread = Thread(name='event_loop_thread', target=self.__start_event_loop, daemon=True)
        self.event_loop_thread.start()

    async def __async_shutdown_cleanup(self) -> None:
        """
        Async shutdown body that must run on the asyncio.run root task.

        Do not await report_* here: aio generators use unbounded queue.get() and can
        hang forever. Abandon + timed join, then cancel tasks.
        """
        await _shutdown_async_queue(self.__segment_queue, 'segment')

        if config.agent_log_reporter_active:
            await _shutdown_async_queue(self.__log_queue, 'log')

        if config.agent_profile_active:
            await _shutdown_async_queue(self.__snapshot_queue, 'snapshot')

        if config.agent_meter_reporter_active:
            await _shutdown_async_queue(self.__meter_queue, 'meter')

        await _cancel_pending_tasks(getattr(self, 'background_tasks', ()))

        aclose = getattr(self.__protocol, 'aclose', None)
        if callable(aclose):
            try:
                await aclose()
            except Exception:  # noqa: BLE001
                pass
        else:
            close = getattr(self.__protocol, 'close', None)
            if callable(close):
                close()

    def __fini(self):
        loop = getattr(self, 'loop', None)
        if loop is not None and not loop.is_closed() and self._finished is not None:
            loop.call_soon_threadsafe(self._finished.set)
        if self.event_loop_thread is not None:
            self.event_loop_thread.join(
                timeout=_SHUTDOWN_LOOP_JOIN_TIMEOUT_SEC + _SHUTDOWN_JOIN_TIMEOUT_SEC * 4,
            )
        if self.event_loop_thread.is_alive():
            logger.warning(
                'Python agent event_loop thread still alive after %.1fs shutdown budget',
                _SHUTDOWN_LOOP_JOIN_TIMEOUT_SEC,
            )
        else:
            logger.info('Finished Python agent event_loop thread')
        # TODO: Unhandled error in sys.excepthook https://github.com/pytest-dev/execnet/issues/30

    def stop(self) -> None:
        """
        Stops the agent and reset the started flag.
        """
        atexit.unregister(self.__fini)
        self.__fini()
        self.__started = False

    @report_with_backoff_async(reporter_name='heartbeat', init_wait=config.agent_collector_heartbeat_period)
    async def __heartbeat(self) -> bool:
        if not self.__protocol.is_ready():
            await asyncio.sleep(0.5)
            return True
        await self.__protocol.heartbeat()
        return False

    @report_with_backoff_async(reporter_name='segment', init_wait=0.02)
    async def __report_segment(self) -> bool:
        """Returns True if the queue is not empty and a send was attempted."""
        if not self.__protocol.is_ready():
            await asyncio.sleep(0.5)
            return True
        queue_not_empty_flag = not self.__segment_queue.empty()
        if queue_not_empty_flag:
            await self.__protocol.report_segment(self.__segment_queue)
        return queue_not_empty_flag

    @report_with_backoff_async(reporter_name='log', init_wait=0.02)
    async def __report_log(self) -> bool:
        """Returns True if the queue is not empty and a send was attempted."""
        if not self.__protocol.is_ready():
            await asyncio.sleep(0.5)
            return True
        queue_not_empty_flag = not self.__log_queue.empty()
        if queue_not_empty_flag:
            await self.__protocol.report_log(self.__log_queue)
        return queue_not_empty_flag

    @report_with_backoff_async(reporter_name='meter', init_wait=config.agent_meter_reporter_period)
    async def __report_meter(self) -> None:
        if not self.__protocol.is_ready():
            await asyncio.sleep(0.5)
            return
        if not self.__meter_queue.empty():
            await self.__protocol.report_meter(self.__meter_queue)

    @report_with_backoff_async(reporter_name='profile_snapshot', init_wait=0.5)
    async def __send_profile_snapshot(self) -> None:
        if not self.__protocol.is_ready():
            await asyncio.sleep(0.5)
            return
        if not self.__snapshot_queue.empty():
            await self.__protocol.report_snapshot(self.__snapshot_queue)

    @report_with_backoff_async(
        reporter_name='query_profile_command',
        init_wait=config.agent_collector_get_profile_task_interval)
    async def __query_profile_command(self) -> None:
        await self.__protocol.query_profile_commands()

    @staticmethod
    async def __command_dispatch() -> None:
        # command dispatch will stuck when there are no commands
        await command_service_async.dispatch()

    def __asyncio_queue_put_nowait(self, q: asyncio.Queue, queue_name: str, item):
        try:
            q.put_nowait(item)
        except asyncio.QueueFull:
            log_dropped_throttled(queue_name)

    def is_segment_queue_full(self):
        return self.__segment_queue.full()

    def archive_segment(self, segment: 'Segment'):
        if not self.loop.is_closed():
            self.loop.call_soon_threadsafe(self.__asyncio_queue_put_nowait, self.__segment_queue, 'segment', segment)

    def archive_log(self, log_data: 'LogData'):
        if not self.loop.is_closed():
            self.loop.call_soon_threadsafe(self.__asyncio_queue_put_nowait, self.__log_queue, 'log', log_data)

    def archive_meter(self, meter_data: 'MeterData'):
        if not self.loop.is_closed():
            self.loop.call_soon_threadsafe(self.__asyncio_queue_put_nowait, self.__meter_queue, 'meter', meter_data)

    async def archive_meter_async(self, meter_data: 'MeterData'):
        try:
            self.__meter_queue.put_nowait(meter_data)
        except asyncio.QueueFull:
            log_dropped_throttled('meter')

    def add_profiling_snapshot(self, snapshot: TracingThreadSnapshot):
        self.loop.call_soon_threadsafe(self.__asyncio_queue_put_nowait, self.__snapshot_queue, 'snapshot', snapshot)

    def notify_profile_finish(self, task: ProfileTask):
        try:
            asyncio.run_coroutine_threadsafe(self.__protocol.notify_profile_task_finish(task), self.loop)
        except Exception as e:
            logger.error(f'notify profile task finish to backend fail. {e}')


# Export for user (backwards compatibility)
# so users still use `from skywalking import agent`
agent = SkyWalkingAgentAsync() if config.agent_asyncio_enhancement else SkyWalkingAgent()
start = agent.start
