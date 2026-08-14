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

import os

from skywalking import Layer, Component
from skywalking.trace.carrier import Carrier
from skywalking.trace.context import get_context
from skywalking.trace.tags import (
    TagMqBroker, TagMqTopic, TagMqMessageKeys, TagMqMessageTags, TagMqStatus,
)
from skywalking.loggings import getLogger

link_vector = ['https://github.com/apache/rocketmq-client-python']
support_matrix = {
    'rocketmq-client-python': {
        '>=3.10': ['2.0.0'],
        '>=3.7': ['2.0.0'],
    }
}
note = ''

logger = getLogger(__name__)

_SendStatus = None
_ReceivedMessage = None

_BROKER_BY_NAMESRV = {}
_get_message_store_host = None
_send_message_async = None
_send_message_async_arity = 0
_FFI_HELPERS_LOADED = False


def _maybe_str(val):
    if val is None:
        return None
    if isinstance(val, bytes):
        return val.decode('utf-8')
    return str(val)


def _namesrv_from_env():
    return os.environ.get('ROCKETMQ_NAMESRV_ADDR') or os.environ.get('NAMESRV_ADDR') or ''


def _get_namesrv(client):
    addr = getattr(client, '_sw_namesrv', None)
    if addr:
        return addr
    domain = getattr(client, '_sw_namesrv_domain', None)
    if domain:
        return domain
    return _namesrv_from_env()


def _bind_send_message_async(fn, dll, send_success_cb_type, send_exception_cb_type, c_void_p):
    global _send_message_async, _send_message_async_arity
    sync_fn = getattr(dll, 'SendMessageSync', None)
    restype = sync_fn.restype if sync_fn is not None else None
    fn.argtypes = [c_void_p, c_void_p, send_success_cb_type, send_exception_cb_type]
    fn.restype = restype
    _send_message_async = fn
    _send_message_async_arity = 4


def _bind_send_message_async_five_arg(fn, dll, send_success_cb_type, send_exception_cb_type, c_void_p):
    global _send_message_async, _send_message_async_arity
    sync_fn = getattr(dll, 'SendMessageSync', None)
    restype = sync_fn.restype if sync_fn is not None else None
    fn.argtypes = [c_void_p, c_void_p, send_success_cb_type, send_exception_cb_type, c_void_p]
    fn.restype = restype
    _send_message_async = fn
    _send_message_async_arity = 5


def _ensure_ffi_helpers():
    global _get_message_store_host, _send_message_async, _send_message_async_arity, _FFI_HELPERS_LOADED
    if _FFI_HELPERS_LOADED:
        return
    _FFI_HELPERS_LOADED = True
    try:
        from rocketmq.ffi import dll, SEND_SUCCESS_CALLBACK, SEND_EXCEPTION_CALLBACK
        from ctypes import c_void_p, c_char_p
    except ImportError:
        _get_message_store_host = False
        _send_message_async = False
        _send_message_async_arity = 0
        return

    # rocketmq-client-python 2.0.0's librocketmq does not export GetMessageStoreHost.
    fn = getattr(dll, 'GetMessageStoreHost', None)
    if fn is not None:
        fn.argtypes = [c_void_p]
        fn.restype = c_char_p
        _get_message_store_host = fn
    else:
        _get_message_store_host = False

    fn = getattr(dll, 'SendMessageAsync', None)
    if fn is not None:
        _bind_send_message_async(fn, dll, SEND_SUCCESS_CALLBACK, SEND_EXCEPTION_CALLBACK, c_void_p)
    else:
        _send_message_async = False
        _send_message_async_arity = 0


def _invoke_send_message_async(producer_handle, msg, success_cb, exception_cb):
    from rocketmq.exceptions import ffi_check
    from rocketmq.ffi import dll, SEND_SUCCESS_CALLBACK, SEND_EXCEPTION_CALLBACK
    from ctypes import c_void_p

    if not _send_message_async:
        raise AttributeError('send_async is not supported by the linked librocketmq')

    if _send_message_async_arity == 5:
        ffi_check(_send_message_async(producer_handle, msg, success_cb, exception_cb, None))
        return

    try:
        ffi_check(_send_message_async(producer_handle, msg, success_cb, exception_cb))
    except Exception:
        fn = getattr(dll, 'SendMessageAsync', None)
        if fn is None:
            raise
        _bind_send_message_async_five_arg(fn, dll, SEND_SUCCESS_CALLBACK, SEND_EXCEPTION_CALLBACK, c_void_p)
        ffi_check(_send_message_async(producer_handle, msg, success_cb, exception_cb, None))


def _normalize_store_host(raw):
    if not raw:
        return ''
    host = _maybe_str(raw).strip()
    while host.startswith('/'):
        host = host[1:]
    return host


def _message_handle(msg):
    handle = getattr(msg, '_handle', None)
    if handle is not None:
        return handle
    if _ReceivedMessage is not None and isinstance(msg, _ReceivedMessage):
        return msg._handle
    return None


def _message_store_host(msg):
    _ensure_ffi_helpers()
    if not _get_message_store_host:
        return ''
    handle = _message_handle(msg)
    if not handle:
        return ''
    try:
        return _normalize_store_host(_get_message_store_host(handle))
    except (OSError, ValueError, TypeError, AttributeError) as ex:
        logger.debug('GetMessageStoreHost failed: %s', ex)
        return ''


def _message_topic(msg):
    topic = getattr(msg, '_sw_topic', None)
    if topic:
        return topic
    if _ReceivedMessage is not None and isinstance(msg, _ReceivedMessage):
        return msg.topic
    return _ReceivedMessage(msg._handle).topic


def _remember_broker(namesrv, broker):
    if namesrv and broker:
        _BROKER_BY_NAMESRV[namesrv] = broker


def _resolve_mq_broker(msg, namesrv: str) -> str:
    """Resolve mq.broker for tags.

    Prefer FFI store host when the linked librocketmq exports it. The
    rocketmq-client-python 2.0.0 wheels do not, so fall back to namesrv
    (same address used as peer) rather than inventing a broker via DNS.
    """
    broker = _message_store_host(msg)
    if broker:
        _remember_broker(namesrv, broker)
        return broker
    if namesrv and namesrv in _BROKER_BY_NAMESRV:
        return _BROKER_BY_NAMESRV[namesrv]
    return namesrv or ''


def _inject_carrier(msg, carrier: Carrier):
    carrier.extension_context.inject_sending_timestamp()
    for item in carrier:
        if item.val:
            msg.set_property(item.key, item.val)


def _extract_carrier(msg):
    carrier = Carrier()
    for item in carrier:
        val = _maybe_str(msg.get_property(item.key))
        if val:
            item.val = val
    return carrier


def _tag_send_status(span, result):
    if result is None:
        return
    status = getattr(result, 'status', None)
    if status is None:
        return
    if _SendStatus is not None and status != _SendStatus.OK:
        span.error_occurred = True
        span.tag(TagMqStatus(status.name))


def _tag_message(span, msg, topic):
    span.tag(TagMqTopic(topic))
    if getattr(msg, '_sw_keys', None):
        span.tag(TagMqMessageKeys(str(msg._sw_keys)))
    if getattr(msg, '_sw_tags', None):
        span.tag(TagMqMessageTags(str(msg._sw_tags)))


def _async_callback_local_span(topic, snapshot, body):
    context = get_context()
    with context.new_local_span(op=f'RocketMQ/{topic}/Producer/Callback') as span:
        span.layer = Layer.MQ
        span.component = Component.RocketMQProducer
        context.continued(snapshot)
        return body(span)


def _install_message_hooks(message_cls):
    _message_init = message_cls.__init__
    _set_keys = message_cls.set_keys
    _set_tags = message_cls.set_tags

    def _sw_message_init(self, topic):
        _message_init(self, topic)
        self._sw_topic = topic
        self._sw_keys = None
        self._sw_tags = None

    def _sw_set_keys(self, keys):
        self._sw_keys = keys
        return _set_keys(self, keys)

    def _sw_set_tags(self, tags):
        self._sw_tags = tags
        return _set_tags(self, tags)

    message_cls.__init__ = _sw_message_init
    message_cls.set_keys = _sw_set_keys
    message_cls.set_tags = _sw_set_tags


def _trace_producer_send(this, msg, send_fn, *args, **kwargs):
    topic = _message_topic(msg)
    namesrv = _get_namesrv(this)
    context = get_context()
    with context.new_exit_span(op=f'RocketMQ/{topic}/Producer', peer=namesrv,
                               component=Component.RocketMQProducer) as span:
        span.layer = Layer.MQ
        _inject_carrier(msg, span.inject())
        try:
            result = send_fn(this, msg, *args, **kwargs)
        except Exception as ex:
            span.log(ex)
            raise
        _tag_send_status(span, result)
        span.tag(TagMqBroker(_resolve_mq_broker(msg, namesrv)))
        _tag_message(span, msg, topic)
        return result


def _send_async_via_ffi(this, msg, on_success, on_exception, send_result_cls, send_status_cls):
    from rocketmq.ffi import SEND_SUCCESS_CALLBACK, SEND_EXCEPTION_CALLBACK

    def _drop_async_callback_refs():
        for cb in (success_cb, exception_cb):
            try:
                this._callback_refs.remove(cb)
            except ValueError:
                pass

    def c_success(c_result):
        try:
            py_result = send_result_cls(
                send_status_cls(c_result.sendStatus),
                c_result.msgId.decode('utf-8'),
                c_result.offset,
            )
            on_success(py_result)
        finally:
            _drop_async_callback_refs()

    def c_exception(c_exc):
        try:
            msg_text = _maybe_str(getattr(c_exc, 'msg', b'')) or 'RocketMQ async send failed'
            on_exception(RuntimeError(msg_text))
        finally:
            _drop_async_callback_refs()

    success_cb = SEND_SUCCESS_CALLBACK(c_success)
    exception_cb = SEND_EXCEPTION_CALLBACK(c_exception)
    this._callback_refs.extend([success_cb, exception_cb])
    _invoke_send_message_async(this._handle, msg, success_cb, exception_cb)


def _install_producer_hooks(producer_cls, send_result_cls, send_status_cls):
    _producer_init = producer_cls.__init__
    _set_ns_producer = producer_cls.set_name_server_address
    _set_ns_domain_producer = producer_cls.set_name_server_domain
    _send_sync = producer_cls.send_sync
    _send_oneway = producer_cls.send_oneway
    _send_orderly = producer_cls.send_orderly_with_sharding_key
    _orig_send_async = getattr(producer_cls, 'send_async', None)

    def _sw_producer_init(self, *args, **kwargs):
        _producer_init(self, *args, **kwargs)
        if not getattr(self, '_sw_namesrv', None):
            self._sw_namesrv = _namesrv_from_env()

    def _sw_set_ns_producer(self, addr):
        self._sw_namesrv = addr
        return _set_ns_producer(self, addr)

    def _sw_set_ns_domain_producer(self, domain):
        self._sw_namesrv_domain = domain
        return _set_ns_domain_producer(self, domain)

    def _sw_send_sync(this, msg):
        return _trace_producer_send(this, msg, _send_sync)

    def _sw_send_oneway(this, msg):
        return _trace_producer_send(this, msg, _send_oneway)

    def _sw_send_orderly(this, msg, sharding_key):
        return _trace_producer_send(this, msg, _send_orderly, sharding_key)

    def _sw_send_async(this, msg, success_callback=None, exception_callback=None):
        topic = _message_topic(msg)
        namesrv = _get_namesrv(this)
        context = get_context()
        with context.new_exit_span(op=f'RocketMQ/{topic}/Producer', peer=namesrv,
                                   component=Component.RocketMQProducer) as span:
            span.layer = Layer.MQ
            _inject_carrier(msg, span.inject())
            snapshot = context.capture()
            _tag_message(span, msg, topic)
            user_success, user_exception = success_callback, exception_callback

            def on_success(result):
                def body(cb_span):
                    _tag_send_status(cb_span, result)
                    if user_success:
                        user_success(result)

                _async_callback_local_span(topic, snapshot, body)

            def on_exception(exc):
                def body(cb_span):
                    cb_span.error_occurred = True
                    cb_span.log(exc)
                    if user_exception:
                        user_exception(exc)

                _async_callback_local_span(topic, snapshot, body)

            try:
                if _orig_send_async is not None:
                    _orig_send_async(this, msg, on_success, on_exception)
                elif _send_message_async:
                    _send_async_via_ffi(this, msg, on_success, on_exception, send_result_cls, send_status_cls)
                else:
                    raise AttributeError('send_async is not supported by the linked librocketmq')
            except Exception as ex:
                span.log(ex)
                raise
            span.tag(TagMqBroker(_resolve_mq_broker(msg, namesrv)))

    producer_cls.__init__ = _sw_producer_init
    producer_cls.set_name_server_address = _sw_set_ns_producer
    producer_cls.set_name_server_domain = _sw_set_ns_domain_producer
    producer_cls.send_sync = _sw_send_sync
    producer_cls.send_oneway = _sw_send_oneway
    producer_cls.send_orderly_with_sharding_key = _sw_send_orderly
    if _orig_send_async is not None or _send_message_async:
        producer_cls.send_async = _sw_send_async


def _install_transaction_hooks():
    try:
        import rocketmq.client as rocketmq_client
    except ImportError:
        return

    txn_producer_cls = getattr(rocketmq_client, 'TransactionMQProducer', None)
    if txn_producer_cls is None or not hasattr(txn_producer_cls, 'send_message_in_transaction'):
        return

    # TransactionMQProducer redefines set_name_server_address; it does not use Producer's.
    _txn_init = txn_producer_cls.__init__
    _txn_set_ns = txn_producer_cls.set_name_server_address
    _txn_set_ns_domain = getattr(txn_producer_cls, 'set_name_server_domain', None)
    _send_in_transaction = txn_producer_cls.send_message_in_transaction

    def _sw_txn_init(self, *args, **kwargs):
        _txn_init(self, *args, **kwargs)
        if not getattr(self, '_sw_namesrv', None):
            self._sw_namesrv = _namesrv_from_env()

    def _sw_txn_set_ns(self, addr):
        self._sw_namesrv = addr
        return _txn_set_ns(self, addr)

    def _sw_send_message_in_transaction(this, msg, *args, **kwargs):
        return _trace_producer_send(this, msg, _send_in_transaction, *args, **kwargs)

    txn_producer_cls.__init__ = _sw_txn_init
    txn_producer_cls.set_name_server_address = _sw_txn_set_ns
    if _txn_set_ns_domain is not None:
        def _sw_txn_set_ns_domain(self, domain):
            self._sw_namesrv_domain = domain
            return _txn_set_ns_domain(self, domain)

        txn_producer_cls.set_name_server_domain = _sw_txn_set_ns_domain
    txn_producer_cls.send_message_in_transaction = _sw_send_message_in_transaction


def _install_consumer_hooks(push_consumer_cls, consume_status_cls):
    _consumer_init = push_consumer_cls.__init__
    _set_ns_consumer = push_consumer_cls.set_name_server_address
    _set_ns_domain_consumer = push_consumer_cls.set_name_server_domain
    _start_consumer = push_consumer_cls.start
    _subscribe = push_consumer_cls.subscribe

    def _sw_consumer_init(self, *args, **kwargs):
        _consumer_init(self, *args, **kwargs)
        if not getattr(self, '_sw_namesrv', None):
            self._sw_namesrv = _namesrv_from_env()

    def _sw_set_ns_consumer(self, addr):
        self._sw_namesrv = addr
        return _set_ns_consumer(self, addr)

    def _sw_set_ns_domain_consumer(self, domain):
        self._sw_namesrv_domain = domain
        return _set_ns_domain_consumer(self, domain)

    def _sw_consumer_start(self):
        if not getattr(self, '_sw_namesrv', None):
            env = _namesrv_from_env()
            if env:
                self._sw_namesrv = env
        return _start_consumer(self)

    def _sw_callback(callback, consumer):
        def wrapped(msg):
            namesrv = _get_namesrv(consumer)
            broker = _resolve_mq_broker(msg, namesrv)
            carrier = _extract_carrier(msg)
            context = get_context()
            with context.new_entry_span(op=f'RocketMQ/{msg.topic}/Consumer', carrier=carrier) as span:
                span.layer = Layer.MQ
                span.component = Component.RocketMQConsumer
                span.peer = namesrv
                span.tag(TagMqBroker(broker))
                span.tag(TagMqTopic(msg.topic))
                try:
                    status = callback(msg)
                except Exception as ex:
                    span.log(ex)
                    raise
                if status == consume_status_cls.RECONSUME_LATER:
                    span.error_occurred = True
                    span.tag(TagMqStatus(status.name))
                return status

        return wrapped

    def _sw_subscribe(this, topic, callback, expression='*'):
        return _subscribe(this, topic, _sw_callback(callback, this), expression)

    push_consumer_cls.__init__ = _sw_consumer_init
    push_consumer_cls.set_name_server_address = _sw_set_ns_consumer
    push_consumer_cls.set_name_server_domain = _sw_set_ns_domain_consumer
    push_consumer_cls.start = _sw_consumer_start
    push_consumer_cls.subscribe = _sw_subscribe


def install():
    from rocketmq.client import Producer, PushConsumer, Message, ConsumeStatus, SendStatus, SendResult, ReceivedMessage

    global _SendStatus, _ReceivedMessage
    _SendStatus = SendStatus
    _ReceivedMessage = ReceivedMessage

    _ensure_ffi_helpers()
    _install_message_hooks(Message)
    _install_producer_hooks(Producer, SendResult, SendStatus)
    _install_transaction_hooks()
    _install_consumer_hooks(PushConsumer, ConsumeStatus)
