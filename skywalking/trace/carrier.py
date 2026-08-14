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

from typing import List

from skywalking import config
from skywalking.utils.lang import b64encode, b64decode


class CarrierItem(object):
    def __init__(self, key: str = '', val: str = ''):
        self.key = key  # type: str
        self.val = val  # type: str

    @property
    def key(self):
        return self.__key

    @key.setter
    def key(self, key: str):
        self.__key = key

    @property
    def val(self):
        return self.__val

    @val.setter
    def val(self, val: str):
        self.__val = val


class Carrier(CarrierItem):
    def __init__(self, trace_id: str = '', segment_id: str = '', span_id: str = '', service: str = '',
                 service_instance: str = '', endpoint: str = '', client_address: str = '',
                 correlation: dict = None):  # pyre-ignore
        super(Carrier, self).__init__(key='sw8')
        self.__val = None
        self.trace_id = trace_id  # type: str
        self.segment_id = segment_id  # type: str
        self.span_id = span_id  # type: str
        self.service = service  # type: str
        self.service_instance = service_instance  # type: str
        self.endpoint = endpoint  # type: str
        self.client_address = client_address  # type: str
        self.extension_context = ExtensionContext()
        self.correlation_carrier = SW8CorrelationCarrier()
        self.extension_carrier = SW8ExtensionCarrier(self.extension_context)
        self.items = [self.correlation_carrier, self.extension_carrier, self]  # type: List[CarrierItem]
        self.omit_empty_items = False  # type: bool
        self.__iter_index = 0  # type: int
        if correlation is not None:
            self.correlation_carrier.correlation = correlation

    @property
    def val(self) -> str:
        return '-'.join([
            '1',
            b64encode(self.trace_id),
            b64encode(self.segment_id),
            self.span_id,
            b64encode(self.service),
            b64encode(self.service_instance),
            b64encode(self.endpoint),
            b64encode(self.client_address),
        ])

    @val.setter
    def val(self, val: str):
        self.__val = val
        if not val:
            return
        parts = val.split('-')
        if len(parts) != 8:
            return
        self.trace_id = b64decode(parts[1])
        self.segment_id = b64decode(parts[2])
        self.span_id = parts[3]
        self.service = b64decode(parts[4])
        self.service_instance = b64decode(parts[5])
        self.endpoint = b64decode(parts[6])
        self.client_address = b64decode(parts[7])

    @property
    def is_valid(self):
        # type: () -> bool
        return len(self.trace_id) > 0 and \
               len(self.segment_id) > 0 and \
               len(self.service) > 0 and \
               len(self.service_instance) > 0 and \
               len(self.endpoint) > 0 and \
               len(self.client_address) > 0 and \
               self.span_id.isnumeric()

    @property
    def is_suppressed(self):  # if is invalid from previous set, ignored or suppressed status propagation downstream
        return self.__val and not self.is_valid

    def __iter__(self):
        self.__iter_index = 0
        return self

    def __next__(self):
        while self.__iter_index < len(self.items):
            n = self.items[self.__iter_index]
            self.__iter_index += 1
            if self.omit_empty_items and not n.val:
                continue
            return n
        raise StopIteration


class SW8CorrelationCarrier(CarrierItem):
    def __init__(self):
        super(SW8CorrelationCarrier, self).__init__(key='sw8-correlation')
        self.correlation = {}  # type: dict

    @property
    def val(self) -> str:
        if self.correlation is None or len(self.correlation) == 0:
            return ''

        return ','.join([
            f'{b64encode(k)}:{b64encode(v)}'
            for k, v in self.correlation.items()
        ])

    @val.setter
    def val(self, val: str):
        self.__val = val
        if not val:
            return
        for per in val.split(','):
            if len(self.correlation) > config.correlation_element_max_number:
                break
            parts = per.split(':')
            if len(parts) != 2:
                continue
            self.correlation[b64decode(parts[0])] = b64decode(parts[1])


class ExtensionContext:
    """Optional SW8 extension fields (sw8-x), aligned with Java ExtensionContext."""

    def __init__(self):
        self.skip_analysis = False
        self.sending_timestamp = None  # type: int | None

    def serialize(self) -> str:
        prefix = '1' if self.skip_analysis else '0'
        ts = self.sending_timestamp if self.sending_timestamp is not None else ' '
        return f'{prefix}-{ts}'

    def deserialize(self, value: str) -> None:
        if not value:
            return
        parts = value.split('-', 1)
        if parts:
            self.skip_analysis = parts[0] == '1'
        if len(parts) > 1 and parts[1].strip():
            try:
                self.sending_timestamp = int(parts[1].strip())
            except ValueError:
                pass

    def inject_sending_timestamp(self) -> None:
        from skywalking.utils.time import current_milli_time
        self.sending_timestamp = current_milli_time()

    def handle(self, span) -> None:
        if self.sending_timestamp is not None:
            from skywalking.utils.time import current_milli_time
            from skywalking.trace.tags import TagTransmissionLatency
            latency = current_milli_time() - self.sending_timestamp
            span.tag(TagTransmissionLatency(str(latency)))


class SW8ExtensionCarrier(CarrierItem):
    def __init__(self, extension_context: ExtensionContext):
        self.extension_context = extension_context
        CarrierItem.__init__(self, key='sw8-x', val='')

    @property
    def val(self) -> str:
        ctx = self.extension_context
        if ctx.sending_timestamp is None and not ctx.skip_analysis:
            return ''
        if ctx.sending_timestamp is None:
            return ''
        return ctx.serialize()

    @val.setter
    def val(self, value: str) -> None:
        CarrierItem.val.fset(self, value)
        if value:
            self.extension_context.deserialize(value)
