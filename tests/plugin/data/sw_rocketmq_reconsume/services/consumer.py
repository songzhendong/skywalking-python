
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

if __name__ == '__main__':
    import time

    from rocketmq.client import PushConsumer, ConsumeStatus

    TOPIC = 'TopicReconsume'
    NAMESRV = 'namesrv:9876'
    READY_FILE = '/tmp/consumer_ready'
    _RETRY_MSG_IDS = set()

    def callback(msg):
        print(msg.id, msg.body)
        if msg.id not in _RETRY_MSG_IDS:
            _RETRY_MSG_IDS.add(msg.id)
            return ConsumeStatus.RECONSUME_LATER
        with open(READY_FILE, 'w', encoding='utf-8') as f:
            f.write('ok')
        return ConsumeStatus.CONSUME_SUCCESS

    consumer = PushConsumer('CID-reconsume')
    consumer.set_name_server_address(NAMESRV)
    consumer.subscribe(TOPIC, callback)
    consumer.start()
    time.sleep(8)
    with open(READY_FILE, 'w', encoding='utf-8') as f:
        f.write('ok')

    while True:
        time.sleep(3600)
