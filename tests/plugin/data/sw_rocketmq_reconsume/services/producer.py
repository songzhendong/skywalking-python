
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
    from flask import Flask, jsonify
    from rocketmq.client import Producer, Message

    TOPIC = 'TopicReconsume'
    NAMESRV = 'namesrv:9876'

    app = Flask(__name__)
    producer = Producer('PID-reconsume')
    producer.set_name_server_address(NAMESRV)
    producer.start()

    @app.route('/users', methods=['POST', 'GET'])
    def application():
        msg = Message(TOPIC)
        msg.set_body('reconsume-later')
        producer.send_sync(msg)
        return jsonify({'status': 'ok'})

    PORT = 9090
    app.run(host='0.0.0.0', port=PORT, debug=False)
