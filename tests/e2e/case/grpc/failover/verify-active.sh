#!/usr/bin/env bash

# ----------------------------------------------------------------------------
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
# ----------------------------------------------------------------------------

# Print the union of both OAPs' service lists (shuffle-safe). Provider and
# consumer shuffle independently, so both backends may already have data.

# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

count_a="$(oap_service_count "${oap_a_host}" "${oap_a_12800}")"
count_b="$(oap_service_count "${oap_b_host}" "${oap_b_12800}")"

if [ "${count_a}" = "0" ] && [ "${count_b}" = "0" ]; then
  echo "FATAL: neither OAP has services yet" >&2
  exit 1
fi

echo "pre-failover union: oap_a=${count_a} oap_b=${count_b}" >&2
oap_service_union_sorted \
  "${oap_a_host}" "${oap_a_12800}" \
  "${oap_b_host}" "${oap_b_12800}"
