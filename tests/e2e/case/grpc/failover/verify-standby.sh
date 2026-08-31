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

# Stop one OAP that currently has services (prefer oap_a), generate traffic,
# print the other OAP's sorted list. Provider/consumer may already be split
# across backends; stopping A still forces the A-side agent onto B.

# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

: "${consumer_host:?}"
: "${consumer_9090:?}"

if [ ! -f "${FAILOVER_STOPPED}" ]; then
  count_a="$(oap_service_count "${oap_a_host}" "${oap_a_12800}")"
  count_b="$(oap_service_count "${oap_b_host}" "${oap_b_12800}")"

  if [ "${count_a}" = "0" ] && [ "${count_b}" = "0" ]; then
    echo "FATAL: neither OAP has services; cannot choose a backend to stop" >&2
    exit 1
  fi

  if [ "${count_a}" != "0" ]; then
    active=oap_a
    standby_host="${oap_b_host}"
    standby_port="${oap_b_12800}"
  else
    active=oap_b
    standby_host="${oap_a_host}"
    standby_port="${oap_a_12800}"
  fi

  echo "stopping ${active} (oap_a=${count_a} oap_b=${count_b}); remaining=${standby_host}:${standby_port}" >&2
  stop_compose_service "${active}"
  printf '%s\n' "${active}" > "${FAILOVER_STOPPED}"
  printf '%s\n' "${standby_host}:${standby_port}" > "${FAILOVER_STANDBY}"
else
  echo "a backend already stopped by an earlier attempt; skipping stop" >&2
fi

sent=0
for _ in $(seq 1 5); do
  if curl -fsS -X POST \
    -H 'Content-Type: application/json' \
    -d '{"song": "Despacito"}' \
    "http://${consumer_host}:${consumer_9090}/artist-consumer" >/dev/null; then
    sent=$((sent + 1))
  fi
  sleep 1
done

if [ "${sent}" -eq 0 ]; then
  echo "FATAL: no post-failover request reached the consumer at" >&2
  echo "       http://${consumer_host}:${consumer_9090}/artist-consumer" >&2
  exit 1
fi
echo "generated ${sent}/5 post-failover requests" >&2

IFS=':' read -r standby_host standby_port < "${FAILOVER_STANDBY}"
oap_service_ls_sorted "${standby_host}" "${standby_port}"
