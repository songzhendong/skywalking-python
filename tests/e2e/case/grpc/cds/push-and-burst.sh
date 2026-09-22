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

# 1) One /pid while bootstrap sample_n=0 (accept-all) → always reported.
# 2) etcd pushes agent.sample_n_per_3_secs=1 without restarting the agent.
# 3) Burst 10 /pid; with rate=1 only ~1 more trace is reported.
# Retries must not burst again or the sampled count keeps growing.
# etcd has no host port; write via docker exec.

set -euo pipefail

export ETCDCTL_API=3

etcd_cid() {
  local cid=""
  if [ -n "${GITHUB_RUN_ID:-}" ]; then
    cid="$(docker ps -q -f "name=${GITHUB_RUN_ID}_etcd" | head -n1)"
    if [ -z "${cid}" ]; then
      cid="$(docker ps -q -f "name=${GITHUB_RUN_ID}-etcd" | head -n1)"
    fi
  fi
  if [ -z "${cid}" ]; then
    cid="$(docker ps -q -f name=etcd | head -n1)"
  fi
  if [ -z "${cid}" ]; then
    echo "etcd container not found" >&2
    exit 1
  fi
  echo "${cid}"
}

if [ ! -f /tmp/skywalking-cds-burst-done ]; then
  curl -sf "http://${provider_host}:${provider_9090}/pid" >/dev/null

  docker exec "$(etcd_cid)" etcdctl put \
    /skywalking/configuration-discovery.default.agentConfigurations \
    "$(printf '%s\n' \
      'configurations:' \
      '  e2e-cds-provider:' \
      '    agent.sample_n_per_3_secs: "1"')"
  # OAP etcd period (5s) plus agent CDS poll (5s), with margin.
  sleep 35

  for _ in $(seq 1 10); do
    curl -sf "http://${provider_host}:${provider_9090}/pid" >/dev/null
  done
  touch /tmp/skywalking-cds-burst-done
fi

echo "ok: true"
