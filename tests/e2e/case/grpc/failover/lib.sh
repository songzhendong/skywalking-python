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

# Shared helpers for gRPC failover E2E (sourced). stdout of callers must stay YAML.

set -euo pipefail

: "${oap_a_host:?}"
: "${oap_a_12800:?}"
: "${oap_b_host:?}"
: "${oap_b_12800:?}"

_FAILOVER_STICKY_DIR="${TMPDIR:-/tmp}/sw-python-e2e-failover"
mkdir -p "${_FAILOVER_STICKY_DIR}"
_FAILOVER_KEY="${oap_a_host}_${oap_a_12800}_${oap_b_host}_${oap_b_12800}"
FAILOVER_STOPPED="${_FAILOVER_STICKY_DIR}/${_FAILOVER_KEY}.stopped"
FAILOVER_STANDBY="${_FAILOVER_STICKY_DIR}/${_FAILOVER_KEY}.standby"

oap_service_count() {
  local host="$1" port="$2" yaml count
  if ! yaml="$(swctl --display yaml --base-url="http://${host}:${port}/graphql" service ls)"; then
    echo "FATAL: could not read service list from ${host}:${port}" >&2
    return 1
  fi
  case "${yaml}" in
    ''|'[]'|'null')
      echo 0
      return 0
      ;;
  esac
  if ! count="$(printf '%s\n' "${yaml}" | yq e 'length' -)"; then
    echo "FATAL: could not parse service list from ${host}:${port}" >&2
    return 1
  fi
  case "${count}" in
    ''|'null')
      echo 0
      return 0
      ;;
    *[!0-9]*)
      echo "FATAL: could not read service list from ${host}:${port} (got ${count})" >&2
      return 1
      ;;
  esac
  echo "${count}"
}

oap_service_ls_yaml() {
  local host="$1" port="$2" yaml
  if ! yaml="$(swctl --display yaml --base-url="http://${host}:${port}/graphql" service ls)"; then
    echo "FATAL: could not read service list from ${host}:${port}" >&2
    return 1
  fi
  case "${yaml}" in
    ''|'[]'|'null')
      echo '[]'
      ;;
    *)
      printf '%s\n' "${yaml}"
      ;;
  esac
}

oap_service_ls_sorted() {
  local host="$1" port="$2"
  oap_service_ls_yaml "${host}" "${port}" | yq e 'sort_by(.name)' -
}

# Union of two service-list YAML documents, unique by name, sorted.
oap_service_union_sorted() {
  local ya yb
  ya="$(oap_service_ls_yaml "$1" "$2")" || return 1
  yb="$(oap_service_ls_yaml "$3" "$4")" || return 1
  yq ea 'select(fileIndex == 0) + select(fileIndex == 1) | unique_by(.name) | sort_by(.name)' \
    <(printf '%s\n' "${ya}") <(printf '%s\n' "${yb}")
}

compose_project_from_oap_b() {
  local project="${COMPOSE_PROJECT_NAME:-}" cid name
  if [ -n "${project}" ]; then
    echo "${project}"
    return 0
  fi
  while read -r cid; do
    [ -z "${cid}" ] && continue
    if docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}{{range $p, $c := .NetworkSettings.Ports}}{{range $c}}{{.HostIp}} {{end}}{{end}}' "${cid}" 2>/dev/null \
      | tr ' ' '\n' | grep -qx "${oap_b_host}"; then
      docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "${cid}"
      return 0
    fi
    name="$(docker inspect -f '{{.Name}}' "${cid}" | sed 's#^/##')"
    if [ "${name}" = "${oap_b_host}" ] || echo "${name}" | grep -q "${oap_b_host}"; then
      docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "${cid}"
      return 0
    fi
  done < <(docker ps -q --filter 'label=com.docker.compose.service=oap_b' || true)
  docker ps \
    --filter 'label=com.docker.compose.service=oap_b' \
    --format '{{.Label "com.docker.compose.project"}}' \
    | head -n1 || true
}

stop_compose_service() {
  local service="$1" project filters running any
  project="$(compose_project_from_oap_b)"
  filters="--filter label=com.docker.compose.service=${service}"
  if [ -n "${project}" ]; then
    filters="${filters} --filter label=com.docker.compose.project=${project}"
  fi
  # shellcheck disable=SC2086
  running="$(docker ps -q ${filters} | head -n1 || true)"
  # shellcheck disable=SC2086
  any="$(docker ps -aq ${filters} | head -n1 || true)"
  if [ -z "${any}" ]; then
    echo "FATAL: no ${service} container found (project=${project:-unknown})" >&2
    docker ps -a --format '{{.Names}} {{.Label "com.docker.compose.project"}}/{{.Label "com.docker.compose.service"}} {{.State}}' >&2 || true
    exit 1
  fi
  if [ -n "${running}" ]; then
    echo "stopping ${service} ${running} (project=${project:-unknown})" >&2
    docker stop "${running}" >/dev/null
  else
    echo "${service} already stopped by an earlier attempt" >&2
  fi
}
