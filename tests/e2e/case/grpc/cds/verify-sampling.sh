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

# One accept-all /pid before CDS, plus ~1 sampled trace from the post-CDS
# burst of 10. A window boundary may add one more.

set -euo pipefail

count="$(
  swctl --display yaml --base-url="http://${oap_host}:${oap_12800}/graphql" trace ls \
    --service-name=e2e-cds-provider \
    | yq e '(.traces // .) | map(select(.endpointnames[]? == "/pid")) | length' -
)"

echo "cds /pid trace count=${count} (expect 2..4)" >&2

if [ "${count}" -lt 2 ] || [ "${count}" -gt 4 ]; then
  exit 1
fi

echo "count: ${count}"
