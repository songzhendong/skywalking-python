#!/bin/sh

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

# Single source of truth for e2e TLS material (SAN + EKU, distinct CA/leaf DNs).
#
# Usage:
#   gen-e2e-tls-certs.sh            # local: write under tests/e2e/case/grpc/{ssl,mtls}
#   gen-e2e-tls-certs.sh all        # same as above
#   gen-e2e-tls-certs.sh ssl        # compose: write to /out/certs and /out/ca
#   gen-e2e-tls-certs.sh mtls       # compose: write to /out/server and /out/client
#
# Compose mounts this script into alpine/openssl (digest-pinned; openssl preinstalled —
# no apk). PEMs are not committed.
#
# Requires: openssl, POSIX sh (works on alpine/openssl and host Git Bash / Linux).

set -eu

MODE=${1:-all}

# Resolve repo paths before cd into WORKDIR. With a relative $0, doing this after
# cd would fold ``tests/.../../../../..`` against the temp dir and silently
# install under WORKDIR (then the EXIT trap deletes it).
# Script lives at tests/e2e/script/prepare/ → repo root is ../../../..
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/../../../.." && pwd)"
SSL_DIR="$ROOT/tests/e2e/case/grpc/ssl"
MTLS_DIR="$ROOT/tests/e2e/case/grpc/mtls"

WORKDIR="${TMPDIR:-/tmp}/skywalking-e2e-tls-$$"
mkdir -p "$WORKDIR"
# shellcheck disable=SC2064
trap 'rm -rf "$WORKDIR"' EXIT
cd "$WORKDIR"

# CA (distinct CN from leaf services)
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 36500 \
  -subj "/CN=skywalking-e2e-ca"

# Server leaf (CN/SAN must match docker service name ``oap``)
printf '%s\n' \
  'subjectAltName=DNS:oap,DNS:localhost,IP:127.0.0.1' \
  'extendedKeyUsage=serverAuth' \
  'basicConstraints=CA:FALSE' \
  'keyUsage=digitalSignature,keyEncipherment' > server.ext
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=oap"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 36500 -extfile server.ext
openssl pkcs8 -topk8 -nocrypt -in server.key -out server.pem
cp server.pem server-key.pem

# Client leaf for mTLS
printf '%s\n' \
  'subjectAltName=DNS:python-agent' \
  'extendedKeyUsage=clientAuth' \
  'basicConstraints=CA:FALSE' \
  'keyUsage=digitalSignature,keyEncipherment' > client.ext
openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=python-agent"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 36500 -extfile client.ext
openssl pkcs8 -topk8 -nocrypt -in client.key -out client.pem

install_ssl_layout() {
  certs_dir=$1
  ca_dir=$2
  mkdir -p "$certs_dir" "$ca_dir"
  cp ca.crt "$ca_dir/ca.crt"
  cp ca.crt server-key.pem server.crt "$certs_dir/"
  cp ca.crt "$certs_dir/ca.crt"
}

install_mtls_layout() {
  server_dir=$1
  client_dir=$2
  mkdir -p "$server_dir" "$client_dir"
  cp ca.crt server.crt server.pem "$server_dir/"
  cp ca.crt client.crt client.pem "$client_dir/"
}

case "$MODE" in
  ssl)
    install_ssl_layout /out/certs /out/ca
    echo "Generated SSL certs under /out/{certs,ca}"
    ;;
  mtls)
    install_mtls_layout /out/server /out/client
    echo "Generated mTLS certs under /out/{server,client}"
    ;;
  all)
    install_ssl_layout "$SSL_DIR/certs" "$SSL_DIR/ca"
    install_mtls_layout "$MTLS_DIR/server" "$MTLS_DIR/client"
    echo "Generated SSL certs under $SSL_DIR"
    echo "Generated mTLS certs under $MTLS_DIR"
    openssl x509 -in "$SSL_DIR/certs/server.crt" -noout -subject -issuer
    openssl x509 -in "$MTLS_DIR/client/client.crt" -noout -subject -issuer
    openssl x509 -in "$SSL_DIR/ca/ca.crt" -noout -subject -issuer
    ;;
  *)
    echo "usage: $0 [all|ssl|mtls]" >&2
    exit 2
    ;;
esac
