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

# Generate e2e TLS certs with distinct CA/server DNs (grpcio/BoringSSL compatible).
# Script lives at tests/e2e/script/prepare/ → repo root is ../../../..
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
SSL_DIR="$ROOT/tests/e2e/case/grpc/ssl"
MTLS_DIR="$ROOT/tests/e2e/case/grpc/mtls"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
cd "$WORKDIR"

# CA (distinct CN from leaf services)
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 36500 \
  -subj "/CN=skywalking-e2e-ca"

# Server leaf for core gRPC / sharing server (CN must match docker service name)
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj "/CN=oap"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 36500

# Client leaf for mTLS
openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr \
  -subj "/CN=python-agent"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 36500

# PKCS#8 private keys (BEGIN PRIVATE KEY) for OAP / agent
openssl pkcs8 -topk8 -nocrypt -in server.key -out server.pem
openssl pkcs8 -topk8 -nocrypt -in client.key -out client.pem
# ssl case historically uses server-key.pem name
cp server.pem server-key.pem

mkdir -p "$SSL_DIR/ca" "$SSL_DIR/certs" "$MTLS_DIR/client" "$MTLS_DIR/server"
cp ca.crt "$SSL_DIR/ca/ca.crt"
cp ca.crt server-key.pem server.crt "$SSL_DIR/certs/"
# keep ca.crt next to server material for OAP trusted CA path
cp ca.crt "$SSL_DIR/certs/ca.crt"

cp ca.crt client.crt client.pem "$MTLS_DIR/client/"
cp ca.crt server.crt server.pem "$MTLS_DIR/server/"

echo "Generated SSL certs under $SSL_DIR"
echo "Generated mTLS certs under $MTLS_DIR"
openssl x509 -in "$SSL_DIR/certs/server.crt" -noout -subject -issuer
openssl x509 -in "$SSL_DIR/ca/ca.crt" -noout -subject -issuer
