# Legacy Setup

You can always fall back to our traditional way of integration as introduced below, 
which is by importing SkyWalking into your project and starting the agent.

## Defaults
By default, SkyWalking Python agent uses gRPC protocol to report data to SkyWalking backend,
in SkyWalking backend, the port of gRPC protocol is `11800`, and the port of HTTP protocol is `12800`,

See all default configuration values in the [Configuration Vocabulary](Configuration.md)

You could configure `agent_collector_backend_services` (or environment variable `SW_AGENT_COLLECTOR_BACKEND_SERVICES`)
and set `agent_protocol` (or environment variable `SW_AGENT_PROTOCOL` to one of
`gprc`, `http` or `kafka` according to the protocol you would like to use.

### Report data via gRPC protocol (Default)

For example, if you want to use gRPC protocol to report data, configure `agent_collector_backend_services`
(or environment variable `SW_AGENT_COLLECTOR_BACKEND_SERVICES`) to `<oap-ip-or-host>:11800`,
such as `127.0.0.1:11800`:

```python
from skywalking import agent, config

config.init(agent_collector_backend_services='127.0.0.1:11800', agent_name='your awesome service', agent_instance_name='your-instance-name or <generated uuid>')

agent.start()
```

#### gRPC multi-address (failover)

Pass a comma-separated list. The agent opens **one** gRPC channel and lets C-core `pick_first` fail over (same idea as Node `sw-static`). Each process shuffles the preferred backend at channel build; `:authority` / TLS SNI still use the **first configured** endpoint.

```python
config.init(
    agent_collector_backend_services='oap-a:11800,oap-b:11800',
    agent_name='your awesome service',
)
agent.start()
```

Implementation notes (maintainers / operators):

- Mixed IPv4/IPv6 stays in one list; IPv4 is encoded as IPv4-mapped IPv6 for grpcio so `pick_first` can try both families.
- Multi-hostname lists are DNS-expanded once at channel build (about 5s lookup budget per name); there is no periodic re-resolve — prefer a single address or stable IPs when DNS changes.
- Channel `:authority` / TLS SAN uses `grpc.default_authority` = the first configured endpoint (before shuffle). With TLS (`agent_force_tls` or a CA file), every backend cert must cover that authority.

#### gRPC / HTTP TLS and mTLS

Aligned with Java `TLSChannelBuilder`:

- `agent_force_tls=true` → TLS with the process trust store (no client cert).
- If `agent_ssl_trusted_ca_path` is a readable PEM file → TLS using that CA, even when `agent_force_tls` is false.
- mTLS is on only when the CA file exists **and** both `agent_ssl_cert_chain_path` and `agent_ssl_key_path` are readable PEMs. Missing cert/key logs a warning and stays one-way TLS (Java parity; does not abort start).
- Paths are absolute or relative to the process working directory. PKCS#1 (`BEGIN RSA PRIVATE KEY`) is converted to PKCS#8 like Java `PrivateKeyUtil`; passphrase-encrypted private keys are not supported.
- E2E coverage (real OAP, same idea as Java `simple/ssl` and `simple/mtls`): `tests/e2e/case/grpc/ssl/` and `tests/e2e/case/grpc/mtls/`.

```python
config.init(
    agent_collector_backend_services='oap.example:11800',
    agent_force_tls=True,
    agent_ssl_trusted_ca_path='/etc/skywalking/ca.crt',
    agent_ssl_cert_chain_path='/etc/skywalking/client.crt',
    agent_ssl_key_path='/etc/skywalking/client.pem',
)
```
- Reporters wait until the channel is READY; non-READY skips the RPC rather than failing fast into a black hole.
- After a silent backend switch that stays READY, instance properties are re-reported on the normal properties period so the new OAP learns the instance.
- Reconnect backoff caps at 30s.

#### gRPC HTTP proxy (behavior change)

`grpc.enable_http_proxy=0` is set on **every** gRPC channel, including a single-address config. Host `http_proxy` / `https_proxy` / `no_proxy` are ignored for OAP traffic.

If you currently reach OAP only through an HTTP CONNECT proxy, upgrading this agent will lose that path. The agent disables the proxy so application proxy env vars cannot silently black-hole telemetry, and because HTTP CONNECT happens before name resolution — it cannot express a comma-separated backend list.

#### Best-effort reporting and buffers

Send failures are discarded and never retried (a failed batch is dropped). On process shutdown the agent flushes only while the channel is READY, with a short time budget, then **abandons** whatever is still queued.

When a reporter queue is full (`SW_AGENT_TRACE_REPORTER_MAX_BUFFER_SIZE` / log / meter / snapshot equivalents), new items are dropped. The agent logs drops at most once per 30 seconds, with the increment since the last line and the process total. Raise the buffer if you routinely see these under load; a full queue during an outage is expected because the READY gate holds data until the backend returns.

### Report data via HTTP protocol

However, if you want to use HTTP protocol to report data, configure `agent_collector_backend_services`
(or environment variable `SW_AGENT_COLLECTOR_BACKEND_SERVICES`) to `<oap-ip-or-host>:12800`,
such as `127.0.0.1:12800`, further set `agent_protocol` (or environment variable `SW_AGENT_PROTOCOL` to `http`):

> Remember you should install `skywalking-python` with extra requires `http`, `pip install "apache-skywalking[http]`.

```python
from skywalking import agent, config

config.init(agent_collector_backend_services='127.0.0.1:12800', agent_name='your awesome service', agent_protocol='http', agent_instance_name='your-instance-name or <generated uuid>')

agent.start()
```

### Report data via Kafka protocol
**Please make sure OAP is consuming the same Kafka topic as your agent produces to, `kafka_namespace` must match OAP side configuration `plugin.kafka.namespace`**

Finally, if you want to use Kafka protocol to report data, configure `kafka_bootstrap_servers`
(or environment variable `SW_KAFKA_BOOTSTRAP_SERVERS`) to `kafka-brokers`,
such as `127.0.0.1:9200`, further set `agent_protocol` (or environment variable `SW_AGENT_PROTOCOL` to `kafka`):

> Remember you should install `skywalking-python` with extra requires `kafka`, `pip install "apache-skywalking[kafka]"`.

```python
from skywalking import agent, config

config.init(kafka_bootstrap_servers='127.0.0.1:9200', agent_name='your awesome service', agent_protocol='kafka', agent_instance_name='your-instance-name or <generated uuid>')

agent.start()
```

Alternatively, you can also pass the configurations via environment variables (such as `SW_AGENT_NAME`, `SW_AGENT_COLLECTOR_BACKEND_SERVICES`, etc.) so that you don't need to call `config.init`.

All supported environment variables can be found in the [Environment Variables List](Configuration.md).
