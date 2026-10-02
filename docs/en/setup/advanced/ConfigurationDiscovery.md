# Configuration Discovery Service (CDS)

CDS lets the OAP push agent configuration at runtime over gRPC, without restarting the process.
The Python agent supports the same dynamic keys as the Java agent CDS watchers.

**gRPC only.** HTTP and Kafka protocols keep the bootstrap value and do not poll CDS.

## Agent side

| Setting | Environment variable | Default | Meaning |
| --- | --- | --- | --- |
| `sample_n_per_3_secs` | `SW_SAMPLE_N_PER_3_SECS` | `0` | Bootstrap rate. `0` or negative: accept every trace. `> 0`: keep at most N new traces every 3 seconds. |
| `agent_collector_get_agent_dynamic_config_interval` | `SW_AGENT_COLLECTOR_GET_AGENT_DYNAMIC_CONFIG_INTERVAL` | `20` | Seconds between `fetchConfigurations` polls. |

The Python agent applies these dynamic keys (same names as the Java agent):

| Key | Effect |
| --- | --- |
| `agent.sample_n_per_3_secs` | Sampling rate. `0` or negative accepts every trace. |
| `agent.ignore_suffix` | Comma-separated operation suffixes to ignore. |
| `agent.trace.ignore_path` | Comma-separated Ant-style paths to ignore. |
| `agent.span_limit_per_segment` | Max spans in one segment. `<= 0` disables the cap. |
| `plugin.jdbc.trace_sql_parameters` | `true` / `false`. Python stores this as `plugin_sql_parameters_max_length` (`0` = off). `true` keeps a positive bootstrap length, or `512` when bootstrap is off. |

Deleting a key (or omitting it on a later sync) restores that key's bootstrap value.

If the OAP does not implement CDS, the agent logs one warning and keeps polling so CDS can recover if the method appears later.

## OAP side

No OAP code change is required. CDS is a generic channel: the OAP stores a map of strings per service name and returns it on `fetchConfigurations`.

1. Enable [dynamic configuration](https://skywalking.apache.org/docs/main/next/en/setup/backend/dynamic-config/) on the OAP (`SW_CONFIGURATION` is not `none`).
2. Set the single config key `configuration-discovery.default.agentConfigurations`.
3. Use the same service name as `SW_AGENT_NAME`.

Example (dynamic configuration value, YAML):

```yaml
configurations:
  your-python-service:
    agent.sample_n_per_3_secs: "10"
    agent.ignore_suffix: ".jpg,.css"
    agent.trace.ignore_path: "/health/**"
    agent.span_limit_per_segment: "300"
    plugin.jdbc.trace_sql_parameters: "false"
```

`"0"` or a negative number turns sampling off (accept all). Remove the key to fall back to the agent bootstrap value.

See also the [Java agent CDS format](https://skywalking.apache.org/docs/skywalking-java/next/en/setup/service-agent/java-agent/configuration-discovery/).

Python e2e covers this with a real OAP: `tests/e2e/case/grpc/cds`. It runs as its own CI job next to the main e2e matrix, on Python 3.12 only, so it does not add time to the other cases.
