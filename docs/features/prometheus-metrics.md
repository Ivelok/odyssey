# Prometheus metrics

This section describes a ways to export Odyssey metrics in Prometheus format.

----

## Exporter

There is metrics exporter in [prometheus/exporter](https://github.com/yandex/odyssey/blob/master/prometheus/exporter/).
This is an http server, that connects to Odyssey console and expose it metrics
in Prometheus format on `/metrics` endpoint on specified address.

To use it, you will need build and run:
```plain
> go mod download && go build -o odyssey-prom-exporter

> ./odyssey-prom-exporter -h
usage: odyssey-prom-exporter [<flags>]


Flags:
  -h, --[no-]help                Show context-sensitive help (also try --help-long and --help-man).
      --odyssey.connectionString="host=localhost port=6432 user=console dbname=console sslmode=disable"  
                                 Connection string for accessing Odyssey.
      --[no-]web.systemd-socket  Use systemd socket activation listeners instead of port listeners (Linux only).
      --web.listen-address=:9876 ...  
                                 Addresses on which to expose metrics and web interface. Repeatable for multiple addresses. Examples: `:9100` or `[::1]:9100` for http,
                                 `vsock://:9100` for vsock
      --web.config.file=""       Path to configuration file that can enable TLS or authentication. See:
                                 https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md
      --[no-]version             Show application version.
```

Currently in developing stage, so if you have any troubles
with this exporter, please, [contact us](../about/contributing.md).

## Route-level metrics

The Go-based exporter scrapes `SHOW POOLS_EXTENDED;` and `SHOW DATABASES;` and now emits **only label-based metrics** (legacy `odyssey_pool_<db>_<user>_*` names have been removed). Each route sample is keyed by the `user` and `database` labels:

| Metric | Labels | Type | Description |
| --- | --- | --- | --- |
| `odyssey_client_pool_active_route` | `user`, `database` | Gauge | Clients currently using the route. |
| `odyssey_client_pool_waiting_route` | `user`, `database` | Gauge | Clients blocked waiting for a server connection. |
| `odyssey_client_pool_maxwait_seconds_route` | `user`, `database` | Gauge | Maximum observed wait in seconds. |
| `odyssey_client_pool_maxwait_microseconds_route` | `user`, `database` | Gauge | Same measurement with microsecond precision. |
| `odyssey_route_pool_mode_info` | `user`, `database`, `mode` | Gauge | `1` for the active pool mode (`session`, `transaction`, `statement`). |
| `odyssey_route_bytes_received_total` | `user`, `database` | Counter | Bytes received from clients on the route. |
| `odyssey_route_bytes_sent_total` | `user`, `database` | Counter | Bytes sent to PostgreSQL backends. |
| `odyssey_route_tcp_connections_total` | `user`, `database` | Counter | TCP connections opened toward the backend. |
| `odyssey_route_query_duration_seconds` | `user`, `database`, `quantile` | Gauge | Query latency quantiles (available when the `quantiles` rule option is set). |
| `odyssey_route_transaction_duration_seconds` | `user`, `database`, `quantile` | Gauge | Transaction latency quantiles. |
| `odyssey_server_pool_active_route` | `user`, `database` | Gauge | Active backend connections for the route. |
| `odyssey_server_pool_idle_route` | `user`, `database` | Gauge | Idle backend connections kept hot. |
| `odyssey_server_pool_used_route` | `user`, `database` | Gauge | Connections recently used and waiting for reuse. |
| `odyssey_server_pool_tested_route` | `user`, `database` | Gauge | Connections undergoing health checks. |
| `odyssey_server_pool_login_route` | `user`, `database` | Gauge | Connections currently authenticating. |
| `odyssey_server_pool_capacity_route` | `user`, `database` | Gauge | Configured `pool_size` (fallback to `sv_active + sv_idle` when unlimited). |

Saturation can still be tracked by comparing gauges, for example:

```
odyssey_server_pool_active_route / odyssey_server_pool_capacity_route
```

Values close to `1` indicate the route is exhausting its server quota. Quantile metrics expose the instantaneous TDigest estimate, so alerting thresholds should be treated like gauges (e.g., `odyssey_route_query_duration_seconds{quantile="0.95"} > 0.5`).

## Error counters

`SHOW ERRORS;` is exported as a single counter family: `odyssey_errors_total{type="OD_ECLIENT_READ"}`. Every error type reported by Odyssey becomes a label value, so new error codes do not require exporter changes.

## Legacy built in support

Not supported anymore. See example of usage in [docker/prometheus-legacy/](https://github.com/yandex/odyssey/tree/master/docker/prometheus-legacy/)
