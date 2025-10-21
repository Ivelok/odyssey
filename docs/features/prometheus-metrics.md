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

## Route-level gauges

When `log_general_stats_prom` is enabled, Odyssey now emits additional gauges on the `/metrics` endpoint:

- `server_pool_active_route{user="<user>",database="<db>"}` — active backend connections for a specific route.
- `server_pool_idle_route{user="<user>",database="<db>"}` — idle backend connections kept warm for that route.
- `server_pool_capacity_route{user="<user>",database="<db>"}` — configured connection ceiling (`pool_size`); falls back to the current pool size when the setting is unset.

The legacy aggregate gauges `server_pool_active` and `server_pool_idle` remain available without labels for backwards compatibility. To monitor pool saturation you can query, for example:

```
server_pool_active_route / server_pool_capacity_route
```

Values close to `1` indicate that a route is exhausting its configured server pool.

## Legacy built in support

Not supported anymore. See example of usage in [docker/prometheus-legacy/](https://github.com/yandex/odyssey/tree/master/docker/prometheus-legacy/)
