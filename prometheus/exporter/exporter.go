// highly inspired by https://github.com/prometheus-community/pgbouncer_exporter/

package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	"github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus"
	versioncollector "github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promslog"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	"github.com/prometheus/exporter-toolkit/web/kingpinflag"
)

const (
	namespace                 = "odyssey"
	metricsHandlePath         = "/metrics"
	showVersionCommand        = "show version;"
	showListsCommand          = "show lists;"
	showIsPausedCommand       = "show is_paused;"
	showErrorsCommand         = "show errors;"
	showStatsCommand          = "show stats;"
	showDatabasesCommand      = "show databases;"
	showPoolsExtendedCommand  = "show pools_extended;"
	poolModeColumnName        = "pool_mode"
	queryQuantilePrefix       = "query_"
	transactionQuantilePrefix = "transaction_"
)

var (
	versionDescription = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "version", "info"),
		"The Odyssey version info",
		[]string{"version"}, nil,
	)

	exporterUpDescription = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "exporter", "up"),
		"The Odyssey exporter status",
		nil, nil,
	)

	isPausedDescription = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "is_paused"),
		"The Odyssey paused status",
		nil, nil,
	)

	avgTxCountDescription = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "database", "avg_tx_per_second"),
		"Average number of transactions per second reported by Odyssey cron",
		[]string{"database"}, nil,
	)

	avgQueryCountDescription = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "database", "avg_query_per_second"),
		"Average number of queries per second reported by Odyssey cron",
		[]string{"database"}, nil,
	)

	clientPoolActiveRouteDescription = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "client_pool", "active_route"),
		"Active clients currently using the route",
		[]string{"user", "database"}, nil,
	)

	clientPoolWaitingRouteDescription = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "client_pool", "waiting_route"),
		"Clients waiting for a server connection on the route",
		[]string{"user", "database"}, nil,
	)

	    serverPoolCapacityConfiguredRouteDescription = prometheus.NewDesc(
	        prometheus.BuildFQName(namespace, "server_pool", "capacity_configured_route"),
	        "Configured server pool capacity for a specific route (0 means unlimited)",
	        []string{"user", "database"}, nil,
	    )




	clientPoolMaxwaitSecondsRouteDescription = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "client_pool", "maxwait_seconds_route"),
		"Maximum observed wait time for clients on the route (seconds)",
		[]string{"user", "database"}, nil,
	)

    // Deprecated: we no longer export microseconds variant

    routePoolModeInfoDescription = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "route", "pool_mode_info"),
		"Pool mode information for the route",
		[]string{"user", "database", "mode"}, nil,
	)

	routeBytesReceivedTotalDescription = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "route", "bytes_received_total"),
		"Total bytes received from clients on the route",
		[]string{"user", "database"}, nil,
	)

	routeBytesSentTotalDescription = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "route", "bytes_sent_total"),
		"Total bytes sent to servers from the route",
		[]string{"user", "database"}, nil,
	)

	routeTCPConnectionsTotalDescription = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "route", "tcp_connections_total"),
		"Total TCP connections established for the route",
		[]string{"user", "database"}, nil,
	)

	routeQueryDurationSecondsDescription = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "route", "query_duration_seconds"),
		"Route query duration quantiles",
		[]string{"user", "database", "quantile"}, nil,
	)

	routeTransactionDurationSecondsDescription = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "route", "transaction_duration_seconds"),
		"Route transaction duration quantiles",
		[]string{"user", "database", "quantile"}, nil,
	)

	errorsTotalDescription = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "errors", "total"),
		"Total number of Odyssey errors grouped by type",
		[]string{"type"}, nil,
	)

	listMetricNameToDescription = map[string]*(prometheus.Desc){
		"databases": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "lists", "databases"),
			"Count of databases", nil, nil),
		"users": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "lists", "users"),
			"Count of users", nil, nil),
		"pools": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "lists", "pools"),
			"Count of pools", nil, nil),
		"free_clients": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "lists", "free_clients"),
			"Count of free clients", nil, nil),
		"used_clients": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "lists", "used_clients"),
			"Count of used clients", nil, nil),
		"login_clients": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "lists", "login_clients"),
			"Count of clients in login state", nil, nil),
		"free_servers": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "lists", "free_servers"),
			"Count of free servers", nil, nil),
		"used_servers": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "lists", "used_servers"),
			"Count of used servers", nil, nil),
		"dns_names": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "lists", "cached_dns_names"),
			"Count of DNS names in the cache", nil, nil),
		"dns_zones": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "lists", "cached_dns_zones"),
			"Count of DNS zones in the cache", nil, nil),
		"dns_queries": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "lists", "in_flight_dns_queries"),
			"Count of in-flight DNS queries", nil, nil),
	}
)

func writePoolModeInfoMetric(ch chan<- prometheus.Metric, database, user, mode string) {
	ch <- prometheus.MustNewConstMetric(
		routePoolModeInfoDescription,
		prometheus.GaugeValue,
		1.0,
		user, database, mode,
	)
}

func extractFloat(val interface{}, columnName string) (float64, bool, error) {
	switch v := val.(type) {
	case nil:
		return 0, false, nil
	case int64:
		return float64(v), true, nil
	case float64:
		return v, true, nil
	case []uint8:
		parsed, err := strconv.ParseFloat(string(v), 64)
		if err != nil {
			return 0, false, fmt.Errorf("can't parse column %q value %q: %w", columnName, string(v), err)
		}
		return parsed, true, nil
	default:
		return 0, false, fmt.Errorf("got unexpected column %q type %T", columnName, val)
	}
}

type Exporter struct {
	connector *pq.Connector
	logger    *slog.Logger
}

type poolColumnMetricDesc struct {
	desc      *prometheus.Desc
	valueType prometheus.ValueType
}

var poolsExtendedColumnToMetric = map[string]poolColumnMetricDesc{
		"cl_active": {
			desc:      clientPoolActiveRouteDescription,
			valueType: prometheus.GaugeValue,
		},
		"cl_waiting": {
			desc:      clientPoolWaitingRouteDescription,
			valueType: prometheus.GaugeValue,
		},

    "maxwait": {
        desc:      clientPoolMaxwaitSecondsRouteDescription,
        valueType: prometheus.GaugeValue,
    },
    // "maxwait_us" is intentionally ignored to avoid duplicate metrics
	"bytes_received": {
		desc:      routeBytesReceivedTotalDescription,
		valueType: prometheus.CounterValue,
	},
    "bytes_sent": {
        desc:      routeBytesSentTotalDescription,
        valueType: prometheus.CounterValue,
    },
	"tcp_conn_count": {
		desc:      routeTCPConnectionsTotalDescription,
		valueType: prometheus.CounterValue,
	},
}

// unified state metric for server pool
var serverPoolStateRouteDescription = prometheus.NewDesc(
    prometheus.BuildFQName(namespace, "server_pool", "state_route"),
    "Server pool state per route",
    []string{"user", "database", "state"}, nil,
)

// routeKey identifies a route by backend database and user
type routeKey struct {
    database string
    user     string
}

func NewExporter(connectionString string, logger *slog.Logger) (*Exporter, error) {
	connector, err := pq.NewConnector(connectionString)
	if err != nil {
		return nil, err
	}

	return &Exporter{
		connector: connector,
		logger:    logger,
	}, nil
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	// TODO: do not collect metrics here ?
	metricCh := make(chan prometheus.Metric)
	doneCh := make(chan struct{})

	go func() {
		for m := range metricCh {
			ch <- m.Desc()
		}
		close(doneCh)
	}()

	e.Collect(metricCh)
	close(metricCh)
	<-doneCh
}

func (exporter *Exporter) getDB() (*sql.DB, error) {
	db := sql.OpenDB(exporter.connector)
	if db == nil {
		return nil, errors.New("error opening DB")
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	return db, nil
}

func (exporter *Exporter) Collect(ch chan<- prometheus.Metric) {
	logger := exporter.logger

	var up = 1.0

	defer func() {
		ch <- prometheus.MustNewConstMetric(exporterUpDescription, prometheus.GaugeValue, up)
	}()

	db, err := exporter.getDB()
	if err != nil {
		logger.Warn("can't connect to Odyssey", "err", err.Error())
		up = 0
		return
	}
	defer db.Close()

	if err = exporter.sendVersionMetric(ch, db); err != nil {
		logger.Error("can't get version", "err", err.Error())
		up = 0
		return
	}

	if err = exporter.sendListsMetrics(ch, db); err != nil {
		logger.Error("can't get lists metrics", "err", err.Error())
		up = 0
		return
	}

	if err = exporter.sendIsPausedMetric(ch, db); err != nil {
		logger.Error("can't get is_pause metric", "err", err.Error())
		up = 0
		return
	}

	if err = exporter.sendErrorMetrics(ch, db); err != nil {
		logger.Error("can't get error metrics", "err", err.Error())
		up = 0
		return
	}

	if err = exporter.sendStatsMetrics(ch, db); err != nil {
		logger.Error("can't get stats metrics", "err", err.Error())
		up = 0
		return
	}

	poolCapacities, err := exporter.collectRoutePoolCapacities(db)
	if err != nil {
		logger.Error("can't get pool capacity", "err", err.Error())
		up = 0
		return
	}

	if err = exporter.sendPoolsExtendedMetrics(ch, db, poolCapacities); err != nil {
		logger.Error("can't get pool metrics", "err", err.Error())
		up = 0
		return
	}
}

func (exporter *Exporter) collectRoutePoolCapacities(db *sql.DB) (map[routeKey]float64, error) {
    rows, err := db.Query(showDatabasesCommand)
    if err != nil {
        return nil, fmt.Errorf("error getting databases: %w", err)
    }
    defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("can't get columns of databases: %w", err)
	}

	nameIdx := -1
	dbIdx := -1
	userIdx := -1
	poolSizeIdx := -1
	for idx, name := range columns {
		switch name {
		case "name":
			nameIdx = idx
		case "database":
			dbIdx = idx
		case "force_user":
			userIdx = idx
		case "pool_size":
			poolSizeIdx = idx
		}
	}

	// require pool_size and at least one database column
	if poolSizeIdx == -1 || (dbIdx == -1 && nameIdx == -1) {
		return nil, fmt.Errorf("unexpected databases output format")
	}

    result := make(map[routeKey]float64)

	rawColumns := make([]sql.RawBytes, len(columns))
	dest := make([]interface{}, len(columns))
	for i := range dest {
		dest[i] = &rawColumns[i]
	}

	for rows.Next() {
		for i := range rawColumns {
			rawColumns[i] = nil
		}

		if err := rows.Scan(dest...); err != nil {
			return nil, fmt.Errorf("error scanning databases row: %w", err)
		}

		backendDatabase := ""
		if dbIdx != -1 && rawColumns[dbIdx] != nil {
			backendDatabase = string(rawColumns[dbIdx])
		} else if nameIdx != -1 && rawColumns[nameIdx] != nil {
			backendDatabase = string(rawColumns[nameIdx])
		}

		backendUser := ""
		if userIdx != -1 && rawColumns[userIdx] != nil {
			backendUser = string(rawColumns[userIdx])
		}

		poolSizeValue := 0.0
		if poolSizeIdx != -1 && rawColumns[poolSizeIdx] != nil {
			poolSizeStr := string(rawColumns[poolSizeIdx])
			if poolSizeStr != "" {
				poolSizeValue, err = strconv.ParseFloat(poolSizeStr, 64)
				if err != nil {
					return nil, fmt.Errorf("can't parse pool_size for %s: %w", backendDatabase, err)
				}
			}
		}

        result[routeKey{database: backendDatabase, user: backendUser}] = poolSizeValue
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating databases rows: %w", err)
	}

    return result, nil
}

func (*Exporter) sendVersionMetric(ch chan<- prometheus.Metric, db *sql.DB) error {
	rows, err := db.Query(showVersionCommand)
	if err != nil {
		return fmt.Errorf("error getting version: %w", err)
	}
	defer rows.Close()

	var columnNames []string
	columnNames, err = rows.Columns()
	if err != nil {
		return fmt.Errorf("can't get columns for version: %w", err)
	}

	if len(columnNames) != 1 || columnNames[0] != "version" {
		return fmt.Errorf("unexpected version command output format")
	}

	var odysseyVersion string
	if !rows.Next() {
		return fmt.Errorf("empty version command output")
	}
	err = rows.Scan(&odysseyVersion)
	if err != nil {
		return fmt.Errorf("can't scan version column: %w", err)
	}

	ch <- prometheus.MustNewConstMetric(
		versionDescription,
		prometheus.GaugeValue,
		1.0,
		odysseyVersion,
	)

	return nil
}

func (exporter *Exporter) sendIsPausedMetric(ch chan<- prometheus.Metric, db *sql.DB) error {
	rows, err := db.Query(showIsPausedCommand)
	if err != nil {
		return fmt.Errorf("error getting is_paused: %w", err)
	}
	defer rows.Close()

	var columnNames []string
	columnNames, err = rows.Columns()
	if err != nil {
		return fmt.Errorf("can't get columns for paused status: %w", err)
	}

	if len(columnNames) != 1 || columnNames[0] != "is_paused" {
		return fmt.Errorf("unexpected paused command output format")
	}

	var isPaused bool
	if !rows.Next() {
		return fmt.Errorf("empty paused command output")
	}
	err = rows.Scan(&isPaused)
	if err != nil {
		return fmt.Errorf("can't scan paused column: %w", err)
	}

	value := 1.0
	if !isPaused {
		value = 0.0
	}

	ch <- prometheus.MustNewConstMetric(
		isPausedDescription,
		prometheus.GaugeValue,
		value,
	)

	return nil
}

func (exporter *Exporter) sendListsMetrics(ch chan<- prometheus.Metric, db *sql.DB) error {
	rows, err := db.Query(showListsCommand)
	if err != nil {
		return fmt.Errorf("error getting version: %w", err)
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return fmt.Errorf("can't get columns of lists")
	}
	if len(columns) != 2 || columns[0] != "list" || columns[1] != "items" {
		return fmt.Errorf("invalid format of lists output")
	}

	var list string
	var items sql.RawBytes
	for rows.Next() {
		if err = rows.Scan(&list, &items); err != nil {
			return fmt.Errorf("error scanning lists row: %w", err)
		}

		value, err := strconv.ParseFloat(string(items), 64)
		if err != nil {
			return fmt.Errorf("can't parse items of %q: %w", string(items), err)
		}

		if description, ok := listMetricNameToDescription[list]; ok {
			ch <- prometheus.MustNewConstMetric(description, prometheus.GaugeValue, value)
		}
	}

	return nil
}

func (exporter *Exporter) sendErrorMetrics(ch chan<- prometheus.Metric, db *sql.DB) error {
	rows, err := db.Query(showErrorsCommand)
	if err != nil {
		return fmt.Errorf("error getting errors: %w", err)
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return fmt.Errorf("can't get columns of errors")
	}
	if len(columns) != 2 || columns[0] != "error_type" || columns[1] != "count" {
		return fmt.Errorf("invalid format of errors output")
	}

	var errorType string
	var count sql.RawBytes
	for rows.Next() {
		if err = rows.Scan(&errorType, &count); err != nil {
			return fmt.Errorf("error scanning lists row: %w", err)
		}

		value, err := strconv.ParseFloat(string(count), 64)
		if err != nil {
			return fmt.Errorf("can't parse count of %q: %w", string(count), err)
		}

		ch <- prometheus.MustNewConstMetric(
			errorsTotalDescription,
			prometheus.CounterValue,
			value,
			errorType,
		)
	}

	return nil
}

func (exporter *Exporter) sendStatsMetrics(ch chan<- prometheus.Metric, db *sql.DB) error {
	rows, err := db.Query(showStatsCommand)
	if err != nil {
		return fmt.Errorf("error getting stats: %w", err)
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return fmt.Errorf("can't get columns of stats")
	}
	if len(columns) == 0 {
		return fmt.Errorf("stats output has no columns")
	}

	databaseIdx := -1
	avgXactIdx := -1
	avgQueryIdx := -1
	for idx, name := range columns {
		switch name {
		case "database":
			databaseIdx = idx
		case "avg_xact_count":
			avgXactIdx = idx
		case "avg_query_count":
			avgQueryIdx = idx
		}
	}

	if databaseIdx == -1 || avgXactIdx == -1 || avgQueryIdx == -1 {
		return fmt.Errorf("unexpected stats columns, database=%d avg_xact_count=%d avg_query_count=%d", databaseIdx, avgXactIdx, avgQueryIdx)
	}

	rawColumns := make([]sql.RawBytes, len(columns))
	dest := make([]interface{}, len(columns))
	for i := range dest {
		dest[i] = &rawColumns[i]
	}

	for rows.Next() {
		for i := range rawColumns {
			rawColumns[i] = nil
		}
		if err = rows.Scan(dest...); err != nil {
			return fmt.Errorf("error scanning stats row: %w", err)
		}

		if rawColumns[databaseIdx] == nil {
			continue
		}
		database := string(rawColumns[databaseIdx])
		if database == "" {
			continue
		}

		avgTxValue := 0.0
		if rawColumns[avgXactIdx] != nil {
			avgTxValue, err = strconv.ParseFloat(string(rawColumns[avgXactIdx]), 64)
			if err != nil {
				return fmt.Errorf("can't parse avg_xact_count for %s: %w", database, err)
			}
		}

		avgQueryValue := 0.0
		if rawColumns[avgQueryIdx] != nil {
			avgQueryValue, err = strconv.ParseFloat(string(rawColumns[avgQueryIdx]), 64)
			if err != nil {
				return fmt.Errorf("can't parse avg_query_count for %s: %w", database, err)
			}
		}

		ch <- prometheus.MustNewConstMetric(
			avgTxCountDescription,
			prometheus.GaugeValue,
			avgTxValue,
			database,
		)

		ch <- prometheus.MustNewConstMetric(
			avgQueryCountDescription,
			prometheus.GaugeValue,
			avgQueryValue,
			database,
		)
	}

	return rows.Err()
}

func (exporter *Exporter) sendPoolsExtendedMetrics(ch chan<- prometheus.Metric, db *sql.DB, capacities map[routeKey]float64) error {
	rows, err := db.Query(showPoolsExtendedCommand)
	if err != nil {
		return fmt.Errorf("error getting pools: %w", err)
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return fmt.Errorf("can't get columns of pools")
	}
	if len(columns) <= 2 || columns[0] != "database" || columns[1] != "user" {
		return fmt.Errorf("invalid format of pools output")
	}

    for rows.Next() {
		vals := make([]interface{}, len(columns))
		for i := range vals {
			vals[i] = new(interface{})
		}

		if err = rows.Scan(vals...); err != nil {
			return fmt.Errorf("error scanning pool extended row: %w", err)
		}

		databaseValue := *(vals[0].(*interface{}))
		database, ok := databaseValue.(string)
		if !ok {
			return fmt.Errorf("first column %q is not string, expected name, got value of type %T", columns[0], vals[0])
		}

		userValue := *(vals[1].(*interface{}))
		user, ok := userValue.(string)
		if !ok {
			return fmt.Errorf("second column %s is not string, expected name, got value of type %T", columns[1], vals[1])
		}

		if database == "aggregated" && user == "aggregated" {
			continue
		}

        serverActive := 0.0
        serverIdle := 0.0
        serverUsed := 0.0
        serverTested := 0.0
        serverLogin := 0.0

		for i := 2; i < len(columns); i++ {
			columnName := columns[i]

			val := *(vals[i].(*interface{}))

			if columnName == poolModeColumnName {
				if val == nil {
					continue
				}
				var mode string
				switch v := val.(type) {
				case string:
					mode = v
				case []uint8:
					mode = string(v)
				default:
					return fmt.Errorf("expected column %q to be string, got %T", poolModeColumnName, val)
				}
				writePoolModeInfoMetric(ch, database, user, mode)
				continue
			}

            if strings.HasPrefix(columnName, queryQuantilePrefix) {
                value, _, err := extractFloat(val, columnName)
                if err != nil {
                    return err
                }
                quantile := strings.TrimPrefix(columnName, queryQuantilePrefix)
				ch <- prometheus.MustNewConstMetric(
					routeQueryDurationSecondsDescription,
					prometheus.GaugeValue,
					value,
					user, database, quantile,
				)
				continue
			}

            if strings.HasPrefix(columnName, transactionQuantilePrefix) {
                value, _, err := extractFloat(val, columnName)
                if err != nil {
                    return err
                }
                quantile := strings.TrimPrefix(columnName, transactionQuantilePrefix)
				ch <- prometheus.MustNewConstMetric(
					routeTransactionDurationSecondsDescription,
					prometheus.GaugeValue,
					value,
					user, database, quantile,
				)
				continue
			}

            value, _, err := extractFloat(val, columnName)
            if err != nil {
                return err
            }

            switch columnName {
            case "sv_active":
                serverActive = value
                continue
            case "sv_idle":
                serverIdle = value
                continue
            case "sv_used":
                serverUsed = value
                // do not continue, let mapping below export per-state metric too
            case "sv_tested":
                serverTested = value
            case "sv_login":
                serverLogin = value
            }

            // Ignore deprecated microseconds column silently
            if columnName == "maxwait_us" {
                continue
            }

            if metricDesc, ok := poolsExtendedColumnToMetric[columnName]; ok {
                ch <- prometheus.MustNewConstMetric(
                    metricDesc.desc,
                    metricDesc.valueType,
                    value,
                    user, database,
                )
                continue
            }

            return fmt.Errorf("got unexpected column %q", columnName)
        }

        // Per-state values are available via the unified family below

        // Always export configured capacity (0 means unlimited) based on SHOW DATABASES
        // Prefer exact database+user match; fall back to database-only if present
        var configuredCapacity float64
        if v, ok := capacities[routeKey{database: database, user: user}]; ok {
            configuredCapacity = v
        } else if v, ok := capacities[routeKey{database: database, user: ""}]; ok {
            configuredCapacity = v
        }
        ch <- prometheus.MustNewConstMetric(
            serverPoolCapacityConfiguredRouteDescription,
            prometheus.GaugeValue,
            configuredCapacity,
            user, database,
        )

        // Current connections can be derived as active+idle from the unified state family

        // Unified state metric family
        ch <- prometheus.MustNewConstMetric(serverPoolStateRouteDescription, prometheus.GaugeValue, serverActive, user, database, "active")
        ch <- prometheus.MustNewConstMetric(serverPoolStateRouteDescription, prometheus.GaugeValue, serverIdle, user, database, "idle")
        ch <- prometheus.MustNewConstMetric(serverPoolStateRouteDescription, prometheus.GaugeValue, serverUsed, user, database, "used")
        ch <- prometheus.MustNewConstMetric(serverPoolStateRouteDescription, prometheus.GaugeValue, serverTested, user, database, "tested")
        ch <- prometheus.MustNewConstMetric(serverPoolStateRouteDescription, prometheus.GaugeValue, serverLogin, user, database, "login")
    }

    return nil
}

func main() {
	connectionStringPtr := kingpin.Flag("odyssey.connectionString", "Connection string for accessing Odyssey.").Default("host=localhost port=6432 user=console dbname=console sslmode=disable").String()

	toolkitFlags := kingpinflag.AddFlags(kingpin.CommandLine, ":9876")

	kingpin.Version(version.Print("odyssey_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	promslogConfig := &promslog.Config{}
	logger := promslog.New(promslogConfig)

	logger.Info("Starting odyssey_exporter", "version", version.Info())

	exporter, err := NewExporter(*connectionStringPtr, logger)
	if err != nil {
		logger.Error("Error creating exporter", "err", err)
		os.Exit(1)
	}

	prometheus.MustRegister(exporter)
	prometheus.MustRegister(versioncollector.NewCollector("odyssey_exporter"))

	http.Handle(metricsHandlePath, promhttp.Handler())

	landingConfig := web.LandingConfig{
		Name:        "Odyssey Exporter",
		Description: "Prometheus Exporter for Odyssey instances",
		Version:     version.Info(),
		Links: []web.LandingLinks{
			{
				Address: metricsHandlePath,
				Text:    "Metrics",
			},
		},
	}
	landingPage, err := web.NewLandingPage(landingConfig)
	if err != nil {
		logger.Error("Error creating landing page", "err", err)
		os.Exit(1)
	}
	http.Handle("/", landingPage)

	srv := &http.Server{}
	if err := web.ListenAndServe(srv, toolkitFlags, logger); err != nil {
		logger.Error("Error starting server", "err", err)
		os.Exit(1)
	}
}
