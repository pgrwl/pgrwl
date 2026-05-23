package receivemetrics

import (
	"context"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	M            pgrwlMetrics = &pgrwlMetricsNoop{}
	processStart              = time.Now()
)

type pgrwlMetrics interface {
	AddWALBytesReceived(float64)
	IncWALFilesReceived()
	IncWALFilesUploaded()
	IncWALFilesDeleted()
	StartUptimeReporter(ctx context.Context)
}

// noop

type pgrwlMetricsNoop struct{}

var _ pgrwlMetrics = &pgrwlMetricsNoop{}

func (p pgrwlMetricsNoop) AddWALBytesReceived(_ float64)         {}
func (p pgrwlMetricsNoop) IncWALFilesReceived()                  {}
func (p pgrwlMetricsNoop) IncWALFilesUploaded()                  {}
func (p pgrwlMetricsNoop) IncWALFilesDeleted()                   {}
func (p pgrwlMetricsNoop) StartUptimeReporter(_ context.Context) {}

// prom

type pgrwlMetricsProm struct {
	walBytesReceived prometheus.Counter
	walFilesReceived prometheus.Counter
	walFilesUploaded prometheus.Counter
	walFilesDeleted  prometheus.Counter

	// maintenance
	uptime     prometheus.Gauge
	uptimeOnce sync.Once
}

var _ pgrwlMetrics = &pgrwlMetricsProm{}

func InitPromMetrics(ctx context.Context) {
	// Unregister default prometheus collectors so we don't collect a bunch of pointless metrics
	prometheus.Unregister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	prometheus.Unregister(collectors.NewGoCollector())

	M = &pgrwlMetricsProm{
		walBytesReceived: promauto.NewCounter(prometheus.CounterOpts{
			Name: "pgrwl_wal_bytes_received_total",
			Help: "Total number of WAL bytes received from PostgreSQL.",
		}),
		walFilesReceived: promauto.NewCounter(prometheus.CounterOpts{
			Name: "pgrwl_wal_files_received_total",
			Help: "Total number of WAL segments received.",
		}),
		walFilesUploaded: promauto.NewCounter(prometheus.CounterOpts{
			Name: "pgrwl_wal_files_uploaded_total",
			Help: "Number of WAL files uploaded, partitioned by storage backend.",
		}),
		walFilesDeleted: promauto.NewCounter(prometheus.CounterOpts{
			Name: "pgrwl_wal_files_deleted_total",
			Help: "Number of WAL segments deleted by retention logic.",
		}),

		// maintenance
		uptime: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "pgrwl_uptime_seconds",
			Help: "Time in seconds since the process started.",
		}),
	}

	M.StartUptimeReporter(ctx)
}

// receive, manage, etc...

func (p *pgrwlMetricsProm) AddWALBytesReceived(f float64) {
	p.walBytesReceived.Add(f)
}

func (p *pgrwlMetricsProm) IncWALFilesReceived() {
	p.walFilesReceived.Inc()
}

func (p *pgrwlMetricsProm) IncWALFilesUploaded() {
	p.walFilesUploaded.Inc()
}

func (p *pgrwlMetricsProm) IncWALFilesDeleted() {
	p.walFilesDeleted.Inc()
}

// maintenance

func (p *pgrwlMetricsProm) UptimeSet() {
	p.uptime.Set(time.Since(processStart).Seconds())
}

func (p *pgrwlMetricsProm) StartUptimeReporter(ctx context.Context) {
	p.uptimeOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					p.UptimeSet()
				}
			}
		}()
	})
}
