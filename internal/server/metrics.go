package server

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/AndrewKarpaty/cluster-guardian/internal/report"
)

// clusterMetrics is one cluster's contribution to /metrics.
type clusterMetrics struct {
	Name         string
	Report       *report.Report // nil until the first successful run
	LastRun      time.Time
	LastDuration time.Duration
	Runs         int
	RunErrors    int
}

// handleMetrics serves Prometheus metrics from state already in memory —
// scraping never triggers an analysis.
func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	var clusters []clusterMetrics
	if s.fleet != nil {
		for _, st := range s.fleet.Statuses() {
			clusters = append(clusters, clusterMetrics{
				Name:         st.Name,
				Report:       s.fleet.Report(st.Name),
				LastRun:      st.LastScan,
				LastDuration: time.Duration(st.LastScanSeconds * float64(time.Second)),
				Runs:         st.Scans,
				RunErrors:    st.ScanErrors,
			})
		}
	} else {
		s.mu.Lock()
		var name string
		if s.client != nil {
			name = s.client.Context
		}
		current := s.cached
		if current == nil {
			current = s.fixture
		}
		if current != nil && current.ClusterName != "" {
			name = current.ClusterName
		}
		clusters = []clusterMetrics{{
			Name:         name,
			Report:       current,
			LastRun:      s.cachedAt,
			LastDuration: s.lastRunDuration,
			Runs:         s.runs,
			RunErrors:    s.runErrors,
		}}
		s.mu.Unlock()
	}
	s.mu.Lock()
	deliveries, deliveryErrors := s.reportDeliveries, s.reportDeliveryErrors
	s.mu.Unlock()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	writeMetrics(w, clusters)
	fmt.Fprintf(w, "# HELP cluster_guardian_report_deliveries_total Scheduled report deliveries attempted since process start.\n# TYPE cluster_guardian_report_deliveries_total counter\ncluster_guardian_report_deliveries_total %d\n", deliveries)
	fmt.Fprintf(w, "# HELP cluster_guardian_report_delivery_errors_total Failed scheduled report deliveries since process start.\n# TYPE cluster_guardian_report_delivery_errors_total counter\ncluster_guardian_report_delivery_errors_total %d\n", deliveryErrors)
}

// writeMetrics renders the Prometheus text exposition format by hand — a few
// gauges and counters don't justify the client_golang dependency (the same
// call the project made for the query client in internal/prom).
func writeMetrics(w io.Writer, clusters []clusterMetrics) {
	family := func(name, help, typ string) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	}

	family("cluster_guardian_findings", "Current findings by cluster, section, namespace and severity.", "gauge")
	for _, c := range clusters {
		if c.Report == nil {
			continue
		}
		emit := func(section, namespace string, fs []report.Finding) {
			var counts [report.SeverityCritical + 1]int
			for _, f := range fs {
				if int(f.Severity) < len(counts) {
					counts[f.Severity]++
				}
			}
			for sev, n := range counts {
				fmt.Fprintf(w, "cluster_guardian_findings{cluster=\"%s\",section=\"%s\",namespace=\"%s\",severity=\"%s\"} %d\n",
					escapeLabel(c.Name), escapeLabel(section), escapeLabel(namespace), report.Severity(sev), n)
			}
		}
		for _, ns := range c.Report.Namespaces {
			emit("workloads", ns.Name, ns.Findings)
		}
		for _, sec := range c.Report.Sections {
			emit(sec.ID, "", sec.Findings)
		}
	}

	family("cluster_guardian_score", "Cluster health score (0-100).", "gauge")
	for _, c := range clusters {
		if c.Report != nil {
			fmt.Fprintf(w, "cluster_guardian_score{cluster=\"%s\"} %d\n", escapeLabel(c.Name), c.Report.Summary.Score)
		}
	}

	family("cluster_guardian_last_run_timestamp_seconds", "Unix time of the most recent analysis attempt.", "gauge")
	for _, c := range clusters {
		if !c.LastRun.IsZero() {
			fmt.Fprintf(w, "cluster_guardian_last_run_timestamp_seconds{cluster=\"%s\"} %d\n", escapeLabel(c.Name), c.LastRun.Unix())
		}
	}

	family("cluster_guardian_run_duration_seconds", "Duration of the most recent analysis run.", "gauge")
	for _, c := range clusters {
		if c.LastDuration > 0 {
			fmt.Fprintf(w, "cluster_guardian_run_duration_seconds{cluster=\"%s\"} %.3f\n", escapeLabel(c.Name), c.LastDuration.Seconds())
		}
	}

	family("cluster_guardian_runs_total", "Analysis runs attempted since process start.", "counter")
	for _, c := range clusters {
		fmt.Fprintf(w, "cluster_guardian_runs_total{cluster=\"%s\"} %d\n", escapeLabel(c.Name), c.Runs)
	}

	family("cluster_guardian_run_errors_total", "Failed analysis runs since process start.", "counter")
	for _, c := range clusters {
		fmt.Fprintf(w, "cluster_guardian_run_errors_total{cluster=\"%s\"} %d\n", escapeLabel(c.Name), c.RunErrors)
	}
}

var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

// escapeLabel escapes a label value per the Prometheus text format.
func escapeLabel(v string) string { return labelEscaper.Replace(v) }
