package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AndrewKarpaty/cluster-guardian/internal/analyzer"
	"github.com/AndrewKarpaty/cluster-guardian/internal/fleet"
	"github.com/AndrewKarpaty/cluster-guardian/internal/kube"
	"github.com/AndrewKarpaty/cluster-guardian/internal/report"
)

func testReport() *report.Report {
	r := &report.Report{
		ClusterName: "prod",
		Namespaces: []report.NamespaceSection{{Name: "payments", Findings: []report.Finding{
			{Severity: report.SeverityWarning, Message: "w1"},
			{Severity: report.SeverityWarning, Message: "w2"},
			{Severity: report.SeverityCritical, Message: "c1"},
		}}},
		Sections: []report.Section{{ID: "security", Title: "Security", Findings: []report.Finding{
			{Severity: report.SeverityInfo, Message: "i1"},
		}}},
	}
	r.Finalize()
	return r
}

func scrape(t *testing.T, s *Server) string {
	t.Helper()
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("unexpected content type %q", ct)
	}
	return rec.Body.String()
}

func TestMetricsSingleCluster(t *testing.T) {
	s := New(&kube.Client{Context: "ctx"}, analyzer.Options{}, time.Minute, nil)
	s.cached = testReport()
	s.cachedAt = time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	s.lastRunDuration = 1500 * time.Millisecond
	s.runs, s.runErrors = 3, 1

	body := scrape(t, s)

	for _, want := range []string{
		`cluster_guardian_findings{cluster="prod",section="workloads",namespace="payments",severity="warning"} 2`,
		`cluster_guardian_findings{cluster="prod",section="workloads",namespace="payments",severity="critical"} 1`,
		`cluster_guardian_findings{cluster="prod",section="workloads",namespace="payments",severity="ok"} 0`,
		`cluster_guardian_findings{cluster="prod",section="security",namespace="",severity="info"} 1`,
		`cluster_guardian_score{cluster="prod"} 76`,
		fmt.Sprintf(`cluster_guardian_last_run_timestamp_seconds{cluster="prod"} %d`, s.cachedAt.Unix()),
		`cluster_guardian_run_duration_seconds{cluster="prod"} 1.500`,
		`cluster_guardian_runs_total{cluster="prod"} 3`,
		`cluster_guardian_run_errors_total{cluster="prod"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing metric line %q in:\n%s", want, body)
		}
	}
}

// Before the first analysis there is no report: only the run counters (at
// zero) may be exposed, and scraping must not trigger an analysis.
func TestMetricsBeforeFirstRun(t *testing.T) {
	s := New(&kube.Client{Context: "ctx"}, analyzer.Options{}, time.Minute, nil)

	body := scrape(t, s)

	if strings.Contains(body, "cluster_guardian_score{") ||
		strings.Contains(body, "cluster_guardian_findings{") ||
		strings.Contains(body, "cluster_guardian_last_run_timestamp_seconds{") {
		t.Errorf("no report yet: report-derived series must be absent, got:\n%s", body)
	}
	if !strings.Contains(body, `cluster_guardian_runs_total{cluster="ctx"} 0`) {
		t.Errorf("expected zero runs counter, got:\n%s", body)
	}
	if s.runs != 0 {
		t.Error("scraping must not trigger an analysis")
	}
}

type staticLister struct{ clusters []fleet.Cluster }

func (l staticLister) Clusters(context.Context) ([]fleet.Cluster, error) { return l.clusters, nil }

func TestMetricsFleet(t *testing.T) {
	m := fleet.NewManager(staticLister{clusters: []fleet.Cluster{{
		Name:   "edge",
		Server: "https://edge",
		Build:  func() (*kube.Client, error) { return nil, errors.New("connection refused") },
	}}}, analyzer.Options{}, time.Minute, "", 2)
	m.ScanAll(context.Background())

	s := New(&kube.Client{Context: "hub"}, analyzer.Options{}, time.Minute, nil)
	s.EnableFleet(m)

	body := scrape(t, s)

	for _, want := range []string{
		`cluster_guardian_runs_total{cluster="edge"} 1`,
		`cluster_guardian_run_errors_total{cluster="edge"} 1`,
		`cluster_guardian_last_run_timestamp_seconds{cluster="edge"} `,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing metric line %q in:\n%s", want, body)
		}
	}
	if strings.Contains(body, `cluster_guardian_findings{cluster="edge"`) {
		t.Errorf("failed cluster has no report and must expose no findings, got:\n%s", body)
	}
}

func TestEscapeLabel(t *testing.T) {
	if got := escapeLabel("a\\b\"c\nd"); got != `a\\b\"c\nd` {
		t.Errorf("unexpected escaping: %q", got)
	}
}
