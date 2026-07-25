package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/AndrewKarpaty/cluster-guardian/internal/analyzer"
	"github.com/AndrewKarpaty/cluster-guardian/internal/deliver"
	"github.com/AndrewKarpaty/cluster-guardian/internal/fleet"
	"github.com/AndrewKarpaty/cluster-guardian/internal/kube"
	"github.com/AndrewKarpaty/cluster-guardian/internal/report"
)

func TestStartReportScheduleValidates(t *testing.T) {
	s := New(&kube.Client{Context: "ctx"}, analyzer.Options{}, time.Minute, nil)
	d, err := deliver.New(deliver.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.StartReportSchedule("not a cron", d, "pdf"); err == nil ||
		!strings.Contains(err.Error(), "report-schedule") {
		t.Errorf("expected cron validation error, got %v", err)
	}
	if err := s.StartReportSchedule("0 8 * * MON", d, "docx"); err == nil {
		t.Error("expected format validation error")
	}
	if err := s.StartReportSchedule("0 8 * * MON", d, "pdf"); err != nil {
		t.Errorf("valid schedule must start: %v", err)
	}
}

func TestFleetDigest(t *testing.T) {
	m := fleet.NewManager(staticLister{clusters: []fleet.Cluster{{
		Name:   "prod",
		Server: "https://prod",
	}}}, analyzer.Options{}, time.Minute, "", 10)

	// Two scans: score drops when a critical finding appears.
	scan := func(sev report.Severity, msgs ...string) {
		var fs []report.Finding
		for _, msg := range msgs {
			fs = append(fs, report.Finding{Severity: sev, Message: msg})
		}
		r := &report.Report{
			GeneratedAt: time.Now().UTC(),
			Sections:    []report.Section{{ID: "security", Title: "Security", Findings: fs}},
		}
		r.Finalize()
		m.SetScanForTest(func(context.Context, fleet.Cluster) (*report.Report, error) { return r, nil })
		m.ScanAll(context.Background())
	}
	scan(report.SeverityWarning, "root containers")
	scan(report.SeverityCritical, "root containers", "privileged container")

	d := fleetDigest(m)
	if d.Title == "" || len(d.Clusters) != 1 {
		t.Fatalf("unexpected digest: %+v", d)
	}
	c := d.Clusters[0]
	if c.Name != "prod" || c.Grade == "" {
		t.Errorf("unexpected cluster line: %+v", c)
	}
	if c.ScoreDelta == nil || *c.ScoreDelta >= 0 {
		t.Errorf("expected a negative score delta, got %+v", c.ScoreDelta)
	}
	if c.NewCritical != 1 {
		t.Errorf("expected 1 new critical, got %d", c.NewCritical)
	}
}
