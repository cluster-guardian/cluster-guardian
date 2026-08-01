package history

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/cluster-guardian/cluster-guardian/internal/report"
)

func testReport(at time.Time, messages ...string) *report.Report {
	var findings []report.Finding
	for _, m := range messages {
		findings = append(findings, report.Finding{Severity: report.SeverityWarning, Message: m})
	}
	r := &report.Report{
		GeneratedAt: at,
		Sections:    []report.Section{{ID: "security", Title: "Security", Findings: findings}},
	}
	r.Finalize()
	return r
}

func TestStorePersistsAndPrunes(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 7, 18, 10, 0, 0, 0, time.UTC)

	s, err := New(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	s.Append(testReport(base, "root containers"))
	s.Append(testReport(base.Add(time.Minute), "root containers", "privileged containers"))
	s.Append(testReport(base.Add(2*time.Minute), "privileged containers"))

	if got := len(s.Entries()); got != 2 {
		t.Errorf("expected pruning to limit 2, got %d entries", got)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "report-*.json"))
	if len(files) != 2 {
		t.Errorf("expected 2 files on disk after pruning, got %d", len(files))
	}

	d := s.LastDiff()
	if d == nil {
		t.Fatal("expected a diff after two runs")
	}
	if len(d.Resolved) != 1 || len(d.New) != 0 {
		t.Errorf("expected 1 resolved (root containers), 0 new; got %+v", d)
	}

	// A reopened store must see the persisted history and diff across restarts.
	s2, err := New(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(s2.Entries()); got != 2 {
		t.Fatalf("expected 2 entries after reopen, got %d", got)
	}
	if d := s2.LastDiff(); d == nil || len(d.Resolved) != 1 {
		t.Errorf("expected same diff after reopen, got %+v", d)
	}

	s2.Append(testReport(base.Add(3*time.Minute), "privileged containers", "wildcard ClusterRoles"))
	if d := s2.LastDiff(); d == nil || len(d.New) != 1 {
		t.Errorf("expected 1 new finding after appending to reopened store, got %+v", d)
	}
}

func TestMemoryOnlyStore(t *testing.T) {
	s, err := New("", 5)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 7, 18, 10, 0, 0, 0, time.UTC)
	s.Append(testReport(base, "a"))
	s.Append(testReport(base.Add(time.Minute), "a", "b"))
	if len(s.Entries()) != 2 {
		t.Errorf("expected 2 in-memory entries, got %d", len(s.Entries()))
	}
	if d := s.LastDiff(); d == nil || len(d.New) != 1 {
		t.Errorf("expected in-memory diff with 1 new, got %+v", d)
	}
}
