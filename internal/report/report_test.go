package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func sampleReport() *Report {
	r := &Report{
		ClusterName:       "production",
		KubernetesVersion: "v1.31.0",
		GeneratedAt:       time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC),
		Namespaces: []NamespaceSection{{
			Name: "payments",
			Findings: []Finding{
				{Severity: SeverityWarning, Message: "5 Pods missing resource requests"},
				{Severity: SeverityCritical, Message: "2 CrashLoopBackOff containers"},
			},
		}},
		Sections: []Section{{
			ID: "security", Title: "Security", Icon: "🔒",
			Findings: []Finding{{Severity: SeverityWarning, Message: "8 containers running as root", Hint: "Set runAsNonRoot."}},
		}},
	}
	r.Finalize()
	return r
}

func TestFinalizeAndMaxSeverity(t *testing.T) {
	r := sampleReport()
	if r.Summary.Total != 3 || r.Summary.Warnings != 2 || r.Summary.Critical != 1 {
		t.Errorf("unexpected summary: %+v", r.Summary)
	}
	if r.MaxSeverity() != SeverityCritical {
		t.Errorf("expected critical max severity, got %s", r.MaxSeverity())
	}
}

func TestScoreAndGrade(t *testing.T) {
	// sampleReport: 1 critical + 2 warnings -> 100 - 15 - 8 = 77 -> C.
	r := sampleReport()
	if r.Summary.Score != 77 || r.Summary.Grade != "C" {
		t.Errorf("expected score 77 grade C, got %d %s", r.Summary.Score, r.Summary.Grade)
	}
	clean := &Report{}
	clean.Finalize()
	if clean.Summary.Score != 100 || clean.Summary.Grade != "A" {
		t.Errorf("empty report should score 100/A, got %d %s", clean.Summary.Score, clean.Summary.Grade)
	}
	for score, want := range map[int]string{95: "A", 85: "B", 75: "C", 65: "D", 30: "F", 0: "F"} {
		if got := GradeOf(score); got != want {
			t.Errorf("GradeOf(%d) = %s, want %s", score, got, want)
		}
	}
	if g := (Section{Findings: []Finding{{Severity: SeverityCritical}}}).Grade(); g != "B" {
		t.Errorf("section with 1 critical should grade B (score 85), got %s", g)
	}
}

func TestFilterControls(t *testing.T) {
	r := sampleReport()
	r.Sections[0].Findings[0].Controls = []string{"PSS/restricted:run-as-nonroot"}
	r.FilterControls("pss/")

	if got := len(r.Sections[0].Findings); got != 1 {
		t.Fatalf("expected 1 tagged security finding to survive, got %d", got)
	}
	if got := len(r.Namespaces[0].Findings); got != 0 {
		t.Errorf("untagged namespace findings should be filtered out, got %d", got)
	}
	if r.Summary.Total != 1 || r.Summary.Critical != 0 {
		t.Errorf("summary not recomputed after filtering: %+v", r.Summary)
	}
}

func TestWriteTerminal(t *testing.T) {
	var buf bytes.Buffer
	WriteTerminal(&buf, sampleReport(), TerminalOptions{NoColor: true, Verbose: true})
	out := buf.String()
	for _, want := range []string{
		"✖ Cluster: production",
		"Namespace: payments",
		"• 5 Pods missing resource requests",
		"Security",
		"↳ Set runAsNonRoot.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\033[") {
		t.Error("NoColor output should not contain ANSI escapes")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if back.Namespaces[0].Findings[1].Severity != SeverityCritical {
		t.Error("severity did not survive JSON round trip")
	}
}

func TestWriteHTMLEscapes(t *testing.T) {
	r := sampleReport()
	r.Namespaces[0].Findings[0].Message = `Deployment "<script>alert(1)</script>" uses :latest tag`
	var buf bytes.Buffer
	if err := WriteHTML(&buf, r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "<script>alert(1)</script>") {
		t.Error("HTML output must escape finding messages")
	}
}

func TestDiff(t *testing.T) {
	older := sampleReport()
	newer := sampleReport()
	// Count-only change: must NOT count as new or resolved.
	newer.Namespaces[0].Findings[0].Message = "3 Pods missing resource requests"
	// CrashLoopBackOff finding gone: resolved.
	newer.Namespaces[0].Findings = newer.Namespaces[0].Findings[:1]
	// Fresh finding in the Security section: new.
	newer.Sections[0].Findings = append(newer.Sections[0].Findings,
		Finding{Severity: SeverityWarning, Message: "2 privileged containers"})

	d := Diff(older, newer)

	if len(d.New) != 1 || !strings.Contains(d.New[0].Message, "privileged") {
		t.Errorf("expected exactly the privileged finding as new, got: %+v", d.New)
	}
	if len(d.New) == 1 && d.New[0].Location != "Security" {
		t.Errorf("expected Security location, got %q", d.New[0].Location)
	}
	if len(d.Resolved) != 1 || !strings.Contains(d.Resolved[0].Message, "CrashLoopBackOff") {
		t.Errorf("expected exactly the CrashLoopBackOff finding as resolved, got: %+v", d.Resolved)
	}
}

// The HTML export has to work from disk with no server and no network: it
// carries its own styles and script and never references an external asset or
// the REST API.
func TestWriteHTMLIsSelfContained(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHTML(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	for _, want := range []string{`id="search"`, `id="nsfilter"`, `data-sev="critical"`, `<details class="card" open`} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in the HTML export", want)
		}
	}
	// Styles and script are inlined, not linked.
	for _, want := range []string{"<style>", "<script>"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in the HTML export", want)
		}
	}
	// Resource loads only — an xmlns namespace URI is an identifier, not a fetch.
	for _, external := range []string{`/static/`, `href="/api/`, `data-api=`, `fetch(`,
		`src="http`, `href="http`, `url(http`} {
		if strings.Contains(out, external) {
			t.Errorf("%q must not appear in the HTML export — it must work offline", external)
		}
	}
}

func TestWriteMarkdown(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "# Cluster report: production") || !strings.Contains(out, "### payments") {
		t.Errorf("unexpected markdown:\n%s", out)
	}
}
