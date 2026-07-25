package report

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestWritePDF(t *testing.T) {
	var buf bytes.Buffer
	if err := WritePDF(&buf, ciTestReport()); err != nil {
		t.Fatal(err)
	}
	out := buf.Bytes()
	if !bytes.HasPrefix(out, []byte("%PDF-")) {
		t.Errorf("expected a PDF header, got %q", out[:8])
	}
	if len(out) < 1500 {
		t.Errorf("suspiciously small PDF: %d bytes", len(out))
	}
}

func TestDigestRenderers(t *testing.T) {
	delta := -6
	d := Digest{
		Title:       "Cluster Guardian — fleet report",
		GeneratedAt: time.Date(2026, 7, 27, 8, 0, 0, 0, time.UTC),
		Clusters: []DigestCluster{
			{Name: "prod", Grade: "B", Score: 84, ScoreDelta: &delta, NewCritical: 2, Critical: 3, Warnings: 9},
			{Name: "edge", Error: "connection refused"},
		},
	}

	var html bytes.Buffer
	if err := WriteDigestHTML(&html, d); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"fleet report", "prod", "84/100", "▼ -6", "connection refused"} {
		if !strings.Contains(html.String(), want) {
			t.Errorf("digest HTML missing %q", want)
		}
	}

	var pdf bytes.Buffer
	if err := WriteDigestPDF(&pdf, d); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(pdf.Bytes(), []byte("%PDF-")) {
		t.Error("expected a PDF header for the digest")
	}
}
