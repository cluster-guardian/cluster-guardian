package report

import (
	"fmt"
	"io"

	"github.com/go-pdf/fpdf"
)

// severityRGB returns the print color for a severity.
func severityRGB(s Severity) (r, g, b int) {
	switch s {
	case SeverityCritical:
		return 161, 38, 38
	case SeverityWarning:
		return 138, 97, 0
	case SeverityInfo:
		return 31, 95, 158
	}
	return 23, 122, 63
}

// WritePDF renders the report as a PDF. Pure Go (no headless browser), so it
// works offline and in the container image unchanged.
func WritePDF(w io.Writer, r *Report) error {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetTitle("Cluster Guardian — "+r.ClusterName, true)
	pdf.SetAutoPageBreak(true, 18)
	pdf.AddPage()
	// Core fonts are cp1252: translate what we can, drop what we can't.
	tr := pdf.UnicodeTranslatorFromDescriptor("")

	pdf.SetFont("Helvetica", "B", 18)
	pdf.SetTextColor(23, 32, 58)
	pdf.CellFormat(0, 10, tr("Cluster Guardian — "+r.ClusterName), "", 1, "L", false, 0, "")

	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(110, 116, 133)
	meta := "Generated " + r.GeneratedAt.Format("2006-01-02 15:04 UTC")
	if r.KubernetesVersion != "" {
		meta += "  ·  Kubernetes " + r.KubernetesVersion
	}
	meta += fmt.Sprintf("  ·  score %d/100 (%s)  ·  %d findings (%d critical, %d warnings)",
		r.Summary.Score, r.Summary.Grade, r.Summary.Total, r.Summary.Critical, r.Summary.Warnings)
	pdf.CellFormat(0, 6, tr(meta), "", 1, "L", false, 0, "")
	pdf.Ln(4)

	heading := func(title string) {
		pdf.SetFont("Helvetica", "B", 13)
		pdf.SetTextColor(23, 32, 58)
		pdf.CellFormat(0, 9, tr(title), "", 1, "L", false, 0, "")
	}
	findings := func(fs []Finding) {
		for _, f := range fs {
			cr, cg, cb := severityRGB(f.Severity)
			pdf.SetFont("Helvetica", "B", 8)
			pdf.SetTextColor(cr, cg, cb)
			pdf.CellFormat(20, 5.5, tr(f.Severity.String()), "", 0, "L", false, 0, "")
			pdf.SetFont("Helvetica", "", 10)
			pdf.SetTextColor(23, 32, 58)
			pdf.MultiCell(0, 5.5, tr(f.Message), "", "L", false)
			if f.Hint != "" {
				pdf.SetX(pdf.GetX() + 20)
				pdf.SetFont("Helvetica", "I", 9)
				pdf.SetTextColor(110, 116, 133)
				pdf.MultiCell(0, 5, tr(f.Hint), "", "L", false)
			}
			pdf.Ln(1)
		}
		pdf.Ln(3)
	}

	for _, ns := range r.Namespaces {
		if len(ns.Findings) == 0 {
			continue
		}
		heading("Namespace: " + ns.Name)
		findings(ns.Findings)
	}
	if healthy := healthyNamespaces(r); len(healthy) > 0 {
		pdf.SetFont("Helvetica", "I", 9)
		pdf.SetTextColor(110, 116, 133)
		pdf.MultiCell(0, 5, tr(fmt.Sprintf("%d healthy namespaces without findings", len(healthy))), "", "L", false)
		pdf.Ln(3)
	}
	for _, sec := range r.Sections {
		if len(sec.Findings) == 0 {
			continue
		}
		heading(sec.Title)
		findings(sec.Findings)
	}

	return pdf.Output(w)
}
