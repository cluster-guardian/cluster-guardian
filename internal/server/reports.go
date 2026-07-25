package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/AndrewKarpaty/cluster-guardian/internal/deliver"
	"github.com/AndrewKarpaty/cluster-guardian/internal/fleet"
	"github.com/AndrewKarpaty/cluster-guardian/internal/history"
	"github.com/AndrewKarpaty/cluster-guardian/internal/report"
)

// StartReportSchedule delivers a report digest on the cron schedule: the
// whole fleet in fleet mode, otherwise the local cluster. format selects the
// attachment ("pdf" or "html").
func (s *Server) StartReportSchedule(spec string, d *deliver.Deliverer, format string) error {
	if format != "pdf" && format != "html" {
		return fmt.Errorf("unknown report format %q (use pdf or html)", format)
	}
	c := cron.New()
	if _, err := c.AddFunc(spec, func() { s.runScheduledReport(d, format) }); err != nil {
		return fmt.Errorf("invalid --report-schedule: %w", err)
	}
	c.Start()
	return nil
}

func (s *Server) runScheduledReport(d *deliver.Deliverer, format string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	payload, err := s.buildReportPayload(ctx, format)
	if err == nil {
		err = d.Deliver(ctx, *payload)
	}

	s.mu.Lock()
	s.reportDeliveries++
	if err != nil {
		s.reportDeliveryErrors++
	}
	s.mu.Unlock()
	if err != nil {
		log.Printf("scheduled report: %v", err)
		return
	}
	log.Printf("scheduled report delivered")
}

func (s *Server) buildReportPayload(ctx context.Context, format string) (*deliver.Payload, error) {
	stamp := time.Now().UTC().Format("2006-01-02")
	if s.fleet != nil {
		digest := fleetDigest(s.fleet)
		return digestPayload(digest, format, "fleet-report-"+stamp)
	}

	r, err := s.report(ctx, false)
	if err != nil {
		return nil, fmt.Errorf("analysis: %w", err)
	}
	digest := singleDigest(r, s.history)
	payload, err := digestPayload(digest, format, "")
	if err != nil {
		return nil, err
	}
	// Single-cluster deliveries attach the full report, not just the digest.
	var full bytes.Buffer
	name := fmt.Sprintf("cluster-guardian-%s-%s.%s", fleet.SanitizeName(r.ClusterName), stamp, format)
	if format == "pdf" {
		err = report.WritePDF(&full, r)
	} else {
		err = report.WriteHTML(&full, r)
	}
	if err != nil {
		return nil, err
	}
	payload.Attachment = &deliver.Attachment{Name: name, MIME: mimeFor(format), Data: full.Bytes()}
	payload.JSON, err = json.Marshal(r)
	return payload, err
}

// digestPayload renders a digest into a delivery payload; attachmentBase ""
// skips the digest attachment (the caller attaches something better).
func digestPayload(digest report.Digest, format, attachmentBase string) (*deliver.Payload, error) {
	var body bytes.Buffer
	if err := report.WriteDigestHTML(&body, digest); err != nil {
		return nil, err
	}
	jsonBody, err := json.Marshal(digest)
	if err != nil {
		return nil, err
	}
	p := &deliver.Payload{
		Subject:  digest.Title + " — " + digest.GeneratedAt.Format("2006-01-02"),
		HTMLBody: body.Bytes(),
		JSON:     jsonBody,
	}
	if attachmentBase != "" {
		var att bytes.Buffer
		if format == "pdf" {
			err = report.WriteDigestPDF(&att, digest)
		} else {
			att.Write(body.Bytes())
		}
		if err != nil {
			return nil, err
		}
		p.Attachment = &deliver.Attachment{Name: attachmentBase + "." + format, MIME: mimeFor(format), Data: att.Bytes()}
	}
	return p, nil
}

func mimeFor(format string) string {
	if format == "pdf" {
		return "application/pdf"
	}
	return "text/html; charset=utf-8"
}

// fleetDigest summarizes every registered cluster: grade, score movement
// since the previous scan, and newly appeared criticals.
func fleetDigest(m *fleet.Manager) report.Digest {
	d := report.Digest{Title: "Cluster Guardian — fleet report", GeneratedAt: time.Now().UTC()}
	for _, st := range m.Statuses() {
		c := report.DigestCluster{Name: st.Name, Error: st.Error}
		if st.Summary != nil {
			c.Grade = st.Summary.Grade
			c.Score = st.Summary.Score
			c.Critical = st.Summary.Critical
			c.Warnings = st.Summary.Warnings
		}
		c.ScoreDelta = scoreDelta(m.History(st.Name))
		if diff := m.Diff(st.Name); diff != nil {
			c.NewCritical = countCritical(diff.New)
		}
		d.Clusters = append(d.Clusters, c)
	}
	return d
}

// singleDigest summarizes one cluster's fresh report.
func singleDigest(r *report.Report, hist *history.Store) report.Digest {
	c := report.DigestCluster{
		Name:     r.ClusterName,
		Grade:    r.Summary.Grade,
		Score:    r.Summary.Score,
		Critical: r.Summary.Critical,
		Warnings: r.Summary.Warnings,
	}
	if hist != nil {
		c.ScoreDelta = scoreDelta(hist.Entries())
		if diff := hist.LastDiff(); diff != nil {
			c.NewCritical = countCritical(diff.New)
		}
	}
	return report.Digest{
		Title:       "Cluster Guardian — " + r.ClusterName,
		GeneratedAt: time.Now().UTC(),
		Clusters:    []report.DigestCluster{c},
	}
}

func scoreDelta(entries []history.Entry) *int {
	if len(entries) < 2 {
		return nil
	}
	delta := entries[len(entries)-1].Summary.Score - entries[len(entries)-2].Summary.Score
	return &delta
}

func countCritical(fs []report.LocatedFinding) int {
	n := 0
	for _, f := range fs {
		if f.Severity == report.SeverityCritical {
			n++
		}
	}
	return n
}
