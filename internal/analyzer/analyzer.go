// Package analyzer orchestrates the cluster snapshot and all checks into a
// single Report.
package analyzer

import (
	"context"
	"fmt"
	"time"

	"github.com/AndrewKarpaty/cluster-guardian/internal/checks"
	"github.com/AndrewKarpaty/cluster-guardian/internal/kube"
	"github.com/AndrewKarpaty/cluster-guardian/internal/report"
)

// Options control the scope of an analysis run.
type Options struct {
	// Namespaces limits the analysis; empty means all non-system namespaces.
	Namespaces []string
	// IncludeSystem also analyzes kube-system and friends.
	IncludeSystem bool
	// PrometheusURL enables usage-based optimization checks when set.
	PrometheusURL string
	// ClusterName overrides the display name (defaults to the kube context).
	ClusterName string

	// RightsizingReport adds the full per-workload rightsizing section
	// instead of folding the top recommendations into Optimization.
	RightsizingReport bool
	// RightsizingWindow is the usage lookback (default 7 days).
	RightsizingWindow time.Duration
	// CostPerCPUMonth and CostPerGiBMonth enable savings estimates.
	CostPerCPUMonth float64
	CostPerGiBMonth float64
}

// Run collects a snapshot and produces the full report.
func Run(ctx context.Context, client *kube.Client, opts Options) (*report.Report, error) {
	snapshot, err := client.Collect(ctx, opts.Namespaces)
	if err != nil {
		return nil, err
	}
	r := Analyze(ctx, snapshot, opts)
	if r.ClusterName == "" {
		r.ClusterName = client.Context
	}
	r.Context = client.Context
	return r, nil
}

// Analyze runs every check over an existing snapshot. Split from Run so tests
// can feed synthetic snapshots.
func Analyze(ctx context.Context, snapshot *kube.Snapshot, opts Options) *report.Report {
	namespaces := snapshot.AppNamespaces(opts.IncludeSystem, opts.Namespaces)

	r := &report.Report{
		ClusterName:       opts.ClusterName,
		KubernetesVersion: snapshot.ClusterVersion,
		GeneratedAt:       time.Now().UTC(),
		Namespaces:        checks.Namespaces(snapshot, namespaces),
		Sections: []report.Section{
			checks.Security(snapshot, namespaces),
			checks.Monitoring(snapshot, namespaces),
			checks.Certificates(snapshot, namespaces),
			checks.Deprecations(snapshot, namespaces),
			checks.GitOps(snapshot),
			checks.Optimization(ctx, snapshot, namespaces, opts.PrometheusURL),
		},
	}
	if opts.PrometheusURL != "" {
		addRightsizing(ctx, r, snapshot, namespaces, opts)
	}
	r.Finalize()
	return r
}

// topRightsizing caps how many recommendations are folded into the
// Optimization section when the full report is not requested.
const topRightsizing = 3

func addRightsizing(ctx context.Context, r *report.Report, snapshot *kube.Snapshot, namespaces []string, opts Options) {
	sec, err := checks.Rightsizing(ctx, snapshot, namespaces, opts.PrometheusURL, checks.RightsizingOptions{
		Window:          opts.RightsizingWindow,
		CostPerCPUMonth: opts.CostPerCPUMonth,
		CostPerGiBMonth: opts.CostPerGiBMonth,
	})
	if err != nil {
		// Optimization already surfaces Prometheus connectivity problems;
		// only the explicitly requested report explains its absence.
		if opts.RightsizingReport {
			sec.Findings = []report.Finding{{
				Severity: report.SeverityInfo,
				Message:  "Could not collect usage for rightsizing: " + err.Error(),
			}}
			r.Sections = append(r.Sections, sec)
		}
		return
	}
	if opts.RightsizingReport {
		r.Sections = append(r.Sections, sec)
		return
	}
	if len(sec.Findings) == 0 {
		return
	}
	top := sec.Findings
	if len(top) > topRightsizing {
		top = top[:topRightsizing]
	}
	for i := range r.Sections {
		if r.Sections[i].ID != "optimization" {
			continue
		}
		r.Sections[i].Findings = append(r.Sections[i].Findings, top...)
		if len(sec.Findings) > len(top) {
			r.Sections[i].Findings = append(r.Sections[i].Findings, report.Finding{
				Severity: report.SeverityInfo,
				Message:  fmt.Sprintf("Run with --rightsizing-report to see all %d rightsizing recommendations", len(sec.Findings)),
			})
		}
		return
	}
}
