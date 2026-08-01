package checks

import (
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/cluster-guardian/cluster-guardian/internal/kube"
	"github.com/cluster-guardian/cluster-guardian/internal/report"
)

// GitOps reports the health of Argo CD Applications and Flux resources.
func GitOps(s *kube.Snapshot) report.Section {
	sec := report.Section{ID: "gitops", Title: "GitOps", Icon: "🚀"}
	if !s.HasArgoCD && !s.HasFlux {
		sec.Findings = append(sec.Findings, report.Finding{
			Severity: report.SeverityInfo,
			Message:  "No GitOps tooling detected (Argo CD or Flux)",
			Hint:     "Declarative, Git-driven deploys make cluster state reproducible and auditable.",
		})
		return sec
	}

	if s.HasArgoCD {
		var degraded, outOfSync []string
		for _, app := range s.ArgoApplications {
			name := app.GetNamespace() + "/" + app.GetName()
			if health, _, _ := unstructured.NestedString(app.Object, "status", "health", "status"); health != "" && health != "Healthy" {
				degraded = append(degraded, fmt.Sprintf("%s (%s)", name, health))
			}
			if sync, _, _ := unstructured.NestedString(app.Object, "status", "sync", "status"); sync == "OutOfSync" {
				outOfSync = append(outOfSync, name)
			}
		}
		if len(degraded) > 0 {
			sec.Findings = append(sec.Findings, report.Finding{
				Severity: report.SeverityWarning,
				Message:  fmt.Sprintf("%d unhealthy Argo CD %s: %s", len(degraded), plural(len(degraded), "Application", "Applications"), joinLimited(degraded, 4)),
			})
		}
		if len(outOfSync) > 0 {
			sec.Findings = append(sec.Findings, report.Finding{
				Severity: report.SeverityWarning,
				Message:  fmt.Sprintf("%d Argo CD %s OutOfSync: %s", len(outOfSync), plural(len(outOfSync), "Application", "Applications"), joinLimited(outOfSync, 4)),
			})
		}
		if len(degraded) == 0 && len(outOfSync) == 0 {
			sec.Findings = append(sec.Findings, report.Finding{
				Severity: report.SeverityOK,
				Message:  fmt.Sprintf("All %d Argo CD Applications are Healthy and Synced", len(s.ArgoApplications)),
			})
		}
	}

	if s.HasFlux {
		notReady := fluxNotReady(s.FluxKustomizations, "Kustomization")
		notReady = append(notReady, fluxNotReady(s.FluxHelmReleases, "HelmRelease")...)
		if len(notReady) > 0 {
			sec.Findings = append(sec.Findings, report.Finding{
				Severity: report.SeverityWarning,
				Message:  fmt.Sprintf("%d Flux %s not Ready: %s", len(notReady), plural(len(notReady), "resource", "resources"), joinLimited(notReady, 4)),
			})
		} else {
			total := len(s.FluxKustomizations) + len(s.FluxHelmReleases)
			sec.Findings = append(sec.Findings, report.Finding{
				Severity: report.SeverityOK,
				Message:  fmt.Sprintf("All %d Flux resources are Ready", total),
			})
		}
	}
	return sec
}

func fluxNotReady(items []unstructured.Unstructured, kind string) []string {
	var out []string
	for _, item := range items {
		conditions, _, _ := unstructured.NestedSlice(item.Object, "status", "conditions")
		ready := false
		for _, c := range conditions {
			cm, ok := c.(map[string]any)
			if !ok {
				continue
			}
			t, _, _ := unstructured.NestedString(cm, "type")
			status, _, _ := unstructured.NestedString(cm, "status")
			if t == "Ready" && status == "True" {
				ready = true
			}
		}
		if !ready {
			out = append(out, fmt.Sprintf("%s %s/%s", kind, item.GetNamespace(), item.GetName()))
		}
	}
	return out
}
