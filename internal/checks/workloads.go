// Package checks contains the analysis checks. Each check is a pure function
// over a kube.Snapshot producing report findings, which keeps them
// unit-testable without a cluster.
package checks

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/cluster-guardian/cluster-guardian/internal/kube"
	"github.com/cluster-guardian/cluster-guardian/internal/report"
)

// Namespaces runs all per-namespace workload checks and returns one section
// per namespace that has findings (plus healthy namespaces with none).
func Namespaces(s *kube.Snapshot, names []string) []report.NamespaceSection {
	var out []report.NamespaceSection
	for _, ns := range names {
		var findings []report.Finding
		findings = append(findings, resourceFindings(s, ns)...)
		findings = append(findings, healthFindings(s, ns)...)
		findings = append(findings, imageFindings(s, ns)...)
		findings = append(findings, probeFindings(s, ns)...)
		findings = append(findings, availabilityFindings(s, ns)...)
		findings = append(findings, disruptionFindings(s, ns)...)
		findings = append(findings, unusedFindings(s, ns)...)
		out = append(out, report.NamespaceSection{Name: ns, Findings: findings})
	}
	sort.Slice(out, func(i, j int) bool {
		si, sj := out[i].MaxSeverity(), out[j].MaxSeverity()
		if si != sj {
			return si > sj
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// resourceFindings flags pods missing CPU/memory requests and limits.
func resourceFindings(s *kube.Snapshot, ns string) []report.Finding {
	var missingRequests, missingLimits int
	for _, pod := range s.Pods {
		if pod.Namespace != ns || pod.Status.Phase == corev1.PodSucceeded {
			continue
		}
		reqOK, limOK := true, true
		for _, c := range pod.Spec.Containers {
			if c.Resources.Requests.Cpu().IsZero() || c.Resources.Requests.Memory().IsZero() {
				reqOK = false
			}
			if c.Resources.Limits.Memory().IsZero() {
				limOK = false
			}
		}
		if !reqOK {
			missingRequests++
		}
		if !limOK {
			missingLimits++
		}
	}
	var out []report.Finding
	if missingRequests > 0 {
		out = append(out, report.Finding{
			Severity: report.SeverityWarning,
			Message:  fmt.Sprintf("%d %s missing resource requests", missingRequests, plural(missingRequests, "Pod", "Pods")),
			Hint:     "Set spec.containers[].resources.requests for CPU and memory so the scheduler can place pods reliably.",
		})
	}
	if missingLimits > 0 {
		out = append(out, report.Finding{
			Severity: report.SeverityInfo,
			Message:  fmt.Sprintf("%d %s missing memory limits", missingLimits, plural(missingLimits, "Pod", "Pods")),
			Hint:     "Memory limits protect nodes from a single pod consuming all memory.",
		})
	}
	return out
}

// healthFindings detects unhealthy pods: CrashLoopBackOff, ImagePullBackOff,
// Pending, OOMKilled and restart storms.
func healthFindings(s *kube.Snapshot, ns string) []report.Finding {
	waitingReasons := map[string]int{}
	var pending, oomKilled, restartStorm int
	for _, pod := range s.Pods {
		if pod.Namespace != ns {
			continue
		}
		if pod.Status.Phase == corev1.PodPending && pod.DeletionTimestamp == nil {
			pending++
		}
		for _, cs := range pod.Status.ContainerStatuses {
			if w := cs.State.Waiting; w != nil {
				switch w.Reason {
				case "CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull", "CreateContainerConfigError", "CreateContainerError", "InvalidImageName":
					waitingReasons[w.Reason]++
				}
			}
			if t := cs.LastTerminationState.Terminated; t != nil && t.Reason == "OOMKilled" {
				oomKilled++
			}
			if cs.RestartCount >= 10 {
				restartStorm++
			}
		}
	}

	var out []report.Finding
	for _, reason := range slices.Sorted(maps.Keys(waitingReasons)) {
		n := waitingReasons[reason]
		sev := report.SeverityWarning
		if reason == "CrashLoopBackOff" {
			sev = report.SeverityCritical
		}
		out = append(out, report.Finding{
			Severity: sev,
			Message:  fmt.Sprintf("%d %s %s", n, reason, plural(n, "container", "containers")),
		})
	}
	if pending > 0 {
		out = append(out, report.Finding{
			Severity: report.SeverityWarning,
			Message:  fmt.Sprintf("%d %s stuck in Pending", pending, plural(pending, "Pod", "Pods")),
			Hint:     "Check node capacity, taints/tolerations and PVC binding.",
		})
	}
	if oomKilled > 0 {
		out = append(out, report.Finding{
			Severity: report.SeverityWarning,
			Message:  fmt.Sprintf("%d %s recently OOMKilled", oomKilled, plural(oomKilled, "container", "containers")),
			Hint:     "Raise memory limits or investigate memory leaks.",
		})
	}
	if restartStorm > 0 {
		out = append(out, report.Finding{
			Severity: report.SeverityWarning,
			Message:  fmt.Sprintf("%d %s with 10+ restarts", restartStorm, plural(restartStorm, "container", "containers")),
		})
	}
	return out
}

// imageFindings flags workloads using mutable :latest (or untagged) images.
func imageFindings(s *kube.Snapshot, ns string) []report.Finding {
	var out []report.Finding
	forEachWorkloadPodSpec(s, ns, func(kind, name string, spec corev1.PodSpec) {
		for _, c := range spec.Containers {
			if isLatestImage(c.Image) {
				out = append(out, report.Finding{
					Severity: report.SeverityWarning,
					Message:  fmt.Sprintf("%s %q uses :latest tag", kind, name),
					Object:   fmt.Sprintf("%s/%s", strings.ToLower(kind), name),
					Hint:     "Pin images to an immutable tag or digest for reproducible deploys and clean rollbacks.",
				})
				return
			}
		}
	})
	return out
}

func isLatestImage(image string) bool {
	if strings.Contains(image, "@sha256:") {
		return false
	}
	// Split off registry:port before checking the tag.
	slash := strings.LastIndex(image, "/")
	tail := image[slash+1:]
	colon := strings.LastIndex(tail, ":")
	if colon == -1 {
		return true // untagged defaults to :latest
	}
	return tail[colon+1:] == "latest"
}

// probeFindings flags containers missing readiness/liveness probes.
func probeFindings(s *kube.Snapshot, ns string) []report.Finding {
	var noReadiness, noLiveness int
	forEachWorkloadPodSpec(s, ns, func(kind, _ string, spec corev1.PodSpec) {
		// CronJob containers are short-lived and don't serve traffic, so
		// probes are not expected on them.
		if kind == "CronJob" {
			return
		}
		for _, c := range spec.Containers {
			if c.ReadinessProbe == nil && c.StartupProbe == nil {
				noReadiness++
			}
			if c.LivenessProbe == nil {
				noLiveness++
			}
		}
	})
	var out []report.Finding
	if noReadiness > 0 {
		out = append(out, report.Finding{
			Severity: report.SeverityWarning,
			Message:  fmt.Sprintf("%d %s without readiness or startup probes", noReadiness, plural(noReadiness, "container", "containers")),
			Hint:     "Without readiness probes, traffic is routed to pods before they can serve it.",
		})
	}
	if noLiveness > 0 {
		out = append(out, report.Finding{
			Severity: report.SeverityInfo,
			Message:  fmt.Sprintf("%d %s without liveness probes", noLiveness, plural(noLiveness, "container", "containers")),
		})
	}
	return out
}

// availabilityFindings flags single-replica deployments and deployments
// without a HorizontalPodAutoscaler.
func availabilityFindings(s *kube.Snapshot, ns string) []report.Finding {
	hpaTargets := map[string]bool{}
	for _, hpa := range s.HPAs {
		if hpa.Namespace == ns {
			hpaTargets[hpa.Spec.ScaleTargetRef.Kind+"/"+hpa.Spec.ScaleTargetRef.Name] = true
		}
	}

	var out []report.Finding
	var singleReplica, noHPA []string
	var deployments int
	for _, d := range s.Deployments {
		if d.Namespace != ns {
			continue
		}
		deployments++
		if d.Spec.Replicas != nil && *d.Spec.Replicas == 1 {
			singleReplica = append(singleReplica, d.Name)
		}
		if !hpaTargets["Deployment/"+d.Name] {
			noHPA = append(noHPA, d.Name)
		}
	}
	if len(singleReplica) > 0 {
		out = append(out, report.Finding{
			Severity: report.SeverityInfo,
			Message:  fmt.Sprintf("%d single-replica %s (%s)", len(singleReplica), plural(len(singleReplica), "Deployment", "Deployments"), joinLimited(singleReplica, 4)),
			Hint:     "Single replicas mean downtime on every rollout, eviction or node failure.",
		})
	}
	if len(noHPA) > 0 {
		msg := "Missing HorizontalPodAutoscaler"
		if len(noHPA) < deployments || len(noHPA) > 1 {
			msg = fmt.Sprintf("Missing HorizontalPodAutoscaler for %s", joinLimited(noHPA, 4))
		}
		out = append(out, report.Finding{
			Severity: report.SeverityInfo,
			Message:  msg,
			Hint:     "HPAs absorb load spikes without manual scaling.",
		})
	}
	return out
}
