package checks

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/cluster-guardian/cluster-guardian/internal/kube"
	"github.com/cluster-guardian/cluster-guardian/internal/report"
)

// disruptionFindings flags multi-replica workloads a node drain or zone outage
// could take down all at once: missing PodDisruptionBudgets, PDBs that permit
// zero disruptions, and pod templates with no spreading constraints.
func disruptionFindings(s *kube.Snapshot, ns string) []report.Finding {
	type workload struct {
		kind, name string
		replicas   int32
		podLabels  labels.Set
		spec       corev1.PodSpec
	}
	var workloads []workload
	for _, d := range s.Deployments {
		if d.Namespace == ns && d.Spec.Replicas != nil && *d.Spec.Replicas >= 2 {
			workloads = append(workloads, workload{"Deployment", d.Name, *d.Spec.Replicas, d.Spec.Template.Labels, d.Spec.Template.Spec})
		}
	}
	for _, ss := range s.StatefulSets {
		if ss.Namespace == ns && ss.Spec.Replicas != nil && *ss.Spec.Replicas >= 2 {
			workloads = append(workloads, workload{"StatefulSet", ss.Name, *ss.Spec.Replicas, ss.Spec.Template.Labels, ss.Spec.Template.Spec})
		}
	}
	if len(workloads) == 0 {
		return nil
	}

	var out []report.Finding
	covered := map[string]bool{}
	for _, pdb := range s.PDBs {
		if pdb.Namespace != ns {
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
		if err != nil {
			continue
		}
		blocking := maxUnavailableIsZero(pdb.Spec.MaxUnavailable)
		for _, w := range workloads {
			if !sel.Matches(w.podLabels) {
				continue
			}
			covered[w.kind+"/"+w.name] = true
			blocking = blocking || minAvailableBlocks(pdb.Spec.MinAvailable, w.replicas)
		}
		if blocking {
			out = append(out, report.Finding{
				Severity: report.SeverityWarning,
				Message:  fmt.Sprintf("PodDisruptionBudget %q allows zero voluntary disruptions", pdb.Name),
				Object:   "poddisruptionbudget/" + pdb.Name,
				Hint:     "A PDB with maxUnavailable: 0 (or minAvailable equal to the replica count) blocks node drains and delays cluster upgrades.",
			})
		}
	}

	var noPDB, noSpread []string
	for _, w := range workloads {
		if !covered[w.kind+"/"+w.name] {
			noPDB = append(noPDB, w.name)
		}
		if len(w.spec.TopologySpreadConstraints) == 0 && (w.spec.Affinity == nil || w.spec.Affinity.PodAntiAffinity == nil) {
			noSpread = append(noSpread, w.name)
		}
	}
	if n := len(noPDB); n > 0 {
		out = append(out, report.Finding{
			Severity: report.SeverityWarning,
			Message:  fmt.Sprintf("%d multi-replica %s without a PodDisruptionBudget (%s)", n, plural(n, "workload", "workloads"), joinLimited(noPDB, 4)),
			Hint:     "Without a PDB, a node drain may evict every replica at once and cause downtime during maintenance.",
		})
	}
	if n := len(noSpread); n > 0 {
		out = append(out, report.Finding{
			Severity: report.SeverityInfo,
			Message:  fmt.Sprintf("%d multi-replica %s without topologySpreadConstraints or pod anti-affinity (%s)", n, plural(n, "workload", "workloads"), joinLimited(noSpread, 4)),
			Hint:     "Replicas may be scheduled onto the same node or zone, so one failure can take all of them down.",
		})
	}
	return out
}

func maxUnavailableIsZero(mu *intstr.IntOrString) bool {
	if mu == nil {
		return false
	}
	if mu.Type == intstr.Int {
		return mu.IntValue() == 0
	}
	return mu.StrVal == "0" || mu.StrVal == "0%"
}

func minAvailableBlocks(ma *intstr.IntOrString, replicas int32) bool {
	if ma == nil {
		return false
	}
	if ma.Type == intstr.Int {
		return int32(ma.IntValue()) >= replicas
	}
	return ma.StrVal == "100%"
}
