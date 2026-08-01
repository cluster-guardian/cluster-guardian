package checks

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/cluster-guardian/cluster-guardian/internal/kube"
	"github.com/cluster-guardian/cluster-guardian/internal/report"
)

// capacityThreshold is the requests/allocatable ratio above which a node is
// considered close to full.
const capacityThreshold = 0.90

// kubeletSkewLimit is how many minor versions a kubelet may trail the
// control plane before upgrades are blocked.
const kubeletSkewLimit = 2

// Nodes runs node-level checks: conditions, version skew, topology and
// capacity. The section is empty when the snapshot holds no nodes (listing
// them needs cluster-wide RBAC and degrades gracefully).
func Nodes(s *kube.Snapshot) report.Section {
	sec := report.Section{ID: "nodes", Title: "Nodes", Icon: "🖥️"}
	if len(s.Nodes) == 0 {
		return sec
	}
	sec.Findings = append(sec.Findings, nodeConditionFindings(s.Nodes)...)
	sec.Findings = append(sec.Findings, nodeVersionFindings(s.Nodes, s.ClusterVersion)...)
	sec.Findings = append(sec.Findings, nodeTopologyFindings(s.Nodes)...)
	sec.Findings = append(sec.Findings, nodeCapacityFindings(s.Nodes, s.Pods)...)
	return sec
}

// nodeConditionFindings flags NotReady nodes, resource pressure, and
// cordoned nodes.
func nodeConditionFindings(nodes []corev1.Node) []report.Finding {
	var notReady, cordoned []string
	pressure := map[string][]string{}
	for _, n := range nodes {
		if n.Spec.Unschedulable {
			cordoned = append(cordoned, n.Name)
		}
		for _, c := range n.Status.Conditions {
			switch c.Type {
			case corev1.NodeReady:
				if c.Status != corev1.ConditionTrue {
					notReady = append(notReady, n.Name)
				}
			case corev1.NodeMemoryPressure, corev1.NodeDiskPressure, corev1.NodePIDPressure:
				if c.Status == corev1.ConditionTrue {
					pressure[string(c.Type)] = append(pressure[string(c.Type)], n.Name)
				}
			}
		}
	}

	var out []report.Finding
	if n := len(notReady); n > 0 {
		out = append(out, report.Finding{
			Severity: report.SeverityCritical,
			Message:  fmt.Sprintf("%d %s NotReady (%s)", n, plural(n, "node is", "nodes are"), joinLimited(notReady, 4)),
			Hint:     "Check kubelet health and node connectivity; pods on these nodes may be rescheduled or stuck.",
		})
	}
	for _, cond := range slices.Sorted(maps.Keys(pressure)) {
		names := pressure[cond]
		out = append(out, report.Finding{
			Severity: report.SeverityWarning,
			Message:  fmt.Sprintf("%d %s under %s (%s)", len(names), plural(len(names), "node", "nodes"), cond, joinLimited(names, 4)),
		})
	}
	if n := len(cordoned); n > 0 {
		out = append(out, report.Finding{
			Severity: report.SeverityWarning,
			Message:  fmt.Sprintf("%d %s cordoned (%s)", n, plural(n, "node is", "nodes are"), joinLimited(cordoned, 4)),
			Hint:     "Cordoned nodes take no new pods. Uncordon them if the maintenance is over.",
		})
	}
	return out
}

// nodeVersionFindings flags kubelets trailing the control plane by more than
// the supported skew, and mixed kubelet versions across the pool.
func nodeVersionFindings(nodes []corev1.Node, clusterVersion string) []report.Finding {
	controlMinor := clusterMinor(clusterVersion)

	versions := map[string][]string{} // kubelet version -> node names
	var behind []string
	for _, n := range nodes {
		v := n.Status.NodeInfo.KubeletVersion
		versions[v] = append(versions[v], n.Name)
		if m := clusterMinor(v); controlMinor > 0 && m > 0 && controlMinor-m > kubeletSkewLimit {
			behind = append(behind, fmt.Sprintf("%s (%s)", n.Name, v))
		}
	}

	var out []report.Finding
	if n := len(behind); n > 0 {
		out = append(out, report.Finding{
			Severity: report.SeverityWarning,
			Message: fmt.Sprintf("%d %s more than %d minors behind the %s control plane: %s",
				n, plural(n, "kubelet is", "kubelets are"), kubeletSkewLimit, clusterVersion, joinLimited(behind, 4)),
			Hint: "Kubelets outside the supported skew block control-plane upgrades. Upgrade these nodes first.",
		})
	}
	if len(versions) > 1 {
		out = append(out, report.Finding{
			Severity: report.SeverityInfo,
			Message: fmt.Sprintf("Mixed kubelet versions across the pool (%s)",
				joinLimited(slices.Sorted(maps.Keys(versions)), 4)),
			Hint: "A partially finished upgrade? Converge nodes onto one version.",
		})
	}
	return out
}

// nodeTopologyFindings flags single-zone pools and untainted control-plane
// nodes in mixed clusters.
func nodeTopologyFindings(nodes []corev1.Node) []report.Finding {
	zones := map[string]bool{}
	labeled := 0
	var workers, untaintedCP []string
	for _, n := range nodes {
		zone := n.Labels["topology.kubernetes.io/zone"]
		if zone == "" {
			zone = n.Labels["failure-domain.beta.kubernetes.io/zone"]
		}
		if zone != "" {
			labeled++
			zones[zone] = true
		}

		if isControlPlaneNode(n) {
			if !hasControlPlaneTaint(n) {
				untaintedCP = append(untaintedCP, n.Name)
			}
		} else {
			workers = append(workers, n.Name)
		}
	}

	var out []report.Finding
	if len(nodes) >= 2 && labeled == len(nodes) && len(zones) == 1 {
		out = append(out, report.Finding{
			Severity: report.SeverityInfo,
			Message:  fmt.Sprintf("All %d nodes are in a single zone (%s)", len(nodes), joinLimited(slices.Sorted(maps.Keys(zones)), 1)),
			Hint:     "One zone outage takes down the whole cluster; spread node pools across zones.",
		})
	}
	// Untainted control planes are intentional on single-node/all-CP
	// clusters; only mixed clusters get flagged.
	if len(untaintedCP) > 0 && len(workers) > 0 {
		n := len(untaintedCP)
		out = append(out, report.Finding{
			Severity: report.SeverityInfo,
			Message:  fmt.Sprintf("%d control-plane %s without a control-plane taint (%s)", n, plural(n, "node", "nodes"), joinLimited(untaintedCP, 4)),
			Hint:     "Workloads can schedule onto the control plane and starve cluster components.",
		})
	}
	return out
}

func isControlPlaneNode(n corev1.Node) bool {
	_, cp := n.Labels["node-role.kubernetes.io/control-plane"]
	_, master := n.Labels["node-role.kubernetes.io/master"]
	return cp || master
}

func hasControlPlaneTaint(n corev1.Node) bool {
	for _, t := range n.Spec.Taints {
		if t.Key == "node-role.kubernetes.io/control-plane" || t.Key == "node-role.kubernetes.io/master" {
			return true
		}
	}
	return false
}

// nodeCapacityFindings flags nodes whose summed pod requests are close to
// allocatable CPU or memory.
func nodeCapacityFindings(nodes []corev1.Node, pods []corev1.Pod) []report.Finding {
	type requests struct{ cpu, mem float64 }
	byNode := map[string]requests{}
	for _, p := range pods {
		if p.Spec.NodeName == "" || p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		r := byNode[p.Spec.NodeName]
		for _, c := range p.Spec.Containers {
			r.cpu += float64(c.Resources.Requests.Cpu().MilliValue()) / 1000
			r.mem += float64(c.Resources.Requests.Memory().Value())
		}
		byNode[p.Spec.NodeName] = r
	}

	var full []string
	for _, n := range nodes {
		r := byNode[n.Name]
		allocCPU := float64(n.Status.Allocatable.Cpu().MilliValue()) / 1000
		allocMem := float64(n.Status.Allocatable.Memory().Value())
		var reasons []string
		if allocCPU > 0 && r.cpu/allocCPU > capacityThreshold {
			reasons = append(reasons, fmt.Sprintf("cpu %.0f%%", r.cpu/allocCPU*100))
		}
		if allocMem > 0 && r.mem/allocMem > capacityThreshold {
			reasons = append(reasons, fmt.Sprintf("memory %.0f%%", r.mem/allocMem*100))
		}
		if len(reasons) > 0 {
			full = append(full, fmt.Sprintf("%s (%s)", n.Name, strings.Join(reasons, ", ")))
		}
	}
	if len(full) == 0 {
		return nil
	}
	n := len(full)
	return []report.Finding{{
		Severity: report.SeverityWarning,
		Message: fmt.Sprintf("%d %s near allocatable limits: %s",
			n, plural(n, "node is", "nodes are"), joinLimited(full, 4)),
		Hint: "Nodes above ~90% requested capacity leave no room for rescheduling during drains or failures; add capacity or right-size requests.",
	}}
}
