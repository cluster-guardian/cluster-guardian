package checks

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cluster-guardian/cluster-guardian/internal/kube"
	"github.com/cluster-guardian/cluster-guardian/internal/report"
)

func node(name string, mutate func(*corev1.Node)) corev1.Node {
	n := corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{"topology.kubernetes.io/zone": "eu-1a"},
		},
		Status: corev1.NodeStatus{
			NodeInfo: corev1.NodeSystemInfo{KubeletVersion: "v1.31.4"},
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
			},
			Allocatable: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("4"),
				corev1.ResourceMemory: resource.MustParse("16Gi"),
			},
		},
	}
	if mutate != nil {
		mutate(&n)
	}
	return n
}

func TestNodes(t *testing.T) {
	s := &kube.Snapshot{
		ClusterVersion: "v1.31.4+k3s1",
		Nodes: []corev1.Node{
			node("worker-1", nil),
			node("worker-2", func(n *corev1.Node) {
				n.Status.Conditions = []corev1.NodeCondition{
					{Type: corev1.NodeReady, Status: corev1.ConditionFalse},
					{Type: corev1.NodeMemoryPressure, Status: corev1.ConditionTrue},
				}
			}),
			node("worker-3", func(n *corev1.Node) {
				n.Spec.Unschedulable = true
				n.Status.NodeInfo.KubeletVersion = "v1.28.2" // 3 minors behind
			}),
			node("cp-1", func(n *corev1.Node) {
				n.Labels["node-role.kubernetes.io/control-plane"] = ""
				// No control-plane taint in a mixed cluster -> flagged.
			}),
		},
		Pods: []corev1.Pod{
			pod("payments", "big-1", func(p *corev1.Pod) {
				p.Spec.NodeName = "worker-1"
				p.Spec.Containers[0].Resources = corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("3900m"), // 97.5% of 4 cores
						corev1.ResourceMemory: resource.MustParse("1Gi"),
					},
				}
			}),
		},
	}

	fs := Nodes(s).Findings

	if f := findMessage(fs, "NotReady"); f == nil || f.Severity != report.SeverityCritical || !strings.Contains(f.Message, "worker-2") {
		t.Errorf("expected critical NotReady finding for worker-2, got: %+v", messages(fs))
	}
	if f := findMessage(fs, "MemoryPressure"); f == nil || f.Severity != report.SeverityWarning {
		t.Errorf("expected MemoryPressure warning, got: %+v", messages(fs))
	}
	if f := findMessage(fs, "cordoned"); f == nil || !strings.Contains(f.Message, "worker-3") {
		t.Errorf("expected cordoned finding for worker-3, got: %+v", messages(fs))
	}
	if f := findMessage(fs, "behind the v1.31.4+k3s1 control plane"); f == nil ||
		f.Severity != report.SeverityWarning || !strings.Contains(f.Message, "worker-3 (v1.28.2)") {
		t.Errorf("expected version-skew warning for worker-3, got: %+v", messages(fs))
	}
	if f := findMessage(fs, "Mixed kubelet versions"); f == nil || f.Severity != report.SeverityInfo {
		t.Errorf("expected mixed-versions info, got: %+v", messages(fs))
	}
	if f := findMessage(fs, "single zone"); f == nil || !strings.Contains(f.Message, "eu-1a") {
		t.Errorf("expected single-zone finding, got: %+v", messages(fs))
	}
	if f := findMessage(fs, "without a control-plane taint"); f == nil || !strings.Contains(f.Message, "cp-1") {
		t.Errorf("expected untainted control-plane finding, got: %+v", messages(fs))
	}
	if f := findMessage(fs, "near allocatable limits"); f == nil ||
		f.Severity != report.SeverityWarning || !strings.Contains(f.Message, "worker-1 (cpu 98%)") {
		t.Errorf("expected capacity warning for worker-1, got: %+v", messages(fs))
	}
}

func TestNodesQuiet(t *testing.T) {
	// No nodes in the snapshot (no RBAC): the section stays empty.
	if fs := Nodes(&kube.Snapshot{}).Findings; len(fs) != 0 {
		t.Errorf("expected no findings without nodes, got: %+v", messages(fs))
	}

	// A healthy single-node cluster (k3s-style): untainted control plane and
	// a single zone are intentional there, kubelet matches the control plane.
	s := &kube.Snapshot{
		ClusterVersion: "v1.31.4+k3s1",
		Nodes: []corev1.Node{node("solo", func(n *corev1.Node) {
			n.Labels["node-role.kubernetes.io/control-plane"] = ""
		})},
	}
	if fs := Nodes(s).Findings; len(fs) != 0 {
		t.Errorf("expected no findings for a healthy single node, got: %+v", messages(fs))
	}
}
