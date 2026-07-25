package checks

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/AndrewKarpaty/cluster-guardian/internal/kube"
	"github.com/AndrewKarpaty/cluster-guardian/internal/report"
)

func policyReport(ns, name string, fails int64) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"namespace": ns, "name": name},
		"summary":  map[string]any{"fail": fails, "pass": int64(10)},
	}}
}

func constraint(kind, name string, violations int64, match map[string]any) unstructured.Unstructured {
	obj := map[string]any{
		"apiVersion": "constraints.gatekeeper.sh/v1beta1",
		"kind":       kind,
		"metadata":   map[string]any{"name": name},
		"status":     map[string]any{"totalViolations": violations},
	}
	if match != nil {
		obj["spec"] = map[string]any{"match": match}
	}
	return unstructured.Unstructured{Object: obj}
}

func TestPolicySilentWithoutEngines(t *testing.T) {
	if fs := Policy(&kube.Snapshot{}, []string{"payments"}).Findings; len(fs) != 0 {
		t.Errorf("expected no findings without policy engines, got: %+v", messages(fs))
	}
}

func TestPolicyViolations(t *testing.T) {
	s := &kube.Snapshot{
		HasKyverno: true,
		KyvernoPolicyReports: []unstructured.Unstructured{
			policyReport("payments", "pr-1", 3),
			policyReport("payments", "pr-2", 2),
			policyReport("secure", "pr-3", 0),
			policyReport("kube-system", "pr-4", 9), // not analyzed
		},
		KyvernoClusterPolicies: []unstructured.Unstructured{{Object: map[string]any{
			"metadata": map[string]any{"name": "require-requests"},
		}}},
		HasGatekeeper: true,
		GatekeeperConstraints: []unstructured.Unstructured{
			constraint("K8sRequiredLabels", "owner-label", 4, nil),
			constraint("K8sAllowedRepos", "repos", 0, nil),
		},
	}

	fs := Policy(s, []string{"payments", "secure"}).Findings

	if f := findMessage(fs, "Kyverno policy violations"); f == nil ||
		f.Severity != report.SeverityWarning ||
		!strings.HasPrefix(f.Message, "5 ") || !strings.Contains(f.Message, "payments: 5") {
		t.Errorf("expected 5 Kyverno violations in payments, got: %+v", messages(fs))
	}
	if f := findMessage(fs, "Gatekeeper constraint violations"); f == nil ||
		f.Severity != report.SeverityWarning ||
		!strings.Contains(f.Message, "K8sRequiredLabels owner-label (4)") {
		t.Errorf("expected 4 Gatekeeper violations, got: %+v", messages(fs))
	}
	// Blanket ClusterPolicy exists -> no coverage gap.
	if f := findMessage(fs, "not covered"); f != nil {
		t.Errorf("cluster-wide Kyverno policy must count as blanket coverage: %q", f.Message)
	}
}

func TestPolicyHealthyAndEmpty(t *testing.T) {
	s := &kube.Snapshot{
		HasKyverno: true,
		KyvernoClusterPolicies: []unstructured.Unstructured{{Object: map[string]any{
			"metadata": map[string]any{"name": "require-requests"},
		}}},
		HasGatekeeper: true, // installed, zero constraints
	}
	fs := Policy(s, []string{"payments"}).Findings

	if f := findMessage(fs, "Kyverno: 1 policy, no violations reported"); f == nil || f.Severity != report.SeverityOK {
		t.Errorf("expected Kyverno OK finding, got: %+v", messages(fs))
	}
	if f := findMessage(fs, "Gatekeeper is installed but no constraints are defined"); f == nil || f.Severity != report.SeverityInfo {
		t.Errorf("expected empty-Gatekeeper info, got: %+v", messages(fs))
	}
}

func TestPolicyCoverageGap(t *testing.T) {
	s := &kube.Snapshot{
		Pods: []corev1.Pod{
			pod("covered", "app-1", nil),
			pod("wild", "app-2", nil),
			pod("excluded", "app-3", nil),
		},
		HasGatekeeper: true,
		GatekeeperConstraints: []unstructured.Unstructured{
			constraint("K8sRequiredLabels", "scoped", 0, map[string]any{
				"namespaces": []any{"covered"},
			}),
			constraint("K8sAllowedRepos", "broad-with-exclusions", 0, map[string]any{
				"excludedNamespaces": []any{"wild", "excluded"},
			}),
		},
	}

	fs := Policy(s, []string{"covered", "wild", "excluded", "empty-ns"}).Findings

	f := findMessage(fs, "not covered by any admission policy")
	if f == nil || f.Severity != report.SeverityWarning {
		t.Fatalf("expected coverage-gap warning, got: %+v", messages(fs))
	}
	// Exactly wild + excluded: "covered" is matched by a constraint, and
	// podless empty-ns must stay quiet despite no coverage.
	if !strings.HasPrefix(f.Message, "2 ") ||
		!strings.Contains(f.Message, "(excluded, wild)") {
		t.Errorf("expected exactly wild and excluded flagged, got: %q", f.Message)
	}
}
