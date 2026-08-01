package checks

import (
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cluster-guardian/cluster-guardian/internal/kube"
	"github.com/cluster-guardian/cluster-guardian/internal/report"
)

const testMi = 1 << 20

// rsDeployment builds a deployment whose pods are selected by app=<name>.
func rsDeployment(ns, name, cpuReq, memReq string) appsv1.Deployment {
	d := deployment(ns, name, "registry.io/app:v1", 2)
	d.Spec.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{"app": name}}
	if cpuReq != "" {
		d.Spec.Template.Spec.Containers[0].Resources = corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(cpuReq),
				corev1.ResourceMemory: resource.MustParse(memReq),
			},
		}
	}
	return d
}

func rsPod(ns, name, app string) corev1.Pod {
	return pod(ns, name, func(p *corev1.Pod) { p.Labels = map[string]string{"app": app} })
}

func TestRightsize(t *testing.T) {
	s := &kube.Snapshot{
		Deployments: []appsv1.Deployment{
			rsDeployment("payments", "api", "500m", "1Gi"),    // overprovisioned
			rsDeployment("payments", "hungry", "100m", "1Gi"), // cpu P95 above request
			rsDeployment("payments", "bare", "", ""),          // no requests at all
			rsDeployment("payments", "sized", "120m", "256Mi"),
			rsDeployment("payments", "no-data", "500m", "1Gi"), // no usage samples
		},
		Pods: []corev1.Pod{
			rsPod("payments", "api-1", "api"),
			rsPod("payments", "api-2", "api"),
			rsPod("payments", "hungry-1", "hungry"),
			rsPod("payments", "bare-1", "bare"),
			rsPod("payments", "sized-1", "sized"),
			rsPod("payments", "no-data-1", "no-data"),
		},
	}
	usage := Usage{
		"payments/api-1":    {CPUP50: 0.05, CPUP95: 0.10, CPUMax: 0.20, MemMax: 200 * testMi},
		"payments/api-2":    {CPUP50: 0.04, CPUP95: 0.08, CPUMax: 0.15, MemMax: 180 * testMi},
		"payments/hungry-1": {CPUP50: 0.20, CPUP95: 0.30, CPUMax: 0.40, MemMax: 300 * testMi},
		"payments/bare-1":   {CPUP50: 0.05, CPUP95: 0.10, CPUMax: 0.20, MemMax: 200 * testMi},
		"payments/sized-1":  {CPUP50: 0.08, CPUP95: 0.10, CPUMax: 0.11, MemMax: 200 * testMi},
	}
	opts := RightsizingOptions{Window: 7 * 24 * time.Hour, CostPerCPUMonth: 15, CostPerGiBMonth: 2}

	sec := rightsize(s, []string{"payments"}, usage, opts)
	fs := sec.Findings

	// api: P95 0.10*1.1 -> 110m; mem max 200Mi*1.15 -> 230Mi -> 256Mi.
	f := findMessage(fs, `Deployment "api" is overprovisioned`)
	if f == nil {
		t.Fatalf("expected api recommendation, got: %+v", messages(fs))
	}
	if !strings.Contains(f.Message, "suggest requests cpu: 110m, memory: 256Mi") {
		t.Errorf("unexpected suggestion: %q", f.Message)
	}
	// Savings: cpu (0.5-0.11)*2*$15 = $11.7, mem (1Gi-256Mi = 0.75GiB)*2*$2 = $3.
	if !strings.Contains(f.Message, "saving ~$15/mo") {
		t.Errorf("expected ~$15/mo savings, got: %q", f.Message)
	}
	if !strings.Contains(f.Hint, `kubectl -n payments patch deployment api`) ||
		!strings.Contains(f.Hint, `"cpu":"110m"`) {
		t.Errorf("expected a kubectl patch hint, got: %q", f.Hint)
	}

	if f := findMessage(fs, `Deployment "hungry" is underprovisioned`); f == nil {
		t.Errorf("expected hungry flagged as underprovisioned, got: %+v", messages(fs))
	}
	if f := findMessage(fs, `Deployment "bare" has no resource requests`); f == nil {
		t.Errorf("expected bare flagged without requests, got: %+v", messages(fs))
	}
	for _, absent := range []string{`"sized"`, `"no-data"`} {
		if f := findMessage(fs, absent); f != nil {
			t.Errorf("workload %s must not be flagged: %q", absent, f.Message)
		}
	}

	// Summary first, biggest saver directly after it.
	if !strings.HasPrefix(fs[0].Message, "Estimated monthly savings from rightsizing: ~$") {
		t.Errorf("expected savings summary first, got %q", fs[0].Message)
	}
	if !strings.Contains(fs[1].Message, `"api"`) {
		t.Errorf("expected api sorted first by savings, got %q", fs[1].Message)
	}

	for _, f := range fs {
		if f.Severity != report.SeverityInfo {
			t.Errorf("rightsizing findings must be info, got %s for %q", f.Severity, f.Message)
		}
	}
}

func TestFormatQuantities(t *testing.T) {
	if got := formatCPU(0.11); got != "110m" {
		t.Errorf("formatCPU(0.11) = %q", got)
	}
	if got := formatCPU(1.5); got != "1.5" {
		t.Errorf("formatCPU(1.5) = %q", got)
	}
	if got := formatCPU(2); got != "2" {
		t.Errorf("formatCPU(2) = %q", got)
	}
	if got := formatMem(256 * testMi); got != "256Mi" {
		t.Errorf("formatMem(256Mi) = %q", got)
	}
	if got := formatMem(2048 * testMi); got != "2Gi" {
		t.Errorf("formatMem(2Gi) = %q", got)
	}
}
