package manifest

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/AndrewKarpaty/cluster-guardian/internal/analyzer"
	"github.com/AndrewKarpaty/cluster-guardian/internal/report"
)

const testManifests = `apiVersion: v1
kind: Namespace
metadata:
  name: payments
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: payments
spec:
  replicas: 1
  selector:
    matchLabels: {app: api}
  template:
    metadata:
      labels: {app: api}
    spec:
      containers:
        - name: app
          image: registry.io/api:latest
---
apiVersion: v1
kind: Service
metadata:
  name: api
  namespace: payments
spec:
  selector: {app: api}
  ports: [{port: 80}]
---
apiVersion: v1
kind: Service
metadata:
  name: ghost
  namespace: payments
spec:
  selector: {app: nothing-has-this-label}
  ports: [{port: 80}]
---
# no namespace: defaults to "default", like kubectl apply
apiVersion: batch/v1beta1
kind: CronJob
metadata:
  name: backup
spec:
  schedule: "0 0 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: backup
              image: backup:v1
`

func writeManifest(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "app.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLoad(t *testing.T) {
	s, namespaces, err := Load([]string{writeManifest(t, testManifests)}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(namespaces, []string{"default", "payments"}) {
		t.Errorf("expected declared+referenced namespaces, got %v", namespaces)
	}
	if len(s.Deployments) != 1 || *s.Deployments[0].Spec.Replicas != 1 {
		t.Fatalf("expected 1 deployment with replicas=1, got %+v", s.Deployments)
	}
	if len(s.Services) != 2 || len(s.CronJobs) != 1 {
		t.Errorf("expected 2 services and 1 cronjob, got %d/%d", len(s.Services), len(s.CronJobs))
	}
	if got := s.CronJobs[0].Namespace; got != "default" {
		t.Errorf("expected namespace defaulting, got %q", got)
	}
	// Original apiVersions land in managedFields for the Deprecations check.
	if mf := s.CronJobs[0].ManagedFields; len(mf) != 1 || mf[0].APIVersion != "batch/v1beta1" {
		t.Errorf("expected batch/v1beta1 in managedFields, got %+v", mf)
	}
	// One pod synthesized per workload template.
	if len(s.Pods) != 2 {
		t.Fatalf("expected 2 synthesized pods, got %d", len(s.Pods))
	}
	if s.Pods[0].Labels["app"] != "api" {
		t.Errorf("synthesized pod must carry template labels, got %v", s.Pods[0].Labels)
	}
}

func TestLoadStdin(t *testing.T) {
	s, namespaces, err := Load([]string{"-"}, strings.NewReader(testManifests))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Deployments) != 1 || len(namespaces) != 2 {
		t.Errorf("stdin load differs from file load: %d deployments, %v", len(s.Deployments), namespaces)
	}
}

func TestLoadBadYAML(t *testing.T) {
	dir := writeManifest(t, "kind: Deployment\napiVersion: apps/v1\nmetadata: [broken")
	if _, _, err := Load([]string{dir}, nil); err == nil {
		t.Error("expected a parse error for broken YAML")
	}
}

func TestLintReport(t *testing.T) {
	s, namespaces, err := Load([]string{writeManifest(t, testManifests)}, nil)
	if err != nil {
		t.Fatal(err)
	}

	r := analyzer.Lint(s, namespaces, "")
	if r.ClusterName != "manifests" {
		t.Errorf("expected default cluster name, got %q", r.ClusterName)
	}

	// Live-only sections must not appear.
	for _, sec := range r.Sections {
		switch sec.ID {
		case "monitoring", "gitops", "optimization", "nodes", "policy", "rightsizing":
			t.Errorf("live-only section %q must not run in lint mode", sec.ID)
		}
	}

	var all []report.Finding
	for _, ns := range r.Namespaces {
		all = append(all, ns.Findings...)
	}
	for _, sec := range r.Sections {
		all = append(all, sec.Findings...)
	}
	find := func(substr string) *report.Finding {
		for i := range all {
			if strings.Contains(all[i].Message, substr) {
				return &all[i]
			}
		}
		return nil
	}

	for _, want := range []string{
		`Deployment "api" uses :latest tag`, // workloads via manifest
		"missing resource requests",         // synthesized pod
		"without a seccomp profile",         // security via synthesized pod
		"Service with no matching Pods",     // ghost: selector matches nothing
		"batch/v1beta1",                     // deprecations via managedFields
		"without Pod Security Standards",    // declared namespace lacks the label
	} {
		if find(want) == nil {
			t.Errorf("expected a finding containing %q", want)
		}
	}
	if f := find("Service with no matching Pods"); f != nil && strings.Contains(f.Message, `"api"`) {
		t.Errorf("api service matches the synthesized pod and must not be flagged: %q", f.Message)
	}
	if r.Summary.Total == 0 || r.MaxSeverity() < report.SeverityWarning {
		t.Errorf("expected gating-relevant findings, got summary %+v", r.Summary)
	}
}
