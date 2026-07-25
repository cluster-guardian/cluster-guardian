package checks

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/AndrewKarpaty/cluster-guardian/internal/kube"
	"github.com/AndrewKarpaty/cluster-guardian/internal/report"
)

func gateway(ns, name string, certRefs ...map[string]any) unstructured.Unstructured {
	refs := make([]any, 0, len(certRefs))
	for _, r := range certRefs {
		refs = append(refs, r)
	}
	return unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"namespace": ns, "name": name},
		"spec": map[string]any{"listeners": []any{
			map[string]any{"name": "https", "tls": map[string]any{"certificateRefs": refs}},
		}},
	}}
}

func httpRoute(ns, name string, backends ...map[string]any) unstructured.Unstructured {
	refs := make([]any, 0, len(backends))
	for _, b := range backends {
		refs = append(refs, b)
	}
	return unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"namespace": ns, "name": name},
		"spec":     map[string]any{"rules": []any{map[string]any{"backendRefs": refs}}},
	}}
}

func TestGatewayCertificates(t *testing.T) {
	now := time.Date(2026, 7, 25, 0, 0, 0, 0, time.UTC)
	s := &kube.Snapshot{
		HasSecretAccess: true,
		HasGatewayAPI:   true,
		Secrets: []corev1.Secret{
			tlsSecret(t, "payments", "gw-soon", now.Add(3*24*time.Hour)),
			tlsSecret(t, "payments", "gw-ok", now.Add(90*24*time.Hour)),
		},
		Gateways: []unstructured.Unstructured{gateway("payments", "web-gw",
			map[string]any{"name": "gw-soon"},
			map[string]any{"name": "gw-ok"},
			map[string]any{"name": "gw-ghost"},
			map[string]any{"name": "other", "namespace": "elsewhere"}, // cross-ns: skipped
			map[string]any{"name": "cm-cert", "kind": "ConfigMap"},    // not a Secret: skipped
		)},
	}

	fs := certificates(s, []string{"payments"}, now).Findings

	if f := findMessage(fs, `"payments/gw-soon" expires in 3 days`); f == nil || f.Severity != report.SeverityCritical {
		t.Errorf("expected critical expiry for gw-soon, got: %+v", messages(fs))
	}
	if f := findMessage(fs, `Gateway "payments/web-gw" references missing TLS secret "gw-ghost"`); f == nil || f.Severity != report.SeverityWarning {
		t.Errorf("expected missing-secret warning for gw-ghost, got: %+v", messages(fs))
	}
	for _, quiet := range []string{"gw-ok", "elsewhere", "cm-cert"} {
		if f := findMessage(fs, quiet); f != nil {
			t.Errorf("%s must not be flagged: %q", quiet, f.Message)
		}
	}
}

func TestGatewayHygiene(t *testing.T) {
	meta := func(name string) metav1.ObjectMeta {
		return metav1.ObjectMeta{Namespace: "payments", Name: name}
	}
	s := &kube.Snapshot{
		HasGatewayAPI: true,
		Services: []corev1.Service{
			{ObjectMeta: meta("api")},
		},
		Secrets: []corev1.Secret{
			{ObjectMeta: meta("gw-tls")}, // referenced only by the Gateway
		},
		Gateways: []unstructured.Unstructured{gateway("payments", "web-gw",
			map[string]any{"name": "gw-tls"},
		)},
		HTTPRoutes: []unstructured.Unstructured{httpRoute("payments", "web",
			map[string]any{"name": "api"},
			map[string]any{"name": "gone"},
			map[string]any{"name": "other", "namespace": "elsewhere"}, // cross-ns: skipped
			map[string]any{"name": "grpc-be", "kind": "GRPCBackend"},  // not a Service: skipped
		)},
	}

	fs := unusedFindings(s, "payments")

	f := findMessage(fs, "HTTPRoute backend routing to a missing Service")
	if f == nil || !strings.Contains(f.Message, "web -> gone") {
		t.Fatalf("expected dangling HTTPRoute backend finding, got: %+v", messages(fs))
	}
	for _, quiet := range []string{"api", "elsewhere", "grpc-be"} {
		if strings.Contains(f.Message, quiet) {
			t.Errorf("backend %s must not be flagged: %q", quiet, f.Message)
		}
	}
	if f := findMessage(fs, "unused Secret"); f != nil {
		t.Errorf("gateway TLS secret must count as referenced, got: %q", f.Message)
	}
}
