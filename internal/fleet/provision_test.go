package fleet

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// issuedToken pre-populates the token secret the fake clientset can't issue
// itself (no token controller runs in tests).
func issuedToken(ns, name string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Type:       corev1.SecretTypeServiceAccountToken,
		Data: map[string][]byte{
			corev1.ServiceAccountTokenKey:  []byte("issued-token"),
			corev1.ServiceAccountRootCAKey: []byte("ca-bytes"),
		},
	}
}

func TestProvision(t *testing.T) {
	cs := fake.NewSimpleClientset(issuedToken("cluster-guardian", "cluster-guardian-token"))

	creds, err := Provision(context.Background(), cs, ProvisionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if creds.Token != "issued-token" || string(creds.CAData) != "ca-bytes" {
		t.Errorf("unexpected credentials: %+v", creds)
	}

	if _, err := cs.CoreV1().ServiceAccounts("cluster-guardian").Get(context.Background(), "cluster-guardian", metav1.GetOptions{}); err != nil {
		t.Errorf("expected serviceaccount to be created: %v", err)
	}
	role, err := cs.RbacV1().ClusterRoles().Get(context.Background(), "cluster-guardian-readonly", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected clusterrole to be created: %v", err)
	}
	for _, rule := range role.Rules {
		// Verbs and groups must never be wildcarded; a resource wildcard is
		// allowed only when scoped to a specific group (Gatekeeper constraint
		// kinds are dynamic). The tool's own RBAC check flags */*/* roles.
		for _, list := range [][]string{rule.Verbs, rule.APIGroups} {
			for _, v := range list {
				if v == "*" {
					t.Errorf("provisioned role must not wildcard verbs or groups, got rule %+v", rule)
				}
			}
		}
		if slices.Contains(rule.Resources, "*") &&
			(len(rule.APIGroups) != 1 || rule.APIGroups[0] != "constraints.gatekeeper.sh") {
			t.Errorf("resource wildcard only allowed for the gatekeeper constraint group, got rule %+v", rule)
		}
		for _, verb := range rule.Verbs {
			if verb != "get" && verb != "list" {
				t.Errorf("provisioned role must be read-only, got verb %q", verb)
			}
		}
	}
	binding, err := cs.RbacV1().ClusterRoleBindings().Get(context.Background(), "cluster-guardian-readonly", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected clusterrolebinding to be created: %v", err)
	}
	if binding.RoleRef.Name != "cluster-guardian-readonly" ||
		len(binding.Subjects) != 1 || binding.Subjects[0].Name != "cluster-guardian" {
		t.Errorf("unexpected binding: %+v", binding)
	}
}

func TestProvisionTokenTimeout(t *testing.T) {
	cs := fake.NewSimpleClientset() // token controller never fills the secret
	_, err := Provision(context.Background(), cs, ProvisionOptions{TokenTimeout: 50 * time.Millisecond})
	if err == nil || !strings.Contains(err.Error(), "waiting for token") {
		t.Errorf("expected token wait timeout, got: %v", err)
	}
}

func TestClusterSecretRoundTrip(t *testing.T) {
	withCA, err := NewClusterSecret("guardian", ClusterSecretSpec{
		ClusterName: "prod",
		Server:      "https://prod.example.com:6443",
		BearerToken: "tok",
		CAData:      []byte("ca-bytes"),
	})
	if err != nil {
		t.Fatal(err)
	}
	// caData round-trips base64-encoded inside the config JSON.
	if config := string(withCA.Data["config"]); !strings.Contains(config, `"caData":"Y2EtYnl0ZXM="`) {
		t.Errorf("config must carry the CA data, got %s", config)
	}
	insecure, err := NewClusterSecret("guardian", ClusterSecretSpec{
		ClusterName: "prod", Server: "s", CAData: []byte("ca-bytes"), Insecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// client-go rejects a CA combined with the insecure flag, so the CA must
	// be dropped from the stored config.
	if config := string(insecure.Data["config"]); strings.Contains(config, "Y2EtYnl0ZXM=") {
		t.Errorf("insecure config must not carry CA data, got %s", config)
	}

	sec, err := NewClusterSecret("guardian", ClusterSecretSpec{
		ClusterName: "prod/eu-1",
		Server:      "https://prod.example.com:6443",
		BearerToken: "tok",
	})
	if err != nil {
		t.Fatal(err)
	}
	if sec.Name != "cluster-prod-eu-1" {
		t.Errorf("secret name must be sanitized, got %q", sec.Name)
	}
	if sec.Labels[SecretLabel] != "cluster" {
		t.Errorf("secret must carry the registry label, got %v", sec.Labels)
	}

	c, err := ParseClusterSecret(*sec)
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "prod/eu-1" || c.Server != "https://prod.example.com:6443" {
		t.Errorf("round trip lost fields: %+v", c)
	}
	client, err := c.Build()
	if err != nil {
		t.Fatal(err)
	}
	if client.Context != "prod/eu-1" || client.Server != "https://prod.example.com:6443" {
		t.Errorf("unexpected client identity: context %q server %q", client.Context, client.Server)
	}
}

func TestApplySecretUpdatesExisting(t *testing.T) {
	cs := fake.NewSimpleClientset()
	build := func(token string) *corev1.Secret {
		sec, err := NewClusterSecret("guardian", ClusterSecretSpec{
			ClusterName: "prod", Server: "https://prod.example.com:6443", BearerToken: token,
		})
		if err != nil {
			t.Fatal(err)
		}
		return sec
	}

	if err := ApplySecret(context.Background(), cs, build("old")); err != nil {
		t.Fatal(err)
	}
	if err := ApplySecret(context.Background(), cs, build("new")); err != nil {
		t.Fatal(err)
	}

	stored, err := cs.CoreV1().Secrets("guardian").Get(context.Background(), "cluster-prod", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(stored.Data["config"]), `"bearerToken":"new"`) {
		t.Errorf("re-applying must rotate the stored token, got %s", stored.Data["config"])
	}
}
