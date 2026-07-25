package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
)

// readOnlyRules grants get/list on everything Collect reads. Deliberately no
// wildcards: a wildcard role bound to a ServiceAccount would be flagged by
// cluster-guardian's own RBAC check.
var readOnlyRules = []rbacv1.PolicyRule{
	{
		APIGroups: []string{""},
		Resources: []string{"namespaces", "nodes", "pods", "services", "configmaps", "secrets", "persistentvolumeclaims", "serviceaccounts"},
		Verbs:     []string{"get", "list"},
	},
	{
		APIGroups: []string{"apps"},
		Resources: []string{"deployments", "statefulsets", "daemonsets"},
		Verbs:     []string{"get", "list"},
	},
	{
		APIGroups: []string{"batch"},
		Resources: []string{"jobs", "cronjobs"},
		Verbs:     []string{"get", "list"},
	},
	{
		APIGroups: []string{"autoscaling"},
		Resources: []string{"horizontalpodautoscalers"},
		Verbs:     []string{"get", "list"},
	},
	{
		APIGroups: []string{"policy"},
		Resources: []string{"poddisruptionbudgets"},
		Verbs:     []string{"get", "list"},
	},
	{
		APIGroups: []string{"networking.k8s.io"},
		Resources: []string{"ingresses", "networkpolicies"},
		Verbs:     []string{"get", "list"},
	},
	{
		APIGroups: []string{"rbac.authorization.k8s.io"},
		Resources: []string{"clusterroles", "clusterrolebindings"},
		Verbs:     []string{"get", "list"},
	},
	{
		APIGroups: []string{"monitoring.coreos.com"},
		Resources: []string{"servicemonitors", "podmonitors", "prometheusrules"},
		Verbs:     []string{"get", "list"},
	},
	{
		APIGroups: []string{"argoproj.io"},
		Resources: []string{"applications"},
		Verbs:     []string{"get", "list"},
	},
	{
		APIGroups: []string{"kustomize.toolkit.fluxcd.io"},
		Resources: []string{"kustomizations"},
		Verbs:     []string{"get", "list"},
	},
	{
		APIGroups: []string{"helm.toolkit.fluxcd.io"},
		Resources: []string{"helmreleases"},
		Verbs:     []string{"get", "list"},
	},
	{
		APIGroups: []string{"cert-manager.io"},
		Resources: []string{"certificates"},
		Verbs:     []string{"get", "list"},
	},
	{
		APIGroups: []string{"gateway.networking.k8s.io"},
		Resources: []string{"gateways", "httproutes"},
		Verbs:     []string{"get", "list"},
	},
}

// ProvisionOptions configure Provision. Zero values use the defaults.
type ProvisionOptions struct {
	// Namespace holds the ServiceAccount and token Secret on the target
	// cluster; created if missing. Defaults to "cluster-guardian".
	Namespace string
	// Name is the base name for the ServiceAccount, ClusterRole and binding.
	// Defaults to "cluster-guardian".
	Name string
	// TokenTimeout bounds the wait for the token controller to issue the
	// token. Defaults to 30s.
	TokenTimeout time.Duration
}

// Credentials is what Provision extracts from the issued token Secret.
type Credentials struct {
	Token  string
	CAData []byte
}

func (o ProvisionOptions) withDefaults() ProvisionOptions {
	if o.Namespace == "" {
		o.Namespace = "cluster-guardian"
	}
	if o.Name == "" {
		o.Name = "cluster-guardian"
	}
	if o.TokenTimeout == 0 {
		o.TokenTimeout = 30 * time.Second
	}
	return o
}

// Provision creates a read-only ServiceAccount on the target cluster —
// namespace, ServiceAccount, ClusterRole, ClusterRoleBinding and a long-lived
// token Secret — and waits for the token controller to issue the token.
// It is idempotent: re-running refreshes the role rules and reuses the
// existing token.
func Provision(ctx context.Context, cs kubernetes.Interface, opts ProvisionOptions) (*Credentials, error) {
	opts = opts.withDefaults()

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: opts.Namespace}}
	if _, err := cs.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return nil, fmt.Errorf("creating namespace %q: %w", opts.Namespace, err)
	}

	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: opts.Namespace, Name: opts.Name}}
	if _, err := cs.CoreV1().ServiceAccounts(opts.Namespace).Create(ctx, sa, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return nil, fmt.Errorf("creating serviceaccount: %w", err)
	}

	roleName := opts.Name + "-readonly"
	role := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: roleName},
		Rules:      readOnlyRules,
	}
	if _, err := cs.RbacV1().ClusterRoles().Create(ctx, role, metav1.CreateOptions{}); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return nil, fmt.Errorf("creating clusterrole: %w", err)
		}
		// Refresh the rules so re-adding picks up newly supported resources.
		if _, err := cs.RbacV1().ClusterRoles().Update(ctx, role, metav1.UpdateOptions{}); err != nil {
			return nil, fmt.Errorf("updating clusterrole: %w", err)
		}
	}

	binding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: roleName},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: roleName},
		Subjects:   []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Namespace: opts.Namespace, Name: opts.Name}},
	}
	if _, err := cs.RbacV1().ClusterRoleBindings().Create(ctx, binding, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return nil, fmt.Errorf("creating clusterrolebinding: %w", err)
	}

	tokenName := opts.Name + "-token"
	tokenSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   opts.Namespace,
			Name:        tokenName,
			Annotations: map[string]string{corev1.ServiceAccountNameKey: opts.Name},
		},
		Type: corev1.SecretTypeServiceAccountToken,
	}
	if _, err := cs.CoreV1().Secrets(opts.Namespace).Create(ctx, tokenSecret, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return nil, fmt.Errorf("creating token secret: %w", err)
	}

	var creds Credentials
	err := wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, opts.TokenTimeout, true,
		func(ctx context.Context) (bool, error) {
			sec, err := cs.CoreV1().Secrets(opts.Namespace).Get(ctx, tokenName, metav1.GetOptions{})
			if err != nil || len(sec.Data[corev1.ServiceAccountTokenKey]) == 0 {
				return false, nil
			}
			creds.Token = string(sec.Data[corev1.ServiceAccountTokenKey])
			creds.CAData = sec.Data[corev1.ServiceAccountRootCAKey]
			return true, nil
		})
	if err != nil {
		return nil, fmt.Errorf("waiting for token in secret %s/%s: %w", opts.Namespace, tokenName, err)
	}
	return &creds, nil
}

// ClusterSecretSpec describes a cluster registration for NewClusterSecret.
type ClusterSecretSpec struct {
	ClusterName string
	Server      string
	BearerToken string
	CAData      []byte
	Insecure    bool
}

// NewClusterSecret builds the labeled Secret that registers a cluster with
// the fleet — the inverse of ParseClusterSecret.
func NewClusterSecret(namespace string, spec ClusterSecretSpec) (*corev1.Secret, error) {
	var cfg clusterSecretConfig
	cfg.BearerToken = spec.BearerToken
	cfg.TLSClientConfig.Insecure = spec.Insecure
	if !spec.Insecure {
		// client-go rejects a config carrying both a CA and the insecure flag.
		cfg.TLSClientConfig.CAData = spec.CAData
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("encoding cluster config: %w", err)
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      "cluster-" + SanitizeName(spec.ClusterName),
			Labels:    map[string]string{SecretLabel: "cluster"},
		},
		Data: map[string][]byte{
			"name":   []byte(spec.ClusterName),
			"server": []byte(spec.Server),
			"config": raw,
		},
	}, nil
}

// ApplySecret creates the secret, or updates it if it already exists (so
// re-adding a cluster rotates its stored credentials). The namespace is
// created if missing.
func ApplySecret(ctx context.Context, cs kubernetes.Interface, sec *corev1.Secret) error {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: sec.Namespace}}
	if _, err := cs.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("creating namespace %q: %w", sec.Namespace, err)
	}
	if _, err := cs.CoreV1().Secrets(sec.Namespace).Create(ctx, sec, metav1.CreateOptions{}); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("creating secret %s/%s: %w", sec.Namespace, sec.Name, err)
		}
		if _, err := cs.CoreV1().Secrets(sec.Namespace).Update(ctx, sec, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("updating secret %s/%s: %w", sec.Namespace, sec.Name, err)
		}
	}
	return nil
}
