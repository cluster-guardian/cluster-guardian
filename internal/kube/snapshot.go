package kube

import (
	"context"
	"fmt"
	"slices"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GVRs for optional CRDs the analyzer knows about.
var (
	gvrServiceMonitor  = schema.GroupVersionResource{Group: "monitoring.coreos.com", Version: "v1", Resource: "servicemonitors"}
	gvrPodMonitor      = schema.GroupVersionResource{Group: "monitoring.coreos.com", Version: "v1", Resource: "podmonitors"}
	gvrPrometheusRule  = schema.GroupVersionResource{Group: "monitoring.coreos.com", Version: "v1", Resource: "prometheusrules"}
	gvrArgoApplication = schema.GroupVersionResource{Group: "argoproj.io", Version: "v1alpha1", Resource: "applications"}
	gvrFluxKustomize   = schema.GroupVersionResource{Group: "kustomize.toolkit.fluxcd.io", Version: "v1", Resource: "kustomizations"}
	gvrFluxHelm        = schema.GroupVersionResource{Group: "helm.toolkit.fluxcd.io", Version: "v2", Resource: "helmreleases"}
	gvrCertificate     = schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "certificates"}
	gvrGateway         = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"}
	gvrHTTPRoute       = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "httproutes"}

	gvrPolicyReport         = schema.GroupVersionResource{Group: "wgpolicyk8s.io", Version: "v1alpha2", Resource: "policyreports"}
	gvrKyvernoPolicy        = schema.GroupVersionResource{Group: "kyverno.io", Version: "v1", Resource: "policies"}
	gvrKyvernoClusterPolicy = schema.GroupVersionResource{Group: "kyverno.io", Version: "v1", Resource: "clusterpolicies"}
	gvrCRD                  = schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}
)

// gatekeeperConstraintGroup is the API group Gatekeeper creates one CRD per
// constraint kind in.
const gatekeeperConstraintGroup = "constraints.gatekeeper.sh"

// SystemNamespaces are excluded from per-namespace workload checks unless
// --include-system is set.
var SystemNamespaces = map[string]bool{
	"kube-system":        true,
	"kube-public":        true,
	"kube-node-lease":    true,
	"local-path-storage": true,
}

// Snapshot is a point-in-time read of everything the checks need. Checks are
// pure functions over a Snapshot, which keeps them unit-testable.
type Snapshot struct {
	ClusterVersion  string
	Namespaces      []corev1.Namespace
	Nodes           []corev1.Node // nil when listing nodes is not permitted
	Pods            []corev1.Pod
	Deployments     []appsv1.Deployment
	StatefulSets    []appsv1.StatefulSet
	DaemonSets      []appsv1.DaemonSet
	Jobs            []batchv1.Job
	CronJobs        []batchv1.CronJob
	HPAs            []autoscalingv2.HorizontalPodAutoscaler
	PDBs            []policyv1.PodDisruptionBudget
	Services        []corev1.Service
	Ingresses       []networkingv1.Ingress
	ConfigMaps      []corev1.ConfigMap
	Secrets         []corev1.Secret // data is stripped after listing; only tls.crt survives on TLS secrets
	PVCs            []corev1.PersistentVolumeClaim
	ServiceAccounts []corev1.ServiceAccount

	// HasSecretAccess distinguishes "no secrets" from "not allowed to list
	// secrets"; secret-dependent checks skip when it is false.
	HasSecretAccess     bool
	NetworkPolicies     []networkingv1.NetworkPolicy
	ClusterRoles        []rbacv1.ClusterRole
	ClusterRoleBindings []rbacv1.ClusterRoleBinding

	// Optional CRDs; nil slices mean the CRD is not installed.
	ServiceMonitors    []unstructured.Unstructured
	PodMonitors        []unstructured.Unstructured
	PrometheusRules    []unstructured.Unstructured
	ArgoApplications   []unstructured.Unstructured
	FluxKustomizations []unstructured.Unstructured
	FluxHelmReleases   []unstructured.Unstructured

	HasServiceMonitorCRD bool
	HasArgoCD            bool
	HasFlux              bool

	Certificates   []unstructured.Unstructured
	HasCertManager bool

	Gateways      []unstructured.Unstructured
	HTTPRoutes    []unstructured.Unstructured
	HasGatewayAPI bool

	// Policy engines. Constraints holds instances of every
	// constraints.gatekeeper.sh kind, discovered dynamically.
	KyvernoPolicyReports   []unstructured.Unstructured
	KyvernoPolicies        []unstructured.Unstructured
	KyvernoClusterPolicies []unstructured.Unstructured
	HasKyverno             bool
	GatekeeperConstraints  []unstructured.Unstructured
	HasGatekeeper          bool
}

// AppNamespaces returns namespaces that per-namespace checks should cover.
func (s *Snapshot) AppNamespaces(includeSystem bool, only []string) []string {
	var out []string
	for _, ns := range s.Namespaces {
		name := ns.Name
		if len(only) > 0 {
			if slices.Contains(only, name) {
				out = append(out, name)
			}
			continue
		}
		if !includeSystem && SystemNamespaces[name] {
			continue
		}
		out = append(out, name)
	}
	return out
}

// Collect reads the cluster state. Failures on optional resources (CRDs,
// RBAC-restricted lists) degrade gracefully; failures on core resources abort.
func (c *Client) Collect(ctx context.Context, namespaces []string) (*Snapshot, error) {
	s := &Snapshot{}

	if v, err := c.Clientset.Discovery().ServerVersion(); err == nil {
		s.ClusterVersion = v.GitVersion
	}

	opts := metav1.ListOptions{}
	nsList, err := c.Clientset.CoreV1().Namespaces().List(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("listing namespaces: %w", err)
	}
	s.Namespaces = filterNamespaces(nsList.Items, namespaces)

	// Nodes are optional: without list permission the node checks skip.
	if v, err := c.Clientset.CoreV1().Nodes().List(ctx, opts); err == nil {
		s.Nodes = v.Items
	}
	if pods, err := c.Clientset.CoreV1().Pods(metav1.NamespaceAll).List(ctx, opts); err == nil {
		s.Pods = pods.Items
	} else {
		return nil, fmt.Errorf("listing pods: %w", err)
	}
	if v, err := c.Clientset.AppsV1().Deployments(metav1.NamespaceAll).List(ctx, opts); err == nil {
		s.Deployments = v.Items
	} else {
		return nil, fmt.Errorf("listing deployments: %w", err)
	}
	if v, err := c.Clientset.AppsV1().StatefulSets(metav1.NamespaceAll).List(ctx, opts); err == nil {
		s.StatefulSets = v.Items
	}
	if v, err := c.Clientset.AppsV1().DaemonSets(metav1.NamespaceAll).List(ctx, opts); err == nil {
		s.DaemonSets = v.Items
	}
	if v, err := c.Clientset.BatchV1().Jobs(metav1.NamespaceAll).List(ctx, opts); err == nil {
		s.Jobs = v.Items
	}
	if v, err := c.Clientset.BatchV1().CronJobs(metav1.NamespaceAll).List(ctx, opts); err == nil {
		s.CronJobs = v.Items
	}
	if v, err := c.Clientset.AutoscalingV2().HorizontalPodAutoscalers(metav1.NamespaceAll).List(ctx, opts); err == nil {
		s.HPAs = v.Items
	}
	if v, err := c.Clientset.PolicyV1().PodDisruptionBudgets(metav1.NamespaceAll).List(ctx, opts); err == nil {
		s.PDBs = v.Items
	}
	if v, err := c.Clientset.CoreV1().Services(metav1.NamespaceAll).List(ctx, opts); err == nil {
		s.Services = v.Items
	}
	if v, err := c.Clientset.NetworkingV1().Ingresses(metav1.NamespaceAll).List(ctx, opts); err == nil {
		s.Ingresses = v.Items
	}
	if v, err := c.Clientset.NetworkingV1().NetworkPolicies(metav1.NamespaceAll).List(ctx, opts); err == nil {
		s.NetworkPolicies = v.Items
	}
	if v, err := c.Clientset.CoreV1().ConfigMaps(metav1.NamespaceAll).List(ctx, opts); err == nil {
		s.ConfigMaps = v.Items
	}
	if v, err := c.Clientset.CoreV1().Secrets(metav1.NamespaceAll).List(ctx, opts); err == nil {
		// Never hold secret payloads in memory: keep only the public
		// certificate of TLS secrets (for expiry checks) and drop the rest.
		for i := range v.Items {
			item := &v.Items[i]
			if item.Type == corev1.SecretTypeTLS && item.Data["tls.crt"] != nil {
				item.Data = map[string][]byte{"tls.crt": item.Data["tls.crt"]}
			} else {
				item.Data = nil
			}
			item.StringData = nil
		}
		s.Secrets = v.Items
		s.HasSecretAccess = true
	}
	if v, err := c.Clientset.CoreV1().PersistentVolumeClaims(metav1.NamespaceAll).List(ctx, opts); err == nil {
		s.PVCs = v.Items
	}
	if v, err := c.Clientset.CoreV1().ServiceAccounts(metav1.NamespaceAll).List(ctx, opts); err == nil {
		s.ServiceAccounts = v.Items
	}
	if v, err := c.Clientset.RbacV1().ClusterRoles().List(ctx, opts); err == nil {
		s.ClusterRoles = v.Items
	}
	if v, err := c.Clientset.RbacV1().ClusterRoleBindings().List(ctx, opts); err == nil {
		s.ClusterRoleBindings = v.Items
	}

	s.ServiceMonitors, s.HasServiceMonitorCRD = c.listCRD(ctx, gvrServiceMonitor)
	s.PodMonitors, _ = c.listCRD(ctx, gvrPodMonitor)
	s.PrometheusRules, _ = c.listCRD(ctx, gvrPrometheusRule)
	s.ArgoApplications, s.HasArgoCD = c.listCRD(ctx, gvrArgoApplication)
	s.FluxKustomizations, s.HasFlux = c.listCRD(ctx, gvrFluxKustomize)
	if helm, ok := c.listCRD(ctx, gvrFluxHelm); ok {
		s.FluxHelmReleases = helm
		s.HasFlux = true
	}
	s.Certificates, s.HasCertManager = c.listCRD(ctx, gvrCertificate)
	s.Gateways, s.HasGatewayAPI = c.listCRD(ctx, gvrGateway)
	if routes, ok := c.listCRD(ctx, gvrHTTPRoute); ok {
		s.HTTPRoutes = routes
		s.HasGatewayAPI = true
	}

	s.KyvernoPolicyReports, s.HasKyverno = c.listCRD(ctx, gvrPolicyReport)
	if pols, ok := c.listCRD(ctx, gvrKyvernoPolicy); ok {
		s.KyvernoPolicies = pols
		s.HasKyverno = true
	}
	if pols, ok := c.listCRD(ctx, gvrKyvernoClusterPolicy); ok {
		s.KyvernoClusterPolicies = pols
		s.HasKyverno = true
	}
	s.GatekeeperConstraints, s.HasGatekeeper = c.listGatekeeperConstraints(ctx)

	return s, nil
}

// listGatekeeperConstraints discovers Gatekeeper constraint kinds (one CRD
// per kind, created from ConstraintTemplates) and lists their instances.
// ok reports whether Gatekeeper is installed at all.
func (c *Client) listGatekeeperConstraints(ctx context.Context) ([]unstructured.Unstructured, bool) {
	crds, ok := c.listCRD(ctx, gvrCRD)
	if !ok {
		return nil, false
	}
	installed := false
	var out []unstructured.Unstructured
	for _, crd := range crds {
		group, _, _ := unstructured.NestedString(crd.Object, "spec", "group")
		if group != gatekeeperConstraintGroup {
			continue
		}
		installed = true
		plural, _, _ := unstructured.NestedString(crd.Object, "spec", "names", "plural")
		version := servedCRDVersion(crd)
		if plural == "" || version == "" {
			continue
		}
		items, _ := c.listCRD(ctx, schema.GroupVersionResource{Group: group, Version: version, Resource: plural})
		out = append(out, items...)
	}
	return out, installed
}

// servedCRDVersion returns the first served version of a CRD.
func servedCRDVersion(crd unstructured.Unstructured) string {
	versions, _, _ := unstructured.NestedSlice(crd.Object, "spec", "versions")
	for _, v := range versions {
		vm, ok := v.(map[string]any)
		if !ok {
			continue
		}
		if served, _, _ := unstructured.NestedBool(vm, "served"); !served {
			continue
		}
		name, _, _ := unstructured.NestedString(vm, "name")
		return name
	}
	return ""
}

func (c *Client) listCRD(ctx context.Context, gvr schema.GroupVersionResource) ([]unstructured.Unstructured, bool) {
	list, err := c.Dynamic.Resource(gvr).Namespace(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, false
	}
	return list.Items, true
}

func filterNamespaces(all []corev1.Namespace, only []string) []corev1.Namespace {
	if len(only) == 0 {
		return all
	}
	var out []corev1.Namespace
	for _, ns := range all {
		for _, o := range only {
			if strings.EqualFold(ns.Name, o) {
				out = append(out, ns)
				break
			}
		}
	}
	return out
}
