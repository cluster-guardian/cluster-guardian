// Package manifest builds a kube.Snapshot from YAML/JSON manifests instead
// of the API server, so the pure checks can lint pre-deploy configuration
// with the same rule set used against live clusters.
package manifest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"

	"github.com/cluster-guardian/cluster-guardian/internal/kube"
)

const gatewayAPIGroup = "gateway.networking.k8s.io/"

// clusterScoped kinds never get a namespace defaulted.
var clusterScoped = map[string]bool{
	"Namespace": true, "ClusterRole": true, "ClusterRoleBinding": true, "List": true,
}

// Load parses manifests from files, directories (recursive, .yaml/.yml/.json)
// or stdin ("-") into a Snapshot, and returns the namespaces to analyze: the
// union of declared Namespace objects and every namespace the manifests
// reference. Namespaced objects without a namespace land in "default", like
// kubectl apply.
func Load(paths []string, stdin io.Reader) (*kube.Snapshot, []string, error) {
	l := &loader{
		snapshot:   &kube.Snapshot{},
		namespaces: map[string]bool{},
	}
	for _, p := range paths {
		if p == "-" {
			if err := l.read(stdin, "stdin"); err != nil {
				return nil, nil, err
			}
			continue
		}
		info, err := os.Stat(p)
		if err != nil {
			return nil, nil, err
		}
		if !info.IsDir() {
			if err := l.readFile(p); err != nil {
				return nil, nil, err
			}
			continue
		}
		err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			switch strings.ToLower(filepath.Ext(path)) {
			case ".yaml", ".yml", ".json":
				return l.readFile(path)
			}
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
	}

	l.synthesizePods()
	return l.snapshot, slices.Sorted(maps.Keys(l.namespaces)), nil
}

type loader struct {
	snapshot   *kube.Snapshot
	namespaces map[string]bool
}

func (l *loader) readFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return l.read(f, path)
}

func (l *loader) read(r io.Reader, source string) error {
	dec := utilyaml.NewYAMLOrJSONDecoder(r, 4096)
	for {
		var doc json.RawMessage
		if err := dec.Decode(&doc); errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return fmt.Errorf("%s: %w", source, err)
		}
		if err := l.add(doc); err != nil {
			return fmt.Errorf("%s: %w", source, err)
		}
	}
}

// add routes one JSON document into the snapshot by kind. Unknown kinds are
// skipped: manifests often mix CRDs the checks don't know.
func (l *loader) add(doc json.RawMessage) error {
	var u unstructured.Unstructured
	if err := json.Unmarshal(doc, &u.Object); err != nil {
		return err
	}
	kind := u.GetKind()
	if kind == "" {
		return nil // not a Kubernetes object (comments-only doc, values file)
	}
	if kind == "List" {
		items, _, _ := unstructured.NestedSlice(u.Object, "items")
		for _, item := range items {
			raw, err := json.Marshal(item)
			if err != nil {
				return err
			}
			if err := l.add(raw); err != nil {
				return err
			}
		}
		return nil
	}

	ns := u.GetNamespace()
	if ns == "" && !clusterScoped[kind] {
		ns = "default"
	}

	s := l.snapshot
	switch kind {
	case "Namespace":
		obj, err := decode[corev1.Namespace](doc, u)
		s.Namespaces = append(s.Namespaces, obj)
		l.namespaces[obj.Name] = true
		return err
	case "Pod":
		return appendTyped(l, doc, u, ns, &s.Pods)
	case "Deployment":
		return appendTyped(l, doc, u, ns, &s.Deployments)
	case "StatefulSet":
		return appendTyped(l, doc, u, ns, &s.StatefulSets)
	case "DaemonSet":
		return appendTyped(l, doc, u, ns, &s.DaemonSets)
	case "Job":
		return appendTyped(l, doc, u, ns, &s.Jobs)
	case "CronJob":
		return appendTyped(l, doc, u, ns, &s.CronJobs)
	case "HorizontalPodAutoscaler":
		return appendTyped(l, doc, u, ns, &s.HPAs)
	case "PodDisruptionBudget":
		return appendTyped(l, doc, u, ns, &s.PDBs)
	case "Service":
		return appendTyped(l, doc, u, ns, &s.Services)
	case "Ingress":
		return appendTyped(l, doc, u, ns, &s.Ingresses)
	case "NetworkPolicy":
		return appendTyped(l, doc, u, ns, &s.NetworkPolicies)
	case "ConfigMap":
		return appendTyped(l, doc, u, ns, &s.ConfigMaps)
	case "Secret":
		return appendTyped(l, doc, u, ns, &s.Secrets)
	case "PersistentVolumeClaim":
		return appendTyped(l, doc, u, ns, &s.PVCs)
	case "ServiceAccount":
		return appendTyped(l, doc, u, ns, &s.ServiceAccounts)
	case "ClusterRole":
		obj, err := decode[rbacv1.ClusterRole](doc, u)
		s.ClusterRoles = append(s.ClusterRoles, obj)
		return err
	case "ClusterRoleBinding":
		obj, err := decode[rbacv1.ClusterRoleBinding](doc, u)
		s.ClusterRoleBindings = append(s.ClusterRoleBindings, obj)
		return err
	case "Gateway":
		if strings.HasPrefix(u.GetAPIVersion(), gatewayAPIGroup) {
			u.SetNamespace(ns)
			l.namespaces[ns] = true
			s.Gateways = append(s.Gateways, u)
			s.HasGatewayAPI = true
		}
		return nil
	case "HTTPRoute":
		if strings.HasPrefix(u.GetAPIVersion(), gatewayAPIGroup) {
			u.SetNamespace(ns)
			l.namespaces[ns] = true
			s.HTTPRoutes = append(s.HTTPRoutes, u)
			s.HasGatewayAPI = true
		}
		return nil
	}
	return nil
}

// decode unmarshals a document into a typed object and stamps its original
// apiVersion into managedFields — the signal the Deprecations check reads,
// so manifests written with removed API versions are flagged. Unknown fields
// (from older API shapes) are dropped.
func decode[T any](doc json.RawMessage, u unstructured.Unstructured) (T, error) {
	var t T
	if err := json.Unmarshal(doc, &t); err != nil {
		return t, fmt.Errorf("parsing %s %q: %w", u.GetKind(), u.GetName(), err)
	}
	return t, nil
}

func appendTyped[T any, PT interface {
	*T
	metav1.Object
}](l *loader, doc json.RawMessage, u unstructured.Unstructured, ns string, out *[]T) error {
	obj, err := decode[T](doc, u)
	if err != nil {
		return err
	}
	meta := PT(&obj)
	meta.SetNamespace(ns)
	meta.SetManagedFields([]metav1.ManagedFieldsEntry{{Manager: "cluster-guardian-lint", APIVersion: u.GetAPIVersion()}})
	l.namespaces[ns] = true
	*out = append(*out, obj)
	return nil
}

// synthesizePods materializes one Pod per workload template, standing in for
// what the API server would create: the pod-level checks (security context,
// resource requests, PSS) and selector matching then see manifest workloads
// exactly like live ones.
func (l *loader) synthesizePods() {
	s := l.snapshot
	add := func(ns, name string, tpl corev1.PodTemplateSpec) {
		s.Pods = append(s.Pods, corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name + "-template", Labels: tpl.Labels},
			Spec:       tpl.Spec,
		})
	}
	for _, d := range s.Deployments {
		add(d.Namespace, d.Name, d.Spec.Template)
	}
	for _, ss := range s.StatefulSets {
		add(ss.Namespace, ss.Name, ss.Spec.Template)
	}
	for _, ds := range s.DaemonSets {
		add(ds.Namespace, ds.Name, ds.Spec.Template)
	}
	for _, j := range s.Jobs {
		add(j.Namespace, j.Name, j.Spec.Template)
	}
	for _, cj := range s.CronJobs {
		add(cj.Namespace, cj.Name, cj.Spec.JobTemplate.Spec.Template)
	}
}
