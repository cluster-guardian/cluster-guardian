package checks

import (
	"encoding/json"
	"fmt"
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cluster-guardian/cluster-guardian/internal/kube"
	"github.com/cluster-guardian/cluster-guardian/internal/report"
)

// apiDeprecation describes an API version that is deprecated or removed.
// Minor versions are relative to Kubernetes 1.x.
type apiDeprecation struct {
	old          string // apiVersion clients wrote with
	kind         string
	replacement  string
	deprecatedIn int
	removedIn    int
}

// deprecatedAPIs covers the kinds held in the snapshot. Sources:
// https://kubernetes.io/docs/reference/using-api/deprecation-guide/
var deprecatedAPIs = []apiDeprecation{
	{"extensions/v1beta1", "Deployment", "apps/v1", 9, 16},
	{"apps/v1beta1", "Deployment", "apps/v1", 9, 16},
	{"apps/v1beta2", "Deployment", "apps/v1", 9, 16},
	{"apps/v1beta1", "StatefulSet", "apps/v1", 9, 16},
	{"apps/v1beta2", "StatefulSet", "apps/v1", 9, 16},
	{"extensions/v1beta1", "DaemonSet", "apps/v1", 9, 16},
	{"apps/v1beta2", "DaemonSet", "apps/v1", 9, 16},
	{"extensions/v1beta1", "NetworkPolicy", "networking.k8s.io/v1", 9, 16},
	{"extensions/v1beta1", "Ingress", "networking.k8s.io/v1", 14, 22},
	{"networking.k8s.io/v1beta1", "Ingress", "networking.k8s.io/v1", 19, 22},
	{"batch/v2alpha1", "CronJob", "batch/v1", 8, 21},
	{"batch/v1beta1", "CronJob", "batch/v1", 21, 25},
	{"policy/v1beta1", "PodDisruptionBudget", "policy/v1", 21, 25},
	{"autoscaling/v2beta1", "HorizontalPodAutoscaler", "autoscaling/v2", 22, 25},
	{"autoscaling/v2beta2", "HorizontalPodAutoscaler", "autoscaling/v2", 23, 26},
}

// Deprecations flags objects whose manifests are still written with API
// versions that are deprecated (warning) or removed in the next minor or
// earlier (critical). The API server serves objects at current versions, so
// the original version is recovered from managedFields and the
// last-applied-configuration annotation — the same signals kubent uses.
func Deprecations(s *kube.Snapshot, namespaces []string) report.Section {
	section := report.Section{ID: "deprecations", Title: "Deprecated APIs", Icon: "⏳"}
	nsSet := namespaceSet(namespaces)
	minor := clusterMinor(s.ClusterVersion)

	type hit struct{ api, kind string }
	objects := map[hit][]string{}
	scan := func(kind string, meta metav1.ObjectMeta) {
		if !nsSet[meta.Namespace] {
			return
		}
		for api := range writtenAPIVersions(meta) {
			for _, d := range deprecatedAPIs {
				if d.old == api && d.kind == kind {
					// Not yet deprecated on this cluster version: stay quiet.
					if minor > 0 && d.deprecatedIn > minor {
						continue
					}
					objects[hit{api, kind}] = append(objects[hit{api, kind}], meta.Namespace+"/"+meta.Name)
				}
			}
		}
	}

	for _, o := range s.Deployments {
		scan("Deployment", o.ObjectMeta)
	}
	for _, o := range s.StatefulSets {
		scan("StatefulSet", o.ObjectMeta)
	}
	for _, o := range s.DaemonSets {
		scan("DaemonSet", o.ObjectMeta)
	}
	for _, o := range s.CronJobs {
		scan("CronJob", o.ObjectMeta)
	}
	for _, o := range s.HPAs {
		scan("HorizontalPodAutoscaler", o.ObjectMeta)
	}
	for _, o := range s.PDBs {
		scan("PodDisruptionBudget", o.ObjectMeta)
	}
	for _, o := range s.Ingresses {
		scan("Ingress", o.ObjectMeta)
	}
	for _, o := range s.NetworkPolicies {
		scan("NetworkPolicy", o.ObjectMeta)
	}

	hits := make([]hit, 0, len(objects))
	for h := range objects {
		hits = append(hits, h)
	}
	sort.Slice(hits, func(i, j int) bool {
		return hits[i].api+hits[i].kind < hits[j].api+hits[j].kind
	})

	for _, h := range hits {
		var dep apiDeprecation
		for _, d := range deprecatedAPIs {
			if d.old == h.api && d.kind == h.kind {
				dep = d
				break
			}
		}
		severity := report.SeverityWarning
		status := fmt.Sprintf("deprecated since 1.%d", dep.deprecatedIn)
		switch {
		case minor > 0 && dep.removedIn <= minor:
			severity = report.SeverityCritical
			status = fmt.Sprintf("removed since 1.%d", dep.removedIn)
		case minor > 0 && dep.removedIn == minor+1:
			severity = report.SeverityCritical
			status = fmt.Sprintf("removed in 1.%d", dep.removedIn)
		}
		names := objects[h]
		n := len(names)
		section.Findings = append(section.Findings, report.Finding{
			Severity: severity,
			Message: fmt.Sprintf("%d %s still written with %s, %s (%s)",
				n, plural(n, h.kind, h.kind+"s"), h.api, status, joinLimited(names, 4)),
			Hint: fmt.Sprintf("Update manifests to %s before upgrading the cluster.", dep.replacement),
		})
	}
	return section
}

// writtenAPIVersions extracts every API version clients have written this
// object with, from managedFields and kubectl's last-applied annotation.
func writtenAPIVersions(meta metav1.ObjectMeta) map[string]bool {
	out := map[string]bool{}
	for _, mf := range meta.ManagedFields {
		if mf.APIVersion != "" {
			out[mf.APIVersion] = true
		}
	}
	if la := meta.Annotations["kubectl.kubernetes.io/last-applied-configuration"]; la != "" {
		var obj struct {
			APIVersion string `json:"apiVersion"`
		}
		if json.Unmarshal([]byte(la), &obj) == nil && obj.APIVersion != "" {
			out[obj.APIVersion] = true
		}
	}
	return out
}

// clusterMinor parses the minor version out of strings like "v1.31.4+k3s1";
// 0 means unknown.
func clusterMinor(version string) int {
	var minor int
	if _, err := fmt.Sscanf(version, "v1.%d", &minor); err == nil {
		return minor
	}
	return 0
}
