package checks

import (
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/cluster-guardian/cluster-guardian/internal/kube"
)

// namespaceSet builds a lookup set from a namespace list.
func namespaceSet(namespaces []string) map[string]bool {
	set := make(map[string]bool, len(namespaces))
	for _, ns := range namespaces {
		set[ns] = true
	}
	return set
}

// forEachWorkloadPodSpec calls fn with the pod template of every Deployment,
// StatefulSet, DaemonSet and CronJob in the namespace, in that order.
func forEachWorkloadPodSpec(s *kube.Snapshot, ns string, fn func(kind, name string, spec corev1.PodSpec)) {
	for _, d := range s.Deployments {
		if d.Namespace == ns {
			fn("Deployment", d.Name, d.Spec.Template.Spec)
		}
	}
	for _, ss := range s.StatefulSets {
		if ss.Namespace == ns {
			fn("StatefulSet", ss.Name, ss.Spec.Template.Spec)
		}
	}
	for _, ds := range s.DaemonSets {
		if ds.Namespace == ns {
			fn("DaemonSet", ds.Name, ds.Spec.Template.Spec)
		}
	}
	for _, cj := range s.CronJobs {
		if cj.Namespace == ns {
			fn("CronJob", cj.Name, cj.Spec.JobTemplate.Spec.Template.Spec)
		}
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func joinLimited(names []string, limit int) string {
	slices.Sort(names)
	if len(names) <= limit {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(names[:limit], ", "), len(names)-limit)
}
