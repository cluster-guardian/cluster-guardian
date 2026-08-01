// Package docs generates Markdown documentation of the cluster's current
// state from a snapshot.
package docs

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/cluster-guardian/cluster-guardian/internal/kube"
)

// Write renders cluster documentation for the given namespaces.
func Write(w io.Writer, s *kube.Snapshot, clusterName string, namespaces []string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# Cluster documentation: %s\n\n", clusterName)
	fmt.Fprintf(&b, "Generated %s", time.Now().UTC().Format("2006-01-02 15:04 UTC"))
	if s.ClusterVersion != "" {
		fmt.Fprintf(&b, " • Kubernetes %s", s.ClusterVersion)
	}
	fmt.Fprintf(&b, " • %d namespaces\n\n", len(namespaces))

	for _, ns := range namespaces {
		deployRows := workloadRows(s, ns)
		svcRows := serviceRows(s, ns)
		ingRows := ingressRows(s, ns)
		if len(deployRows)+len(svcRows)+len(ingRows) == 0 {
			continue
		}
		fmt.Fprintf(&b, "## Namespace: %s\n\n", ns)

		if len(deployRows) > 0 {
			b.WriteString("### Workloads\n\n| Kind | Name | Replicas | Images |\n|---|---|---|---|\n")
			for _, row := range deployRows {
				b.WriteString(row + "\n")
			}
			b.WriteString("\n")
		}
		if len(svcRows) > 0 {
			b.WriteString("### Services\n\n| Name | Type | Ports |\n|---|---|---|\n")
			for _, row := range svcRows {
				b.WriteString(row + "\n")
			}
			b.WriteString("\n")
		}
		if len(ingRows) > 0 {
			b.WriteString("### Ingresses\n\n| Name | Hosts |\n|---|---|\n")
			for _, row := range ingRows {
				b.WriteString(row + "\n")
			}
			b.WriteString("\n")
		}
	}

	_, err := io.WriteString(w, b.String())
	return err
}

func workloadRows(s *kube.Snapshot, ns string) []string {
	var rows []string
	add := func(kind, name string, replicas string, spec corev1.PodSpec) {
		images := make([]string, 0, len(spec.Containers))
		for _, c := range spec.Containers {
			images = append(images, "`"+c.Image+"`")
		}
		rows = append(rows, fmt.Sprintf("| %s | %s | %s | %s |", kind, name, replicas, strings.Join(images, ", ")))
	}
	for _, d := range s.Deployments {
		if d.Namespace == ns {
			add("Deployment", d.Name, fmt.Sprint(*d.Spec.Replicas), d.Spec.Template.Spec)
		}
	}
	for _, ss := range s.StatefulSets {
		if ss.Namespace == ns {
			replicas := "1"
			if ss.Spec.Replicas != nil {
				replicas = fmt.Sprint(*ss.Spec.Replicas)
			}
			add("StatefulSet", ss.Name, replicas, ss.Spec.Template.Spec)
		}
	}
	for _, ds := range s.DaemonSets {
		if ds.Namespace == ns {
			add("DaemonSet", ds.Name, fmt.Sprint(ds.Status.DesiredNumberScheduled), ds.Spec.Template.Spec)
		}
	}
	for _, cj := range s.CronJobs {
		if cj.Namespace == ns {
			add("CronJob", cj.Name, cj.Spec.Schedule, cj.Spec.JobTemplate.Spec.Template.Spec)
		}
	}
	sort.Strings(rows)
	return rows
}

func serviceRows(s *kube.Snapshot, ns string) []string {
	var rows []string
	for _, svc := range s.Services {
		if svc.Namespace != ns {
			continue
		}
		ports := make([]string, 0, len(svc.Spec.Ports))
		for _, p := range svc.Spec.Ports {
			ports = append(ports, fmt.Sprintf("%d/%s", p.Port, p.Protocol))
		}
		rows = append(rows, fmt.Sprintf("| %s | %s | %s |", svc.Name, svc.Spec.Type, strings.Join(ports, ", ")))
	}
	sort.Strings(rows)
	return rows
}

func ingressRows(s *kube.Snapshot, ns string) []string {
	var rows []string
	for _, ing := range s.Ingresses {
		if ing.Namespace != ns {
			continue
		}
		var hosts []string
		for _, rule := range ing.Spec.Rules {
			if rule.Host != "" {
				hosts = append(hosts, rule.Host)
			}
		}
		rows = append(rows, fmt.Sprintf("| %s | %s |", ing.Name, strings.Join(hosts, ", ")))
	}
	sort.Strings(rows)
	return rows
}
