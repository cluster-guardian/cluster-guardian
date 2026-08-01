package checks

import (
	"fmt"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/cluster-guardian/cluster-guardian/internal/kube"
	"github.com/cluster-guardian/cluster-guardian/internal/report"
)

// statefulComponents maps image substrings to display names for the
// "missing alerts" check.
var statefulComponents = map[string]string{
	"redis": "Redis", "postgres": "PostgreSQL", "mysql": "MySQL",
	"mariadb": "MariaDB", "mongo": "MongoDB", "kafka": "Kafka",
	"rabbitmq": "RabbitMQ", "elasticsearch": "Elasticsearch", "memcached": "Memcached",
}

// Monitoring validates the Prometheus stack and its coverage.
func Monitoring(s *kube.Snapshot, namespaces []string) report.Section {
	sec := report.Section{ID: "monitoring", Title: "Monitoring", Icon: "📊"}
	nsSet := namespaceSet(namespaces)

	hasPrometheus := hasPodWithImage(s, "prometheus")
	hasAlertmanager := hasPodWithImage(s, "alertmanager")

	if !hasPrometheus {
		sec.Findings = append(sec.Findings, report.Finding{
			Severity: report.SeverityWarning,
			Message:  "No Prometheus installation detected",
			Hint:     "Install kube-prometheus-stack to get metrics, dashboards and alerting.",
		})
		return sec
	}
	if !hasAlertmanager {
		sec.Findings = append(sec.Findings, report.Finding{
			Severity: report.SeverityWarning,
			Message:  "Prometheus found but no Alertmanager detected",
			Hint:     "Metrics without alert routing means nobody is paged when things break.",
		})
	}

	if s.HasServiceMonitorCRD {
		if n, sample := unscrapedServices(s, nsSet); n > 0 {
			sec.Findings = append(sec.Findings, report.Finding{
				Severity: report.SeverityInfo,
				Message:  fmt.Sprintf("%d %s not scraped by Prometheus (%s)", n, plural(n, "Service is", "Services are"), joinLimited(sample, 4)),
				Hint:     "Add a ServiceMonitor (or PodMonitor) if these services expose metrics.",
			})
		}
	} else {
		sec.Findings = append(sec.Findings, report.Finding{
			Severity: report.SeverityInfo,
			Message:  "ServiceMonitor CRD not installed; scrape coverage not verified",
		})
	}

	if missing := componentsWithoutAlerts(s, nsSet); len(missing) > 0 {
		sec.Findings = append(sec.Findings, report.Finding{
			Severity: report.SeverityWarning,
			Message:  "Missing alerts for " + strings.Join(missing, " and "),
			Hint:     "Add PrometheusRules covering availability and saturation of these components.",
		})
	}
	return sec
}

func hasPodWithImage(s *kube.Snapshot, substr string) bool {
	for _, pod := range s.Pods {
		for _, c := range pod.Spec.Containers {
			if strings.Contains(c.Image, substr) {
				return true
			}
		}
	}
	return false
}

// unscrapedServices counts services in app namespaces not matched by any
// ServiceMonitor (label-subset match, honoring namespaceSelector).
func unscrapedServices(s *kube.Snapshot, nsSet map[string]bool) (int, []string) {
	var count int
	var sample []string
	for _, svc := range s.Services {
		if !nsSet[svc.Namespace] || svc.Name == "kubernetes" || len(svc.Spec.Selector) == 0 {
			continue
		}
		matched := false
		for _, sm := range s.ServiceMonitors {
			if serviceMonitorMatches(sm, svc.Namespace, svc.Labels) {
				matched = true
				break
			}
		}
		if !matched {
			count++
			if len(sample) < 8 {
				sample = append(sample, svc.Namespace+"/"+svc.Name)
			}
		}
	}
	return count, sample
}

func serviceMonitorMatches(sm unstructured.Unstructured, svcNamespace string, svcLabels map[string]string) bool {
	// Namespace selector: default is the ServiceMonitor's own namespace.
	nsOK := sm.GetNamespace() == svcNamespace
	if matchAny, found, _ := unstructured.NestedBool(sm.Object, "spec", "namespaceSelector", "any"); found && matchAny {
		nsOK = true
	}
	if names, found, _ := unstructured.NestedStringSlice(sm.Object, "spec", "namespaceSelector", "matchNames"); found {
		for _, n := range names {
			if n == svcNamespace {
				nsOK = true
			}
		}
	}
	if !nsOK {
		return false
	}
	matchLabels, found, _ := unstructured.NestedStringMap(sm.Object, "spec", "selector", "matchLabels")
	if !found || len(matchLabels) == 0 {
		// Selector uses matchExpressions or matches everything; treat as a match
		// rather than producing false "unscraped" noise.
		return true
	}
	for k, v := range matchLabels {
		if svcLabels[k] != v {
			return false
		}
	}
	return true
}

// componentsWithoutAlerts detects well-known stateful services running in the
// cluster that no PrometheusRule mentions.
func componentsWithoutAlerts(s *kube.Snapshot, nsSet map[string]bool) []string {
	running := map[string]string{} // keyword -> display name
	for _, pod := range s.Pods {
		if !nsSet[pod.Namespace] {
			continue
		}
		for _, c := range pod.Spec.Containers {
			img := strings.ToLower(c.Image)
			for keyword, display := range statefulComponents {
				if strings.Contains(img, keyword) {
					running[keyword] = display
				}
			}
		}
	}
	if len(running) == 0 {
		return nil
	}

	var rulesText strings.Builder
	for _, pr := range s.PrometheusRules {
		groups, _, _ := unstructured.NestedSlice(pr.Object, "spec", "groups")
		for _, g := range groups {
			gm, ok := g.(map[string]any)
			if !ok {
				continue
			}
			rules, _, _ := unstructured.NestedSlice(gm, "rules")
			for _, r := range rules {
				rm, ok := r.(map[string]any)
				if !ok {
					continue
				}
				if alert, _, _ := unstructured.NestedString(rm, "alert"); alert != "" {
					rulesText.WriteString(strings.ToLower(alert) + "\n")
				}
				if expr, _, _ := unstructured.NestedString(rm, "expr"); expr != "" {
					rulesText.WriteString(strings.ToLower(expr) + "\n")
				}
			}
		}
	}
	corpus := rulesText.String()

	var missing []string
	for keyword, display := range running {
		if !strings.Contains(corpus, keyword) {
			missing = append(missing, display)
		}
	}
	sort.Strings(missing)
	return missing
}
