package checks

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/cluster-guardian/cluster-guardian/internal/kube"
	"github.com/cluster-guardian/cluster-guardian/internal/prom"
	"github.com/cluster-guardian/cluster-guardian/internal/report"
)

// Optimization compares resource requests (from the cluster snapshot) with
// actual usage (from Prometheus) to estimate overprovisioning.
func Optimization(ctx context.Context, s *kube.Snapshot, namespaces []string, prometheusURL string) report.Section {
	sec := report.Section{ID: "optimization", Title: "Optimization", Icon: "💰"}

	if prometheusURL == "" {
		hint := "Pass --prometheus-url to enable cost analysis."
		if svc := findPrometheusService(s); svc != "" {
			hint = fmt.Sprintf("Run `kubectl port-forward -n %s svc/%s 9090:9090` and pass --prometheus-url http://localhost:9090.",
				strings.Split(svc, "/")[0], strings.Split(svc, "/")[1])
		}
		sec.Findings = append(sec.Findings, report.Finding{
			Severity: report.SeverityInfo,
			Message:  "Prometheus URL not configured; skipping cost analysis",
			Hint:     hint,
		})
		return sec
	}

	cpuRequests, memRequests := totalRequests(s, namespaces)
	if cpuRequests == 0 && memRequests == 0 {
		sec.Findings = append(sec.Findings, report.Finding{
			Severity: report.SeverityInfo,
			Message:  "No resource requests set; cannot estimate overprovisioning",
		})
		return sec
	}

	client := prom.NewClient(prometheusURL)
	nsMatcher := promNamespaceMatcher(namespaces)

	cpuUsage, cpuErr := client.QueryScalar(ctx,
		fmt.Sprintf(`sum(rate(container_cpu_usage_seconds_total{%s,container!="",container!="POD"}[5m]))`, nsMatcher))
	memUsage, memErr := client.QueryScalar(ctx,
		fmt.Sprintf(`sum(container_memory_working_set_bytes{%s,container!="",container!="POD"})`, nsMatcher))

	if cpuErr != nil && memErr != nil {
		sec.Findings = append(sec.Findings, report.Finding{
			Severity: report.SeverityInfo,
			Message:  fmt.Sprintf("Could not query Prometheus at %s: %v", prometheusURL, cpuErr),
		})
		return sec
	}

	if cpuErr == nil && cpuRequests > 0 {
		sec.Findings = append(sec.Findings, overprovisionFinding("CPU", cpuUsage/cpuRequests,
			fmt.Sprintf("requested %.1f cores, using %.2f cores", cpuRequests, cpuUsage)))
	}
	if memErr == nil && memRequests > 0 {
		sec.Findings = append(sec.Findings, overprovisionFinding("Memory", memUsage/memRequests,
			fmt.Sprintf("requested %s, using %s", humanBytes(memRequests), humanBytes(memUsage))))
	}
	return sec
}

func overprovisionFinding(resource string, utilization float64, detail string) report.Finding {
	over := (1 - utilization) * 100
	if over < 0 {
		return report.Finding{
			Severity: report.SeverityWarning,
			Message:  fmt.Sprintf("%s usage exceeds requests by %.0f%% (%s)", resource, -over, detail),
			Hint:     "Requests below real usage cause noisy-neighbor evictions and unreliable scheduling.",
		}
	}
	sev := report.SeverityOK
	if over >= 60 {
		sev = report.SeverityWarning
	} else if over >= 30 {
		sev = report.SeverityInfo
	}
	return report.Finding{
		Severity: sev,
		Message:  fmt.Sprintf("Estimated %s overprovisioning: %.0f%% (%s)", resource, over, detail),
		Hint:     "Right-size requests toward observed usage (keep headroom for spikes) to reclaim cluster capacity.",
	}
}

// totalRequests sums container CPU (cores) and memory (bytes) requests of
// running pods in the given namespaces.
func totalRequests(s *kube.Snapshot, namespaces []string) (cpuCores, memBytes float64) {
	nsSet := namespaceSet(namespaces)
	for _, pod := range s.Pods {
		if !nsSet[pod.Namespace] || pod.Status.Phase != corev1.PodRunning {
			continue
		}
		for _, c := range pod.Spec.Containers {
			cpuCores += float64(c.Resources.Requests.Cpu().MilliValue()) / 1000
			memBytes += float64(c.Resources.Requests.Memory().Value())
		}
	}
	return cpuCores, memBytes
}

func findPrometheusService(s *kube.Snapshot) string {
	for _, svc := range s.Services {
		name := strings.ToLower(svc.Name)
		if strings.Contains(name, "prometheus") && !strings.Contains(name, "operator") && !strings.Contains(name, "node-exporter") {
			for _, p := range svc.Spec.Ports {
				if p.Port == 9090 {
					return svc.Namespace + "/" + svc.Name
				}
			}
		}
	}
	return ""
}

func humanBytes(b float64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	i := 0
	for b >= 1024 && i < len(units)-1 {
		b /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", b, units[i])
}
