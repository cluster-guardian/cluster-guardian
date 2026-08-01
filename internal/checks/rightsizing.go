package checks

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/cluster-guardian/cluster-guardian/internal/kube"
	"github.com/cluster-guardian/cluster-guardian/internal/prom"
	"github.com/cluster-guardian/cluster-guardian/internal/report"
)

// RightsizingOptions tune the rightsizing analysis.
type RightsizingOptions struct {
	// Window is the usage lookback; defaults to 7 days.
	Window time.Duration
	// CostPerCPUMonth and CostPerGiBMonth turn request deltas into monthly
	// savings estimates; zero disables the estimate.
	CostPerCPUMonth float64
	CostPerGiBMonth float64
}

// PodUsage holds observed usage of one pod (summed across its containers).
// CPU is in cores, memory in bytes.
type PodUsage struct {
	CPUP50, CPUP95, CPUMax float64
	MemP50, MemP95, MemMax float64
}

// Usage maps "namespace/pod" to its observed usage.
type Usage map[string]PodUsage

// Rightsizing compares per-workload resource requests with usage observed by
// Prometheus and recommends concrete values. Findings are sorted by wasted
// capacity, worst first.
func Rightsizing(ctx context.Context, s *kube.Snapshot, namespaces []string, prometheusURL string, opts RightsizingOptions) (report.Section, error) {
	if opts.Window <= 0 {
		opts.Window = 7 * 24 * time.Hour
	}
	usage, err := collectUsage(ctx, prom.NewClient(prometheusURL), namespaces, opts.Window)
	if err != nil {
		return report.Section{}, err
	}
	return rightsize(s, namespaces, usage, opts), nil
}

// promNamespaceMatcher builds the label matcher restricting a query to the
// analyzed namespaces.
func promNamespaceMatcher(namespaces []string) string {
	return fmt.Sprintf(`namespace=~"%s"`, strings.Join(namespaces, "|"))
}

// collectUsage queries P50/P95/max CPU and memory per pod over the window.
func collectUsage(ctx context.Context, client *prom.Client, namespaces []string, window time.Duration) (Usage, error) {
	nsMatcher := promNamespaceMatcher(namespaces)
	win := fmt.Sprintf("%dh", int(math.Ceil(window.Hours())))
	cpu := fmt.Sprintf(`(sum by (namespace,pod) (rate(container_cpu_usage_seconds_total{%s,container!="",container!="POD"}[5m])))[%s:5m]`, nsMatcher, win)
	mem := fmt.Sprintf(`(sum by (namespace,pod) (container_memory_working_set_bytes{%s,container!="",container!="POD"}))[%s:5m]`, nsMatcher, win)

	queries := []struct {
		expr string
		set  func(u *PodUsage, v float64)
	}{
		{fmt.Sprintf(`quantile_over_time(0.50, %s)`, cpu), func(u *PodUsage, v float64) { u.CPUP50 = v }},
		{fmt.Sprintf(`quantile_over_time(0.95, %s)`, cpu), func(u *PodUsage, v float64) { u.CPUP95 = v }},
		{fmt.Sprintf(`max_over_time(%s)`, cpu), func(u *PodUsage, v float64) { u.CPUMax = v }},
		{fmt.Sprintf(`quantile_over_time(0.50, %s)`, mem), func(u *PodUsage, v float64) { u.MemP50 = v }},
		{fmt.Sprintf(`quantile_over_time(0.95, %s)`, mem), func(u *PodUsage, v float64) { u.MemP95 = v }},
		{fmt.Sprintf(`max_over_time(%s)`, mem), func(u *PodUsage, v float64) { u.MemMax = v }},
	}

	out := Usage{}
	for _, q := range queries {
		samples, err := client.QueryVector(ctx, q.expr)
		if err != nil {
			return nil, err
		}
		for _, sm := range samples {
			key := sm.Labels["namespace"] + "/" + sm.Labels["pod"]
			u := out[key]
			q.set(&u, sm.Value)
			out[key] = u
		}
	}
	return out, nil
}

// recommendation is one workload's rightsizing result. Requests and usage
// are per pod; CPU in cores, memory in bytes.
type recommendation struct {
	kind, namespace, name string
	container             string // set only for single-container pods
	pods                  int    // running pods observed
	curCPU, curMem        float64
	sugCPU, sugMem        float64
	usage                 PodUsage
	savings               float64 // $/month across all pods; 0 without cost hints
	waste                 float64 // sort key: overprovisioned capacity in core-equivalents
}

// rightsize is the pure core of Rightsizing, split out so tests can feed
// synthetic usage.
func rightsize(s *kube.Snapshot, namespaces []string, usage Usage, opts RightsizingOptions) report.Section {
	sec := report.Section{ID: "rightsizing", Title: "Rightsizing", Icon: "📏"}
	nsSet := namespaceSet(namespaces)

	var recs []recommendation
	add := func(kind, ns, name string, selector *metav1.LabelSelector, spec corev1.PodSpec) {
		if !nsSet[ns] {
			return
		}
		if r, ok := recommend(s, usage, opts, kind, ns, name, selector, spec); ok {
			recs = append(recs, r)
		}
	}
	for _, d := range s.Deployments {
		add("Deployment", d.Namespace, d.Name, d.Spec.Selector, d.Spec.Template.Spec)
	}
	for _, ss := range s.StatefulSets {
		add("StatefulSet", ss.Namespace, ss.Name, ss.Spec.Selector, ss.Spec.Template.Spec)
	}
	for _, ds := range s.DaemonSets {
		add("DaemonSet", ds.Namespace, ds.Name, ds.Spec.Selector, ds.Spec.Template.Spec)
	}

	sort.Slice(recs, func(i, j int) bool {
		if recs[i].savings != recs[j].savings {
			return recs[i].savings > recs[j].savings
		}
		return recs[i].waste > recs[j].waste
	})

	var totalSavings float64
	for _, r := range recs {
		totalSavings += r.savings
	}
	if totalSavings >= 1 {
		sec.Findings = append(sec.Findings, report.Finding{
			Severity: report.SeverityInfo,
			Message:  fmt.Sprintf("Estimated monthly savings from rightsizing: ~$%.0f", totalSavings),
			Hint:     "Based on --cost-per-cpu/--cost-per-gb and the positive request deltas below.",
		})
	}
	for _, r := range recs {
		sec.Findings = append(sec.Findings, r.finding(opts))
	}
	return sec
}

// recommend analyzes one workload; ok is false when it has no observed usage
// or is already sized reasonably.
func recommend(s *kube.Snapshot, usage Usage, opts RightsizingOptions, kind, ns, name string, selector *metav1.LabelSelector, spec corev1.PodSpec) (recommendation, bool) {
	var r recommendation
	if selector == nil {
		return r, false
	}
	sel, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil || sel.Empty() {
		return r, false
	}

	var found bool
	var agg PodUsage
	pods := 0
	for _, p := range s.Pods {
		if p.Namespace != ns || p.Status.Phase != corev1.PodRunning || !sel.Matches(labels.Set(p.Labels)) {
			continue
		}
		pods++
		u, ok := usage[ns+"/"+p.Name]
		if !ok {
			continue
		}
		found = true
		agg.CPUP50 = math.Max(agg.CPUP50, u.CPUP50)
		agg.CPUP95 = math.Max(agg.CPUP95, u.CPUP95)
		agg.CPUMax = math.Max(agg.CPUMax, u.CPUMax)
		agg.MemP50 = math.Max(agg.MemP50, u.MemP50)
		agg.MemP95 = math.Max(agg.MemP95, u.MemP95)
		agg.MemMax = math.Max(agg.MemMax, u.MemMax)
	}
	if !found || pods == 0 {
		return r, false
	}

	var curCPU, curMem float64
	for _, c := range spec.Containers {
		curCPU += float64(c.Resources.Requests.Cpu().MilliValue()) / 1000
		curMem += float64(c.Resources.Requests.Memory().Value())
	}

	const mi = 1 << 20
	sugCPU := roundCPU(math.Max(agg.CPUP95*1.1, 0.01))
	sugMem := roundMem(math.Max(agg.MemMax*1.15, 32*mi))

	over := (curCPU > sugCPU*1.5 && curCPU-sugCPU >= 0.05) || (curMem > sugMem*1.5 && curMem-sugMem >= 64*mi)
	under := (curCPU > 0 && agg.CPUP95 > curCPU) || (curMem > 0 && agg.MemMax > curMem)
	unset := curCPU == 0 && curMem == 0
	if !over && !under && !unset {
		return r, false
	}

	r = recommendation{
		kind: kind, namespace: ns, name: name,
		pods:   pods,
		curCPU: curCPU, curMem: curMem,
		sugCPU: sugCPU, sugMem: sugMem,
		usage: agg,
	}
	if len(spec.Containers) == 1 {
		r.container = spec.Containers[0].Name
	}
	if dCPU, dMem := curCPU-sugCPU, curMem-sugMem; dCPU > 0 || dMem > 0 {
		r.waste = (math.Max(dCPU, 0) + math.Max(dMem, 0)/(4<<30)) * float64(pods)
		r.savings = math.Max(dCPU, 0)*float64(pods)*opts.CostPerCPUMonth +
			math.Max(dMem, 0)/(1<<30)*float64(pods)*opts.CostPerGiBMonth
	}
	return r, true
}

func (r recommendation) finding(opts RightsizingOptions) report.Finding {
	window := fmt.Sprintf("%dd", int(opts.Window.Hours()/24))
	usage := fmt.Sprintf("%s usage per pod: cpu P50 %s / P95 %s / max %s, memory max %s",
		window, formatCPU(r.usage.CPUP50), formatCPU(r.usage.CPUP95), formatCPU(r.usage.CPUMax), formatMem(r.usage.MemMax))
	suggest := fmt.Sprintf("suggest requests cpu: %s, memory: %s", formatCPU(r.sugCPU), formatMem(r.sugMem))

	var state string
	switch {
	case r.curCPU == 0 && r.curMem == 0:
		state = "has no resource requests"
	case r.usage.CPUP95 > r.curCPU && r.curCPU > 0, r.usage.MemMax > r.curMem && r.curMem > 0:
		state = fmt.Sprintf("is underprovisioned (requests cpu %s / memory %s per pod)", formatCPU(r.curCPU), formatMem(r.curMem))
	default:
		state = fmt.Sprintf("is overprovisioned (requests cpu %s / memory %s per pod)", formatCPU(r.curCPU), formatMem(r.curMem))
	}
	msg := fmt.Sprintf("%s %q %s; %s — %s", r.kind, r.name, state, usage, suggest)
	if r.savings >= 1 {
		msg += fmt.Sprintf(", saving ~$%.0f/mo", r.savings)
	}

	hint := fmt.Sprintf("Suggested values are per pod (sum of containers); split them across this workload's containers by their usage share. Observed across %d running %s.", r.pods, plural(r.pods, "pod", "pods"))
	if r.container != "" {
		memLimit := roundMem(r.usage.MemMax * 1.5)
		hint = fmt.Sprintf(`kubectl -n %s patch %s %s --type merge -p '{"spec":{"template":{"spec":{"containers":[{"name":%q,"resources":{"requests":{"cpu":%q,"memory":%q},"limits":{"memory":%q}}}]}}}}'`,
			r.namespace, strings.ToLower(r.kind), r.name, r.container, formatCPU(r.sugCPU), formatMem(r.sugMem), formatMem(memLimit))
	}
	return report.Finding{
		Severity: report.SeverityInfo,
		Message:  msg,
		Object:   strings.ToLower(r.kind) + "/" + r.name,
		Hint:     hint,
	}
}

// epsilon keeps Ceil from amplifying float noise (0.1*1.1 = 0.11000...01).
const epsilon = 1e-9

// roundCPU rounds up to 10m granularity below one core, 100m above.
func roundCPU(cores float64) float64 {
	if cores < 1 {
		return math.Ceil(cores*100-epsilon) / 100
	}
	return math.Ceil(cores*10-epsilon) / 10
}

// roundMem rounds up to the next 32Mi.
func roundMem(bytes float64) float64 {
	const step = 32 << 20
	return math.Ceil(bytes/step-epsilon) * step
}

func formatCPU(cores float64) string {
	m := int64(math.Round(cores * 1000))
	switch {
	case m < 1000:
		return fmt.Sprintf("%dm", m)
	case m%1000 == 0:
		return fmt.Sprintf("%d", m/1000)
	default:
		return fmt.Sprintf("%.1f", float64(m)/1000)
	}
}

func formatMem(bytes float64) string {
	mi := int64(math.Ceil(bytes / (1 << 20)))
	if mi >= 1024 && mi%1024 == 0 {
		return fmt.Sprintf("%dGi", mi/1024)
	}
	return fmt.Sprintf("%dMi", mi)
}
