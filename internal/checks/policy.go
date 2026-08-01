package checks

import (
	"fmt"
	"slices"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/cluster-guardian/cluster-guardian/internal/kube"
	"github.com/cluster-guardian/cluster-guardian/internal/report"
)

// Policy aggregates policy-engine state (Kyverno, Gatekeeper) into the
// report: violation counts and namespaces no policy covers. The section is
// empty when neither engine is installed.
func Policy(s *kube.Snapshot, namespaces []string) report.Section {
	sec := report.Section{ID: "policy", Title: "Policy", Icon: "📜"}
	if !s.HasKyverno && !s.HasGatekeeper {
		return sec
	}
	nsSet := namespaceSet(namespaces)
	if s.HasKyverno {
		sec.Findings = append(sec.Findings, kyvernoFindings(s, nsSet)...)
	}
	if s.HasGatekeeper {
		sec.Findings = append(sec.Findings, gatekeeperFindings(s)...)
	}
	sec.Findings = append(sec.Findings, policyCoverageFindings(s, namespaces)...)
	return sec
}

// kyvernoFindings sums PolicyReport failures per namespace.
func kyvernoFindings(s *kube.Snapshot, nsSet map[string]bool) []report.Finding {
	failsByNS := map[string]int64{}
	var total int64
	for _, pr := range s.KyvernoPolicyReports {
		ns := pr.GetNamespace()
		if !nsSet[ns] {
			continue
		}
		fails, _, _ := unstructured.NestedInt64(pr.Object, "summary", "fail")
		if fails > 0 {
			failsByNS[ns] += fails
			total += fails
		}
	}

	policies := len(s.KyvernoPolicies) + len(s.KyvernoClusterPolicies)
	switch {
	case total > 0:
		parts := make([]string, 0, len(failsByNS))
		for ns, n := range failsByNS {
			parts = append(parts, fmt.Sprintf("%s: %d", ns, n))
		}
		return []report.Finding{{
			Severity: report.SeverityWarning,
			Message: fmt.Sprintf("%d Kyverno policy %s across %d %s (%s)",
				total, plural(int(total), "violation", "violations"),
				len(failsByNS), plural(len(failsByNS), "namespace", "namespaces"), joinLimited(parts, 4)),
			Hint: "Inspect PolicyReports in these namespaces (kubectl get policyreport -n <ns>) for the failing rules.",
		}}
	case policies == 0:
		return []report.Finding{{
			Severity: report.SeverityInfo,
			Message:  "Kyverno is installed but no policies are defined",
			Hint:     "An admission controller with zero policies enforces nothing.",
		}}
	default:
		return []report.Finding{{
			Severity: report.SeverityOK,
			Message:  fmt.Sprintf("Kyverno: %d %s, no violations reported", policies, plural(policies, "policy", "policies")),
		}}
	}
}

// gatekeeperFindings sums constraint violations from audit status.
func gatekeeperFindings(s *kube.Snapshot) []report.Finding {
	var total int64
	var parts []string
	for _, c := range s.GatekeeperConstraints {
		v, _, _ := unstructured.NestedInt64(c.Object, "status", "totalViolations")
		if v > 0 {
			parts = append(parts, fmt.Sprintf("%s %s (%d)", c.GetKind(), c.GetName(), v))
			total += v
		}
	}

	switch {
	case total > 0:
		return []report.Finding{{
			Severity: report.SeverityWarning,
			Message: fmt.Sprintf("%d Gatekeeper constraint %s (%s)",
				total, plural(int(total), "violation", "violations"), joinLimited(parts, 3)),
			Hint: "See each constraint's status.violations for the offending objects.",
		}}
	case len(s.GatekeeperConstraints) == 0:
		return []report.Finding{{
			Severity: report.SeverityInfo,
			Message:  "Gatekeeper is installed but no constraints are defined",
			Hint:     "Constraint templates without constraints enforce nothing.",
		}}
	default:
		n := len(s.GatekeeperConstraints)
		return []report.Finding{{
			Severity: report.SeverityOK,
			Message:  fmt.Sprintf("All %d Gatekeeper %s report no violations", n, plural(n, "constraint", "constraints")),
		}}
	}
}

// policyCoverageFindings flags analyzed namespaces (with pods) that no
// installed engine covers: no Kyverno report or namespaced policy, not
// matched by any Gatekeeper constraint, and no blanket cluster-wide policy.
func policyCoverageFindings(s *kube.Snapshot, namespaces []string) []report.Finding {
	// A Kyverno ClusterPolicy applies cluster-wide by default; treat any as
	// blanket coverage rather than evaluating its match block.
	if len(s.KyvernoClusterPolicies) > 0 {
		return nil
	}

	covered := map[string]bool{}
	for _, pr := range s.KyvernoPolicyReports {
		covered[pr.GetNamespace()] = true
	}
	for _, p := range s.KyvernoPolicies {
		covered[p.GetNamespace()] = true
	}
	for _, c := range s.GatekeeperConstraints {
		matched, found, _ := unstructured.NestedStringSlice(c.Object, "spec", "match", "namespaces")
		if found && len(matched) > 0 {
			for _, ns := range matched {
				covered[ns] = true
			}
			continue
		}
		// No namespace list: the constraint applies everywhere except its
		// exclusions.
		excluded, _, _ := unstructured.NestedStringSlice(c.Object, "spec", "match", "excludedNamespaces")
		for _, ns := range namespaces {
			if !slices.Contains(excluded, ns) {
				covered[ns] = true
			}
		}
	}

	var uncovered []string
	for _, ns := range namespaces {
		if !covered[ns] && namespaceHasPods(s, ns) {
			uncovered = append(uncovered, ns)
		}
	}
	if len(uncovered) == 0 {
		return nil
	}
	n := len(uncovered)
	return []report.Finding{{
		Severity: report.SeverityWarning,
		Message: fmt.Sprintf("%d %s not covered by any admission policy (%s)",
			n, plural(n, "namespace is", "namespaces are"), joinLimited(uncovered, 4)),
		Hint: "A policy engine is installed, but workloads in these namespaces are admitted unchecked.",
	}}
}
