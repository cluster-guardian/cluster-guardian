package checks

import (
	"fmt"
	"strings"

	"github.com/cluster-guardian/cluster-guardian/internal/report"
)

// complianceControl is a single control in a compliance framework that the
// checks can observe from a snapshot. Control IDs use the form
// "<framework>/<profile>:<control>"; finding tags and --framework match on it.
type complianceControl struct {
	ID   string
	Name string
}

// Pod Security Standards controls observable from workload specs. Further
// frameworks (NSA/CISA, CIS) join the same registry as their mappings land.
const (
	ctrlPrivileged     = "PSS/baseline:privileged"
	ctrlHostNamespaces = "PSS/baseline:host-namespaces"
	ctrlCapabilities   = "PSS/baseline:capabilities"
	ctrlRunAsNonRoot   = "PSS/restricted:run-as-nonroot"
	ctrlSeccomp        = "PSS/restricted:seccomp"
)

var pssControls = []complianceControl{
	{ID: ctrlPrivileged, Name: "Privileged Containers"},
	{ID: ctrlHostNamespaces, Name: "Host Namespaces"},
	{ID: ctrlCapabilities, Name: "Capabilities"},
	{ID: ctrlRunAsNonRoot, Name: "Running as Non-root"},
	{ID: ctrlSeccomp, Name: "Seccomp Profile"},
}

// complianceSummary reports how many PSS controls pass given the security
// findings produced so far. The summary is tagged with every control it
// covers so it survives --framework filtering.
func complianceSummary(findings []report.Finding) report.Finding {
	failing := map[string]bool{}
	for _, f := range findings {
		if f.Severity < report.SeverityWarning {
			continue
		}
		for _, c := range f.Controls {
			failing[c] = true
		}
	}
	var failed []string
	allIDs := make([]string, len(pssControls))
	for i, c := range pssControls {
		allIDs[i] = c.ID
		if failing[c.ID] {
			failed = append(failed, c.Name)
		}
	}
	f := report.Finding{
		Severity: report.SeverityOK,
		Message:  fmt.Sprintf("Pod Security Standards: %d of %d observable controls passing", len(pssControls)-len(failed), len(pssControls)),
		Controls: allIDs,
	}
	if len(failed) > 0 {
		f.Severity = report.SeverityInfo
		f.Message += fmt.Sprintf(" (failing: %s)", strings.Join(failed, ", "))
		f.Hint = "See https://kubernetes.io/docs/concepts/security/pod-security-standards/ for the control definitions."
	}
	return f
}
