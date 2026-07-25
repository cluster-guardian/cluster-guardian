package report

import "regexp"

// LocatedFinding is a finding plus where in the report it lives
// (a section title or "namespace <name>") and, for namespace findings, the
// owning team.
type LocatedFinding struct {
	Location string `json:"location"`
	Team     string `json:"team,omitempty"`
	Finding
}

// DiffResult lists findings that appeared in or disappeared from a report
// relative to an older one.
type DiffResult struct {
	New      []LocatedFinding `json:"new"`
	Resolved []LocatedFinding `json:"resolved"`
}

var diffNumbers = regexp.MustCompile(`[0-9]+`)

// findingKey identifies a finding across runs. Numbers are normalized so a
// count change ("5 Pods missing requests" -> "3 Pods missing requests") is
// not reported as new + resolved.
func findingKey(location string, f Finding) string {
	return location + "|" + f.Object + "|" + diffNumbers.ReplaceAllString(f.Message, "#")
}

// Diff compares two reports. OK findings never appear in the result.
func Diff(older, newer *Report) DiffResult {
	oldKeys := findingKeys(older)
	newKeys := findingKeys(newer)
	var d DiffResult
	forEachFinding(newer, func(loc, team string, f Finding) {
		if f.Severity != SeverityOK && !oldKeys[findingKey(loc, f)] {
			d.New = append(d.New, LocatedFinding{Location: loc, Team: team, Finding: f})
		}
	})
	forEachFinding(older, func(loc, team string, f Finding) {
		if f.Severity != SeverityOK && !newKeys[findingKey(loc, f)] {
			d.Resolved = append(d.Resolved, LocatedFinding{Location: loc, Team: team, Finding: f})
		}
	})
	return d
}

func findingKeys(r *Report) map[string]bool {
	out := map[string]bool{}
	forEachFinding(r, func(loc, _ string, f Finding) {
		if f.Severity != SeverityOK {
			out[findingKey(loc, f)] = true
		}
	})
	return out
}

func forEachFinding(r *Report, fn func(location, team string, f Finding)) {
	for _, ns := range r.Namespaces {
		for _, f := range ns.Findings {
			fn("namespace "+ns.Name, ns.Team, f)
		}
	}
	for _, s := range r.Sections {
		for _, f := range s.Findings {
			fn(s.Title, "", f)
		}
	}
}
