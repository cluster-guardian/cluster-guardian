package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"
	"time"
)

func ciTestReport() *Report {
	r := &Report{
		ClusterName: "prod",
		GeneratedAt: time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC),
		Namespaces: []NamespaceSection{{Name: "payments", Findings: []Finding{
			{Severity: SeverityWarning, Message: "3 Pods missing resource requests", Hint: "Set requests."},
		}}},
		Sections: []Section{{ID: "security", Title: "Security", Findings: []Finding{
			{Severity: SeverityCritical, Message: "1 privileged container", Object: "pod/bad"},
			{Severity: SeverityInfo, Message: "1 container without readOnlyRootFilesystem"},
			{Severity: SeverityOK, Message: "all good otherwise"},
		}}},
	}
	r.Finalize()
	return r
}

func TestWriteSARIF(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, ciTestReport()); err != nil {
		t.Fatal(err)
	}

	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Message   struct{ Text string }
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("unexpected SARIF envelope: version %q, %d runs", log.Version, len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "cluster-guardian" || len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("expected 2 rules, got %+v", run.Tool.Driver.Rules)
	}
	// OK findings are omitted: 1 warning + 1 critical + 1 info.
	if len(run.Results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(run.Results))
	}
	levels := map[string]string{}
	for _, res := range run.Results {
		levels[res.Level] = res.RuleID
		if len(res.PartialFingerprints) != 1 {
			t.Errorf("expected a fingerprint on %q", res.Message.Text)
		}
	}
	if levels["warning"] != "cluster-guardian/workloads" ||
		levels["error"] != "cluster-guardian/security" ||
		levels["note"] != "cluster-guardian/security" {
		t.Errorf("unexpected level/rule mapping: %v", levels)
	}
	for _, res := range run.Results {
		if res.Level == "error" {
			if uri := res.Locations[0].PhysicalLocation.ArtifactLocation.URI; uri != "pod/bad" {
				t.Errorf("expected the finding object as location URI, got %q", uri)
			}
		}
	}
	// Fingerprints must be count-stable so re-runs deduplicate.
	a := findingKey("namespace/payments", Finding{Message: "3 Pods missing resource requests"})
	b := findingKey("namespace/payments", Finding{Message: "5 Pods missing resource requests"})
	if a != b {
		t.Error("fingerprints must normalize counts")
	}
}

func TestWriteJUnit(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJUnit(&buf, ciTestReport()); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(buf.String(), xml.Header) {
		t.Error("expected an XML header")
	}

	var suites struct {
		Name     string `xml:"name,attr"`
		Tests    int    `xml:"tests,attr"`
		Failures int    `xml:"failures,attr"`
		Suites   []struct {
			Name     string `xml:"name,attr"`
			Failures int    `xml:"failures,attr"`
			Cases    []struct {
				Name    string `xml:"name,attr"`
				Failure *struct {
					Message string `xml:"message,attr"`
					Type    string `xml:"type,attr"`
					Body    string `xml:",chardata"`
				} `xml:"failure"`
			} `xml:"testcase"`
		} `xml:"testsuite"`
	}
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("invalid JUnit XML: %v", err)
	}
	// 4 findings total (OK included as a passing case), 2 failures.
	if suites.Tests != 4 || suites.Failures != 2 {
		t.Errorf("expected 4 tests / 2 failures, got %d/%d", suites.Tests, suites.Failures)
	}
	if len(suites.Suites) != 2 || suites.Suites[0].Name != "namespace/payments" || suites.Suites[1].Name != "security" {
		t.Fatalf("unexpected suites: %+v", suites.Suites)
	}
	nsCase := suites.Suites[0].Cases[0]
	if nsCase.Failure == nil || nsCase.Failure.Type != "warning" || nsCase.Failure.Body != "Set requests." {
		t.Errorf("expected warning failure with hint body, got %+v", nsCase.Failure)
	}
	var okSeen, infoFailed bool
	for _, c := range suites.Suites[1].Cases {
		if c.Name == "all good otherwise" && c.Failure == nil {
			okSeen = true
		}
		if strings.Contains(c.Name, "readOnlyRootFilesystem") && c.Failure != nil {
			infoFailed = true
		}
	}
	if !okSeen {
		t.Error("OK findings must appear as passing cases")
	}
	if infoFailed {
		t.Error("info findings must not fail the suite")
	}
}
