package report

import (
	"encoding/xml"
	"io"
)

// JUnit XML: one testsuite per namespace and per section, one testcase per
// finding. Warning and critical findings render as failures so CI systems
// (GitLab, Jenkins) surface them as failed tests; info and OK findings are
// passing cases, keeping the full report visible without failing builds.

type junitTestSuites struct {
	XMLName  xml.Name         `xml:"testsuites"`
	Name     string           `xml:"name,attr"`
	Tests    int              `xml:"tests,attr"`
	Failures int              `xml:"failures,attr"`
	Suites   []junitTestSuite `xml:"testsuite"`
}

type junitTestSuite struct {
	Name     string          `xml:"name,attr"`
	Tests    int             `xml:"tests,attr"`
	Failures int             `xml:"failures,attr"`
	Cases    []junitTestCase `xml:"testcase"`
}

type junitTestCase struct {
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Body    string `xml:",chardata"`
}

// WriteJUnit renders the report as JUnit XML.
func WriteJUnit(w io.Writer, r *Report) error {
	suites := junitTestSuites{Name: "cluster-guardian: " + r.ClusterName}

	suite := func(name string, findings []Finding) {
		if len(findings) == 0 {
			return
		}
		s := junitTestSuite{Name: name, Tests: len(findings)}
		for _, f := range findings {
			c := junitTestCase{Name: f.Message, Classname: name}
			if f.Severity >= SeverityWarning {
				c.Failure = &junitFailure{
					Message: f.Message,
					Type:    f.Severity.String(),
					Body:    f.Hint,
				}
				s.Failures++
			}
			s.Cases = append(s.Cases, c)
		}
		suites.Tests += s.Tests
		suites.Failures += s.Failures
		suites.Suites = append(suites.Suites, s)
	}

	for _, ns := range r.Namespaces {
		suite("namespace/"+ns.Name, ns.Findings)
	}
	for _, sec := range r.Sections {
		suite(sec.ID, sec.Findings)
	}

	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(suites); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}
