package report

import (
	"encoding/json"
	"io"
)

// SARIF v2.1.0, the subset GitHub code scanning ingests. Severity maps to
// SARIF levels: critical -> error, warning -> warning, info -> note; OK
// findings are omitted (they are not problems).

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string    `json:"id"`
	ShortDescription sarifText `json:"shortDescription"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// WriteSARIF renders the report as SARIF 2.1.0 for code-scanning ingestion.
// Cluster findings have no source file, so locations use synthetic URIs
// (the object, the namespace, or the section); fingerprints reuse the
// number-normalized diff key so re-runs deduplicate.
func WriteSARIF(w io.Writer, r *Report) error {
	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           "cluster-guardian",
			InformationURI: "https://github.com/AndrewKarpaty/cluster-guardian",
		}},
		Results: []sarifResult{},
	}

	seenRules := map[string]bool{}
	addRule := func(id, description string) {
		if seenRules[id] {
			return
		}
		seenRules[id] = true
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
			ID:               id,
			ShortDescription: sarifText{Text: description},
		})
	}

	add := func(ruleID, description, location string, f Finding) {
		level := ""
		switch f.Severity {
		case SeverityCritical:
			level = "error"
		case SeverityWarning:
			level = "warning"
		case SeverityInfo:
			level = "note"
		default:
			return // OK findings are not problems
		}
		addRule(ruleID, description)

		uri := f.Object
		if uri == "" {
			uri = location
		}
		text := f.Message
		if f.Hint != "" {
			text += " — " + f.Hint
		}
		var loc sarifLocation
		loc.PhysicalLocation.ArtifactLocation.URI = uri
		loc.PhysicalLocation.Region.StartLine = 1
		run.Results = append(run.Results, sarifResult{
			RuleID:    ruleID,
			Level:     level,
			Message:   sarifText{Text: text},
			Locations: []sarifLocation{loc},
			PartialFingerprints: map[string]string{
				"clusterGuardianFinding/v1": findingKey(location, f),
			},
		})
	}

	for _, ns := range r.Namespaces {
		for _, f := range ns.Findings {
			add("cluster-guardian/workloads", "Per-namespace workload checks", "namespace/"+ns.Name, f)
		}
	}
	for _, sec := range r.Sections {
		for _, f := range sec.Findings {
			add("cluster-guardian/"+sec.ID, sec.Title, sec.ID, f)
		}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	})
}
