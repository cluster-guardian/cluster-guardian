package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cluster-guardian/cluster-guardian/internal/analyzer"
	"github.com/cluster-guardian/cluster-guardian/internal/report"
)

func fixtureServer() *Server {
	r := &report.Report{
		ClusterName: "demo",
		Namespaces: []report.NamespaceSection{{
			Name:     "shop",
			Findings: []report.Finding{{Severity: report.SeverityCritical, Message: "privileged container"}},
		}},
	}
	r.Finalize()
	s := New(nil, analyzer.Options{}, time.Minute, nil)
	s.SetFixture(r)
	return s
}

func TestIndexListsEndpoints(t *testing.T) {
	rec := httptest.NewRecorder()
	fixtureServer().Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var body struct {
		Name      string   `json:"name"`
		Mode      string   `json:"mode"`
		Endpoints []string `json:"endpoints"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("index is not JSON: %v", err)
	}
	if body.Mode != "single-cluster" || len(body.Endpoints) == 0 {
		t.Errorf("unexpected index: %+v", body)
	}
}

// The UI lives in cluster-guardian-ui. This server must never grow an HTML
// surface back by accident: no rendered pages, no /static/ asset mount.
func TestServerServesNoHTML(t *testing.T) {
	h := fixtureServer().Handler()

	for _, path := range []string{"/", "/api/report", "/api/history", "/api/history/diff"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if ct := rec.Header().Get("Content-Type"); strings.Contains(ct, "text/html") {
			t.Errorf("%s served %s, want no HTML", path, ct)
		}
		if strings.Contains(rec.Body.String(), "<!DOCTYPE html") {
			t.Errorf("%s returned an HTML document", path)
		}
	}

	for _, path := range []string{"/static/dashboard.css", "/static/dashboard.js", "/clusters/demo"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404 (UI routes are gone)", path, rec.Code)
		}
	}
}
