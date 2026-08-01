package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cluster-guardian/cluster-guardian/internal/report"
)

func located(sev report.Severity, location, msg string) report.LocatedFinding {
	return report.LocatedFinding{
		Location: location,
		Finding:  report.Finding{Severity: sev, Message: msg},
	}
}

// capture returns a webhook server recording each request body.
func capture(t *testing.T, status int) (*httptest.Server, *[]string) {
	t.Helper()
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("unexpected content type %q", ct)
		}
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, &bodies
}

func TestNotifySlack(t *testing.T) {
	srv, bodies := capture(t, http.StatusOK)
	n, err := New(srv.URL, "slack", "critical")
	if err != nil {
		t.Fatal(err)
	}

	err = n.Notify(context.Background(), "prod", []report.LocatedFinding{
		located(report.SeverityCritical, "Security", "1 privileged container"),
		located(report.SeverityWarning, "namespace payments", "below threshold"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(*bodies) != 1 {
		t.Fatalf("expected 1 webhook post, got %d", len(*bodies))
	}
	var payload struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal([]byte((*bodies)[0]), &payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload.Text, "1 new finding on *prod*") ||
		!strings.Contains(payload.Text, "[critical] Security: 1 privileged container") {
		t.Errorf("unexpected slack text: %q", payload.Text)
	}
	if strings.Contains(payload.Text, "below threshold") {
		t.Errorf("below-threshold finding must be filtered: %q", payload.Text)
	}
}

func TestNotifyJSON(t *testing.T) {
	srv, bodies := capture(t, http.StatusAccepted)
	n, err := New(srv.URL, "json", "warning")
	if err != nil {
		t.Fatal(err)
	}

	err = n.Notify(context.Background(), "prod", []report.LocatedFinding{
		located(report.SeverityWarning, "Security", "warning finding"),
	})
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Cluster     string                  `json:"cluster"`
		NewFindings []report.LocatedFinding `json:"newFindings"`
	}
	if err := json.Unmarshal([]byte((*bodies)[0]), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Cluster != "prod" || len(payload.NewFindings) != 1 ||
		payload.NewFindings[0].Message != "warning finding" {
		t.Errorf("unexpected json payload: %+v", payload)
	}
}

func TestNotifySkipsWhenNothingQualifies(t *testing.T) {
	srv, bodies := capture(t, http.StatusOK)
	n, err := New(srv.URL, "slack", "critical")
	if err != nil {
		t.Fatal(err)
	}
	err = n.Notify(context.Background(), "prod", []report.LocatedFinding{
		located(report.SeverityInfo, "Security", "just info"),
	})
	if err != nil || len(*bodies) != 0 {
		t.Errorf("expected no post for below-threshold findings, got %d posts, err %v", len(*bodies), err)
	}
}

func TestRouterRoutesPerTeam(t *testing.T) {
	globalSrv, globalBodies := capture(t, http.StatusOK)
	teamSrv, teamBodies := capture(t, http.StatusOK)
	global, err := New(globalSrv.URL, "slack", "warning")
	if err != nil {
		t.Fatal(err)
	}
	teamN, err := New(teamSrv.URL, "slack", "warning")
	if err != nil {
		t.Fatal(err)
	}
	router := NewRouter(global, map[string]*Notifier{"payments-team": teamN})

	findings := []report.LocatedFinding{
		{Location: "namespace payments", Team: "payments-team",
			Finding: report.Finding{Severity: report.SeverityCritical, Message: "payments issue"}},
		{Location: "namespace other", Team: "other-team",
			Finding: report.Finding{Severity: report.SeverityWarning, Message: "other issue"}},
		{Location: "Security", // cluster-wide: no team
			Finding: report.Finding{Severity: report.SeverityWarning, Message: "cluster issue"}},
	}
	if err := router.Notify(context.Background(), "prod", findings); err != nil {
		t.Fatal(err)
	}

	if len(*globalBodies) != 1 || !strings.Contains((*globalBodies)[0], "cluster issue") {
		t.Errorf("global sink must receive everything, got %v", *globalBodies)
	}
	if len(*teamBodies) != 1 {
		t.Fatalf("expected exactly 1 team post, got %d", len(*teamBodies))
	}
	teamBody := (*teamBodies)[0]
	if !strings.Contains(teamBody, "payments issue") ||
		strings.Contains(teamBody, "other issue") || strings.Contains(teamBody, "cluster issue") {
		t.Errorf("team must only hear about its own namespaces, got %s", teamBody)
	}
}

func TestNotifyErrors(t *testing.T) {
	srv, _ := capture(t, http.StatusForbidden)
	n, err := New(srv.URL, "slack", "info")
	if err != nil {
		t.Fatal(err)
	}
	err = n.Notify(context.Background(), "prod", []report.LocatedFinding{
		located(report.SeverityCritical, "Security", "boom"),
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("expected HTTP 403 error, got %v", err)
	}

	if _, err := New("http://x", "teams", "critical"); err == nil {
		t.Error("expected error for unknown format")
	}
	if _, err := New("http://x", "slack", "severe"); err == nil {
		t.Error("expected error for unknown severity")
	}
}
