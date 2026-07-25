package fleet

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/AndrewKarpaty/cluster-guardian/internal/analyzer"
	"github.com/AndrewKarpaty/cluster-guardian/internal/kube"
	"github.com/AndrewKarpaty/cluster-guardian/internal/notify"
	"github.com/AndrewKarpaty/cluster-guardian/internal/report"
)

func clusterSecret(name, label string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "guardian",
			Name:      name + "-secret",
			Labels:    map[string]string{label: "cluster"},
		},
		Data: map[string][]byte{
			"name":   []byte(name),
			"server": []byte("https://" + name + ".example.com:6443"),
			"config": []byte(`{"bearerToken":"tok","tlsClientConfig":{"insecure":false,"caData":"Y2E="}}`),
		},
	}
}

func TestParseClusterSecret(t *testing.T) {
	c, err := ParseClusterSecret(*clusterSecret("prod", SecretLabel))
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "prod" || c.Server != "https://prod.example.com:6443" {
		t.Errorf("unexpected cluster: %+v", c)
	}
	if _, err := ParseClusterSecret(corev1.Secret{}); err == nil {
		t.Error("expected error for secret without name/server")
	}
}

func TestRegistryListsLocalAndSecrets(t *testing.T) {
	cs := fake.NewSimpleClientset(
		clusterSecret("prod", SecretLabel),
		clusterSecret("unlabeled", "other-label"),
	)
	reg := &Registry{
		Local:     &kube.Client{Context: "local-ctx", Clientset: cs},
		Clientset: cs,
		Namespace: "guardian",
	}
	clusters, err := reg.Clusters(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, c := range clusters {
		names[c.Name] = true
	}
	for _, want := range []string{"local-ctx", "prod"} {
		if !names[want] {
			t.Errorf("expected cluster %q in registry, got %v", want, names)
		}
	}
	if names["unlabeled"] {
		t.Error("unlabeled secret must not be registered")
	}
}

func testFleetReport(msgs ...string) *report.Report {
	var fs []report.Finding
	for _, m := range msgs {
		fs = append(fs, report.Finding{Severity: report.SeverityWarning, Message: m})
	}
	r := &report.Report{
		GeneratedAt: time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC),
		Sections:    []report.Section{{ID: "security", Title: "Security", Findings: fs}},
	}
	r.Finalize()
	return r
}

type staticLister struct{ clusters []Cluster }

func (l staticLister) Clusters(context.Context) ([]Cluster, error) { return l.clusters, nil }

func TestManagerNotifiesOnlyNewFindings(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
	}))
	defer srv.Close()
	posts := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(bodies)
	}

	n, err := notify.New(srv.URL, "slack", "warning")
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(staticLister{clusters: []Cluster{{Name: "good", Server: "https://good"}}},
		analyzer.Options{}, time.Minute, "", 10)
	m.EnableNotifications(n)

	scanWith := func(msgs ...string) {
		m.scan = func(context.Context, Cluster) (*report.Report, error) {
			return testFleetReport(msgs...), nil
		}
		m.ScanAll(context.Background())
	}

	scanWith("root containers")                         // first run: nothing to diff against
	scanWith("root containers", "privileged container") // one new finding -> one post
	scanWith("root containers", "privileged container") // unchanged -> silent

	deadline := time.Now().Add(2 * time.Second)
	for posts() < 1 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond) // allow any spurious extra posts to land
	if got := posts(); got != 1 {
		t.Fatalf("expected exactly 1 notification, got %d: %v", got, bodies)
	}
	mu.Lock()
	body := bodies[0]
	mu.Unlock()
	if !strings.Contains(body, "good") || !strings.Contains(body, "privileged container") ||
		strings.Contains(body, "root containers") {
		t.Errorf("notification must name the cluster and only the new finding, got: %s", body)
	}
}

func TestManagerScanAll(t *testing.T) {
	lister := staticLister{clusters: []Cluster{
		{Name: "good", Server: "https://good"},
		{Name: "broken", Server: "https://broken"},
	}}
	m := NewManager(lister, analyzer.Options{}, time.Minute, "", 10)
	m.scan = func(_ context.Context, c Cluster) (*report.Report, error) {
		if c.Name == "broken" {
			return nil, errors.New("connection refused")
		}
		return testFleetReport("root containers"), nil
	}

	m.ScanAll(context.Background())

	statuses := m.Statuses()
	if len(statuses) != 2 {
		t.Fatalf("expected 2 statuses, got %d", len(statuses))
	}
	byName := map[string]Status{}
	for _, s := range statuses {
		byName[s.Name] = s
	}
	if byName["good"].Summary == nil || byName["good"].Summary.Warnings != 1 {
		t.Errorf("expected good cluster summary with 1 warning, got %+v", byName["good"])
	}
	if byName["broken"].Error == "" || byName["broken"].Summary != nil {
		t.Errorf("expected broken cluster to report its error, got %+v", byName["broken"])
	}
	if m.Report("good") == nil || m.Report("broken") != nil || m.Report("ghost") != nil {
		t.Error("Report() should return only successful scans of known clusters")
	}

	// Second scan with one finding resolved: history diff per cluster.
	m.scan = func(_ context.Context, c Cluster) (*report.Report, error) {
		if c.Name == "broken" {
			return nil, errors.New("connection refused")
		}
		return testFleetReport(), nil
	}
	m.ScanAll(context.Background())
	if d := m.Diff("good"); d == nil || len(d.Resolved) != 1 {
		t.Errorf("expected 1 resolved finding for good cluster, got %+v", d)
	}
	if entries := m.History("good"); len(entries) != 2 {
		t.Errorf("expected 2 history entries, got %d", len(entries))
	}
}
