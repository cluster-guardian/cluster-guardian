package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/cluster-guardian/cluster-guardian/internal/analyzer"
	"github.com/cluster-guardian/cluster-guardian/internal/auth"
	"github.com/cluster-guardian/cluster-guardian/internal/fleet"
	"github.com/cluster-guardian/cluster-guardian/internal/report"
	"github.com/cluster-guardian/cluster-guardian/internal/teams"
)

const testNS = "cluster-guardian"

// adminServer builds a server with the write API on, auth in proxy mode
// trusting the loopback address httptest uses.
func adminServer(t *testing.T, objects ...any) (*Server, *fake.Clientset) {
	t.Helper()
	cs := fake.NewSimpleClientset()
	for _, o := range objects {
		if cm, ok := o.(*corev1.ConfigMap); ok {
			if _, err := cs.CoreV1().ConfigMaps(cm.Namespace).Create(t.Context(), cm, metav1.CreateOptions{}); err != nil {
				t.Fatalf("seeding configmap: %v", err)
			}
		}
	}

	s := New(nil, analyzer.Options{}, time.Minute, nil)
	s.SetFixture(&report.Report{ClusterName: "demo"})
	nets, err := auth.ParseTrustedProxies([]string{"192.0.2.0/24"})
	if err != nil {
		t.Fatalf("parsing proxies: %v", err)
	}
	s.EnableAuth(auth.Config{
		Enabled:        true,
		GroupRoles:     map[string]auth.Role{"admins": auth.RoleAdmin, "leads": auth.RoleOperator},
		DefaultRole:    auth.RoleViewer,
		AnonymousRole:  auth.RoleViewer,
		TrustedProxies: nets,
	})
	// Admin.Fleet is left nil so writes do not kick off a rescan against a
	// cluster that does not exist; the rescan path is exercised in fleet's own
	// tests.
	s.EnableAdmin(&Admin{
		Clientset: cs,
		Namespace: testNS,
		Teams:     &teams.Store{Clientset: cs, Namespace: testNS, Name: "cg-teams"},
	})
	// Fleet routes must exist for the cluster write routes to be registered.
	s.EnableFleet(&fleet.Manager{})
	return s, cs
}

// do issues a request as a user in the given groups, from a trusted peer.
func do(t *testing.T, s *Server, method, path, groups string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encoding body: %v", err)
		}
	}
	r := httptest.NewRequest(method, path, &buf)
	r.RemoteAddr = "192.0.2.10:5555"
	if groups != "" {
		r.Header.Set(auth.DefaultUserHeader, "tester")
		r.Header.Set(auth.DefaultGroupsHeader, groups)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func validCluster() clusterRequest {
	return clusterRequest{
		Name:        "prod",
		Server:      "https://prod.example.com:6443",
		BearerToken: "tok",
		CAData:      base64.StdEncoding.EncodeToString([]byte("-----BEGIN CERTIFICATE-----")),
	}
}

func TestMeReportsRoleAndFeatures(t *testing.T) {
	s, _ := adminServer(t)
	w := do(t, s, http.MethodGet, "/api/me", "admins", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var got struct {
		Identity auth.Identity   `json:"identity"`
		Features map[string]bool `json:"features"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if got.Identity.User != "tester" || got.Identity.Role != auth.RoleAdmin {
		t.Fatalf("identity = %+v, want tester/admin", got.Identity)
	}
	if !got.Features["clusters"] || !got.Features["teams"] {
		t.Errorf("features = %v, want both enabled", got.Features)
	}
}

func TestMeIsReachableWithoutPermissions(t *testing.T) {
	// A caller mapped to no role still needs to learn that, or the UI cannot
	// tell "no access" from "server down".
	s, _ := adminServer(t)
	s.auth.DefaultRole = auth.RoleNone
	w := do(t, s, http.MethodGet, "/api/me", "nobody", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", w.Code, w.Body)
	}
}

func TestCreateClusterRequiresAdmin(t *testing.T) {
	for _, tc := range []struct {
		groups string
		want   int
	}{
		{"", http.StatusForbidden},        // anonymous -> viewer
		{"viewers", http.StatusForbidden}, // unmapped -> default viewer
		{"leads", http.StatusForbidden},   // operator
		{"admins", http.StatusCreated},
	} {
		s, _ := adminServer(t)
		w := do(t, s, http.MethodPost, "/api/clusters", tc.groups, validCluster())
		if w.Code != tc.want {
			t.Errorf("groups %q: status %d, want %d (%s)", tc.groups, w.Code, tc.want, w.Body)
		}
	}
}

func TestCreateClusterWritesARegistrationSecret(t *testing.T) {
	s, cs := adminServer(t)
	w := do(t, s, http.MethodPost, "/api/clusters", "admins", validCluster())
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}

	sec, err := cs.CoreV1().Secrets(testNS).Get(t.Context(), "cluster-prod", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("reading secret: %v", err)
	}
	if got := string(sec.Data["name"]); got != "prod" {
		t.Errorf("secret name key = %q, want prod", got)
	}
	if sec.Labels[fleet.SecretLabel] != "cluster" {
		t.Errorf("labels = %v, want the registration label", sec.Labels)
	}
	// The registry must be able to read back what the API wrote.
	c, err := fleet.ParseClusterSecret(*sec)
	if err != nil {
		t.Fatalf("registry cannot parse the secret this endpoint wrote: %v", err)
	}
	if c.Name != "prod" || c.Server != "https://prod.example.com:6443" {
		t.Errorf("parsed %+v, want prod at its server URL", c)
	}
}

func TestCreateClusterRejectsBadRequests(t *testing.T) {
	cases := map[string]func(*clusterRequest){
		"no name":             func(c *clusterRequest) { c.Name = "" },
		"no token":            func(c *clusterRequest) { c.BearerToken = "" },
		"relative server":     func(c *clusterRequest) { c.Server = "prod.example.com" },
		"non-http scheme":     func(c *clusterRequest) { c.Server = "ftp://prod.example.com" },
		"no CA, not insecure": func(c *clusterRequest) { c.CAData = "" },
		"CA and insecure":     func(c *clusterRequest) { c.Insecure = true },
		"CA not base64":       func(c *clusterRequest) { c.CAData = "!!!not base64!!!" },
	}
	for name, mutate := range cases {
		s, _ := adminServer(t)
		body := validCluster()
		mutate(&body)
		w := do(t, s, http.MethodPost, "/api/clusters", "admins", body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400 (%s)", name, w.Code, w.Body)
		}
	}
}

func TestCreateClusterIsIdempotent(t *testing.T) {
	// Re-adding a cluster rotates its credentials rather than failing, which
	// is what `cluster add` does and what a UI "save" should do.
	s, cs := adminServer(t)
	if w := do(t, s, http.MethodPost, "/api/clusters", "admins", validCluster()); w.Code != http.StatusCreated {
		t.Fatalf("first create: %d %s", w.Code, w.Body)
	}
	second := validCluster()
	second.BearerToken = "rotated"
	if w := do(t, s, http.MethodPost, "/api/clusters", "admins", second); w.Code != http.StatusCreated {
		t.Fatalf("second create: %d %s", w.Code, w.Body)
	}
	sec, err := cs.CoreV1().Secrets(testNS).Get(t.Context(), "cluster-prod", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("reading secret: %v", err)
	}
	if !bytes.Contains(sec.Data["config"], []byte("rotated")) {
		t.Error("re-adding a cluster did not rotate the stored token")
	}
}

func TestDeleteCluster(t *testing.T) {
	s, cs := adminServer(t)
	if w := do(t, s, http.MethodPost, "/api/clusters", "admins", validCluster()); w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	if w := do(t, s, http.MethodDelete, "/api/clusters/prod", "admins", nil); w.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", w.Code, w.Body)
	}
	if _, err := cs.CoreV1().Secrets(testNS).Get(t.Context(), "cluster-prod", metav1.GetOptions{}); err == nil {
		t.Error("secret still present after delete")
	}
}

func TestDeleteUnknownClusterIs404(t *testing.T) {
	// The local cluster has no secret behind it, so this is also the answer
	// for "remove the cluster the hub itself runs in".
	s, _ := adminServer(t)
	w := do(t, s, http.MethodDelete, "/api/clusters/local", "admins", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404: %s", w.Code, w.Body)
	}
}

func TestDeleteClusterRequiresAdmin(t *testing.T) {
	s, _ := adminServer(t)
	if w := do(t, s, http.MethodDelete, "/api/clusters/prod", "leads", nil); w.Code != http.StatusForbidden {
		t.Errorf("operator delete: status %d, want 403", w.Code)
	}
}

func TestTeamsRoundTrip(t *testing.T) {
	s, _ := adminServer(t)
	spec := teams.Spec{Teams: []teams.Team{
		{Name: "payments", Namespaces: []string{"checkout", "payments"}, NotifyURL: "https://hooks.example.com/abc"},
		{Name: "platform", Namespaces: []string{"monitoring"}},
	}}
	if w := do(t, s, http.MethodPut, "/api/teams", "leads", spec); w.Code != http.StatusOK {
		t.Fatalf("put: %d %s", w.Code, w.Body)
	}

	w := do(t, s, http.MethodGet, "/api/teams", "viewers", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get: %d %s", w.Code, w.Body)
	}
	var got teams.Spec
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if len(got.Teams) != 2 {
		t.Fatalf("got %d teams, want 2", len(got.Teams))
	}
	if got.Teams[0].Name != "payments" || got.Teams[1].Name != "platform" {
		t.Errorf("teams = %+v, want sorted by name", got.Teams)
	}
	if got.Teams[0].NotifyURL != teams.RedactedURL {
		t.Errorf("notifyUrl = %q, want it redacted — a webhook URL is a credential", got.Teams[0].NotifyURL)
	}
}

func TestTeamsPutPreservesRedactedWebhooks(t *testing.T) {
	// A UI only ever sees "***". Saving an unrelated edit must not wipe the
	// real URL.
	s, cs := adminServer(t)
	original := teams.Spec{Teams: []teams.Team{
		{Name: "payments", Namespaces: []string{"payments"}, NotifyURL: "https://hooks.example.com/keep-me"},
	}}
	if w := do(t, s, http.MethodPut, "/api/teams", "admins", original); w.Code != http.StatusOK {
		t.Fatalf("seed put: %d %s", w.Code, w.Body)
	}

	edited := teams.Spec{Teams: []teams.Team{
		{Name: "payments", Namespaces: []string{"payments", "checkout"}, NotifyURL: teams.RedactedURL},
	}}
	if w := do(t, s, http.MethodPut, "/api/teams", "admins", edited); w.Code != http.StatusOK {
		t.Fatalf("edit put: %d %s", w.Code, w.Body)
	}

	cm, err := cs.CoreV1().ConfigMaps(testNS).Get(t.Context(), "cg-teams", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("reading configmap: %v", err)
	}
	if !bytes.Contains([]byte(cm.Data[teams.DefaultConfigMapKey]), []byte("keep-me")) {
		t.Fatalf("the webhook was wiped by an edit that sent it back redacted:\n%s", cm.Data[teams.DefaultConfigMapKey])
	}
}

func TestTeamsPutRequiresOperator(t *testing.T) {
	s, _ := adminServer(t)
	spec := teams.Spec{Teams: []teams.Team{{Name: "a", Namespaces: []string{"x"}}}}
	if w := do(t, s, http.MethodPut, "/api/teams", "viewers", spec); w.Code != http.StatusForbidden {
		t.Errorf("viewer put: status %d, want 403", w.Code)
	}
}

func TestTeamsPutRejectsOverlappingNamespaces(t *testing.T) {
	s, _ := adminServer(t)
	spec := teams.Spec{Teams: []teams.Team{
		{Name: "a", Namespaces: []string{"shared"}},
		{Name: "b", Namespaces: []string{"shared"}},
	}}
	w := do(t, s, http.MethodPut, "/api/teams", "admins", spec)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400: %s", w.Code, w.Body)
	}
}

func TestWriteRoutesAbsentWithoutAdminAPI(t *testing.T) {
	// Not 403: this deployment has no write capability at all, and "forbidden"
	// would imply the right role could use it. The path is registered for GET,
	// so the mux answers 405 — "this server does not do that".
	s := New(nil, analyzer.Options{}, time.Minute, nil)
	s.SetFixture(&report.Report{ClusterName: "demo"})
	s.EnableFleet(&fleet.Manager{})

	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/api/clusters"},
		{http.MethodDelete, "/api/clusters/prod"},
		{http.MethodPut, "/api/teams"},
	} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code == http.StatusOK || w.Code == http.StatusForbidden {
			t.Errorf("%s %s: status %d — the route must not be served at all", tc.method, tc.path, w.Code)
		}
	}
	// /api/teams is not registered for any method here, so it is a plain 404.
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/teams", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("GET /api/teams: status %d, want 404", w.Code)
	}
}

func TestReadsStillOpenWhenAuthDisabled(t *testing.T) {
	// The default deployment must behave exactly as it did before roles
	// existed: anonymous callers can read.
	s := New(nil, analyzer.Options{}, time.Minute, nil)
	s.SetFixture(&report.Report{ClusterName: "demo"})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/report", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status %d, want 200: %s", w.Code, w.Body)
	}
}

func TestHealthzAndMetricsSkipAuth(t *testing.T) {
	// A kubelet probe and a Prometheus scrape carry no identity headers.
	s, _ := adminServer(t)
	s.auth.AnonymousRole = auth.RoleNone
	for _, path := range []string{"/healthz", "/metrics"} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK {
			t.Errorf("%s: status %d, want 200", path, w.Code)
		}
	}
}

func TestReadsDeniedForRoleNone(t *testing.T) {
	s, _ := adminServer(t)
	s.auth.AnonymousRole = auth.RoleNone
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/report", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("status %d, want 403", w.Code)
	}
}
