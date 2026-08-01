package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func proxyConfig(t *testing.T, trusted ...string) Config {
	t.Helper()
	if len(trusted) == 0 {
		trusted = []string{"10.0.0.0/8"}
	}
	nets, err := ParseTrustedProxies(trusted)
	if err != nil {
		t.Fatalf("parsing trusted proxies: %v", err)
	}
	return Config{
		Enabled:        true,
		GroupRoles:     map[string]Role{"platform": RoleAdmin, "sre": RoleOperator, "dev": RoleViewer},
		DefaultRole:    RoleViewer,
		AnonymousRole:  RoleViewer,
		TrustedProxies: nets,
	}.WithDefaults()
}

func request(remote string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/report", nil)
	r.RemoteAddr = remote
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestRolePermissions(t *testing.T) {
	cases := []struct {
		role Role
		perm Permission
		want bool
	}{
		{RoleNone, PermReadReports, false},
		{RoleViewer, PermReadReports, true},
		{RoleViewer, PermManageTeams, false},
		{RoleOperator, PermManageTeams, true},
		{RoleOperator, PermManageClusters, false},
		{RoleAdmin, PermManageClusters, true},
	}
	for _, c := range cases {
		if got := c.role.Can(c.perm); got != c.want {
			t.Errorf("%s.Can(%s) = %v, want %v", c.role, c.perm, got, c.want)
		}
	}
}

func TestParseRole(t *testing.T) {
	for in, want := range map[string]Role{
		"none": RoleNone, "viewer": RoleViewer, "OPERATOR": RoleOperator, "admin": RoleAdmin,
		"": RoleViewer, // an unset flag means the safe default, not an error
	} {
		got, err := ParseRole(in)
		if err != nil {
			t.Fatalf("ParseRole(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("ParseRole(%q) = %v, want %v", in, got, want)
		}
	}
	if _, err := ParseRole("superuser"); err == nil {
		t.Error("ParseRole accepted an unknown role")
	}
}

func TestDisabledAuthIsAnonymous(t *testing.T) {
	c := Config{AnonymousRole: RoleViewer}.WithDefaults()
	// Headers are ignored entirely when auth is off — otherwise turning auth
	// off would leave a trivially spoofable admin path open.
	id, err := c.Identify(request("1.2.3.4:5555", map[string]string{
		DefaultUserHeader:   "attacker",
		DefaultGroupsHeader: "platform",
	}))
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if !id.Anonymous || id.User != "" || id.Role != RoleViewer {
		t.Fatalf("got %+v, want anonymous viewer with no user", id)
	}
	if id.Role.Can(PermManageClusters) {
		t.Error("anonymous viewer must not manage clusters")
	}
}

func TestIdentityFromTrustedProxy(t *testing.T) {
	c := proxyConfig(t)
	id, err := c.Identify(request("10.1.2.3:4444", map[string]string{
		DefaultUserHeader:   "astriletskyi",
		DefaultGroupsHeader: "dev, platform",
	}))
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if id.User != "astriletskyi" || id.Anonymous {
		t.Fatalf("got %+v, want a named, non-anonymous identity", id)
	}
	// dev grants viewer and platform grants admin: the highest wins.
	if id.Role != RoleAdmin {
		t.Errorf("role = %v, want admin (highest of dev, platform)", id.Role)
	}
}

func TestIdentityHeadersFromUntrustedPeerRejected(t *testing.T) {
	c := proxyConfig(t)
	_, err := c.Identify(request("203.0.113.9:1234", map[string]string{
		DefaultUserHeader:   "attacker",
		DefaultGroupsHeader: "platform",
	}))
	if err != ErrUntrustedProxy {
		t.Fatalf("err = %v, want ErrUntrustedProxy — spoofed headers must not be silently downgraded", err)
	}
}

func TestNoHeadersFromUntrustedPeerIsAnonymous(t *testing.T) {
	// A direct request that claims nothing is not an attack; it just gets the
	// anonymous role. Only *claiming* an identity off-path is rejected.
	c := proxyConfig(t)
	id, err := c.Identify(request("203.0.113.9:1234", nil))
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if !id.Anonymous || id.Role != RoleViewer {
		t.Fatalf("got %+v, want anonymous viewer", id)
	}
}

func TestEmptyTrustedProxiesFailsClosed(t *testing.T) {
	c := Config{Enabled: true, AnonymousRole: RoleViewer}.WithDefaults()
	_, err := c.Identify(request("10.1.2.3:4444", map[string]string{DefaultUserHeader: "someone"}))
	if err != ErrUntrustedProxy {
		t.Fatalf("err = %v, want ErrUntrustedProxy: no configured proxies must trust nobody", err)
	}
}

func TestTrustAnyProxy(t *testing.T) {
	c := proxyConfig(t, "any")
	id, err := c.Identify(request("203.0.113.9:1234", map[string]string{
		DefaultUserHeader:   "someone",
		DefaultGroupsHeader: "sre",
	}))
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if id.Role != RoleOperator {
		t.Errorf("role = %v, want operator", id.Role)
	}
}

func TestUnmatchedGroupsGetDefaultRole(t *testing.T) {
	c := proxyConfig(t)
	c.DefaultRole = RoleNone
	id, err := c.Identify(request("10.0.0.1:1", map[string]string{
		DefaultUserHeader:   "someone",
		DefaultGroupsHeader: "contractors",
	}))
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if id.Role != RoleNone {
		t.Errorf("role = %v, want none — an unmapped group must not inherit viewer", id.Role)
	}
}

func TestParseTrustedProxiesAcceptsIPsAndCIDRs(t *testing.T) {
	nets, err := ParseTrustedProxies([]string{"10.0.0.0/8", "192.168.1.7", " ", "fd00::/8"})
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}
	if len(nets) != 3 {
		t.Fatalf("got %d networks, want 3 (blank entries skipped)", len(nets))
	}
	if _, err := ParseTrustedProxies([]string{"not-an-ip"}); err == nil {
		t.Error("ParseTrustedProxies accepted a non-address")
	}
}

func TestRequireRejectsInsufficientRole(t *testing.T) {
	handler := Require(PermManageClusters, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	for _, tc := range []struct {
		role Role
		want int
	}{
		{RoleViewer, http.StatusForbidden},
		{RoleOperator, http.StatusForbidden},
		{RoleAdmin, http.StatusNoContent},
	} {
		r := httptest.NewRequest(http.MethodPost, "/api/clusters", nil)
		r = r.WithContext(NewContext(r.Context(), Identity{Role: tc.role}))
		w := httptest.NewRecorder()
		handler(w, r)
		if w.Code != tc.want {
			t.Errorf("role %s: status %d, want %d", tc.role, w.Code, tc.want)
		}
	}
}

func TestRequireDeniesWithoutMiddleware(t *testing.T) {
	// A handler reached without Middleware has no identity in context. The
	// zero Identity is RoleNone, so it must deny rather than allow.
	handler := Require(PermReadReports, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	w := httptest.NewRecorder()
	handler(w, httptest.NewRequest(http.MethodGet, "/api/report", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("status %d, want 403 when no identity was attached", w.Code)
	}
}

func TestMiddlewareAttachesIdentity(t *testing.T) {
	c := proxyConfig(t)
	var got Identity
	h := c.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = FromContext(r.Context())
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request("10.0.0.5:1", map[string]string{
		DefaultUserHeader:   "someone",
		DefaultGroupsHeader: "sre",
	}))
	if got.User != "someone" || got.Role != RoleOperator {
		t.Fatalf("got %+v, want someone/operator", got)
	}
}

func TestMiddlewareRejectsSpoofedHeaders(t *testing.T) {
	c := proxyConfig(t)
	reached := false
	h := c.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request("203.0.113.1:1", map[string]string{DefaultUserHeader: "attacker"}))
	if w.Code != http.StatusForbidden {
		t.Errorf("status %d, want 403", w.Code)
	}
	if reached {
		t.Error("handler ran for a request with spoofed identity headers")
	}
}

func TestPermissionsListIsOrderedAndScoped(t *testing.T) {
	if got := RoleViewer.Permissions(); len(got) != 1 || got[0] != PermReadReports {
		t.Errorf("viewer permissions = %v, want [reports:read]", got)
	}
	if got := RoleAdmin.Permissions(); len(got) != 3 {
		t.Errorf("admin permissions = %v, want all three", got)
	}
	if got := RoleNone.Permissions(); len(got) != 0 {
		t.Errorf("none permissions = %v, want empty", got)
	}
}
