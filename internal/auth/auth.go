// Package auth resolves who is making a request and what they may do.
//
// Identity comes from headers set by an authenticating proxy (oauth2-proxy, an
// ingress with OIDC, a service mesh). cluster-guardian deliberately does not
// speak OIDC itself: it is a read-only analysis tool, and owning a session
// store, a redirect flow and token refresh is a large security surface to add
// for no capability the surrounding infrastructure does not already provide.
//
// Trusting a header means trusting whoever can set it. That is only safe when
// the server is unreachable except through the proxy, so proxy mode requires an
// explicit list of trusted peers and rejects identity headers from anywhere
// else. Auth is off by default, and with it off the API stays read-only.
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// Role is what a request may do. Ordered: each role includes the previous.
type Role int

// Roles, least to most privileged.
const (
	// RoleNone can do nothing — the result of a group mapping that matched
	// nothing and an explicit "deny by default" configuration.
	RoleNone Role = iota
	RoleViewer
	RoleOperator
	RoleAdmin
)

// String returns the role's configuration name.
func (r Role) String() string {
	switch r {
	case RoleNone:
		return "none"
	case RoleViewer:
		return "viewer"
	case RoleOperator:
		return "operator"
	case RoleAdmin:
		return "admin"
	}
	return "unknown"
}

// MarshalJSON encodes the role as its name.
func (r Role) MarshalJSON() ([]byte, error) {
	return []byte(`"` + r.String() + `"`), nil
}

// UnmarshalJSON decodes a role from its name, so /api/me round-trips through
// a Go client rather than only encoding.
func (r *Role) UnmarshalJSON(data []byte) error {
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	parsed, err := ParseRole(v)
	if err != nil {
		return err
	}
	*r = parsed
	return nil
}

// ParseRole converts a role name into its value.
func ParseRole(v string) (Role, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "none":
		return RoleNone, nil
	case "viewer", "":
		return RoleViewer, nil
	case "operator":
		return RoleOperator, nil
	case "admin":
		return RoleAdmin, nil
	}
	return RoleNone, fmt.Errorf("unknown role %q (want none, viewer, operator or admin)", v)
}

// Permission is a single capability. Reports are readable by any role that can
// reach the API at all; the write permissions are what roles actually gate.
type Permission string

// The permission set. Kept small on purpose — every one of these maps to a
// route, and the UI renders its controls from whatever /api/me reports.
const (
	PermReadReports    Permission = "reports:read"
	PermManageTeams    Permission = "teams:write"
	PermManageClusters Permission = "clusters:write"
)

// minRole is the least privileged role holding each permission.
var minRole = map[Permission]Role{
	PermReadReports:    RoleViewer,
	PermManageTeams:    RoleOperator,
	PermManageClusters: RoleAdmin,
}

// Can reports whether the role holds the permission.
func (r Role) Can(p Permission) bool {
	need, ok := minRole[p]
	return ok && r >= need
}

// Permissions lists everything the role may do, for /api/me.
func (r Role) Permissions() []Permission {
	// Fixed order so the response is stable across requests.
	all := []Permission{PermReadReports, PermManageTeams, PermManageClusters}
	out := []Permission{}
	for _, p := range all {
		if r.Can(p) {
			out = append(out, p)
		}
	}
	return out
}

// Identity is who a request belongs to.
type Identity struct {
	// User is empty when the proxy sent no identity, or auth is disabled.
	User   string   `json:"user,omitempty"`
	Groups []string `json:"groups,omitempty"`
	Role   Role     `json:"role"`
	// Anonymous marks a request that carried no identity. Such requests still
	// get AnonymousRole, so a deployment can stay open for reading.
	Anonymous   bool         `json:"anonymous"`
	Permissions []Permission `json:"permissions"`
}

// Config describes how to identify a request.
type Config struct {
	// Enabled turns on proxy-header identity. With it false every request is
	// anonymous with AnonymousRole.
	Enabled bool
	// UserHeader and GroupsHeader name the headers the proxy sets.
	UserHeader   string
	GroupsHeader string
	// GroupRoles maps a group name to the role it grants. A user in several
	// mapped groups gets the highest.
	GroupRoles map[string]Role
	// DefaultRole applies to an authenticated user whose groups matched
	// nothing.
	DefaultRole Role
	// AnonymousRole applies when no identity is present — either auth is off,
	// or the proxy sent no user header.
	AnonymousRole Role
	// TrustedProxies lists the peers whose identity headers are believed.
	// Empty with Enabled means nothing is trusted, which fails closed.
	TrustedProxies []*net.IPNet
}

// Default header names, matching oauth2-proxy's --set-xauthrequest output and
// the convention most ingress auth annotations follow.
const (
	DefaultUserHeader   = "X-Forwarded-User"
	DefaultGroupsHeader = "X-Forwarded-Groups"
)

// WithDefaults fills in header names and roles left unset.
func (c Config) WithDefaults() Config {
	if c.UserHeader == "" {
		c.UserHeader = DefaultUserHeader
	}
	if c.GroupsHeader == "" {
		c.GroupsHeader = DefaultGroupsHeader
	}
	if c.GroupRoles == nil {
		c.GroupRoles = map[string]Role{}
	}
	return c
}

// ParseTrustedProxies turns CIDRs and bare IPs into networks. The literal
// "any" disables the check — an escape hatch for a sidecar or a mesh where the
// peer address is not predictable, and a foot-gun everywhere else.
func ParseTrustedProxies(entries []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, raw := range entries {
		e := strings.TrimSpace(raw)
		if e == "" {
			continue
		}
		if strings.EqualFold(e, "any") {
			_, v4, _ := net.ParseCIDR("0.0.0.0/0")
			_, v6, _ := net.ParseCIDR("::/0")
			return []*net.IPNet{v4, v6}, nil
		}
		if _, n, err := net.ParseCIDR(e); err == nil {
			out = append(out, n)
			continue
		}
		ip := net.ParseIP(e)
		if ip == nil {
			return nil, fmt.Errorf("trusted proxy %q is neither an IP nor a CIDR", raw)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return out, nil
}

// ErrUntrustedProxy is returned when identity headers arrive from a peer that
// is not in TrustedProxies. It is deliberately an error rather than a silent
// downgrade to anonymous: headers from an unexpected peer mean either a
// misconfiguration or an attempt to bypass the proxy, and both should be loud.
var ErrUntrustedProxy = fmt.Errorf("identity headers from an untrusted peer")

func (c Config) trusts(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range c.TrustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// roleFor resolves the highest role the groups grant.
func (c Config) roleFor(groups []string) Role {
	role := RoleNone
	matched := false
	for _, g := range groups {
		if r, ok := c.GroupRoles[g]; ok {
			matched = true
			if r > role {
				role = r
			}
		}
	}
	if !matched {
		return c.DefaultRole
	}
	return role
}

// Identify resolves the identity of a request.
func (c Config) Identify(r *http.Request) (Identity, error) {
	anonymous := Identity{Anonymous: true, Role: c.AnonymousRole}
	anonymous.Permissions = anonymous.Role.Permissions()

	if !c.Enabled {
		return anonymous, nil
	}

	user := strings.TrimSpace(r.Header.Get(c.UserHeader))
	rawGroups := strings.TrimSpace(r.Header.Get(c.GroupsHeader))

	// Check the peer before reading anything into the identity: a request
	// carrying headers it should not is rejected whether or not we would have
	// honoured them.
	if (user != "" || rawGroups != "") && !c.trusts(r.RemoteAddr) {
		return Identity{}, ErrUntrustedProxy
	}
	if user == "" {
		return anonymous, nil
	}

	var groups []string
	for _, g := range strings.Split(rawGroups, ",") {
		if g = strings.TrimSpace(g); g != "" {
			groups = append(groups, g)
		}
	}

	id := Identity{User: user, Groups: groups, Role: c.roleFor(groups)}
	id.Permissions = id.Role.Permissions()
	return id, nil
}

type contextKey struct{}

// NewContext returns ctx carrying id.
func NewContext(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}

// FromContext returns the identity attached by Middleware. An absent identity
// yields the zero value, whose role is RoleNone — so a handler reached without
// the middleware denies rather than allows.
func FromContext(ctx context.Context) Identity {
	id, _ := ctx.Value(contextKey{}).(Identity)
	return id
}

// Middleware resolves the identity once per request and attaches it.
func (c Config) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := c.Identify(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(NewContext(r.Context(), id)))
	})
}

// Require wraps h so only a caller holding p reaches it.
func Require(p Permission, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := FromContext(r.Context())
		if !id.Role.Can(p) {
			// Say what was needed and what was held: the common cause is a
			// group mapping that did not match, and a bare 403 hides that.
			http.Error(w, fmt.Sprintf("%s requires %q; this request has role %q",
				r.URL.Path, p, id.Role), http.StatusForbidden)
			return
		}
		h(w, r)
	}
}
