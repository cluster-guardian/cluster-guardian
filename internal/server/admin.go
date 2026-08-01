package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/cluster-guardian/cluster-guardian/internal/auth"
	"github.com/cluster-guardian/cluster-guardian/internal/fleet"
	"github.com/cluster-guardian/cluster-guardian/internal/teams"
)

// Admin holds what the write endpoints need: a clientset for the hub cluster
// and the namespace its configuration lives in. It is nil unless the server
// was started with a cluster connection, which is what makes the write routes
// appear at all.
type Admin struct {
	Clientset kubernetes.Interface
	Namespace string
	Teams     *teams.Store
	// Fleet is refreshed after a cluster is added or removed so the change is
	// visible without waiting for the next scheduled scan.
	Fleet *fleet.Manager
}

// EnableAdmin turns on the write API. Without it the server serves reads only,
// which is the default and the whole behaviour before roles existed.
func (s *Server) EnableAdmin(a *Admin) { s.admin = a }

// handleMe reports who the caller is and what they may do. The UI renders its
// navigation and controls from this rather than guessing, so a viewer never
// sees a button that would 403.
func (s *Server) handleMe(w http.ResponseWriter, req *http.Request) {
	id := auth.FromContext(req.Context())
	writeJSON(w, map[string]any{
		"identity": id,
		// Whether the write routes exist at all is a deployment fact, separate
		// from the caller's role: an admin talking to a server with no cluster
		// connection still cannot manage anything.
		"features": map[string]bool{
			"clusters": s.admin != nil && s.fleet != nil,
			"teams":    s.admin != nil && s.admin.Teams != nil,
		},
	})
}

// clusterRequest is the body of POST /api/clusters.
type clusterRequest struct {
	Name        string `json:"name"`
	Server      string `json:"server"`
	BearerToken string `json:"bearerToken"`
	// CAData is the base64 PEM bundle, as it appears in a kubeconfig.
	CAData   string `json:"caData,omitempty"`
	Insecure bool   `json:"insecure,omitempty"`
}

func (c clusterRequest) validate() ([]byte, error) {
	if strings.TrimSpace(c.Name) == "" {
		return nil, fmt.Errorf("name is required")
	}
	if strings.TrimSpace(c.BearerToken) == "" {
		return nil, fmt.Errorf("bearerToken is required")
	}
	u, err := url.Parse(strings.TrimSpace(c.Server))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("server must be an absolute URL, e.g. https://prod.example.com:6443")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("server must be http or https, got %q", u.Scheme)
	}
	// Refuse the combination rather than silently dropping one: a caller who
	// sends both has a mistaken idea of which one is in effect.
	if c.Insecure && c.CAData != "" {
		return nil, fmt.Errorf("insecure and caData are mutually exclusive")
	}
	if !c.Insecure && c.CAData == "" {
		return nil, fmt.Errorf("caData is required unless insecure is set")
	}
	if c.CAData == "" {
		return nil, nil
	}
	ca, err := base64.StdEncoding.DecodeString(c.CAData)
	if err != nil {
		return nil, fmt.Errorf("caData must be base64-encoded PEM: %w", err)
	}
	return ca, nil
}

// handleCreateCluster registers a cluster by writing the same labeled Secret
// `cluster add` writes, so a cluster added here and one added from the CLI are
// indistinguishable afterwards.
//
// It stores credentials the caller supplies rather than provisioning them:
// provisioning needs admin access to the *target* cluster, which the hub does
// not have and should not be given. `cluster add` still does the provisioning,
// from an operator's own kubeconfig.
func (s *Server) handleCreateCluster(w http.ResponseWriter, req *http.Request) {
	var body clusterRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, req.Body, 1<<20)).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	ca, err := body.validate()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	sec, err := fleet.NewClusterSecret(s.admin.Namespace, fleet.ClusterSecretSpec{
		ClusterName: body.Name,
		Server:      body.Server,
		BearerToken: body.BearerToken,
		CAData:      ca,
		Insecure:    body.Insecure,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := fleet.ApplySecret(req.Context(), s.admin.Clientset, sec); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	log.Printf("cluster %q registered by %s", body.Name, actor(req))
	s.rescan()
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]any{"name": body.Name, "server": body.Server})
}

// handleDeleteCluster removes a registration. The local cluster is always in
// the fleet and has no Secret behind it, so it cannot be removed.
func (s *Server) handleDeleteCluster(w http.ResponseWriter, req *http.Request) {
	name := req.PathValue("name")
	secretName := "cluster-" + fleet.SanitizeName(name)
	err := s.admin.Clientset.CoreV1().Secrets(s.admin.Namespace).
		Delete(req.Context(), secretName, metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		http.Error(w, fmt.Sprintf("no registration secret for cluster %q — the local cluster cannot be removed", name),
			http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	log.Printf("cluster %q removed by %s", name, actor(req))
	s.rescan()
	w.WriteHeader(http.StatusNoContent)
}

// handleGetTeams returns the ownership mapping with webhooks redacted.
func (s *Server) handleGetTeams(w http.ResponseWriter, req *http.Request) {
	spec, err := s.admin.Teams.Get(req.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, spec.Redacted())
}

// handlePutTeams replaces the mapping. Webhook URLs the client sends back
// redacted are restored from the stored mapping, so an edit made through a UI
// that never saw them does not wipe them.
func (s *Server) handlePutTeams(w http.ResponseWriter, req *http.Request) {
	var spec teams.Spec
	if err := json.NewDecoder(http.MaxBytesReader(w, req.Body, 1<<20)).Decode(&spec); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	prev, err := s.admin.Teams.Get(req.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	merged := spec.MergeSecrets(prev)
	if err := merged.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.admin.Teams.Put(req.Context(), merged); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	log.Printf("teams updated by %s (%d teams)", actor(req), len(merged.Teams))
	// Ownership is stamped onto reports during analysis, so the change shows up
	// on the next scan. Refresh the cached mapping now so that scan uses it.
	s.refreshTeams(req.Context())
	writeJSON(w, merged.Redacted())
}

// rescan picks up a registry change without waiting for the interval. It runs
// detached: a full fleet scan takes far longer than a request should.
func (s *Server) rescan() {
	if s.admin == nil || s.admin.Fleet == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		s.admin.Fleet.ScanAll(ctx)
	}()
}

// refreshTeams re-reads the ownership mapping into the analyzer options used
// by subsequent runs. Best-effort: a read failure leaves the previous mapping
// in place rather than dropping ownership entirely.
func (s *Server) refreshTeams(ctx context.Context) {
	if s.admin == nil || s.admin.Teams == nil {
		return
	}
	mapping, err := s.admin.Teams.NamespaceTeam(ctx)
	if err != nil {
		log.Printf("refreshing teams: %v", err)
		return
	}
	s.mu.Lock()
	s.opts.TeamOf = mapping
	// The cached report still carries the old ownership; drop it so the next
	// read re-analyzes rather than serving a stale mapping.
	s.cached = nil
	s.mu.Unlock()
	if s.admin.Fleet != nil {
		s.admin.Fleet.SetTeamOf(mapping)
	}
}

// actor names the caller for the audit log. Writes are consequential —
// registering a cluster stores credentials, removing one stops its scanning —
// so who did it belongs in the log even when auth is off.
func actor(req *http.Request) string {
	id := auth.FromContext(req.Context())
	if id.User != "" {
		return fmt.Sprintf("%s (role %s)", id.User, id.Role)
	}
	return fmt.Sprintf("an anonymous caller from %s (role %s)", req.RemoteAddr, id.Role)
}
