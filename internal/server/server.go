// Package server exposes the analyzer as a REST API. The web UI is a separate
// application (cluster-guardian-ui) that consumes these endpoints.
package server

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/cluster-guardian/cluster-guardian/internal/analyzer"
	"github.com/cluster-guardian/cluster-guardian/internal/auth"
	"github.com/cluster-guardian/cluster-guardian/internal/fleet"
	"github.com/cluster-guardian/cluster-guardian/internal/history"
	"github.com/cluster-guardian/cluster-guardian/internal/kube"
	"github.com/cluster-guardian/cluster-guardian/internal/notify"
	"github.com/cluster-guardian/cluster-guardian/internal/report"
)

// Server serves the REST API. Reports are cached briefly so a busy client
// doesn't hammer the Kubernetes API server.
type Server struct {
	client   *kube.Client
	opts     analyzer.Options
	ttl      time.Duration
	history  *history.Store
	fleet    *fleet.Manager
	notifier notify.Sink
	fixture  *report.Report
	auth     auth.Config
	admin    *Admin

	mu              sync.Mutex
	cached          *report.Report
	cachedAt        time.Time
	lastRunDuration time.Duration
	runs, runErrors int

	reportDeliveries, reportDeliveryErrors int
}

// New returns a Server that analyzes via client, caches reports for cacheTTL,
// and records each fresh analysis in hist (may be nil to disable history).
func New(client *kube.Client, opts analyzer.Options, cacheTTL time.Duration, hist *history.Store) *Server {
	return &Server{
		client: client, opts: opts, ttl: cacheTTL, history: hist,
		// Auth off, reads open: the behaviour before roles existed. A caller
		// that wants anything else calls EnableAuth.
		auth: auth.Config{AnonymousRole: auth.RoleViewer}.WithDefaults(),
	}
}

// EnableFleet switches the server into fleet mode: per-cluster routes under
// /api/clusters are served from m. Call before Handler / ListenAndServe.
func (s *Server) EnableFleet(m *fleet.Manager) { s.fleet = m }

// EnableNotifications posts new findings to n after each fresh analysis.
func (s *Server) EnableNotifications(n notify.Sink) { s.notifier = n }

// SetFixture makes the server serve a canned report instead of analyzing a
// cluster: no kubeconfig needed. This is how cluster-guardian-ui develops and
// tests against the API, and how demos run without a cluster.
func (s *Server) SetFixture(r *report.Report) { s.fixture = r }

// EnableAuth resolves each request's identity from proxy headers. Without it
// every request is anonymous and gets the role New installed, which is viewer.
func (s *Server) EnableAuth(c auth.Config) { s.auth = c.WithDefaults() }

// Handler returns the HTTP routes for the REST API, metrics and health probe.
// The web UI is a separate product (cluster-guardian-ui) and consumes these
// endpoints; this server renders no HTML.
func (s *Server) Handler() http.Handler {
	// Unauthenticated: a kubelet probe and a Prometheus scrape do not carry
	// identity headers, and neither exposes findings. Everything under /api
	// goes through the middleware.
	root := http.NewServeMux()
	root.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	root.HandleFunc("GET /metrics", s.handleMetrics)
	root.HandleFunc("GET /{$}", s.handleIndex)

	api := http.NewServeMux()
	// /api/me carries no findings and is deliberately ungated: a caller with
	// no permissions still needs to be told so, and the UI renders "you have
	// no access" from this rather than from a bare 403 on some other route.
	api.HandleFunc("GET /api/me", s.handleMe)
	api.HandleFunc("GET /api/report", auth.Require(auth.PermReadReports, s.handleReport(report.WriteJSON, "application/json")))
	api.HandleFunc("GET /api/report/markdown", auth.Require(auth.PermReadReports, s.handleReport(report.WriteMarkdown, "text/markdown; charset=utf-8")))
	api.HandleFunc("GET /api/history", auth.Require(auth.PermReadReports, s.handleHistory))
	api.HandleFunc("GET /api/history/diff", auth.Require(auth.PermReadReports, s.handleHistoryDiff))
	if s.fleet != nil {
		api.HandleFunc("GET /api/clusters", auth.Require(auth.PermReadReports, s.handleClusters))
		api.HandleFunc("GET /api/clusters/{name}/report", auth.Require(auth.PermReadReports, s.handleClusterReport(report.WriteJSON, "application/json")))
		api.HandleFunc("GET /api/clusters/{name}/report/markdown", auth.Require(auth.PermReadReports, s.handleClusterReport(report.WriteMarkdown, "text/markdown; charset=utf-8")))
		api.HandleFunc("GET /api/clusters/{name}/history", auth.Require(auth.PermReadReports, s.handleClusterHistory))
		api.HandleFunc("GET /api/clusters/{name}/history/diff", auth.Require(auth.PermReadReports, s.handleClusterHistoryDiff))
	}
	// The write routes exist only when the server has a cluster connection to
	// write through. Leaving them unregistered means a deployment without the
	// write API answers 405 on POST /api/clusters (the path exists for GET)
	// rather than 403 — "this server does not do that" instead of "you may
	// not", which is the truthful distinction.
	if s.admin != nil {
		if s.fleet != nil {
			api.HandleFunc("POST /api/clusters", auth.Require(auth.PermManageClusters, s.handleCreateCluster))
			api.HandleFunc("DELETE /api/clusters/{name}", auth.Require(auth.PermManageClusters, s.handleDeleteCluster))
		}
		if s.admin.Teams != nil {
			api.HandleFunc("GET /api/teams", auth.Require(auth.PermReadReports, s.handleGetTeams))
			api.HandleFunc("PUT /api/teams", auth.Require(auth.PermManageTeams, s.handlePutTeams))
		}
	}
	root.Handle("/api/", s.auth.Middleware(api))

	return root
}

// handleIndex lists the available endpoints so hitting the root of the server
// tells you what it serves instead of 404ing.
func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	endpoints := []string{
		"GET /healthz",
		"GET /metrics",
		"GET /api/me",
		"GET /api/report",
		"GET /api/report/markdown",
		"GET /api/history",
		"GET /api/history/diff",
	}
	mode := "single-cluster"
	if s.fleet != nil {
		mode = "fleet"
		endpoints = append(endpoints,
			"GET /api/clusters",
			"GET /api/clusters/{name}/report",
			"GET /api/clusters/{name}/report/markdown",
			"GET /api/clusters/{name}/history",
			"GET /api/clusters/{name}/history/diff",
		)
	}
	if s.admin != nil {
		if s.fleet != nil {
			endpoints = append(endpoints, "POST /api/clusters", "DELETE /api/clusters/{name}")
		}
		if s.admin.Teams != nil {
			endpoints = append(endpoints, "GET /api/teams", "PUT /api/teams")
		}
	}
	writeJSON(w, map[string]any{
		"name":      "cluster-guardian",
		"mode":      mode,
		"auth":      map[string]any{"enabled": s.auth.Enabled, "anonymousRole": s.auth.AnonymousRole},
		"endpoints": endpoints,
	})
}

// ListenAndServe blocks serving HTTP on addr.
func (s *Server) ListenAndServe(addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("cluster-guardian API listening on http://%s", addr)
	return srv.ListenAndServe()
}

func (s *Server) handleReport(render func(w io.Writer, r *report.Report) error, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		r, err := s.report(req.Context(), req.URL.Query().Get("refresh") == "true")
		if err != nil {
			http.Error(w, "analysis failed: "+err.Error(), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", contentType)
		if err := render(w, r); err != nil {
			log.Printf("rendering report: %v", err)
		}
	}
}

func (s *Server) report(ctx context.Context, forceRefresh bool) (*report.Report, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fixture != nil {
		return s.fixture, nil
	}
	if !forceRefresh && s.cached != nil && time.Since(s.cachedAt) < s.ttl {
		return s.cached, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	start := time.Now()
	r, err := analyzer.Run(ctx, s.client, s.opts)
	s.lastRunDuration = time.Since(start)
	s.runs++
	if err != nil {
		s.runErrors++
		return nil, err
	}
	s.cached, s.cachedAt = r, time.Now()
	if s.history != nil {
		s.history.Append(r)
		if s.notifier != nil {
			if d := s.history.LastDiff(); d != nil && len(d.New) > 0 {
				// Post outside the request path; the run is done either way.
				go func(findings []report.LocatedFinding) {
					nctx, ncancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer ncancel()
					if err := s.notifier.Notify(nctx, r.ClusterName, findings); err != nil {
						log.Printf("notify: %v", err)
					}
				}(d.New)
			}
		}
	}
	return r, nil
}

func (s *Server) handleHistory(w http.ResponseWriter, _ *http.Request) {
	var entries []history.Entry
	if s.history != nil {
		entries = s.history.Entries()
	}
	writeJSON(w, map[string]any{"entries": entries})
}

func (s *Server) handleHistoryDiff(w http.ResponseWriter, _ *http.Request) {
	d := &report.DiffResult{}
	if s.history != nil {
		if last := s.history.LastDiff(); last != nil {
			d = last
		}
	}
	writeJSON(w, d)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("encoding response: %v", err)
	}
}
