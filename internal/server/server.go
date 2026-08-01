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
	return &Server{client: client, opts: opts, ttl: cacheTTL, history: hist}
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

// Handler returns the HTTP routes for the REST API, metrics and health probe.
// The web UI is a separate product (cluster-guardian-ui) and consumes these
// endpoints; this server renders no HTML.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	mux.HandleFunc("GET /api/report", s.handleReport(report.WriteJSON, "application/json"))
	mux.HandleFunc("GET /api/report/markdown", s.handleReport(report.WriteMarkdown, "text/markdown; charset=utf-8"))
	mux.HandleFunc("GET /api/history", s.handleHistory)
	mux.HandleFunc("GET /api/history/diff", s.handleHistoryDiff)
	if s.fleet != nil {
		mux.HandleFunc("GET /api/clusters", s.handleClusters)
		mux.HandleFunc("GET /api/clusters/{name}/report", s.handleClusterReport(report.WriteJSON, "application/json"))
		mux.HandleFunc("GET /api/clusters/{name}/report/markdown", s.handleClusterReport(report.WriteMarkdown, "text/markdown; charset=utf-8"))
		mux.HandleFunc("GET /api/clusters/{name}/history", s.handleClusterHistory)
		mux.HandleFunc("GET /api/clusters/{name}/history/diff", s.handleClusterHistoryDiff)
	}
	return mux
}

// handleIndex lists the available endpoints so hitting the root of the server
// tells you what it serves instead of 404ing.
func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	endpoints := []string{
		"GET /healthz",
		"GET /metrics",
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
	writeJSON(w, map[string]any{
		"name":      "cluster-guardian",
		"mode":      mode,
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
