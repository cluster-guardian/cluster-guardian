// Package server exposes the analyzer as a REST API and a web dashboard.
package server

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/AndrewKarpaty/cluster-guardian/internal/analyzer"
	"github.com/AndrewKarpaty/cluster-guardian/internal/fleet"
	"github.com/AndrewKarpaty/cluster-guardian/internal/history"
	"github.com/AndrewKarpaty/cluster-guardian/internal/kube"
	"github.com/AndrewKarpaty/cluster-guardian/internal/notify"
	"github.com/AndrewKarpaty/cluster-guardian/internal/report"
)

// Server serves the dashboard and REST API. Reports are cached briefly so a
// busy dashboard doesn't hammer the API server.
type Server struct {
	client   *kube.Client
	opts     analyzer.Options
	ttl      time.Duration
	history  *history.Store
	fleet    *fleet.Manager
	notifier *notify.Notifier

	mu              sync.Mutex
	cached          *report.Report
	cachedAt        time.Time
	lastRunDuration time.Duration
	runs, runErrors int
}

// New returns a Server that analyzes via client, caches reports for cacheTTL,
// and records each fresh analysis in hist (may be nil to disable history).
func New(client *kube.Client, opts analyzer.Options, cacheTTL time.Duration, hist *history.Store) *Server {
	return &Server{client: client, opts: opts, ttl: cacheTTL, history: hist}
}

// EnableFleet switches the server into fleet mode: the root page becomes the
// fleet overview and per-cluster routes are served from m. Call before
// Handler / ListenAndServe.
func (s *Server) EnableFleet(m *fleet.Manager) { s.fleet = m }

// EnableNotifications posts new findings to n after each fresh analysis.
func (s *Server) EnableNotifications(n *notify.Notifier) { s.notifier = n }

// Handler returns the HTTP routes for the dashboard, REST API and health probe.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	mux.HandleFunc("GET /api/report", s.handleReport(report.WriteJSON, "application/json"))
	mux.HandleFunc("GET /api/report/markdown", s.handleReport(report.WriteMarkdown, "text/markdown; charset=utf-8"))
	mux.HandleFunc("GET /api/history", s.handleHistory)
	mux.HandleFunc("GET /api/history/diff", s.handleHistoryDiff)
	if s.fleet != nil {
		mux.HandleFunc("GET /{$}", s.handleFleetPage)
		mux.HandleFunc("GET /clusters/{name}", s.handleClusterDashboard)
		mux.HandleFunc("GET /api/clusters", s.handleClusters)
		mux.HandleFunc("GET /api/clusters/{name}/report", s.handleClusterReport(report.WriteJSON, "application/json"))
		mux.HandleFunc("GET /api/clusters/{name}/report/markdown", s.handleClusterReport(report.WriteMarkdown, "text/markdown; charset=utf-8"))
		mux.HandleFunc("GET /api/clusters/{name}/history", s.handleClusterHistory)
		mux.HandleFunc("GET /api/clusters/{name}/history/diff", s.handleClusterHistoryDiff)
	} else {
		mux.HandleFunc("GET /{$}", s.handleReport(report.WriteDashboard, "text/html; charset=utf-8"))
	}
	return mux
}

// ListenAndServe blocks serving HTTP on addr.
func (s *Server) ListenAndServe(addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("cluster-guardian dashboard listening on http://%s", addr)
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
