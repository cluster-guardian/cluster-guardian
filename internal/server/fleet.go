package server

import (
	"io"
	"log"
	"net/http"

	"github.com/cluster-guardian/cluster-guardian/internal/report"
)

func (s *Server) handleClusters(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"clusters": s.fleet.Statuses()})
}

func (s *Server) handleClusterReport(render func(w io.Writer, r *report.Report) error, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		r := s.fleet.Report(req.PathValue("name"))
		if r == nil {
			http.Error(w, "unknown cluster or not scanned yet", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", contentType)
		if err := render(w, r); err != nil {
			log.Printf("rendering cluster report: %v", err)
		}
	}
}

func (s *Server) handleClusterHistory(w http.ResponseWriter, req *http.Request) {
	writeJSON(w, map[string]any{"entries": s.fleet.History(req.PathValue("name"))})
}

func (s *Server) handleClusterHistoryDiff(w http.ResponseWriter, req *http.Request) {
	d := s.fleet.Diff(req.PathValue("name"))
	if d == nil {
		d = &report.DiffResult{}
	}
	writeJSON(w, d)
}
