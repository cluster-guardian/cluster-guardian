package server

import (
	_ "embed"
	"html/template"
	"io"
	"log"
	"net/http"

	"github.com/AndrewKarpaty/cluster-guardian/internal/report"
)

// The fleet page's markup lives in assets/fleet.gohtml; its stylesheet is
// served from the shared /static/ mount.
//
//go:embed assets/fleet.gohtml
var fleetTemplateSrc string

func (s *Server) handleFleetPage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := fleetTemplate.Execute(w, s.fleet.Statuses()); err != nil {
		log.Printf("rendering fleet page: %v", err)
	}
}

func (s *Server) handleClusters(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"clusters": s.fleet.Statuses()})
}

func (s *Server) handleClusterDashboard(w http.ResponseWriter, req *http.Request) {
	name := req.PathValue("name")
	r := s.fleet.Report(name)
	if r == nil {
		http.Error(w, "unknown cluster or not scanned yet", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := report.WriteClusterDashboard(w, r, "/api/clusters/"+name, "/"); err != nil {
		log.Printf("rendering cluster dashboard: %v", err)
	}
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

var fleetTemplate = template.Must(template.New("fleet").Parse(fleetTemplateSrc))
