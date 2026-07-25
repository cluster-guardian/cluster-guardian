package notify

import (
	"context"
	"errors"

	"github.com/AndrewKarpaty/cluster-guardian/internal/report"
)

// Sink receives the new findings after a run. Both Notifier and Router
// implement it.
type Sink interface {
	Notify(ctx context.Context, cluster string, newFindings []report.LocatedFinding) error
}

// Router fans new findings out: the global sink receives everything, and
// each team's sink receives only findings from namespaces that team owns —
// so a team only hears about its own workloads.
type Router struct {
	global *Notifier // may be nil
	teams  map[string]*Notifier
}

// NewRouter combines an optional global notifier with per-team notifiers.
func NewRouter(global *Notifier, teams map[string]*Notifier) *Router {
	return &Router{global: global, teams: teams}
}

// Notify implements Sink.
func (r *Router) Notify(ctx context.Context, cluster string, newFindings []report.LocatedFinding) error {
	var errs []error
	if r.global != nil {
		errs = append(errs, r.global.Notify(ctx, cluster, newFindings))
	}
	if len(r.teams) > 0 {
		byTeam := map[string][]report.LocatedFinding{}
		for _, f := range newFindings {
			if f.Team != "" {
				byTeam[f.Team] = append(byTeam[f.Team], f)
			}
		}
		for team, n := range r.teams {
			if findings := byTeam[team]; len(findings) > 0 {
				errs = append(errs, n.Notify(ctx, cluster, findings))
			}
		}
	}
	return errors.Join(errs...)
}
