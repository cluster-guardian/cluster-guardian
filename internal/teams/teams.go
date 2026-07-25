// Package teams loads the namespace-ownership mapping that makes reports
// and notifications team-aware.
package teams

import (
	"encoding/json"
	"fmt"
	"os"

	"sigs.k8s.io/yaml"
)

// Config is the resolved team ownership mapping.
type Config struct {
	// NamespaceTeam maps a namespace to its owning team.
	NamespaceTeam map[string]string
	// NotifyURLs maps a team to its webhook URL, when configured.
	NotifyURLs map[string]string
}

// Load reads a teams file. Two shapes are accepted per team — the terse
// namespace list and the structured form with a notification webhook:
//
//	teams:
//	  payments-team: [payments, checkout]
//	  platform-team:
//	    namespaces: [kube-system, monitoring]
//	    notifyUrl: https://hooks.slack.com/services/...
func Load(path string) (Config, error) {
	cfg := Config{NamespaceTeam: map[string]string{}, NotifyURLs: map[string]string{}}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	var raw struct {
		Teams map[string]json.RawMessage `json:"teams"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return cfg, fmt.Errorf("parsing %s: %w", path, err)
	}

	for team, msg := range raw.Teams {
		var namespaces []string
		if err := json.Unmarshal(msg, &namespaces); err != nil {
			var full struct {
				Namespaces []string `json:"namespaces"`
				NotifyURL  string   `json:"notifyUrl"`
			}
			if err := json.Unmarshal(msg, &full); err != nil {
				return cfg, fmt.Errorf("parsing %s: team %q: expected a namespace list or {namespaces, notifyUrl}", path, team)
			}
			namespaces = full.Namespaces
			if full.NotifyURL != "" {
				cfg.NotifyURLs[team] = full.NotifyURL
			}
		}
		for _, ns := range namespaces {
			if owner, taken := cfg.NamespaceTeam[ns]; taken && owner != team {
				return cfg, fmt.Errorf("parsing %s: namespace %q mapped to both %q and %q", path, ns, owner, team)
			}
			cfg.NamespaceTeam[ns] = team
		}
	}
	return cfg, nil
}
