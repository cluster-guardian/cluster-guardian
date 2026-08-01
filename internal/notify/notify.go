// Package notify posts webhook notifications when an analysis run surfaces
// findings that were not present in the previous run. Only new findings are
// sent — repeats stay silent to avoid alert fatigue.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cluster-guardian/cluster-guardian/internal/report"
)

// maxListed caps the findings spelled out in a Slack message.
const maxListed = 10

// Notifier posts new findings to a webhook.
type Notifier struct {
	url    string
	format string // "slack" or "json"
	min    report.Severity
	client *http.Client
}

// New validates the format ("slack" or "json") and minimum severity name and
// returns a Notifier.
func New(url, format, minSeverity string) (*Notifier, error) {
	if format != "slack" && format != "json" {
		return nil, fmt.Errorf("unknown notify format %q (use slack or json)", format)
	}
	threshold, err := report.ParseSeverity(minSeverity)
	if err != nil {
		return nil, err
	}
	return &Notifier{
		url:    url,
		format: format,
		min:    threshold,
		client: &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// Notify posts the new findings at or above the severity threshold. Nothing
// is posted when no finding qualifies.
func (n *Notifier) Notify(ctx context.Context, cluster string, newFindings []report.LocatedFinding) error {
	var qualifying []report.LocatedFinding
	for _, f := range newFindings {
		if f.Severity >= n.min {
			qualifying = append(qualifying, f)
		}
	}
	if len(qualifying) == 0 {
		return nil
	}

	var payload any
	if n.format == "slack" {
		payload = map[string]string{"text": slackText(cluster, qualifying)}
	} else {
		payload = map[string]any{"cluster": cluster, "newFindings": qualifying}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func slackText(cluster string, findings []report.LocatedFinding) string {
	var b strings.Builder
	fmt.Fprintf(&b, ":rotating_light: *cluster-guardian*: %d new %s on *%s*\n",
		len(findings), pluralize(len(findings), "finding", "findings"), cluster)
	for i, f := range findings {
		if i == maxListed {
			fmt.Fprintf(&b, "…and %d more\n", len(findings)-maxListed)
			break
		}
		fmt.Fprintf(&b, "• [%s] %s: %s\n", f.Severity, f.Location, f.Message)
	}
	return b.String()
}

func pluralize(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
