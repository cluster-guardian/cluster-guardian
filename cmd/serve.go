package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/AndrewKarpaty/cluster-guardian/internal/deliver"
	"github.com/AndrewKarpaty/cluster-guardian/internal/fleet"
	"github.com/AndrewKarpaty/cluster-guardian/internal/history"
	"github.com/AndrewKarpaty/cluster-guardian/internal/notify"
	"github.com/AndrewKarpaty/cluster-guardian/internal/server"
)

var (
	flagListen        string
	flagCacheTTL      time.Duration
	flagHistoryDir    string
	flagHistoryLimit  int
	flagFleet         bool
	flagFleetInterval time.Duration
	flagFleetNS       string
	flagNotifyURL     string
	flagNotifyFormat  string
	flagNotifyMinSev  string

	flagReportSchedule string
	flagReportFormat   string
	flagReportEmailTo  []string
	flagReportSMTPHost string
	flagReportSMTPFrom string
	flagReportWebhook  string
	flagReportDir      string
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve the REST API and web dashboard",
	Long: `Starts an HTTP server exposing:

  GET /                    web dashboard (HTML report)
  GET /api/report          report as JSON (append ?refresh=true to bypass cache)
  GET /api/report/markdown report as Markdown
  GET /metrics             Prometheus metrics (findings, score, run stats)
  GET /healthz             liveness probe`,
	RunE: func(_ *cobra.Command, _ []string) error {
		client, err := newKubeClient()
		if err != nil {
			return err
		}
		hist, err := history.New(flagHistoryDir, flagHistoryLimit)
		if err != nil {
			return err
		}
		opts, err := analyzerOptions()
		if err != nil {
			return err
		}
		srv := server.New(client, opts, flagCacheTTL, hist)

		notifier, err := buildNotifier()
		if err != nil {
			return err
		}
		if notifier != nil {
			srv.EnableNotifications(notifier)
		}
		if flagReportSchedule != "" {
			del, err := deliver.New(deliver.Options{
				EmailTo:    flagReportEmailTo,
				SMTPHost:   flagReportSMTPHost,
				SMTPFrom:   flagReportSMTPFrom,
				WebhookURL: flagReportWebhook,
				Dir:        flagReportDir,
			})
			if err != nil {
				return err
			}
			if err := srv.StartReportSchedule(flagReportSchedule, del, flagReportFormat); err != nil {
				return err
			}
		}
		if flagFleet {
			reg := &fleet.Registry{
				Local:     client,
				Clientset: client.Clientset,
				Namespace: fleetNamespace(),
			}
			mgr := fleet.NewManager(reg, opts, flagFleetInterval, flagHistoryDir, flagHistoryLimit)
			if notifier != nil {
				mgr.EnableNotifications(notifier)
			}
			srv.EnableFleet(mgr)
			go mgr.Run(context.Background())
		}
		return srv.ListenAndServe(flagListen)
	},
}

func init() {
	serveCmd.Flags().StringVar(&flagListen, "listen", "127.0.0.1:8080", "address to listen on")
	serveCmd.Flags().DurationVar(&flagCacheTTL, "cache-ttl", 60*time.Second, "how long to cache analysis results")
	serveCmd.Flags().StringVar(&flagHistoryDir, "history-dir", "", "directory to persist reports for trend history (empty = in-memory only)")
	serveCmd.Flags().IntVar(&flagHistoryLimit, "history-limit", 100, "maximum runs to keep in history")
	serveCmd.Flags().BoolVar(&flagFleet, "fleet", false, "fleet mode: scan clusters registered via labeled Secrets and serve the fleet scorecard")
	serveCmd.Flags().DurationVar(&flagFleetInterval, "fleet-interval", 5*time.Minute, "how often to scan registered clusters in fleet mode")
	serveCmd.Flags().StringVar(&flagFleetNS, "fleet-namespace", "", "namespace holding cluster secrets (default: the pod's own namespace)")
	serveCmd.Flags().StringVar(&flagNotifyURL, "notify-url", "", "webhook URL to notify when a run surfaces new findings")
	serveCmd.Flags().StringVar(&flagNotifyFormat, "notify-format", "slack", "webhook payload format: slack or json")
	serveCmd.Flags().StringVar(&flagNotifyMinSev, "notify-min-severity", "critical", "notify only for new findings at or above this severity: info, warning, critical")
	serveCmd.Flags().StringVar(&flagReportSchedule, "report-schedule", "", `cron schedule for report delivery, e.g. "0 8 * * MON" (empty = disabled)`)
	serveCmd.Flags().StringVar(&flagReportFormat, "report-format", "pdf", "scheduled report attachment format: pdf or html")
	serveCmd.Flags().StringSliceVar(&flagReportEmailTo, "report-email-to", nil, "email recipients for scheduled reports (repeatable)")
	serveCmd.Flags().StringVar(&flagReportSMTPHost, "report-smtp-host", "", "SMTP server as host:port (credentials via SMTP_USERNAME/SMTP_PASSWORD)")
	serveCmd.Flags().StringVar(&flagReportSMTPFrom, "report-smtp-from", "", "From address for scheduled report emails")
	serveCmd.Flags().StringVar(&flagReportWebhook, "report-webhook-url", "", "webhook POSTed the report JSON on schedule")
	serveCmd.Flags().StringVar(&flagReportDir, "report-dir", "", "directory to write scheduled report files into")
	rootCmd.AddCommand(serveCmd)
}

// buildNotifier assembles the notification sink: the global --notify-url
// plus one notifier per team webhook from --teams-file. Returns nil when
// nothing is configured.
func buildNotifier() (notify.Sink, error) {
	tc, err := loadTeams()
	if err != nil {
		return nil, err
	}
	var global *notify.Notifier
	if flagNotifyURL != "" {
		if global, err = notify.New(flagNotifyURL, flagNotifyFormat, flagNotifyMinSev); err != nil {
			return nil, err
		}
	}
	if len(tc.NotifyURLs) == 0 {
		if global == nil {
			return nil, nil
		}
		return global, nil
	}
	teamSinks := make(map[string]*notify.Notifier, len(tc.NotifyURLs))
	for team, url := range tc.NotifyURLs {
		n, err := notify.New(url, flagNotifyFormat, flagNotifyMinSev)
		if err != nil {
			return nil, fmt.Errorf("team %q webhook: %w", team, err)
		}
		teamSinks[team] = n
	}
	return notify.NewRouter(global, teamSinks), nil
}

// fleetNamespace resolves where cluster secrets live: the flag, the pod's own
// namespace when running in-cluster, or "default".
func fleetNamespace() string {
	if flagFleetNS != "" {
		return flagFleetNS
	}
	if data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		if ns := strings.TrimSpace(string(data)); ns != "" {
			return ns
		}
	}
	return "default"
}
