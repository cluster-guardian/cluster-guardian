package cmd

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

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
		srv := server.New(client, analyzerOptions(), flagCacheTTL, hist)
		var notifier *notify.Notifier
		if flagNotifyURL != "" {
			notifier, err = notify.New(flagNotifyURL, flagNotifyFormat, flagNotifyMinSev)
			if err != nil {
				return err
			}
			srv.EnableNotifications(notifier)
		}
		if flagFleet {
			reg := &fleet.Registry{
				Local:     client,
				Clientset: client.Clientset,
				Namespace: fleetNamespace(),
			}
			mgr := fleet.NewManager(reg, analyzerOptions(), flagFleetInterval, flagHistoryDir, flagHistoryLimit)
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
	rootCmd.AddCommand(serveCmd)
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
