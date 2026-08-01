package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/cluster-guardian/cluster-guardian/internal/analyzer"
	"github.com/cluster-guardian/cluster-guardian/internal/auth"
	"github.com/cluster-guardian/cluster-guardian/internal/deliver"
	"github.com/cluster-guardian/cluster-guardian/internal/fleet"
	"github.com/cluster-guardian/cluster-guardian/internal/history"
	"github.com/cluster-guardian/cluster-guardian/internal/kube"
	"github.com/cluster-guardian/cluster-guardian/internal/notify"
	"github.com/cluster-guardian/cluster-guardian/internal/report"
	"github.com/cluster-guardian/cluster-guardian/internal/server"
	"github.com/cluster-guardian/cluster-guardian/internal/teams"
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
	flagFixture        []string

	flagAuthMode       string
	flagAuthUserHeader string
	flagAuthGroupsHdr  string
	flagAuthProxies    []string
	flagAuthGroupRoles []string
	flagAuthDefaultRl  string
	flagAuthAnonRole   string
	flagAdmin          bool
	flagTeamsConfigMap string
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve the REST API",
	Long: `Starts an HTTP server exposing:

  GET /                    index of available endpoints
  GET /api/me              caller's identity, role and permissions
  GET /api/report          report as JSON (append ?refresh=true to bypass cache)
  GET /api/report/markdown report as Markdown
  GET /api/history         past runs (summaries)
  GET /api/history/diff    what changed since the previous run
  GET /metrics             Prometheus metrics (findings, score, run stats)
  GET /healthz             liveness probe

With --fleet, per-cluster equivalents are served under /api/clusters.

Authentication and roles
------------------------
By default nothing authenticates and every caller is an anonymous viewer,
which can read but not change anything. --auth-mode=proxy takes the caller's
identity from headers set by an authenticating proxy (oauth2-proxy, an ingress
with OIDC, a mesh) and maps their groups to roles:

  serve --auth-mode=proxy \
        --auth-trusted-proxies=10.0.0.0/8 \
        --auth-group-role=platform=admin \
        --auth-group-role=sre=operator \
        --auth-default-role=viewer

Roles are ordered: viewer reads, operator also edits team ownership, admin
also registers and removes clusters.

A header is only as trustworthy as whoever can set it, so proxy mode requires
--auth-trusted-proxies and rejects identity headers from any other peer. Put
the server behind the proxy and keep it unreachable otherwise — a
NetworkPolicy restricting ingress to the proxy's pods is the usual way.

Write API
---------
--admin-api adds the endpoints the UI needs to manage a fleet:

  POST   /api/clusters          register a cluster (admin)
  DELETE /api/clusters/{name}   remove a registration (admin)
  GET    /api/teams             team ownership (viewer)
  PUT    /api/teams             replace team ownership (operator)

Cluster registration stores credentials the caller supplies; it does not
provision them. Provisioning needs admin rights on the target cluster, which
the hub does not have and should not be given — "cluster add" still does that
from an operator's own kubeconfig. Team editing needs --teams-configmap.

The web UI is a separate application (cluster-guardian-ui) that consumes this
API; this server renders no HTML. For a report you can open in a browser
without a server, use "analyze -o html".`,
	RunE: func(_ *cobra.Command, _ []string) error {
		if len(flagFixture) > 0 {
			return serveFixture()
		}
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

		authCfg, err := authConfig()
		if err != nil {
			return err
		}
		srv.EnableAuth(authCfg)

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
		var mgr *fleet.Manager
		if flagFleet {
			reg := &fleet.Registry{
				Local:     client,
				Clientset: client.Clientset,
				Namespace: fleetNamespace(),
			}
			mgr = fleet.NewManager(reg, opts, flagFleetInterval, flagHistoryDir, flagHistoryLimit)
			if notifier != nil {
				mgr.EnableNotifications(notifier)
			}
			srv.EnableFleet(mgr)
			go mgr.Run(context.Background())
		}

		if flagAdmin {
			if err := enableAdmin(srv, client, mgr, authCfg); err != nil {
				return err
			}
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
	serveCmd.Flags().StringSliceVar(&flagFixture, "fixture", nil, "serve canned report JSON files instead of analyzing a cluster (repeatable; for demos and UI tests)")

	serveCmd.Flags().StringVar(&flagAuthMode, "auth-mode", "none", `how to identify callers: "none" (everyone anonymous) or "proxy" (identity from headers set by an authenticating proxy)`)
	serveCmd.Flags().StringVar(&flagAuthUserHeader, "auth-user-header", auth.DefaultUserHeader, "header carrying the authenticated username")
	serveCmd.Flags().StringVar(&flagAuthGroupsHdr, "auth-groups-header", auth.DefaultGroupsHeader, "header carrying the caller's groups, comma-separated")
	serveCmd.Flags().StringSliceVar(&flagAuthProxies, "auth-trusted-proxies", nil, `CIDRs or IPs whose identity headers are believed; "any" trusts every peer (required with --auth-mode=proxy)`)
	serveCmd.Flags().StringSliceVar(&flagAuthGroupRoles, "auth-group-role", nil, "map a group to a role, e.g. platform=admin (repeatable)")
	serveCmd.Flags().StringVar(&flagAuthDefaultRl, "auth-default-role", "viewer", "role for an authenticated caller whose groups match no mapping: none, viewer, operator, admin")
	serveCmd.Flags().StringVar(&flagAuthAnonRole, "auth-anonymous-role", "viewer", "role for a caller with no identity: none, viewer, operator, admin")
	serveCmd.Flags().BoolVar(&flagAdmin, "admin-api", false, "serve the write API (cluster registration, team ownership); requires a cluster connection")
	serveCmd.Flags().StringVar(&flagTeamsConfigMap, "teams-configmap", "", "ConfigMap holding the team mapping, made editable via PUT /api/teams (default: disabled)")

	rootCmd.AddCommand(serveCmd)
}

// authConfig builds the identity configuration from the flags, refusing the
// combinations that would quietly leave the API open.
func authConfig() (auth.Config, error) {
	anon, err := auth.ParseRole(flagAuthAnonRole)
	if err != nil {
		return auth.Config{}, fmt.Errorf("--auth-anonymous-role: %w", err)
	}
	def, err := auth.ParseRole(flagAuthDefaultRl)
	if err != nil {
		return auth.Config{}, fmt.Errorf("--auth-default-role: %w", err)
	}
	cfg := auth.Config{
		UserHeader:    flagAuthUserHeader,
		GroupsHeader:  flagAuthGroupsHdr,
		GroupRoles:    map[string]auth.Role{},
		DefaultRole:   def,
		AnonymousRole: anon,
	}

	switch strings.ToLower(flagAuthMode) {
	case "", "none":
		// Nothing authenticates the caller, so nothing may be trusted to name
		// them. Refuse to hand out write permissions to everyone by accident.
		if anon > auth.RoleViewer {
			return auth.Config{}, fmt.Errorf(
				"--auth-anonymous-role=%s requires --auth-mode=proxy: with no authentication every caller would hold that role", anon)
		}
	case "proxy":
		cfg.Enabled = true
		if len(flagAuthProxies) == 0 {
			return auth.Config{}, fmt.Errorf(
				"--auth-mode=proxy requires --auth-trusted-proxies: identity headers are only meaningful from a peer that cannot be bypassed")
		}
		nets, err := auth.ParseTrustedProxies(flagAuthProxies)
		if err != nil {
			return auth.Config{}, fmt.Errorf("--auth-trusted-proxies: %w", err)
		}
		cfg.TrustedProxies = nets
	default:
		return auth.Config{}, fmt.Errorf(`--auth-mode: unknown mode %q (want "none" or "proxy")`, flagAuthMode)
	}

	for _, pair := range flagAuthGroupRoles {
		group, roleName, ok := strings.Cut(pair, "=")
		if !ok {
			return auth.Config{}, fmt.Errorf("--auth-group-role %q: expected group=role", pair)
		}
		role, err := auth.ParseRole(roleName)
		if err != nil {
			return auth.Config{}, fmt.Errorf("--auth-group-role %q: %w", pair, err)
		}
		cfg.GroupRoles[strings.TrimSpace(group)] = role
	}
	return cfg, nil
}

// enableAdmin turns on the write API. It refuses to do so when nothing
// authenticates the caller and anonymous callers could reach it — registering
// a cluster stores credentials, and that is not an anonymous operation.
func enableAdmin(srv *server.Server, client *kube.Client, mgr *fleet.Manager, authCfg auth.Config) error {
	if !authCfg.Enabled && authCfg.AnonymousRole >= auth.RoleOperator {
		return fmt.Errorf("--admin-api needs --auth-mode=proxy: without it every caller would hold role %s", authCfg.AnonymousRole)
	}
	ns := fleetNamespace()
	adm := &server.Admin{Clientset: client.Clientset, Namespace: ns, Fleet: mgr}
	if flagTeamsConfigMap != "" {
		adm.Teams = &teams.Store{Clientset: client.Clientset, Namespace: ns, Name: flagTeamsConfigMap}
	}
	srv.EnableAdmin(adm)
	return nil
}

// serveFixture serves canned report JSON files instead of analyzing a
// cluster: no kubeconfig needed. Files are appended to history in order and
// the last one becomes the current report — two or more files light up the
// trend chart and run-over-run diff. Enabler for UI e2e tests and demos.
func serveFixture() error {
	hist, err := history.New("", flagHistoryLimit)
	if err != nil {
		return err
	}
	var last *report.Report
	for _, path := range flagFixture {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var r report.Report
		if err := json.Unmarshal(data, &r); err != nil {
			return fmt.Errorf("parsing fixture %s: %w", path, err)
		}
		hist.Append(&r)
		last = &r
	}
	srv := server.New(nil, analyzer.Options{}, flagCacheTTL, hist)
	srv.SetFixture(last)

	authCfg, err := authConfig()
	if err != nil {
		return err
	}
	srv.EnableAuth(authCfg)

	// The write API needs a cluster to write to, so fixture mode serves reads
	// only. Auth still applies, which is the point: --auth-mode=proxy with
	// --auth-trusted-proxies=any lets the UI exercise every role by setting
	// request headers, with no cluster and no identity provider.
	if flagAdmin {
		log.Printf("--admin-api ignored in fixture mode: the write API needs a cluster to write to")
	}
	return srv.ListenAndServe(flagListen)
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
