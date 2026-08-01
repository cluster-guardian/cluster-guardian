package cmd

import (
	"github.com/spf13/cobra"

	"github.com/cluster-guardian/cluster-guardian/internal/analyzer"
	"github.com/cluster-guardian/cluster-guardian/internal/manifest"
)

var lintCmd = &cobra.Command{
	Use:   "lint <file|dir|-> ...",
	Short: "Analyze Kubernetes manifests without a cluster",
	Long: `Runs the cluster-agnostic checks (workloads, security, hygiene,
certificates, deprecated APIs) over manifests: files, directories
(recursively, *.yaml/*.yml/*.json), or stdin with "-". Live-only checks
(pod health status, monitoring coverage, GitOps, usage-based optimization,
policy engines, nodes) are skipped automatically.

Output formats, --framework and --fail-on/--fail-below work exactly like
analyze, so CI uses one tool and one rule set pre- and post-deploy:

  helm template ./chart | cluster-guardian lint - --fail-on critical
  kustomize build ./overlays/prod | cluster-guardian lint -
  cluster-guardian lint ./deploy -o json

The manifest set is assumed self-contained (a rendered chart or overlay):
references to objects that only exist in the live cluster surface as
findings.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateFramework(); err != nil {
			return err
		}
		snapshot, namespaces, err := manifest.Load(args, cmd.InOrStdin())
		if err != nil {
			return err
		}
		tc, err := loadTeams()
		if err != nil {
			return err
		}
		r := analyzer.Lint(snapshot, namespaces, flagClusterName)
		analyzer.AssignTeams(r, snapshot, tc.NamespaceTeam, flagTeamLabel)
		return finishReport(cmd, r)
	},
}

func init() {
	rootCmd.AddCommand(lintCmd)
}
