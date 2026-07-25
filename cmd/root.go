// Package cmd wires the cluster-guardian CLI.
package cmd

import (
	"github.com/spf13/cobra"

	"github.com/AndrewKarpaty/cluster-guardian/internal/analyzer"
	"github.com/AndrewKarpaty/cluster-guardian/internal/kube"
)

var (
	flagKubeconfig    string
	flagContext       string
	flagNamespaces    []string
	flagIncludeSystem bool
	flagPrometheusURL string
	flagClusterName   string
)

var rootCmd = &cobra.Command{
	Use:   "cluster-guardian",
	Short: "Analyze a Kubernetes cluster for reliability, security, monitoring and cost issues",
	Long: `Cluster Guardian analyzes a Kubernetes cluster and reports actionable
findings: unhealthy workloads, missing resource requests and probes, security
misconfigurations, monitoring coverage gaps, GitOps drift and cost
optimization opportunities.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	// Running without a subcommand analyzes the cluster.
	RunE: func(cmd *cobra.Command, args []string) error {
		return analyzeCmd.RunE(cmd, args)
	},
}

// Execute runs the CLI and returns the process exit code.
func Execute() int {
	if err := rootCmd.Execute(); err != nil {
		if code, ok := failCode(err); ok {
			return code
		}
		rootCmd.PrintErrln("Error:", err)
		return 1
	}
	return 0
}

func init() {
	pf := rootCmd.PersistentFlags()
	pf.StringVar(&flagKubeconfig, "kubeconfig", "", "path to kubeconfig (defaults to $KUBECONFIG or ~/.kube/config)")
	pf.StringVar(&flagContext, "context", "", "kubeconfig context to use")
	pf.StringSliceVarP(&flagNamespaces, "namespace", "n", nil, "restrict analysis to these namespaces (repeatable)")
	pf.BoolVar(&flagIncludeSystem, "include-system", false, "also analyze kube-system and other system namespaces")
	pf.StringVar(&flagPrometheusURL, "prometheus-url", "", "Prometheus base URL for usage-based optimization checks")
	pf.StringVar(&flagClusterName, "cluster-name", "", "display name for the cluster (defaults to the kube context)")
}

func newKubeClient() (*kube.Client, error) {
	return kube.NewClient(flagKubeconfig, flagContext)
}

func analyzerOptions() analyzer.Options {
	return analyzer.Options{
		Namespaces:        flagNamespaces,
		IncludeSystem:     flagIncludeSystem,
		PrometheusURL:     flagPrometheusURL,
		ClusterName:       flagClusterName,
		RightsizingReport: flagRightsizingReport,
		RightsizingWindow: flagRightsizingWindow,
		CostPerCPUMonth:   flagCostPerCPU,
		CostPerGiBMonth:   flagCostPerGB,
	}
}
