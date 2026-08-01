package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/cluster-guardian/cluster-guardian/internal/fleet"
	"github.com/cluster-guardian/cluster-guardian/internal/kube"
)

var (
	flagRemoteKubeconfig string
	flagRemoteContext    string
	flagRemoteServer     string
	flagSANamespace      string
	flagInsecureTLS      bool
)

var clusterCmd = &cobra.Command{
	Use:   "cluster",
	Short: "Manage the fleet cluster registry",
}

var clusterAddCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Register a remote cluster for fleet scanning",
	Long: `Registers a cluster with the fleet in one step instead of hand-writing the
registration Secret:

  1. On the remote cluster (--remote-context/--remote-kubeconfig): creates a
     namespace, a read-only ServiceAccount, a ClusterRole scoped to exactly
     the resources cluster-guardian reads, a binding, and a long-lived token.
  2. On the local hub cluster (--context/--kubeconfig): stores the connection
     details in a Secret labeled ` + fleet.SecretLabel + `=cluster, where
     'serve --fleet' discovers it.

Re-running is safe: it refreshes the ClusterRole rules and rotates the
stored credentials.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		remote, err := kube.NewClient(flagRemoteKubeconfig, flagRemoteContext)
		if err != nil {
			return fmt.Errorf("connecting to remote cluster: %w", err)
		}
		local, err := newKubeClient()
		if err != nil {
			return fmt.Errorf("connecting to local cluster: %w", err)
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Minute)
		defer cancel()
		out := cmd.OutOrStdout()

		creds, err := fleet.Provision(ctx, remote.Clientset, fleet.ProvisionOptions{Namespace: flagSANamespace})
		if err != nil {
			return fmt.Errorf("provisioning access on %q: %w", remote.Context, err)
		}
		fmt.Fprintf(out, "✔ Read-only ServiceAccount and token ready on %q\n", remote.Context)

		server := flagRemoteServer
		if server == "" {
			server = remote.Server
		}
		if strings.Contains(server, "127.0.0.1") || strings.Contains(server, "localhost") {
			fmt.Fprintf(out, "⚠ Server URL %s may not be reachable from inside the hub cluster; override it with --server\n", server)
		}

		sec, err := fleet.NewClusterSecret(fleetNamespace(), fleet.ClusterSecretSpec{
			ClusterName: name,
			Server:      server,
			BearerToken: creds.Token,
			CAData:      creds.CAData,
			Insecure:    flagInsecureTLS,
		})
		if err != nil {
			return err
		}
		if err := fleet.ApplySecret(ctx, local.Clientset, sec); err != nil {
			return fmt.Errorf("registering cluster on %q: %w", local.Context, err)
		}
		fmt.Fprintf(out, "✔ Cluster %q registered in Secret %s/%s on %q\n", name, sec.Namespace, sec.Name, local.Context)
		fmt.Fprintln(out, "Run `cluster-guardian serve --fleet` on the hub to start scanning it.")
		return nil
	},
}

func init() {
	f := clusterAddCmd.Flags()
	f.StringVar(&flagRemoteKubeconfig, "remote-kubeconfig", "", "kubeconfig for the cluster being added (defaults to the local kubeconfig)")
	f.StringVar(&flagRemoteContext, "remote-context", "", "kubeconfig context of the cluster being added")
	f.StringVar(&flagRemoteServer, "server", "", "API server URL to store in the registration (defaults to the remote kubeconfig's URL)")
	f.StringVar(&flagSANamespace, "sa-namespace", "cluster-guardian", "remote namespace for the ServiceAccount and its token")
	f.StringVar(&flagFleetNS, "fleet-namespace", "", "local namespace for the registration secret (default: the pod's own namespace or \"default\")")
	f.BoolVar(&flagInsecureTLS, "insecure-skip-tls-verify", false, "skip TLS verification when scanning the remote cluster")
	clusterCmd.AddCommand(clusterAddCmd)
	rootCmd.AddCommand(clusterCmd)
}
