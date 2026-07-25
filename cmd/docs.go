package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/AndrewKarpaty/cluster-guardian/internal/docs"
)

var flagDocsFile string

var docsCmd = &cobra.Command{
	Use:   "docs",
	Short: "Generate Markdown documentation of the cluster's workloads, services and ingresses",
	// Delete this file and internal/docs in the release after the
	// deprecation ships (#52).
	Deprecated: "cluster documentation is out of scope and will be removed in the release after next.\n" +
		"See https://github.com/AndrewKarpaty/cluster-guardian/issues/52 to object or to adopt it.",
	RunE: func(cmd *cobra.Command, _ []string) error {
		client, err := newKubeClient()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), 3*time.Minute)
		defer cancel()

		snapshot, err := client.Collect(ctx, flagNamespaces)
		if err != nil {
			return err
		}
		name := flagClusterName
		if name == "" {
			name = client.Context
		}

		out := cmd.OutOrStdout()
		var closer io.Closer
		if flagDocsFile != "" {
			f, err := os.Create(flagDocsFile)
			if err != nil {
				return err
			}
			out, closer = f, f
		}
		namespaces := snapshot.AppNamespaces(flagIncludeSystem, flagNamespaces)
		err = docs.Write(out, snapshot, name, namespaces)
		if closer != nil {
			if cerr := closer.Close(); cerr != nil && err == nil {
				err = cerr
			}
		}
		if err != nil {
			return err
		}
		if flagDocsFile != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "Documentation written to %s\n", flagDocsFile)
		}
		return nil
	},
}

func init() {
	docsCmd.Flags().StringVar(&flagDocsFile, "output-file", "", "write documentation to a file instead of stdout")
	rootCmd.AddCommand(docsCmd)
}
