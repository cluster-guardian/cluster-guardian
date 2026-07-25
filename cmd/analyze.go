package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/AndrewKarpaty/cluster-guardian/internal/analyzer"
	"github.com/AndrewKarpaty/cluster-guardian/internal/report"
)

var (
	flagOutput            string
	flagOutputFile        string
	flagFailOn            string
	flagVerbose           bool
	flagNoColor           bool
	flagFramework         string
	flagFailBelow         int
	flagRightsizingReport bool
	flagRightsizingWindow time.Duration
	flagCostPerCPU        float64
	flagCostPerGB         float64
)

// failError carries the exit code for --fail-on threshold violations, so CI
// pipelines can gate on findings.
type failError struct{ code int }

func (e failError) Error() string { return "findings at or above the --fail-on threshold" }

func failCode(err error) (int, bool) {
	if fe, ok := errors.AsType[failError](err); ok {
		return fe.code, true
	}
	return 0, false
}

var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze the cluster and print a report",
	RunE: func(cmd *cobra.Command, _ []string) error {
		if err := validateFramework(); err != nil {
			return err
		}
		client, err := newKubeClient()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), 3*time.Minute)
		defer cancel()

		r, err := analyzer.Run(ctx, client, analyzerOptions())
		if err != nil {
			return err
		}
		return finishReport(cmd, r)
	},
}

func validateFramework() error {
	if flagFramework != "" && !strings.EqualFold(flagFramework, "pss") {
		return fmt.Errorf("unknown --framework %q (supported: pss)", flagFramework)
	}
	return nil
}

// finishReport applies the framework filter, renders the report in the
// selected format, and returns the --fail-on/--fail-below gating error.
// Shared by analyze and lint so CI gets one rule set pre- and post-deploy.
func finishReport(cmd *cobra.Command, r *report.Report) error {
	if flagFramework != "" {
		r.FilterControls(flagFramework + "/")
	}

	out := cmd.OutOrStdout()
	var closer io.Closer
	if flagOutputFile != "" {
		f, err := os.Create(flagOutputFile)
		if err != nil {
			return err
		}
		out, closer = f, f
	}

	var err error
	switch flagOutput {
	case "terminal", "":
		noColor := flagNoColor || os.Getenv("NO_COLOR") != "" || flagOutputFile != ""
		report.WriteTerminal(out, r, report.TerminalOptions{NoColor: noColor, Verbose: flagVerbose})
	case "json":
		err = report.WriteJSON(out, r)
	case "markdown", "md":
		err = report.WriteMarkdown(out, r)
	case "html":
		err = report.WriteHTML(out, r)
	case "sarif":
		err = report.WriteSARIF(out, r)
	case "junit":
		err = report.WriteJUnit(out, r)
	default:
		return fmt.Errorf("unknown output format %q (use terminal, json, markdown, html, sarif or junit)", flagOutput)
	}
	if closer != nil {
		if cerr := closer.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	if err != nil {
		return err
	}
	if flagOutputFile != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "Report written to %s\n", flagOutputFile)
	}

	return checkFailThreshold(r)
}

func checkFailThreshold(r *report.Report) error {
	if flagFailBelow > 0 && r.Summary.Score < flagFailBelow {
		return failError{code: 2}
	}
	highest := r.MaxSeverity()
	switch flagFailOn {
	case "", "none":
		return nil
	case "warning":
		if highest >= report.SeverityWarning {
			return failError{code: 2}
		}
	case "critical":
		if highest >= report.SeverityCritical {
			return failError{code: 3}
		}
	default:
		return fmt.Errorf("unknown --fail-on value %q (use none, warning or critical)", flagFailOn)
	}
	return nil
}

func init() {
	for _, cmd := range []*cobra.Command{analyzeCmd, rootCmd, lintCmd} {
		f := cmd.Flags()
		f.StringVarP(&flagOutput, "output", "o", "terminal", "output format: terminal, json, markdown, html, sarif, junit")
		f.StringVar(&flagOutputFile, "output-file", "", "write the report to a file instead of stdout")
		f.StringVar(&flagFailOn, "fail-on", "none", "exit non-zero if findings reach this severity: none, warning, critical")
		f.StringVar(&flagFramework, "framework", "", "only show findings mapped to a compliance framework: pss")
		f.IntVar(&flagFailBelow, "fail-below", 0, "exit non-zero if the health score is below this value (0 = disabled)")
		f.BoolVarP(&flagVerbose, "verbose", "v", false, "show remediation hints for each finding")
		f.BoolVar(&flagNoColor, "no-color", false, "disable colored output")
		f.BoolVar(&flagRightsizingReport, "rightsizing-report", false, "full per-workload rightsizing section (requires --prometheus-url)")
		f.DurationVar(&flagRightsizingWindow, "rightsizing-window", 7*24*time.Hour, "usage lookback window for rightsizing")
		f.Float64Var(&flagCostPerCPU, "cost-per-cpu", 0, "monthly cost of one CPU core; enables rightsizing savings estimates")
		f.Float64Var(&flagCostPerGB, "cost-per-gb", 0, "monthly cost of one GiB of memory; enables rightsizing savings estimates")
	}
	rootCmd.AddCommand(analyzeCmd)
}
