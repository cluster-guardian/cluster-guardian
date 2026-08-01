// Command cluster-guardian analyzes a Kubernetes cluster and reports
// reliability, security, monitoring and cost findings.
package main

import (
	"os"

	"github.com/cluster-guardian/cluster-guardian/cmd"
)

func main() {
	os.Exit(cmd.Execute())
}
