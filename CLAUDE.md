# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Cluster Guardian is a Go CLI (with an optional web dashboard) that analyzes a Kubernetes cluster and reports findings on workload health, security, monitoring coverage, GitOps status, and cost optimization. Module path: `github.com/AndrewKarpaty/cluster-guardian`. Go version is pinned in `.go-version`.

## Commands

```sh
make build                           # build the binary (or: go build -o cluster-guardian .)
make test                            # go test -race ./...
make lint                            # golangci-lint run (config: .golangci.yml)
go test ./internal/checks/ -run TestSecurity -v   # run a single test
```

CI (`.github/workflows/ci.yml`) runs build, vet, `test -race`, and golangci-lint on every PR. Pushing a `v*` tag triggers `release.yml`: GoReleaser builds binaries (version injected into `cmd.Version` via ldflags) and a multi-arch Docker image is pushed to `ghcr.io/andrewkarpaty/cluster-guardian`.

Running locally requires a reachable cluster via kubeconfig:

```sh
./cluster-guardian analyze --context <ctx> -n <namespace> --verbose
./cluster-guardian serve --listen 127.0.0.1:8080   # dashboard + REST API
./cluster-guardian docs --output-file CLUSTER.md   # cluster documentation (deprecated, removal tracked in #52)
```

## Architecture

The core design is **snapshot → pure checks → report → renderers**:

1. `internal/kube` — `Client.Collect()` reads everything once into a `Snapshot` struct (pods, workloads, RBAC, network policies, plus optional CRDs). Checks never talk to the API server.
2. `internal/checks` — each file (`workloads.go`, `security.go`, `monitoring.go`, `gitops.go`, `optimization.go`) is a pure function `Snapshot → report.Section` (or per-namespace sections). Purity is deliberate: tests feed synthetic snapshots, no fakes or mocks needed (see `checks_test.go`).
3. `internal/analyzer` — orchestration. `Run()` = collect + analyze; `Analyze()` is split out so tests can inject snapshots.
4. `internal/report` — the `Report`/`Section`/`Finding` model and four renderers: terminal (color), JSON, Markdown, HTML. `Severity` marshals to/from strings in JSON.
5. `cmd` — cobra CLI (`analyze` is also the root command's default action; `serve`, `docs`, `cluster add`, `version`). Persistent flags (kubeconfig, context, namespaces, prometheus-url) live in `root.go`.
6. `internal/server` — HTTP wrapper around the analyzer with a TTL report cache; `?refresh=true` bypasses it. Routes use Go 1.22+ method patterns (`GET /{$}`).
7. `internal/prom` — minimal Prometheus HTTP API client used only by the optimization check when `--prometheus-url` is set.

Conventions that matter when extending it:

- **Optional CRDs** (ServiceMonitors, Argo CD Applications, Flux resources, cert-manager Certificates, Gateway API Gateways/HTTPRoutes, Kyverno PolicyReports/Policies, Gatekeeper constraints) are fetched via the dynamic client as `unstructured.Unstructured`; a nil slice in `Snapshot` means the CRD is not installed, and checks must degrade gracefully. GVRs are declared at the top of `internal/kube/snapshot.go`.
- **System namespaces** (`kube-system`, etc.) are excluded from per-namespace checks unless `--include-system`; the list is `kube.SystemNamespaces`.
- **Exit codes** are part of the CI contract: `--fail-on` returns exit 2 (warning) / 3 (critical) via the `failError` type in `cmd/analyze.go`; plain errors exit 1.
- A new check area = a new file in `internal/checks` returning a `report.Section`, wired into the `Sections` list in `internal/analyzer/analyzer.go`.
