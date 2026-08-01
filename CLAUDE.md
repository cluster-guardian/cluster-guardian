# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Cluster Guardian is a Go analysis engine, REST API and CLI that analyzes a Kubernetes cluster and reports findings on workload health, security, monitoring coverage, GitOps status, and cost optimization. Module path: `github.com/cluster-guardian/cluster-guardian`. Go version is pinned in `.go-version`.

This repo is **backend and CLI only — it serves no HTML**. Two sibling repos in the same org:

- [cluster-guardian-ui](https://github.com/cluster-guardian/cluster-guardian-ui) — the web UI, consuming this repo's REST API
- [cluster-guardian-helm](https://github.com/cluster-guardian/cluster-guardian-helm) — Helm charts (the in-repo `charts/` is being migrated there)

Because the UI ships from a different repo on its own cadence, `/api/*` is a **published contract**, not an internal detail: additive changes only, and `testdata/fixtures/*.json` (served by `serve --fixture`) is what the UI repo develops against. Changing the report schema is a cross-repo change.

## Commands

```sh
make build                           # build the binary (or: go build -o cluster-guardian .)
make test                            # go test -race ./...
make lint                            # golangci-lint run (config: .golangci.yml)
go test ./internal/checks/ -run TestSecurity -v   # run a single test
./cluster-guardian serve --fixture testdata/fixtures/run1.json --fixture testdata/fixtures/run2.json
```

The only remaining HTML is the **self-contained `-o html` export** (`internal/report/assets/dashboard.*`, inlined into a single offline file by `report.WriteHTML`). It is a report format alongside JSON/Markdown/PDF/SARIF/JUnit — not a UI, and it must never fetch anything at runtime (`TestWriteHTMLIsSelfContained` enforces this).

CI (`.github/workflows/ci.yml`) runs build, vet, `test -race`, golangci-lint, and an `api-contract` job that boots `serve --fixture` and asserts the endpoint shapes the UI repo depends on. Pushing a `v*` tag triggers `release.yml`: GoReleaser builds binaries (version injected into `cmd.Version` via ldflags — the module path is hardcoded in `Makefile`, `.goreleaser.yaml` and `Dockerfile`, and a stale path fails silently) and a multi-arch Docker image is pushed to `ghcr.io/cluster-guardian/cluster-guardian`.

Running locally requires a reachable cluster via kubeconfig:

```sh
./cluster-guardian analyze --context <ctx> -n <namespace> --verbose
./cluster-guardian serve --listen 127.0.0.1:8080   # REST API
./cluster-guardian docs --output-file CLUSTER.md   # cluster documentation (deprecated, removal tracked in #52)
```

## Architecture

The core design is **snapshot → pure checks → report → renderers**:

1. `internal/kube` — `Client.Collect()` reads everything once into a `Snapshot` struct (pods, workloads, RBAC, network policies, plus optional CRDs). Checks never talk to the API server.
2. `internal/checks` — each file (`workloads.go`, `security.go`, `monitoring.go`, `gitops.go`, `optimization.go`) is a pure function `Snapshot → report.Section` (or per-namespace sections). Purity is deliberate: tests feed synthetic snapshots, no fakes or mocks needed (see `checks_test.go`).
3. `internal/analyzer` — orchestration. `Run()` = collect + analyze; `Analyze()` is split out so tests can inject snapshots.
4. `internal/report` — the `Report`/`Section`/`Finding` model and four renderers: terminal (color), JSON, Markdown, HTML. `Severity` marshals to/from strings in JSON.
5. `cmd` — cobra CLI (`analyze` is also the root command's default action; `serve`, `lint`, `docs`, `cluster add`, `version`). Persistent flags (kubeconfig, context, namespaces, prometheus-url) live in `root.go`. `internal/manifest` builds a Snapshot from YAML for `lint`, which runs only the cluster-agnostic checks via `analyzer.Lint`.
6. `internal/server` — JSON REST API over the analyzer with a TTL report cache; `?refresh=true` bypasses it. Routes use Go 1.22+ method patterns (`GET /{$}`). It returns no HTML and mounts no static assets; `routes_test.go` pins that invariant.
7. `internal/prom` — minimal Prometheus HTTP API client used only by the optimization check when `--prometheus-url` is set.

Conventions that matter when extending it:

- **Optional CRDs** (ServiceMonitors, Argo CD Applications, Flux resources, cert-manager Certificates, Gateway API Gateways/HTTPRoutes, Kyverno PolicyReports/Policies, Gatekeeper constraints) are fetched via the dynamic client as `unstructured.Unstructured`; a nil slice in `Snapshot` means the CRD is not installed, and checks must degrade gracefully. GVRs are declared at the top of `internal/kube/snapshot.go`.
- **System namespaces** (`kube-system`, etc.) are excluded from per-namespace checks unless `--include-system`; the list is `kube.SystemNamespaces`.
- **Exit codes** are part of the CI contract: `--fail-on` returns exit 2 (warning) / 3 (critical) via the `failError` type in `cmd/analyze.go`; plain errors exit 1.
- A new check area = a new file in `internal/checks` returning a `report.Section`, wired into the `Sections` list in `internal/analyzer/analyzer.go`.
