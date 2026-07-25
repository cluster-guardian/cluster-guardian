# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Policy section (#35): aggregates policy-engine state into the report — Kyverno PolicyReport failures summed per namespace, Gatekeeper constraint violations from audit status (constraint kinds discovered dynamically via the CRD list), info findings when an engine is installed with zero policies/constraints, and a coverage-gap warning for namespaces with pods that no admission policy covers. Silent when neither engine is installed. Chart role and `cluster add` provisioning grant the required reads.

- Gateway API awareness (#43): Gateways and HTTPRoutes are fetched via the optional-CRD pattern and extend the existing checks — HTTPRoute backendRefs to missing Services join the hygiene findings, Gateway listener `certificateRefs` get the same expiry and missing-secret checks as Ingress TLS, and Gateway-referenced secrets are no longer flagged unused. Cross-namespace refs are skipped (they would need ReferenceGrant evaluation). The chart role and `cluster add` provisioning grant `gateway.networking.k8s.io` read.

- Nodes section (#38): NotReady nodes (critical), memory/disk/PID pressure, cordoned nodes, kubelet version skew beyond the supported 2 minors and mixed kubelet versions, single-zone node pools, control-plane nodes without taints in mixed clusters, and nodes whose summed pod requests exceed ~90% of allocatable. Node listing is optional — without RBAC the section silently skips; the Helm chart role and `cluster add` provisioning now grant nodes read.

- Per-workload rightsizing recommendations (#28): with `--prometheus-url` set, workloads are compared against P50/P95/max usage over a window (`--rightsizing-window`, default 7d) and get concrete suggested requests, a `kubectl patch` snippet in verbose mode, and monthly savings estimates when `--cost-per-cpu`/`--cost-per-gb` are provided. The top recommendations fold into the Optimization section; `--rightsizing-report` adds the full per-workload section to every output format.

## [0.2.0] - 2026-07-25

### Added

- Extended security checks (#17): namespaces without a Pod Security Standards enforcement label, pods without a seccomp profile (tagged with the PSS `restricted` seccomp control, so the compliance summary now covers 5 controls), containers without `readOnlyRootFilesystem`, pods automounting ServiceAccount tokens (respecting opt-outs on the pod or its ServiceAccount), and containers receiving Secrets via environment variables.

- `cluster add <name>` command (#42, phase 4): registers a cluster with the fleet in one step — provisions a read-only ServiceAccount (wildcard-free ClusterRole scoped to exactly what the analyzer reads) and a long-lived token on the remote cluster, then stores the connection details in the labeled hub Secret. Idempotent: re-running refreshes the role rules and rotates the stored credentials.
- Prometheus metrics endpoint (#10): serve mode exposes `/metrics` with current findings by cluster/section/namespace/severity, the health score, and per-run timestamp, duration and error counters — rendered from the cached report, so scraping never triggers an analysis. Fleet mode emits one series set per registered cluster, and fleet statuses now report scan counts, failures and durations. The Helm chart can create a ServiceMonitor (`serviceMonitor.enabled`).

- Pod Security Standards compliance mapping: security findings are tagged with the PSS controls they violate, the Security section reports how many observable controls pass, and `--framework pss` filters the report to compliance-relevant findings (#30)
- Unused and orphaned resource detection: unused ConfigMaps/Secrets (with auto-generated ones excluded), unmounted and unbound PVCs, Services matching no pods, Ingress paths routing to missing Services, HPAs targeting missing workloads, and PDBs selecting nothing (#29). Secret contents are stripped at collection time; only names and types are kept.
- Certificates section: Ingress TLS certificates expiring within 30 days (critical under 7 days or already expired), Ingresses referencing missing TLS secrets, and cert-manager Certificate resources that are not Ready, detected via the optional-CRD pattern (#22). Only the public `tls.crt` of TLS secrets is retained in memory.
- Dashboard UX: severity and namespace filters, free-text search, collapsible sections with critical/warning counts in headers, an auto-refresh toggle (uses `?refresh=true`), and JSON/Markdown download buttons (#18). Filters and search also work in exported HTML reports; the live controls appear only in serve mode.
- Deprecated APIs section: objects still written with deprecated API versions, recovered from managedFields and the last-applied-configuration annotation. Warning when deprecated, critical when the API is removed in the cluster's next minor version or already gone (#15).
- Helm chart (#9, `charts/cluster-guardian`): Deployment with health probes and hardened defaults (non-root, read-only rootfs, seccomp, resource requests/limits — passing the tool's own checks), read-only ClusterRole with an opt-out for Secret access, optional PVC-backed history, fleet mode with a namespace-scoped fallback Role for cluster secrets, Service with Ingress or Gateway API HTTPRoute exposure, and a NetworkPolicy enabled by default.
- Cluster health score and grades (#26): every report carries a severity-weighted 0–100 score and A–F grade (overall and per section), shown in the terminal header, dashboard, and JSON summary; `--fail-below <score>` gates CI on it. Scores flow into history entries, so the trend chart can track them.
- Fleet mode (#42, phases 1–3; subsumes #20): `serve --fleet` turns the server into a hosted multi-cluster scorecard. Clusters register declaratively via Secrets labeled `cluster-guardian.io/secret-type: cluster` (`name`, `server`, and a `config` JSON with bearer token and CA), the local cluster is included automatically, and a scheduler scans the fleet on `--fleet-interval` with bounded concurrency and per-cluster timeouts. The root page becomes a fleet overview with per-cluster grades linking to scoped dashboards; per-cluster reports, history, and diffs are exposed under `/api/clusters/{name}/...`.
- Report history and trends (#19): serve mode records every analysis run (`--history-dir` persists them as JSON files across restarts, `--history-limit` caps retention), the dashboard shows a findings-over-time chart and a new/resolved strip, and `/api/history` + `/api/history/diff` expose the data. The run-over-run diff engine (`report.Diff`) normalizes counts in messages so "5 Pods" → "3 Pods" is not reported as a new finding, and is reusable for webhook notifications (#11) and the diff command (#37).

### Deprecated

- The `docs` command (Markdown cluster documentation). Cluster documentation is out of scope for an analyzer and the command will be removed in the release after this one; the dashboard and the planned MCP server mode (#39) cover the "what is running" question. Running it now prints a deprecation notice. (#52)

### Changed

- Project logo (`assets/logo.svg`) shown in the README, dashboard, and fleet page; both pages now ship a favicon.
- Dashboard and fleet UI restyled on a shared design system: CSS variables with a proper dark theme, refined cards and controls, a circular score gauge color-coded by grade, and focus states for keyboard use.
- Removed the deprecated Go Report Card badge from the README

## [0.1.0] - 2026-07-17

### Added

- Cluster analysis CLI: workload, health, security, monitoring, GitOps, and cost optimization checks
- PodDisruptionBudget and topology spread checks: multi-replica workloads without a PDB, PDBs that allow zero voluntary disruptions, and workloads without topologySpreadConstraints or pod anti-affinity (#16)
- Report export in JSON, Markdown, and HTML
- Web dashboard and REST API (`serve`)
- Cluster documentation generation (`docs`)
- `--fail-on` exit-code gating for CI/CD
- Dockerfile (distroless, non-root)
- CI, release automation (GoReleaser + GHCR image), linting, and Dependabot
