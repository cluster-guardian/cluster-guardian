<p align="center">
  <img src="assets/logo.svg" alt="Cluster Guardian logo" width="140">
</p>

# Cluster Guardian

[![Build Status][actions-badge]][actions-url]
[![Go Reference][godoc-badge]][godoc-url]
[![Release][release-badge]][release-url]
[![License: MIT][license-badge]][license-url]

[actions-badge]: https://github.com/cluster-guardian/cluster-guardian/actions/workflows/ci.yml/badge.svg
[actions-url]: https://github.com/cluster-guardian/cluster-guardian/actions/workflows/ci.yml
[godoc-badge]: https://pkg.go.dev/badge/github.com/cluster-guardian/cluster-guardian.svg
[godoc-url]: https://pkg.go.dev/github.com/cluster-guardian/cluster-guardian
[release-badge]: https://img.shields.io/github/v/release/cluster-guardian/cluster-guardian?include_prereleases
[release-url]: https://github.com/cluster-guardian/cluster-guardian/releases
[license-badge]: https://img.shields.io/badge/License-MIT-blue.svg
[license-url]: LICENSE

Cluster Guardian is an open-source tool that analyzes Kubernetes clusters and provides actionable recommendations for improving reliability, security, performance, and operational efficiency.

```
✔ Cluster: production

⚠ Namespace: payments
  • 5 Pods missing resource requests
  • 2 CrashLoopBackOff containers
  • Deployment "api" uses :latest tag
  • Missing HorizontalPodAutoscaler

⚠ Security
  • 8 containers running as root
  • 3 namespaces without NetworkPolicies

⚠ Monitoring
  • 4 Services are not scraped by Prometheus
  • Missing alerts for Redis and PostgreSQL

💰 Optimization
  • Estimated CPU overprovisioning: 68%
  • Estimated Memory overprovisioning: 41%
```

## Features

* Cluster health analysis
* Workload validation (Deployments, StatefulSets, DaemonSets, Jobs, CronJobs)
* Resource optimization using Prometheus metrics
* Detection of unhealthy workloads (CrashLoopBackOff, Pending, ImagePullBackOff, OOMKilled, restart storms)
* Identification of missing CPU/Memory requests and limits
* Readiness, Liveness, and Startup Probe validation
* PodDisruptionBudget coverage and topology spread validation
* Unused resource detection (ConfigMaps, Secrets, PVCs, Services without pods, dangling Ingress/HPA/PDB targets)
* TLS certificate checks (Ingress certificates near expiry, missing TLS secrets, cert-manager Certificate readiness)
* Deprecated API detection (kubent-style, severity based on the cluster's version)
* Security checks (root containers, privileged pods, dangerous capabilities, host namespaces, RBAC, Network Policies)
* Pod Security Standards compliance summary (`--framework pss` shows only PSS-mapped findings)
* Monitoring validation (Prometheus, Alertmanager, ServiceMonitors, PodMonitors, PrometheusRules)
* Argo CD / Flux health integration
* Cost optimization recommendations
* Automatic cluster documentation generation
* Cluster health score (0–100) and A–F grades, with `--fail-below` gating
* Fleet mode: hosted multi-cluster scorecard with declarative, Secret-based cluster registration
* Static manifest linting (`lint`): the same rule set pre-deploy, no cluster needed
* Export reports in JSON, Markdown, HTML, SARIF (GitHub code scanning), and JUnit XML
* REST API consumed by the separate [web UI](https://github.com/cluster-guardian/cluster-guardian-ui)
* CLI for automation and CI/CD integration

## Installation

```sh
go install github.com/cluster-guardian/cluster-guardian@latest
```

Or build from source:

```sh
git clone https://github.com/cluster-guardian/cluster-guardian.git
cd cluster-guardian
go build -o cluster-guardian .
```

### Docker

```sh
docker build -t cluster-guardian .

# CLI: analyze using your local kubeconfig
docker run --rm -v ~/.kube:/kube:ro -e KUBECONFIG=/kube/config cluster-guardian

# API server: bind to 0.0.0.0 so the published port is reachable
docker run --rm -p 8080:8080 -v ~/.kube:/kube:ro -e KUBECONFIG=/kube/config \
  cluster-guardian serve --listen 0.0.0.0:8080
```

When running in-cluster (e.g. as a Deployment serving the API), no kubeconfig is needed — the ServiceAccount token is picked up automatically.

### Helm

A chart lives in [`charts/cluster-guardian`](charts/cluster-guardian). It ships the read-only ClusterRole, health probes, a NetworkPolicy (on by default), and hardened pod defaults that pass cluster-guardian's own checks:

```sh
helm install cluster-guardian ./charts/cluster-guardian \
  --namespace cluster-guardian --create-namespace \
  --set persistence.enabled=true \      # keep trend history on a PVC
  --set fleet.enabled=true              # multi-cluster scorecard mode
```

Key values: `prometheusUrl`, `ingress.*` (or `httpRoute.*` for Gateway API), `persistence.*`, `fleet.*`, `serviceMonitor.*`, `rbac.includeSecrets` (disable to run without cluster-wide Secret read access; the affected checks skip). See [values.yaml](charts/cluster-guardian/values.yaml) for the full list.

### Verify a release

Releases are signed with [cosign](https://github.com/sigstore/cosign) (keyless,
GitHub OIDC), ship SPDX SBOMs, and carry SLSA build provenance. To verify:

```sh
# Image signature: proves the image was built by this repo's release workflow
cosign verify ghcr.io/cluster-guardian/cluster-guardian:v0.3.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp 'https://github.com/cluster-guardian/cluster-guardian/\.github/workflows/release\.yml@refs/tags/v.*'

# Checksums signature, then verify a downloaded archive against it
cosign verify-blob checksums.txt --signature checksums.txt.sig --certificate checksums.txt.pem \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp 'https://github.com/cluster-guardian/cluster-guardian/\.github/workflows/release\.yml@refs/tags/v.*'
sha256sum --check --ignore-missing checksums.txt

# SLSA provenance of an archive (multiple.intoto.jsonl from the release page)
slsa-verifier verify-artifact cluster-guardian_*_linux_amd64.tar.gz \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/cluster-guardian/cluster-guardian

# Image SBOM and provenance (BuildKit attestations on the manifest)
docker buildx imagetools inspect ghcr.io/cluster-guardian/cluster-guardian:v0.3.0 \
  --format '{{ json .SBOM }}'
```

Per-archive SPDX SBOMs (`*.sbom.json`) are attached to every GitHub release.

## Usage

Analyze the cluster from your current kubeconfig context:

```sh
cluster-guardian
```

Common options:

```sh
cluster-guardian analyze \
  --context production \                    # kubeconfig context
  -n payments -n checkout \                 # limit to specific namespaces
  --prometheus-url http://localhost:9090 \  # enable usage-based cost analysis
  --verbose                                 # show remediation hints for each finding
```

If Prometheus is not exposed outside the cluster, port-forward it first:

```sh
kubectl port-forward -n monitoring svc/prometheus-operated 9090:9090
cluster-guardian --prometheus-url http://localhost:9090
```

### Rightsizing recommendations

With `--prometheus-url` set, the report also recommends concrete per-workload
requests: current values vs P50/P95/max usage over the last 7 days
(`--rightsizing-window`), with a suggested `cpu:`/`memory:` block and — in
`--verbose` mode — a ready-to-apply `kubectl patch` snippet. The top
recommendations appear in the Optimization section; `--rightsizing-report`
adds a full per-workload section (also in JSON/Markdown/HTML exports). Add
cost hints for monthly savings estimates:

```sh
cluster-guardian --prometheus-url http://localhost:9090 \
  --rightsizing-report --cost-per-cpu 15 --cost-per-gb 2 -v
```

Unlike Goldilocks (needs the VPA) or cost platforms, this is read-only and
uses the Prometheus you already have.

### Lint manifests without a cluster

`lint` runs the cluster-agnostic checks (workloads, security, hygiene,
certificates, deprecated APIs) over local YAML — files, directories, or
stdin — with the same findings, severities, output formats and exit-code
gating as `analyze`. One rule set pre- and post-deploy, no drift between
what you lint in CI and what you audit in the cluster:

```sh
helm template ./chart | cluster-guardian lint - --fail-on critical
kustomize build ./overlays/prod | cluster-guardian lint -
cluster-guardian lint ./deploy -o json
```

Live-only checks (pod health, monitoring coverage, GitOps, usage-based
optimization, policy engines, nodes) are skipped automatically. Lint assumes
a self-contained manifest set (a rendered chart or overlay), so references
to objects that only exist in the live cluster surface as findings.

### Export reports

```sh
cluster-guardian analyze -o json     --output-file report.json
cluster-guardian analyze -o markdown --output-file report.md
cluster-guardian analyze -o html     --output-file report.html
cluster-guardian analyze -o sarif    --output-file results.sarif   # GitHub code scanning
cluster-guardian analyze -o junit    --output-file report.xml      # GitLab / Jenkins test reports
```

SARIF findings carry count-normalized fingerprints, so re-runs deduplicate
in code scanning; in JUnit output warnings and criticals render as failed
tests while info findings stay visible as passing cases. Both formats also
work with `lint`, so PR annotations cover manifests pre-deploy:

```sh
helm template ./chart | cluster-guardian lint - -o sarif --output-file results.sarif
```

### Cluster documentation (deprecated)

The `docs` command (Markdown documentation of workloads, services, and
ingresses) is deprecated and will be removed in the release after next —
cluster documentation is out of scope for an analyzer. See
[#52](https://github.com/cluster-guardian/cluster-guardian/issues/52).

### REST API

```sh
cluster-guardian serve --listen 127.0.0.1:8080
```

The server exposes the analysis as JSON. It renders no HTML: the web UI is a
separate application, [cluster-guardian-ui](https://github.com/cluster-guardian/cluster-guardian-ui),
which consumes these endpoints. For a report you can open in a browser without
running anything, use `analyze -o html` — a single self-contained file with
search and filtering that works offline.

Each analysis run is recorded in a history, which backs the trend and
run-over-run diff endpoints. Pass `--history-dir /path` to persist history
across restarts (use a PVC when running in-cluster); without it history is
in-memory only. `--history-limit` caps the number of retained runs
(default 100).

| Endpoint                   | Description                                      |
|----------------------------|--------------------------------------------------|
| `GET /`                    | Index of available endpoints                     |
| `GET /api/report`          | Report as JSON (`?refresh=true` bypasses cache)  |
| `GET /api/report/markdown` | Report as Markdown                               |
| `GET /api/history`         | History index: time + severity counts per run    |
| `GET /api/history/diff`    | New and resolved findings vs the previous run    |
| `GET /metrics`             | Prometheus metrics: findings, score, run stats   |
| `GET /healthz`             | Liveness probe                                   |

In fleet mode the per-cluster equivalents are served under
`/api/clusters/{name}/…`.

To develop against the API without a cluster, serve canned reports:

```sh
cluster-guardian serve --fixture testdata/fixtures/run1.json \
                       --fixture testdata/fixtures/run2.json
```

### Team ownership

Map namespaces to teams and every output becomes team-aware. Ownership comes
from a `team` namespace label (`--team-label` to change the key) and/or a
teams file:

```yaml
# teams.yaml
teams:
  payments-team: [payments, checkout]
  platform-team:
    namespaces: [monitoring]
    notifyUrl: https://hooks.slack.com/services/...   # this team's webhook
```

```sh
cluster-guardian analyze --teams-file teams.yaml --team payments-team   # one team's report
```

Namespace sections carry a `team` field in JSON, the API exposes a team
filter next to the namespace dropdown, and webhook notifications route per
team — each team only hears about new findings in its own namespaces, while
the global `--notify-url` still receives everything. Helm: `teams` and
`teamLabel` values (the mapping ships as a ConfigMap).

### Scheduled reports and PDF export

Every report renders to PDF — pure Go, offline, no headless browser:

```sh
cluster-guardian report -o pdf --output-file report.pdf     # report = alias for analyze
cluster-guardian lint ./deploy -o pdf --output-file lint.pdf
```

Serve mode delivers reports on a schedule — the artifact leadership actually
reads. In fleet mode it's a digest (per-cluster grade, score delta since the
previous scan, new criticals); single-cluster mode attaches the full report:

```sh
cluster-guardian serve \
  --report-schedule "0 8 * * MON" \
  --report-email-to platform-team@example.com \
  --report-smtp-host smtp.example.com:587 --report-smtp-from guardian@example.com \
  --report-format pdf                # or html
```

SMTP credentials come from `SMTP_USERNAME`/`SMTP_PASSWORD`. Other targets:
`--report-webhook-url` (POSTs the report/digest JSON) and `--report-dir`
(writes files for pull-based workflows); targets combine, and one failing
never blocks the others. Deliveries surface in logs and in `/metrics`
(`cluster_guardian_report_deliveries_total` / `_delivery_errors_total`).
Helm: `reports.*` values, with `reports.smtpSecret` for credentials.

### Webhook notifications

Serve mode can notify a webhook when a run surfaces findings that were not
present in the previous run — repeats stay silent, so alerts don't fatigue.
The diff engine normalizes counts ("5 Pods" → "3 Pods" is not new):

```sh
cluster-guardian serve \
  --notify-url https://hooks.slack.com/services/... \
  --notify-format slack \            # or json for a generic payload
  --notify-min-severity critical     # info, warning, or critical
```

In fleet mode each cluster is diffed and notified independently. Helm:
`notifications.url`, `notifications.format`, `notifications.minSeverity`.

### Prometheus metrics

`serve` exposes the guardian's own metrics at `/metrics`, rendered from the
cached report (scraping never triggers an analysis): findings as
`cluster_guardian_findings{cluster,section,namespace,severity}`, the health
score, and per-run timestamp, duration and error counters — in fleet mode one
series set per registered cluster. Alert on them with your existing stack:

```yaml
- alert: ClusterGuardianCriticalFindings
  expr: sum by (cluster) (cluster_guardian_findings{severity="critical"}) > 0
- alert: ClusterGuardianScansStale
  expr: time() - cluster_guardian_last_run_timestamp_seconds > 3600
```

With the Helm chart, `--set serviceMonitor.enabled=true` creates a
ServiceMonitor (requires the Prometheus Operator).

### Fleet mode: hosted multi-cluster scorecard

Run cluster-guardian in a cluster and let it scan your whole fleet on a
schedule, SecurityScorecard-style — every cluster gets a 0–100 health score
and an A–F grade:

```sh
cluster-guardian serve --fleet --fleet-interval 5m --history-dir /data
```

The `cluster add` helper registers a cluster in one step — it provisions a
read-only ServiceAccount (with a ClusterRole scoped to exactly the resources
cluster-guardian reads) and a long-lived token on the target cluster, then
stores the connection details on the hub:

```sh
cluster-guardian cluster add prod --remote-context prod-admin
```

Re-running it refreshes the ClusterRole rules and rotates the stored
credentials. Use `--server` when the kubeconfig URL is not reachable from
inside the hub cluster.

Alternatively, register clusters declaratively: create a Secret in the
tool's namespace labeled `cluster-guardian.io/secret-type: cluster` with
`name`, `server`, and a `config` JSON holding a bearer token for a read-only
ServiceAccount on the target cluster:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: cluster-prod
  labels:
    cluster-guardian.io/secret-type: cluster
stringData:
  name: prod
  server: https://prod.example.com:6443
  config: |
    {"bearerToken": "<token>", "tlsClientConfig": {"caData": "<base64 CA>"}}
```

The local cluster is always included automatically.

`GET /api/clusters` returns each cluster's grade, score, counts, last-scan time
and any scan error; the per-cluster routes are
`/api/clusters/{name}/report`, `/api/clusters/{name}/history` (+`/diff`).

One unreachable cluster never stalls the rest: scans run concurrently with a
per-cluster timeout, and failures surface as an `error` field on that
cluster's status rather than removing it from the list. **Security note:** a
fleet instance holds credentials for every registered cluster — restrict its
namespace with RBAC and NetworkPolicies, and grant target ServiceAccounts only
view-level access.

### CI/CD integration

Use `--fail-on` to gate pipelines on findings:

```sh
cluster-guardian analyze --fail-on critical   # exit code 3 on critical findings
cluster-guardian analyze --fail-on warning    # exit code 2 on warnings or worse
cluster-guardian analyze --fail-below 80      # exit code 2 if the health score drops below 80
```

Every report carries a 0–100 health score and A–F grade (severity-weighted),
shown in the terminal header and the JSON `summary`.

## Checks

| Area         | What is checked                                                                                     |
|--------------|-----------------------------------------------------------------------------------------------------|
| Workloads    | Missing resource requests/limits, `:latest` tags, missing probes, single replicas, missing HPAs, missing or drain-blocking PodDisruptionBudgets, missing topology spread |
| Health       | CrashLoopBackOff, ImagePullBackOff, Pending pods, OOMKilled containers, restart storms               |
| Security     | Root/privileged containers, dangerous capabilities, host network/PID/IPC, missing seccomp profiles, writable root filesystems, ServiceAccount token automounting, Secrets in env vars, namespaces without PSS enforcement labels or NetworkPolicies, wildcard ClusterRoles, cluster-admin ServiceAccounts; findings are tagged with Pod Security Standards controls and summarized per framework |
| Policy       | Kyverno PolicyReport violations per namespace, Gatekeeper constraint violations, engines installed with zero policies, and namespaces no admission policy covers |
| Nodes        | NotReady nodes, memory/disk/PID pressure, cordoned-and-forgotten nodes, kubelet version skew and mixed versions, single-zone pools, untainted control planes, nodes near allocatable limits |
| Monitoring   | Prometheus/Alertmanager presence, ServiceMonitor scrape coverage, missing alerts for Redis, PostgreSQL, Kafka, and other stateful services |
| Hygiene      | Unused ConfigMaps and Secrets, unmounted or unbound PVCs, Services matching no pods, Ingress paths and HTTPRoute backends to missing Services, HPAs targeting missing workloads, PDBs selecting nothing |
| Certificates | Ingress and Gateway TLS certificates expiring within 30 days (critical under 7), Ingresses and Gateway listeners referencing missing TLS secrets, cert-manager Certificates not Ready |
| Deprecations | Objects still written with deprecated API versions (from managedFields / last-applied), critical when the API is removed in the next minor version or earlier |
| GitOps       | Argo CD Application health and sync status, Flux Kustomization/HelmRelease readiness                 |
| Optimization | CPU and memory overprovisioning, estimated from requests vs. actual usage in Prometheus; per-workload rightsizing recommendations with concrete request values, patch snippets and optional savings estimates |

System namespaces (`kube-system`, etc.) are skipped by default; include them with `--include-system`.

## Requirements

- Kubernetes 1.25+ with read-only access (a `view`-like ClusterRole covers most checks; RBAC checks additionally need read access to ClusterRoles and ClusterRoleBindings, and Secret hygiene checks need list access to Secrets — only names and types are read, secret data is never held. Checks whose resources are not readable are skipped silently.)
- Optional: Prometheus for usage-based optimization checks
- Optional: Prometheus Operator, Argo CD, Flux, or cert-manager CRDs — detected automatically

## License

MIT — see [LICENSE](LICENSE).
