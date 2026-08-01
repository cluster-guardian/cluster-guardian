# Contributing to Cluster Guardian

Thanks for your interest in contributing!

## Development setup

You need Go (version pinned in [`.go-version`](.go-version)) and access to a Kubernetes cluster for manual testing — [kind](https://kind.sigs.k8s.io/) or minikube work fine.

```sh
git clone https://github.com/cluster-guardian/cluster-guardian.git
cd cluster-guardian
make build          # build ./cluster-guardian
make test           # go test -race ./...
make lint           # golangci-lint run (install: https://golangci-lint.run/welcome/install/)
```

Run against your current kubeconfig context:

```sh
./cluster-guardian analyze --verbose
```

No cluster? Serve canned reports and exercise the API:

```sh
./cluster-guardian serve --fixture testdata/fixtures/run1.json \
                         --fixture testdata/fixtures/run2.json
curl -s localhost:8080/api/report | jq .summary
```

## Scope of this repository

This repo is the analysis engine, REST API and CLI. Two siblings live in the
same org:

- [cluster-guardian-ui](https://github.com/cluster-guardian/cluster-guardian-ui) — the web UI
- [cluster-guardian-helm](https://github.com/cluster-guardian/cluster-guardian-helm) — Helm charts

Because the UI ships separately, **`/api/*` is a published contract**. Prefer
additive changes; if you must change the report schema, regenerate
`testdata/fixtures/*.json` and flag it in your PR so the UI repo can follow.

## Making changes

1. Fork the repo and create a branch from `main`.
2. Make your change. Checks live in `internal/checks` and are pure functions over a `kube.Snapshot` — add tests with synthetic snapshots (see `internal/checks/checks_test.go`); no cluster or mocks needed.
3. Ensure `make test` and `make lint` pass.
4. Open a pull request — the template will guide you. Reference any related issue.

Keep pull requests focused: one logical change per PR is much easier to review.

## Reporting bugs and requesting features

Use the [issue templates](https://github.com/cluster-guardian/cluster-guardian/issues/new/choose). For security vulnerabilities, see [SECURITY.md](SECURITY.md) — please do not open a public issue.
