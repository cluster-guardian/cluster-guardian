# e2e fixtures

Canned reports served by `cluster-guardian serve --fixture` in the Playwright
tests (and handy for demos/screenshots). Generated with `lint` over synthetic
manifests — two runs so the trend chart and run-over-run diff light up:

```sh
cluster-guardian lint app.yaml  --cluster-name demo --teams-file teams.yaml -o json --output-file run1.json
cluster-guardian lint app.yaml app2.yaml --cluster-name demo --teams-file teams.yaml -o json --output-file run2.json
```

The manifests define namespace `shop` (team `shop-team`, one deliberately
broken deployment: `:latest`, privileged, no requests/probes) and, in run2,
namespace `payments` (team `payments-team`). Regenerate whenever the report
schema changes shape.
