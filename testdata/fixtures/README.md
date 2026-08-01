# Report fixtures

Canned reports served by `cluster-guardian serve --fixture`, which runs the
REST API without a cluster or a kubeconfig:

```sh
cluster-guardian serve --fixture testdata/fixtures/run1.json \
                       --fixture testdata/fixtures/run2.json \
                       --listen 127.0.0.1:8099
```

These are a **published part of the API contract**, not just test data:
[cluster-guardian-ui](https://github.com/cluster-guardian/cluster-guardian-ui)
develops and tests against this fixture server, so a change to the report
schema means regenerating them and coordinating with that repo.

Two runs are provided so history and the run-over-run diff have something to
return. Regenerate with `lint` over the synthetic manifests here:

```sh
cluster-guardian lint app.yaml --cluster-name demo --teams-file teams.yaml \
  -o json --output-file run1.json
cluster-guardian lint app.yaml app2.yaml --cluster-name demo --teams-file teams.yaml \
  -o json --output-file run2.json
```

The manifests define namespace `shop` (team `shop-team`, with one deliberately
broken deployment: `:latest`, privileged, no requests or probes) and, in run2,
namespace `payments` (team `payments-team`).
