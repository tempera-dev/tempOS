# Model Router

`beater-os-model-router` is the first metadata-only model routing slice. It
does not call providers, read credentials, open sockets, or trust model output.
It decides whether a proposed model call can use a trusted route before prompt
data crosses a provider boundary.

## Contract

Inputs:

- trusted `ModelRouteCatalog` entries,
- the session `ModelPolicy`,
- canonical call purpose (`planner`, `verifier`, `executor`, and related
  classes),
- kernel/provenance-derived `DataClass` and taint labels,
- static route retention/locality/cost/latency/context metadata,
- request cost, latency, local-only, tools, multimodal, and retention
  constraints.

Output:

- `ModelRouteDecision` with `result: allowed` and one selected route, or
- `ModelRouteDecision` with `result: denied` and per-route rejection reasons.

The decision carries route id, provider, model/version, locality, retention,
estimated cents, p95 latency, context/output caps, policy summary, and a stable
decision hash. The runtime and HTTP boundaries journal compact
`ModelRouteDecided` evidence before any future model-call adapter sends prompt
data. The journal record stores hashes of the routed request, trusted catalog,
selected route metadata, effective session policy, and full decision payload so
offline audit can compare replay inputs without embedding prompt data, provider
credentials, or full catalog bodies in the journal. The daemon store derives
those hashes from the typed router inputs at the journal boundary, rather than
trusting caller-supplied compact evidence fields. The runtime schema mirror is
[`contracts/schema/model-route-decision.schema.json`](../contracts/schema/model-route-decision.schema.json);
the HTTP/runtime wrapper contract is
[`contracts/schema/model-route-runtime.schema.json`](../contracts/schema/model-route-runtime.schema.json).

`beater-os-runtime` exposes the same selector as a runtime boundary:

```text
POST /v1/sessions/<session-id>/model-routes/choose
```

The HTTP server is started with a trusted `--model-route-catalog` file supplied
by local configuration or generated client code; model-authored text must not
mint or modify route metadata. The HTTP body carries a top-level `session_id`
and one proposed call `request`. The route session id must match both the
top-level `session_id` and `request.session_id`.

Runtime flow:

1. `beater-osd-http` parses
   `POST /v1/sessions/<id>/model-routes/choose`, requires a body, and
   deserializes a strict HTTP request containing `session_id` and one
   `ModelRouteRequest`.
2. The HTTP adapter rejects requests where the path `<id>` and
   either body `session_id` differs.
3. The HTTP adapter combines the daemon-started trusted route catalog with the
   proposed call shape, then calls `AgentRuntime::choose_model_route`.
4. `AgentRuntime::choose_model_route` projects the daemon session and takes
   `ModelPolicy` plus `budget.max_model_cents` from that projection as the
   authoritative policy and cost inputs.
5. The runtime journals compact `ModelRouteDecided` evidence and returns
   `RuntimeModelRouteOutcome`, containing the `ModelRouteDecision`, journal
   seq/hash, and the session projection summary.

This endpoint performs no provider I/O: it does not call providers, send prompt
data, read provider credentials, create grants, or write receipts.
It also refuses fresh route-decision evidence while unresolved execution leases
make recovery state ambiguous.

## Invariants

- Trusted route metadata comes from configuration/fixtures, not from agent text.
- Catalog routes are enabled by default; set `enabled: false` explicitly to
  keep a trusted route configured but unavailable for selection.
- Route-level `max_data_class` is optional. Omitting it means the route adds no
  extra route-local ceiling beyond the session `ModelPolicy`.
- `ModelPolicy.allowed_routes` is enforced when populated.
- `ModelPolicy.local_only` excludes public/private cloud routes.
- `ModelPolicy.max_data_class` is enforced using an explicit sensitivity
  lattice, not `DataClass` enum declaration order. Its default ceiling is
  `internal`; an unlimited route policy must be explicit.
- Retention, purpose, context size, output size, cost, latency, tools, and
  multimodal requirements are fail-closed filters.
- Arithmetic overflow in token and cost estimates is treated as an unavailable
  route, not as a free or unbounded route.
- Planner and verifier routes can be selected independently.
- The router does not issue grants, admit side effects, or make model output
  authoritative.

## Release Eval Fixtures

The lightweight K11 release fixture is
[`scripts/run-beater-osd-http-model-router-smoke.py`](../scripts/run-beater-osd-http-model-router-smoke.py).
It exercises the loopback runtime boundary with the daemon-projected
`ModelPolicy` and a server-configured route catalog:

| Fixture | Expected result |
| --- | --- |
| `k11_model_route_internal_allowed_journaled` | An internal planner request selects `cloud/planner`, records the daemon policy ceiling, and returns `ModelRouteDecided` journal evidence. |
| `k11_model_route_secret_data_denied_no_selected_route` | The same planner request with `data_classes: ["secret"]` returns a denied decision, no selected route, a `data_class_too_high` rejection for `cloud/planner`, and journal evidence for the denial. |

This fixture is metadata-only: it proves prompt data is stopped before route
selection would cross a provider boundary. It intentionally does not claim live
provider-call receipt coverage.

## Remaining Integration

This slice closes the metadata-selection gap and exposes it through the runtime
HTTP boundary, but it is not yet a live model call service. Future work should
emit model-call metadata receipts and bind prompt redaction/provenance to those
receipts.
