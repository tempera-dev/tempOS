# beaterOS Repository Map and Runtime Frontier

This map is the working dependency map for runtime-first development.
Use it when planning PR scope, writing migration evidence, and validating code
review boundaries.

## 1) Runtime and authority foundation (must remain healthy first)

- `crates/beater-os-core`
  - Contracts (`AgentSession`, `CapabilityGrant`, `ActionManifest`,
    `PolicyDecision`, `CapabilityReceipt`, `MemoryRecord`, `PaymentMandate`).
  - Policy decision and journal semantics.
- `crates/beater-os-session`
  - Session model and lifecycle semantics used by all upper layers.
- `crates/beater-osd`
  - Runtime daemon store, admission boundary, projection, receipt append path.
  - Durable session budget replay for tool-call and wall-clock runtime quotas.
  - Daemon-recorded human approval evidence via `Store::record_approval`.
    `ApprovalRecorded` events are action-bound admission evidence, bound to
    `action_id`, `manifest_hash`, `grant_id`, `reviewer_id`, `approved_at`,
    and `policy_version`, and can unblock later re-admission without
    fabricating a receipt or proving any side effect occurred.
  - Durable execution leases between `Allowed` policy decisions and spawned
    side-effecting tools; unresolved open leases are projected as recovery
    blockers and prevent blind replay, new admission, and session resume after
    crash windows until explicit operator reconciliation records
    `outcome_unknown` without fabricating a receipt.
  - Local loopback control-plane API for health and token-gated session
    projection.
  - Store-owned claimable execution-action projection so scheduler workers get
    manifest hash, decision id, target, budget, grants, and pinned tool
    version/digest from the daemon authority instead of re-deriving lossy state.
  - Store-owned memory context selection loads and verifies the journal under
    the session lock, projects `MemoryWritten` records through
    `beater-os-memory`, and returns selected/rejected context with journal root
    evidence.
  - Canonical proof of authority writes (`PolicyEngine` is only invocation point
    for admission decisions).
- `crates/beater-osd-http`
  - Loopback HTTP control-plane binary over `beater-osd` and the tool gateway,
    including token-gated local shell execution, hosted runtime bundle
    submission, metadata-only model-route selection, action-bound approval
    recording, and scheduler execution-lease claim/completion routes.
  - Worker preflight route returns a side-effect-free scheduler plan before
    execution: wait on a live lease, recover an expired lease, dispatch a
    matching runnable action, idle, or report that runnable work does not match
    the worker recipe.
  - Session projection responses expose execution-lease recovery blockers and
    split open leases into live versus expired-recoverable ids so operators and
    schedulers can distinguish ordinary idle state from runnable pending work,
    wait-required in-flight work, paused admission, and recoverable side-effect
    debt without exporting the full journal.
  - Scheduler claim routes derive execution leases from journaled manifest and
    policy decision state using expected manifest/decision/tool
    compare-and-set fields, resolve pinned tool identity through the
    daemon-owned registry, and return the derived target/grants/budget lease
    authority; bounded heartbeat renewal can extend a still-live open lease
    only within the original action wall budget, completion requires the exact
    open lease id before appending a receipt, and reconciliation can close an
    expired open lease as `outcome_unknown` without fabricating success or
    no-side-effect evidence.
  - Local-shell execution can dispatch an existing scheduler-runnable pending
    action only when the journal projection proves it has no receipt, open
    execution lease, or outcome-unknown reconciliation; the daemon execution
    lease remains the atomic worker claim.
  - `POST /v1/sessions/<id>/model-routes/choose` uses the server-started
    `--model-route-catalog` as trusted route metadata, accepts only `session_id`
    plus a proposed call request in the HTTP body, rejects path/body session
    mismatches, and returns `RuntimeModelRouteOutcome` without provider I/O.
  - `POST /v1/sessions/<id>/memory/context/select` accepts
    `RuntimeMemoryContextRequest`, rejects path/body session mismatches, and
    returns bounded, source-anchored `RuntimeMemoryContextOutcome` context
    without creating grants, approvals, model routes, receipts, or trusted
    instructions.
  - `POST /v1/sessions/<id>/memory/records` records one non-authoritative
    `MemoryWritten` event through the daemon boundary, requiring path/body
    session match, running-session state, session memory-scope compatibility,
    and journal-validated source-event anchoring.
- `crates/beaterosctl`
  - Operator CLI for session/grant/manifests/receipts, including trace
    projection/export of daemon-recorded approvals.

## 2) Service planes (runtime depends on these contracts)

- `crates/beater-os-sandbox`
  - Tool and action execution paths with path confinement, environment
    normalization, and side-effect evidence constraints.
- `crates/beater-os-memory`
  - Memory and provenance surface on top of session/journal evidence.
  - Policy-safe context selection must use active, non-expired records whose
    source event/digest provenance is anchored in projected journal records,
    enforce access policy, explicit sensitivity allowlists, denied source
    taint/data classes, optional trusted-writer filters, and bounded output, and
    surface memory only as non-authoritative context for models/tools.
- `crates/beater-os-model-router`
  - Model route selection over `ModelPolicy`, data-class ceilings, route
    locality, provider retention, purpose, latency, and token-cost metadata.
  - Service-plane adapter only: it issues no grants, does not make model output
    authoritative, and does not weaken daemon admission, journal, receipt, or
    audit boundaries.
- `crates/beater-os-tool-registry`
  - Tool schema registry, tool risk metadata, and execution manifest binding.
- `crates/beater-os-tool-gateway`
  - Registered-tool resolution, kernel-derived manifest construction, daemon
    admission, durable execution lease acquisition, sandbox execution, and
    receipt append for local shell tools.
  - Lease-bound local-shell worker execution for already-admitted actions:
    re-check active grants, registry pin, admitted input digest, confinement,
    and observed side effects before completing the open daemon lease. The
    claimed-worker path snapshots the open lease under the daemon session lock,
    releases the lock while sandbox execution runs, then reacquires it only for
    exact lease-id receipt completion so local lifecycle controls are not
    serialized behind blocking tool work.
- `crates/beater-os-mcp`
  - MCP stdio adoption gateway exposing exactly one model-facing tool,
    `tempos.local_shell`, over the existing daemon admission, tool gateway,
    sandbox, execution-lease, receipt, bounded-output, and compact-summary path.
  - The crate is a transport adapter, not a new authority boundary: it creates
    no grants, forwards no daemon/MCP/provider/shell credentials, canonicalizes
    cwd before admission, and requires explicit existing grant ids per call.
- `crates/beater-os-runtime`
  - Typed agent runtime loop over the daemon store: session bootstrap, bounded
    grant issuance, sequential step admission, and no-side-effect observation
    receipts.
  - Runtime model-route selection projects the daemon session, applies the
    daemon-projected session `ModelPolicy` to trusted
    `beater-os-model-router` route metadata, and returns
    `RuntimeModelRouteOutcome` route decision evidence after journaling
    `ModelRouteDecided`; it performs no provider I/O.
  - Runtime memory context selection enforces running-session state and
    `AgentSession.memory_scope`, delegates source-anchored selection to the
    daemon store, and returns `RuntimeMemoryContextOutcome` without mutating the
    journal.
  - Runtime admission consumes daemon-projected approvals recorded through
    `Store::record_approval`, so action-bound approval evidence can unblock
    re-admission without bypassing policy or creating receipts.
  - Bounded `beater-os-runtime-worker supervise-local-shell` service binary that
    repeatedly runs the supervised local-shell cycle without direct store
    mutation authority: expired open leases are reconciled as `outcome_unknown`,
    live leases block, and runnable work is claimed/completed through daemon
    execution leases.
  - Typed local-shell worker-once API that registers the exact command digest,
    selects a daemon-claimable admitted action, claims a durable execution
    lease, optionally emits bounded heartbeat renewals while the sandboxed
    command is still running, executes through the gateway, and returns the
    completed receipt plus projection summary.
  - Deterministic step replay evidence anchored to proposal, decision, receipt,
    journal-root, and receipt-root hashes.
  - Bundle projection summaries include pending/runnable action queues, open
    execution-lease blockers split into live versus expired-recoverable ids,
    admission blockers, and reconciliation counts for scheduler/operator
    visibility.
  - Local-shell worker preflight shares the same command digest and
    claimable-action matching rules as execution, but does not claim, recover,
    execute, or append receipts.
  - Service-facing `RuntimeBundle` contract used by daemon HTTP adapters without
    exposing direct store mutation APIs.
- `crates/beater-os-audit`
  - Trace/receipt validation, integrity reporting, read-only verification
    tooling, and full trace/action bundle serialization.
  - Independent execution-lease lifecycle audit gate derives issued, heartbeat,
    receipt-closed, reconciliation-closed, and still-open lease state from the
    journal rather than trusting daemon or worker self-report.
  - `verify-trace` checks exported full trace bundles offline without importing
    them into daemon state, including execution-lease lifecycle evidence,
    session-transition evidence, capability revocation evidence, compact
    model-route decision evidence, memory write evidence, and scenario/incident
    annotations.

## 3) Infrastructure and hardening gates

- `scripts/collect-bare-metal-host-profile.py`
  - Deterministic host snapshot capture.
- `scripts/check-bare-metal-readiness.py`
  - Manifest + host compatibility + migration-phase inference.
- `scripts/run-bare-metal-e2e-matrix.py`
  - Multi-host deterministic migration assertions.
- `scripts/run-beater-osd-runtime-smoke.py`
  - Runtime first smoke proof.
- `scripts/run-beater-os-runtime-smoke.py`
  - Hosted agent runtime bundle smoke proof over `beater-os-runtime`.
- `scripts/run-beater-os-runtime-worker-smoke.py`
  - Typed runtime worker-once smoke proving an admitted local-shell action is
    selected, claimed, executed through the gateway, completed with a receipt,
    and removed from the runnable queue.
- `scripts/run-beater-os-runtime-worker-recovery-smoke.py`
  - Typed runtime recovery smoke proving an expired worker lease is reconciled
    as `outcome_unknown`, clears the recovery blocker, and does not fabricate a
    receipt or rerun the action.
- `scripts/run-beater-os-runtime-worker-loop-smoke.py`
  - Bounded runtime worker-loop smoke proving multiple admitted local-shell
    actions are repeatedly selected, claimed, executed, receipted, and drained
    without treating `Allowed` as direct execution authority.
- `scripts/run-beater-os-runtime-supervised-worker-smoke.py`
  - Supervised runtime worker-cycle smoke proving expired lost leases are
    reconciled as `outcome_unknown` before later admitted work is dispatched,
    while live leases block without recovery and reconciled actions are not
    retried.
- `scripts/run-beater-os-runtime-supervisor-service-smoke.py`
  - Runtime worker supervisor service smoke proving the standalone
    `beater-os-runtime-worker` binary can recover expired lease debt and drain
    later runnable local-shell work through the same daemon lease/receipt path.
- `scripts/run-beater-osd-http-execute-smoke.py`
  - Token-gated daemon HTTP execution smoke over the local shell gateway.
- `scripts/run-beater-osd-http-pending-worker-smoke.py`
  - Token-gated HTTP proof that a pre-admitted runnable action dispatches
    through the existing-action path, claims a daemon lease, executes via the
    gateway, completes a receipt, and drains from the runnable queue.
- `scripts/run-beater-osd-http-worker-loop-smoke.py`
  - Token-gated HTTP proof that an external runner can drive the bounded
    runtime local-shell worker loop over multiple admitted actions without
    receiving direct store authority.
- `scripts/run-beater-osd-http-supervised-worker-smoke.py`
  - Token-gated HTTP proof that opt-in supervised recovery blocks on live
    leases, exposes live versus expired-recoverable open lease state through
    session projection and worker preflight plans, reconciles expired lost
    leases as `outcome_unknown`, and dispatches later admitted work through a
    short initial runtime worker lease that emits heartbeat evidence without
    retrying the reconciled action.
- `scripts/run-beater-osd-http-claims-smoke.py`
  - Token-gated daemon HTTP scheduler claim/complete smoke covering pinned
    tool compare-and-set refusal, bounded live-lease heartbeat renewal, exact
    lease-id completion after original short expiry, live-lease reconcile
    refusal, expired-lease heartbeat refusal, expired-lease `outcome_unknown`
    reconciliation, and journal verification.
- `scripts/run-beater-os-mcp-stdio-gateway-smoke.py`
  - MCP stdio proof that an MCP-speaking client can initialize, list the single
    `tempos.local_shell` tool, call it through daemon admission and the
    local-shell gateway path, receive bounded model-visible output, and
    leave a durable receipt-backed side effect.
- `scripts/local-e2e.py`
  - Aggregate gate when doing full lane validation locally.

## 4) Documents that shape architecture boundaries

- `final.md`
  - Product and architecture intent. **Do not shorten or weaken.**
- `docs/architecture-runtime-to-metal-path.md`
  - Execution contract for moving from runtime into optional metal lanes.
- `docs/mcp-stdio-gateway.md`
  - Operator-facing contract for the first MCP stdio adoption gateway: one
    local-shell tool, daemon admission, sandbox execution, durable leases,
    receipts, bounded output, no token passthrough, and model-visible
    summaries.
- `docs/memory-context.md`
  - Policy-facing memory context service surface: active/non-expired,
    source-record anchored, access-policy filtered, explicit sensitivity
    allowlist, denied source taint/data classes, optional trusted-writer
    filter, bounded, and non-authoritative.
- `docs/engineering/bare-metal-readiness-manifest.json`
  - Source-of-truth lane graph, profiles, and workload classes.
- `docs/engineering/bare-metal-readiness.md`
  - Readiness semantics and migration terminology.
- `docs/engineering/bare-metal-e2e-matrix.json`
  - Deterministic phase and lane matrix fixtures.
- `contracts/schema/worker-preflight-plan.schema.json`
  - Model/runner-facing schema for the side-effect-free scheduler plan that
    precedes lease claims and local-shell worker dispatch.
- `contracts/schema/model-route-decision.schema.json`
  - Journalable model-router decision schema for metadata-only route selection
    before prompt data crosses a provider boundary.
- `docs/implementation-backlog.md`
  - Slice assignments, sequencing, and ownership.
- `docs/governance/review-checklist.md`
  - Mandatory reviewer gates.

## 5) Operating rulebook

1. Keep runtime contracts green before adding non-runtime work.
2. Don’t widen the migration frontier without:
   - manifest entry updates,
   - matrix/evidence updates,
   - and a non-author reviewer sign-off.
3. No claim can remove the hosted control plane contract without a staged
   replacement with equivalent evidence.
