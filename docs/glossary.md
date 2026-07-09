# beaterOS glossary

Shared vocabulary so any reviewer — including one seeing a component for the
first time — can reason about the code. Terms are grounded in [`final.md`](../final.md);
section references point to the authoritative definition.

## Core contracts (final.md §12)

- **AgentSession** — the container for one goal-directed run: intent, scope,
  policy profile, initial capabilities, budgets, model policy, memory scope, and
  a journal root. A session cannot execute actions without at least one grant.
- **CapabilityGrant** — the central authority object: explicit, scoped
  permission bound to a holder, session, resource, and action set, with
  constraints (time, budget, data-sensitivity), delegation rule, approval rule,
  and a revocation handle. Cannot be broadened by the holder; delegated grants
  are equal-or-narrower.
- **ActionManifest** — a pre-declaration of a proposed side effect or
  observation (tool, target, input digest, expected side effects, risk class,
  data classes, idempotency key, compensation plan). Submitted *before*
  execution so policy can inspect it.
- **PolicyDecision** — the deterministic admission result for a manifest:
  `Allowed`, `Denied`, `NeedsApproval`, `NeedsSimulation`, or
  `NeedsNarrowedGrant`, plus matched rules and an explanation. Recorded before
  execution.
- **ApprovalEvidence** — daemon-recorded human approval for one proposed action.
  It is appended through `Store::record_approval` as `ApprovalRecorded` and is
  bound to `action_id`, `manifest_hash`, `grant_id`, `reviewer_id`,
  `approved_at`, and `policy_version` (plus a `review_id` event identifier).
  It can satisfy a later admission check for the same action/manifest/grant
  without inventing a receipt or asserting that any side effect occurred.
- **CapabilityReceipt** — the tamper-evident record of what actually happened:
  input/output digests, side-effect summary, external ids, and a hash link to
  the previous receipt. Append-only.
- **MemoryRecord** — knowledge with provenance: source event/digest, writer,
  time, confidence, sensitivity, expiry, and access policy. Rebuildable and
  redactable. When selected into model context it remains non-authoritative
  context, not a grant, approval, receipt, or trusted instruction.
- **PaymentMandate** — bounded economic authority: who may spend, rail, asset,
  max amount, counterparty policy, purpose, approval threshold, idempotency,
  receipt requirement, and allowed payment adapters/envelope formats.
- **PaymentIntent** — a chain-neutral projection of a proposed payment carried
  by an action manifest: mandate id, rail, adapter, asset, amount, counterparty
  binding, purpose, idempotency key, envelope format, and envelope hash.
- **ScenarioManifest** — a testable task specification: goal, environment,
  fixtures, allowed tools, forbidden actions, oracle, success criteria, risk
  traps, budget, and expected trace properties.

## Authority and safety

- **Ambient authority** — power a principal holds implicitly without an explicit
  grant. beaterOS's central goal is to eliminate it (final.md §13.2).
- **Attenuation** — deriving a *narrower* capability from a broader one when
  delegating. Delegation may only attenuate, never amplify (§13.3).
- **Taint / provenance labels** — source labels on information (e.g.
  `trusted_user_instruction`, `untrusted_web`, `secret`, `customer_data`) that
  policy uses to decide what may flow where (§13.4).
- **Prompt injection** — untrusted content attempting to be treated as trusted
  instruction. Defended outside the model, not by prompting (§13.5).
- **Fail closed** — on missing/expired/revoked authority or ambiguity, deny by
  default rather than allow.
- **Risk class** — the severity tier of an action. May be *raised* by policy,
  never *lowered* by the agent (§26).
- **Receipt / journal** — journal records intent *before* side effects; receipts
  record outcomes *after*. Together they form the causal chain (§4.5, §10.4).
- **Memory context selection** — the policy-gated projection step that chooses
  which memories may be shown to a model or tool. Selection must use only active
  journal-projected records, reject expired records, verify source event/digest
  provenance, enforce access policy, and filter by taint/data-class ceilings.
  Confidence and relevance can rank memories, but cannot make them authoritative.
- **Approval / receipt boundary** — approvals are pre-execution admission
  evidence and receipts are post-execution outcome evidence. A durable approval
  may unblock re-admission after `NeedsApproval`; it must never be presented as
  proof of execution, success, no-side-effect, or settlement.
- **Execution lease** — durable authority between an `Allowed` policy decision
  and the side-effecting tool process. An unresolved lease means the journal
  proves execution may have crossed the side-effect boundary, but no receipt
  proves the outcome. Expiry ends executable authority; it does not prove the
  side effect did not happen, so unresolved leases are recovery blockers for
  blind retry, new admission, and session resume until reconciled.
- **Execution lease reconciliation** — an operator-authored journal event that
  closes an expired unresolved execution lease as `outcome_unknown`. It is not a
  receipt, does not claim success or absence of side effects, and does not make
  the original action executable again.

## Runtime and services (final.md §9, §10)

- **Agent kernel (`beater-osd`)** — the small trusted core: sessions,
  capability issuance, policy evaluation, action admission, journal writes,
  receipt verification, revocation, audit, eval gates.
- **Service fabric** — least-privileged system services (tool gateway, browser,
  sandbox, memory, model router, observability, eval, human review, payment,
  registry), each mediated by capabilities.
- **Sandbox lane** — an isolated execution context (pure-function, WASI,
  container, browser, VM, remote-tool). Every lane emits receipts.
- **Tool gateway** — normalizes MCP/A2A/OpenAPI/CLI/local tools into a policed
  registry; enforces grants, redaction, and egress limits at the boundary.
- **Model router** — selects model/provider routes under `ModelPolicy`,
  data-class, retention, budget, purpose, and locality constraints. It is a
  service-fabric component, not a root of trust; model outputs remain untrusted
  proposals until admitted by policy and backed by journal or receipt evidence.
- **MCP stdio gateway** — the local model-facing stdio adapter for MCP clients.
  It exposes `tempos.local_shell` but does not own authority: every call must
  reuse existing session/grant state and flow through daemon admission, sandbox
  execution, execution leases, and receipts.
- **TCB (trusted computing base)** — the minimal set that must be trusted:
  capability service, policy engine, journal verifier, secret broker, sandbox
  launcher (§20.2). Everything else is less trusted.

## Process (this repo)

- **DPR (Deep PR Review)** — an independent, adversarial review by a non-author,
  recorded as a GitHub review verdict and in the agent-layer ledger. See the
  review gate in [`governance/review-checklist.md`](governance/review-checklist.md).
- **Slice** — one coherent, review-sized feature mapped to a `final.md` section.
  Slices and their dependencies are tracked in
  [`implementation-backlog.md`](implementation-backlog.md).
- **Coordination ledger** — the append-only agent-layer record of who authored,
  reviewed, and merged each PR (approvals can't use GitHub's Approve state because
  all agents share one account). See
  [`governance/coordination-ledger.md`](governance/coordination-ledger.md), linted
  by [`scripts/check-governance.py`](../scripts/check-governance.py).
