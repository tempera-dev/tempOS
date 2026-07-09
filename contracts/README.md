# tempOS Runtime And Evidence Schemas

JSON Schemas (draft 2020-12) for runtime, evidence, optimization, and eval
artifacts that sit around the tempOS core contracts.

This directory is **not** the canonical source of truth for the core wire
contracts. The canonical, language-neutral core contract source is
[`spec/contracts`](../spec/contracts), documented in
[`spec/README.md`](../spec/README.md), and validated by
[`spec/conformance/validate.py`](../spec/conformance/validate.py). When a schema
name exists in both directories, `spec/contracts` owns the portable core
contract shape.

`contracts/schema` may carry broader runtime/evidence schemas and compatibility
mirrors needed by local tooling. Those mirrors must either be regenerated from
the core source or explicitly documented as runtime-specific extensions before
they diverge.

## Schemas

| Schema | Contract | `final.md` |
| --- | --- | --- |
| `agent-session.schema.json` | AgentSession runtime mirror; core shape owned by `spec/contracts` | §7.2, §12.1 |
| `capability-grant.schema.json` | CapabilityGrant runtime mirror; core shape owned by `spec/contracts` | §7.3, §12.2 |
| `action-manifest.schema.json` | ActionManifest runtime mirror; core shape owned by `spec/contracts` | §7.4, §12.3 |
| `policy-decision.schema.json` | PolicyDecision runtime mirror; core shape owned by `spec/contracts` | §7.5, §12.4 |
| `capability-receipt.schema.json` | CapabilityReceipt runtime mirror; core shape owned by `spec/contracts` | §7.6, §12.5 |
| `memory-record.schema.json` | MemoryRecord runtime mirror and policy-safe context-selection notes; core shape owned by `spec/contracts` | §7.7, §12.6, §13.4 |
| `memory-context-request.schema.json` | Runtime selector policy for bounded, source-anchored, non-authoritative memory context | §7.7, §12.6, §13.4 |
| `memory-context-selection.schema.json` | Runtime memory context result with selected items, structured rejections, truncation, policy summary, and provenance | §7.7, §12.6, §13.4 |
| `runtime-memory-record-request.schema.json` | HTTP/runtime request for recording one non-authoritative memory fact in a daemon session journal | §7.7, §12.6, §13.4 |
| `runtime-memory-record-response.schema.json` | HTTP/runtime response after a daemon-journaled `MemoryWritten` record | §7.7, §12.6, §13.4 |
| `runtime-memory-context-request.schema.json` | HTTP/runtime wrapper for selecting memory context under one daemon session | §7.7, §12.6, §13.4 |
| `runtime-memory-context-outcome.schema.json` | HTTP/runtime memory context response bound to journal root and projection summary | §7.7, §12.6, §13.4 |
| `payment-mandate.schema.json` | PaymentMandate runtime mirror; core shape owned by `spec/contracts` | §12.7, §16.1 |
| `scenario-manifest.schema.json` | ScenarioManifest runtime mirror; core shape owned by `spec/contracts` | §7.10, §12.8 |
| `journal.schema.json` | JournalRecord + JournalEvent | §4.5, §10.4 |
| `common.schema.json` | Shared enums + sub-structures | — |
| `trace-bundle.schema.json` | A full end-to-end run (harness input) | §24 |
| `security-scenario.schema.json` | Adversarial eval + admission probe | §14.5 |
| `performance-trace.schema.json` | Optimization trace evidence envelope | §8, §13 |
| `accelerator-telemetry.schema.json` | Vendor-neutral accelerator job telemetry | §8, §13 |
| `worker-preflight-plan.schema.json` | Side-effect-free worker scheduler plan | §4.4, §6.4, §7 |
| `model-route-decision.schema.json` | Journalable metadata-only model route decision before prompt egress | §6.10, §13.4, §24 |
| `model-route-runtime.schema.json` | HTTP/runtime request and response wrapper for metadata-only model route selection | §6.10, §13.4, §24 |
| `mcp-local-shell-call.schema.json` | Argument payload for the `tempos.local_shell` MCP stdio tool | §8.6, §13.6, §24 |
| `mcp-local-shell-result.schema.json` | Structured result payload for the `tempos.local_shell` MCP stdio tool | §8.6, §13.6, §24 |

## Versioning & provenance

- Runtime mirrors should track the `crates/beater-os-core` wire format: exact
  field names and snake_case enum values that match serde's
  `rename_all = "snake_case"`. Core contract changes start in `spec/contracts`.
- `additionalProperties: false` throughout, so the corpus is validated strictly.
  When the Rust core adds a field, add it here in the same or a follow-up change
  and note it in `AGENTS.md` (PR #19/#20 own that coordination doc).
- Enum orderings that carry meaning (`risk_class`, `data_class`) are listed in
  severity order; the conformance harness relies on that order for ceiling
  comparisons.
- Memory context selectors must treat `MemoryRecord` as evidence-bound context
  only: select active, non-expired records; verify `source_event_id` anchoring
  in the journal projection, preserve `source_digest`; enforce `access_policy`,
  explicit sensitivity allowlists and denied taint/data-class labels; bound both
  selected items and returned rejections; and never use memory as authority for
  grants, approvals, receipts, or trusted instructions.

## Validation

The schemas are exercised by the conformance gate:

```
python3 tools/conformance/validate.py
```

See `tools/conformance/README.md` for the semantic invariants (admission,
causality, hash chains) layered on top of structural validation, and for the
open cross-language canonical-hashing item.

Run the canonicality wording guard after editing this README:

```
python3 scripts/check-contract-canonicality.py
```
