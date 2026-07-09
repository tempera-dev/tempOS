# Example Traces

Machine-readable, end-to-end trace bundles that make `final.md`'s reproducibility
and MVP claims concrete (§2.2, §24). Each `*.trace.json` conforms to
`contracts/schema/trace-bundle.schema.json` and is checked by the conformance
gate for schema conformance, hash-linked receipt/journal chains, journal
causality, independent policy admission of every recorded decision,
execution-lease lifecycle evidence matching lease journal events, and top-level
model-route decision evidence matching `model_route_decided` journal events.
Memory write evidence is likewise checked against `memory_written` journal
events in append order, and scenario/incident evidence is checked against
`scenario_evaluated` and `incident_annotated` events. These fixtures do not
exercise daemon execution leases, model routing, memory writes, or scenario
evaluations yet, so their `execution_*`, `model_route_decisions`,
`memory_records`, and `scenario_evaluations` sections are present and empty; the
resilience fixture includes one `incident_annotations` entry for its timeout
incident.

## Bundles

- `coding-workflow.trace.json` — the §24 MVP proof: an agent reads a file
  (allowed), is **blocked** trying to write outside its granted path
  (`needs_narrowed_grant`), writes the fix in scope (allowed), and runs the test
  runner (allowed). Every side effect carries a receipt; every step is journaled.
- `payment-workflow.trace.json` — the human-review *approval-satisfied* path
  (§7.9, §13.14, §16.1): a bounded vendor `spend` over the grant's approval
  threshold is admitted **only because** valid, action-bound human approval
  evidence exists. Carries a `PaymentMandate` (§12.7) and a payment receipt.
  Complements the adversarial scenarios, which show approval being *required* but
  never *granted*.
- `resilience-review-timeout.trace.json` — the fail-closed resilience path
  (§14.2, §13.15): a high-risk production deploy needs human approval, the
  approval **never arrives**, and the system fails closed — the action is never
  executed (**no receipt exists**), the timeout is recorded as an
  `incident_annotated` journal event, and the session ends `canceled`.

## Regenerating

This bundle is generated (not hand-authored) so its 14 linked hashes stay
consistent:

```
python3 tools/conformance/build_fixtures.py           # regenerate
python3 tools/conformance/build_fixtures.py --check    # assert no drift (CI)
```

These are *prose-free machine fixtures* for the gate. A separate worked,
narrated example lives in the docs lane (PR #21, `docs/examples/`); the two are
complementary — this one is executed, that one is read.
