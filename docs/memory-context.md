# Memory Context Service

The memory context service is the policy-facing view over projected memory. It
selects a bounded set of provenance-carrying memory records that may be shown to
models or tools as context. It does not mint authority, approve actions, prove
side effects, or turn remembered text into trusted instructions.

This document describes the service surface. The source of memory truth remains
the journal: context is derived from `MemoryWritten` records and their
projection metadata, not from an independent cache.

## Runtime Surface

The typed runtime entrypoint is
`AgentRuntime::select_memory_context(RuntimeMemoryContextRequest)`. It reads the
daemon-owned session, enforces that the session is running, applies
`AgentSession.memory_scope` as a default or hard constraint, and delegates the
selection to the daemon store under the session lock.

The loopback control-plane write endpoint is:

`POST /v1/sessions/<session_id>/memory/records`

The body is a memory write request:

```json
{
  "session_id": "session-1",
  "memory": {
    "memory_id": "mem-1",
    "source_event_id": "session-1",
    "source_digest": "sha256:source",
    "writer": "memory-writer",
    "created_at": "2026-07-09T12:00:00Z",
    "scope": "project-alpha",
    "kind": "fact",
    "content_ref": "memory://mem-1",
    "summary": "A bounded fact summary.",
    "confidence_basis_points": 9000,
    "sensitivity": "internal",
    "source_taint": [],
    "source_data_classes": [],
    "expires_at": null,
    "access_policy": "runtime-context"
  }
}
```

The path session id and body `session_id` must match. The daemon appends a
`MemoryWritten` event only when the session is running and `source_event_id`
names a prior event in the same session journal. The response returns
`memory_seq`, `memory_journal_hash`, and `final_journal_root_hash` so callers can
carry durable evidence without treating memory as authority.

The loopback control-plane selection endpoint is:

`POST /v1/sessions/<session_id>/memory/context/select`

The body is a `RuntimeMemoryContextRequest`:

```json
{
  "session_id": "session-1",
  "context": {
    "max_items": 8,
    "max_rejections": 32,
    "allowed_sensitivities": ["public", "internal"],
    "denied_source_taint": ["untrusted_web"],
    "denied_source_data_classes": ["secret"]
  }
}
```

The path session id and body `session_id` must match. The response includes the
`MemoryContextSelection`, selected/rejected/truncated counts, and the verified
journal record count plus journal root hash that bound the source projection.
The projection summary is derived from the same journal snapshot as the
reported memory-context `journal_root_hash`.

## Scope

The selector accepts a memory projection plus a `MemoryContextRequest` and
returns a `MemoryContextSelection`.

Inputs:

- projected memory records from the journal or a journal snapshot;
- the caller's context purpose expressed as scope, kind, sensitivity, taint,
  data-class, access-policy, writer, confidence, redaction, and content-ref
  constraints;
- a maximum item count, defaulting to the service limit when omitted.

Outputs:

- selected `MemoryContextItem` records, each carrying summary, sensitivity,
  source taint/data classes, access policy, provenance, and warnings;
- rejected memory ids with structured rejection reasons;
- a `truncated` count when more records matched than the selection bound allowed;
- a `selection_policy` summary that records the filters actually applied.

## Selection Rules

A memory may be selected only when all of these checks pass:

- It is active at the projection time and not expired. Expired memory can remain
  visible to audit, but it is not model context.
- Its source is record-anchored. By default the selector requires the source
  event named by the memory to be present in the projected record set and
  anchored by journal sequence/hash metadata.
- Its `access_policy` is allowed by the request when the request supplies an
  access-policy allowlist.
- Its `sensitivity` appears in the explicit sensitivity allowlist when that
  allowlist is populated. The selector does not treat `DataClass` declaration
  order as a linear sensitivity ceiling.
- None of its inherited `source_taint` labels appear in
  `denied_source_taint`.
- None of its inherited `source_data_classes` appear in
  `denied_source_data_classes`.
- Its kind and scope match when the request constrains either field.
- Its writer is in `trusted_writers` when the request chooses to constrain
  writers.
- It is not redacted unless `include_redacted` is explicitly enabled.
- It meets the request's minimum confidence.

The writer filter is optional on purpose. Some contexts need "all relevant
memory, but with provenance and warnings"; other contexts need a specific
trusted-writer allowlist. When no writer allowlist is supplied, selected items
carry a warning so downstream prompts and audit views do not mistake the result
for a trusted-writer assertion.

## Bounds

Selection is bounded by `max_items`, or by the service default when `max_items`
is omitted. Matching records are ranked deterministically before truncation by
confidence, recency, and memory id. The `truncated` field reports how many
otherwise-accepted records were left out by the bound.

Structured rejection output is bounded separately by `max_rejections`, or by the
service default when omitted. The `truncated_rejections` field reports how many
audit-visible rejected records were omitted from the returned payload.

The selector may omit `content_ref` from selected items. This lets model-facing
context carry summaries and provenance without creating an implicit dereference
capability for the underlying content.

## Non-Authority

Selected memory is evidence, not authority. A selected `MemoryContextItem` can
explain what the system remembers and where that memory came from, but it cannot:

- create or widen a capability grant;
- satisfy a policy approval requirement;
- stand in for a receipt or side-effect outcome;
- override route, sandbox, secret, payment, or tool policy;
- convert page, email, document, tool-output, or other tainted source text into
  trusted instructions.

Callers that use memory context in prompts must preserve this framing. Text
fallbacks should summarize selected memory and provenance; they should not
serialize a second full payload or present selected memory as an instruction
channel.

## Release Eval Fixtures

The K13 release fixture set is intentionally small and checks only the selector
contract that must hold before memory is included in model context:

| Fixture | Record shape | Expected result |
| --- | --- | --- |
| `k13_memory_clean_record_selected` | Active, source-anchored, unredacted record with allowed sensitivity, allowed access policy, trusted writer, and no denied source labels. | Selected with provenance and the `memory_is_context_not_authority` warning. |
| `k13_memory_poisoned_untrusted_source_rejected` | Active record whose `source_taint` includes `untrusted_web` while the request denies that taint. | Rejected with `source_taint_denied`; not present in selected context. |
| `k13_memory_expired_record_rejected` | Source-anchored record whose `expires_at` is at or before selection time. | Rejected with `expired`; retained only for audit. |
| `k13_memory_secret_source_rejected` | Active record whose sensitivity or inherited source data classes exceed the request allowlist. | Rejected with `sensitivity_not_allowed` or `source_data_class_denied`; not present in selected context. |
| `k13_memory_access_policy_disallowed_rejected` | Active record whose `access_policy` is absent from `allowed_access_policies`. | Rejected with `access_policy_not_allowed`; not present in selected context. |

These fixtures prove that poisoned, expired, and policy-disallowed records are
observable as structured rejections rather than silently entering prompt
context. They do not make selected memory authoritative; the non-authority
warning remains part of the passing fixture.

## Audit and Failure Mode

The service is fail-closed for context selection and audit-open for
accountability. Rejected records include structured reasons such as `expired`,
`source_record_missing`, `sensitivity_not_allowed`,
`source_taint_denied`, `source_data_class_denied`,
`access_policy_not_allowed`, and `writer_not_trusted`.

That split is intentional: records that cannot be safely selected remain
explainable to operators and tests, but they do not silently enter model or tool
context.
