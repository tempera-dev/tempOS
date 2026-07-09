# MCP Stdio Gateway

This document defines the first operator-facing MCP gateway slice. It is a
minimal stdio MCP server that lets an existing MCP-speaking agent call one
local shell tool while tempOS remains the authority boundary.

The gateway is an adoption seam, not a new trust root. It must not execute a
process, pass credentials, or publish model-visible tool output until the call
has gone through the existing daemon admission, sandbox, execution lease, and
receipt path.

## Scope

The first gateway exposes exactly one tool:

- `tempos.local_shell`
  - Runs a local command only through daemon-mediated local-shell execution.
  - Uses the daemon-owned tool registry, grant checks, policy admission,
    durable execution leases, sandbox confinement, capped stdout/stderr, and
    receipt append path.
  - Returns a bounded model-visible summary plus stable receipt and projection
    identifiers.

Out of scope for this slice:

- Proxying arbitrary remote MCP servers.
- Importing untrusted tool catalogs.
- OAuth delegation or provider-token exchange.
- Direct filesystem, network, browser, or memory tools.
- Any route that gives the MCP client direct store mutation authority.

Remote MCP federation can build on this later, but only after remote tool
descriptors are normalized into local registry entries with trusted side-effect
metadata, canonical arguments, version/digest pinning, and no token passthrough.

## Operator Surface

The operator starts the gateway as a stdio process over an existing local
daemon store:

```console
$ beater-os-mcp-stdio serve-local-shell --root .beateros
```

The process reads Content-Length-framed MCP JSON-RPC from stdin and writes
Content-Length-framed MCP JSON-RPC to stdout. Logs and diagnostics must go to
stderr so protocol output remains machine-readable.

Required runtime inputs:

- Store root for the local `beater-osd` authority.
- Explicit per-call session id and grant ids.
- Workspace `cwd` that the gateway canonicalizes before admission.
- Server-side caps for stdio header lines, aggregate headers, full frame bytes,
  and model-visible text bytes.
- Per-call caps for wall-clock runtime, sandbox stdout/stderr bytes, argument
  vector length, argument byte length, grant count, identifier length, cwd
  length, and model-visible text bytes.

The gateway should fail closed at startup when required authority inputs are
missing. It should fail closed per call when requested grants, cwd, command,
digest, timeout, or output caps cannot be represented by the existing
local-shell execution contract.

## Call Flow

For every `tempos.local_shell` call:

1. Parse and bound the MCP frame, JSON-RPC id, `tools/call` params, and local
   shell arguments before contacting the daemon.
2. Canonicalize `cwd` and derive the file-path target at the adapter boundary.
3. Resolve the local-shell tool identity through the daemon-owned registry.
4. Ask the daemon to admit the action and journal the proposal and policy
   decision.
5. If policy denies, return a denial summary and no receipt.
6. If policy allows, acquire a durable execution lease before spawning any
   process.
7. Run the process only through the sandboxed local-shell gateway path.
8. Complete the exact open lease with the observed receipt, including capped
   stdout/stderr and side-effect evidence.
9. Return a model-visible summary that names the outcome, truncation state,
   receipt id, lease id, journal root, and any runnable/recovery blockers the
   daemon projection reports.

`Allowed` is not executable authority by itself. The execution lease is the
atomic claim that prevents duplicate local side effects, crash-window replay,
and stale worker dispatch.

## Model-Visible Result

The MCP response must carry one authoritative structured payload. Any text
shown to the model is a summary of that payload, not a second serialized copy of
large stdout, stderr, JSON, or binary data.

The text fallback in `content[0].text` is the short human-readable summary.
The authoritative `structuredContent` payload should match the advertised
`outputSchema`:

- Admission-refused calls include `status: admission_refused`, `decision`,
  `matched_rules`, `explanation`, `session_id`, `action_id`, `manifest_hash`,
  `decision_id`, and `final_journal_root_hash`.
- Post-lease execution failures include `status: execution_incomplete`,
  `decision: allowed`, `session_id`, `action_id`, `error`,
  `final_journal_root_hash`, open/live/expired execution lease ids and
  statuses, and scheduler blockers so operators can reconcile instead of
  retrying blindly.
- Executed calls include sandbox `status` (`ok`, `failed`, `timeout`, or
  `signaled`), `decision: allowed`, `session_id`, `action_id`, `lease_id`,
  `tool_ref`, `manifest_hash`, `decision_id`, proposal/decision/lease
  seq-hash anchors, `tool_id`, `exit_code`, `stdout_digest`,
  `stdout_truncated`, `stderr_truncated`, capped filesystem diff paths plus
  full counts/truncation flags, `receipt_id`, `receipt_hash`,
  receipt seq/hash/root anchors, `final_journal_root_hash`, and projection
  counts such as `receipts`, `runnable_pending_actions`, and
  `open_execution_leases`.

The advertised MCP tool descriptor includes both `inputSchema` and
`outputSchema`. The input schema rejects unknown properties, slash-containing
commands, duplicate grants, duplicate enum arrays, overlong identifiers, and
oversized argument vectors before daemon access. The output schema has distinct
success and admission-refusal shapes so callers can distinguish “not admitted”
from “executed and failed”. The language-neutral copies of those contracts are
[`contracts/schema/mcp-local-shell-call.schema.json`](../contracts/schema/mcp-local-shell-call.schema.json)
and
[`contracts/schema/mcp-local-shell-result.schema.json`](../contracts/schema/mcp-local-shell-result.schema.json).

The response must not include raw bearer tokens, inherited environment values,
global MCP credentials, uncapped command output, or a second full serialized
receipt embedded inside prose.

## Security Invariants

- No token passthrough: daemon tokens, MCP client tokens, shell environment
  secrets, caller-provided `BEATER_*` variables whose names look
  credential-bearing, and future provider credentials are never forwarded to
  tools.
- Kernel-derived manifest fields come from the gateway, daemon, sandbox, or
  registry, not from agent-authored MCP text.
- Output is capped while collecting and before model exposure; a post-hoc
  truncation after fully materializing remote-driven output is not a memory
  bound.
- The gateway uses the same local-shell execution path as the daemon HTTP and
  worker surfaces; it does not grow a parallel process launcher.
- Stdio is a transport boundary only. The MCP client is still untrusted, and
  every side effect must be admitted, leased, sandboxed, receipted, and
  replayable.
- Open execution leases remain recovery blockers. The gateway reports them to
  the model/operator instead of retrying or fabricating success.

## Done Criteria

The implementation slice is complete when an MCP-speaking agent can call
`tempos.local_shell` through stdio and the resulting side effect is
indistinguishable, in daemon evidence, from an admitted local-shell action run
through the existing gateway path:

- Admission and denial are journaled by the daemon.
- Execution starts only after a durable lease is issued.
- The sandbox enforces cwd, environment, timeout, and output caps.
- Receipts bind observed output and side effects to the admitted manifest.
- Model-visible output is summarized and bounded.
- No token, secret, or credential value is passed through the MCP surface.
