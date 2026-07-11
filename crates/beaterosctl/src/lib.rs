//! `beaterosctl`: the operator CLI and durable local store for the beaterOS
//! agent kernel.
//!
//! This crate is the human/operator surface over the hosted `beater-osd`
//! runtime. It opens the daemon-owned durable store directly for now, so grants,
//! admission decisions, and receipts are written through the same single-writer
//! authority boundary that a long-running daemon process will expose later.
//!
//! See `docs/beaterosctl.md` for the command reference and a worked MVP flow.

mod args;
mod commands;
mod error;

pub use beater_osd::{LocalShellToolRegistration, SessionProjection, Store};
pub use commands::POLICY_VERSION;
pub use error::{CliError, CliResult};

use std::env;
use std::path::PathBuf;

use args::ParsedArgs;

/// Default store location when neither `--home` nor `BEATEROS_HOME` is set.
pub const DEFAULT_HOME: &str = ".beateros";

/// The environment variable that selects the store root.
pub const HOME_ENV: &str = "BEATEROS_HOME";

/// Run the CLI from an argument iterator (including the program name).
///
/// Returns the text to print on success. Errors are returned to the caller so
/// the binary can render them and choose an exit code.
pub fn run<I: Iterator<Item = String>>(mut raw: I) -> CliResult<String> {
    let _program = raw.next();
    let args = ParsedArgs::parse(raw)?;

    if args.has_flag("help")
        || args.positional(0).is_none()
        || matches!(args.positional(0), Some("help"))
    {
        return Ok(help_text());
    }

    let home = resolve_home(&args);
    let store = Store::open(home)?;
    commands::dispatch(&store, &args)
}

/// Resolve the store root: `--home` beats `BEATEROS_HOME` beats the default.
fn resolve_home(args: &ParsedArgs) -> PathBuf {
    if let Some(home) = args.get("home") {
        return PathBuf::from(home);
    }
    match env::var(HOME_ENV) {
        Ok(value) if !value.is_empty() => PathBuf::from(value),
        _ => PathBuf::from(DEFAULT_HOME),
    }
}

/// The CLI usage/help text.
pub fn help_text() -> String {
    format!(
        "beaterosctl — operator CLI for the beaterOS agent kernel\n\
         \n\
         Store root precedence: --home > ${HOME_ENV} > ./{DEFAULT_HOME}\n\
         \n\
         COMMANDS\n\
         \x20 session create --agent <id> --workspace <id> --goal <text>\n\
         \x20                [--session <id>] [--created-by <id>] [--policy-profile <p>]\n\
         \x20                [--initial-capability-id <id>]...\n\
         \x20 session list\n\
         \x20 session show    --session <id>\n\
         \x20 session pause   --session <id>\n\
         \x20 session resume  --session <id>\n\
         \x20 session cancel  --session <id>\n\
         \x20 grant issue     --session <id> --resource-kind <kind> [--resource-id <id>]\n\
         \x20                 --actions <a,b> [--path-prefix <p>]... [--network-allow <h>]...\n\
         \x20                 [--max-risk <r>] [--expires-in-secs <n>]\n\
         \x20                 [--approval-mode <none|human|multi_party>]\n\
         \x20                 [--approval-threshold-risk <r>] [--reviewer <id>]...\n\
         \x20                 [--revocation-handle <h>] [--reason <text>]\n\
         \x20 grant revoke    --session <id> --grant-id <id> --reason <text>\n\
         \x20                 [--revoked-by <id>]\n\
         \x20 payment-mandate issue --session <id> --mandate <id> --rail <rail>\n\
         \x20                 --asset <asset> --max-minor-units <n>\n\
         \x20                 --counterparty-policy <policy> --purpose <text>\n\
         \x20                 --expires-at <rfc3339> --payment-idempotency-key <key>\n\
         \x20                 [--approval-threshold-minor-units <n>]\n\
         \x20                 --adapter <id>... --envelope-format <fmt>...\n\
         \x20 payment-spend propose --session <id> --action-id <id> --mandate <id>\n\
         \x20                 --grants <g1,g2> --amount-minor-units <n>\n\
         \x20                 --adapter-id <id> --counterparty-ref <ref>\n\
         \x20                 --counterparty-binding-hash <hex64>\n\
         \x20                 --envelope-format <fmt> --envelope-hash <hex64>\n\
         \x20 action propose  --session <id> --tool <id> --kind <action>\n\
         \x20                 --target-kind <kind> --target <id> --grants <g1,g2>\n\
         \x20                 [--risk <r>] [--side-effects <s,..>] [--data-classes <d,..>]\n\
         \x20                 [--taint <t,..>] [--revoked-handle <h>]...\n\
         \x20                 [--idempotency-key <k>] [--summary <text>]\n\
         \x20                 [--inputs-digest <sha256>] [--max-wall-ms <n>]\n\
         \x20 action execute  --session <id> --tool <id> --command <cmd> [--arg <a>]...\n\
         \x20                 --cwd <dir> --grants <g1,g2> [--risk <r>]\n\
         \x20                 [--tool-version <v>] [--tool-digest <sha256>]\n\
         \x20                 [--side-effects <s,..>] [--revoked-handle <h>]...\n\
         \x20                 [--idempotency-key <k>]\n\
         \x20                 [--timeout-secs <n>] [--max-output-bytes <n>]\n\
         \x20                 [--env <NAME=VALUE>]...\n\
         \x20 execution-lease reconcile --session <id> --action <id> --lease-id <id>\n\
         \x20                 --resolution outcome_unknown --reason <text>\n\
         \x20                 [--reconciliation-id <id>] [--reconciled-by <id>]\n\
         \x20                 [--evidence <ref>]...\n\
         \x20 approval record --session <id> --action <id> --grant-id <id>\n\
         \x20                 --reviewer <id> [--review-id <id>] [--approved-at <rfc3339>]\n\
         \x20                 [--readmit]\n\
         \x20 simulation record --session <id> --action <id>\n\
         \x20                 [--simulation-id <id>] [--scenario-id <id>]\n\
         \x20 model-route choose --session <id> --routes-file <json> --request-file <json>\n\
         \x20 memory record  --session <id> --memory-id <id> --source-event <id>\n\
         \x20                --source-digest <digest> --kind <kind> --content-ref <ref>\n\
         \x20                --summary <text> --sensitivity <data-class>\n\
         \x20                --access-policy <policy> [--writer <id>] [--scope <scope>]\n\
         \x20                [--confidence-basis-points <0..10000>]\n\
         \x20                [--source-taint <t,..>] [--source-data-class <d,..>]\n\
         \x20 memory context --session <id> [--scope <scope>] [--max-items <n>]\n\
         \x20                [--max-rejections <n>] [--min-confidence-basis-points <0..10000>]\n\
         \x20                [--allow-sensitivity <d,..>] [--deny-source-taint <t,..>]\n\
         \x20                [--deny-source-data-class <d,..>] [--trusted-writer <id>]...\n\
         \x20 receipt record  --session <id> --action <id> [--status <s>] [--summary <text>]\n\
         \x20                 [--rail-receipt-hash <hex64>]\n\
         \x20                 [--settlement-status <submitted|settled|failed|canceled>]\n\
         \x20                 [--settled-at <rfc3339>] # required only for settled\n\
         \x20 journal verify  --session <id>\n\
         \x20 trace show      --session <id>\n\
         \x20 trace export    --session <id> [--bundle-id <id>] [--description <text>]\n\
         \n\
         Enum values (kinds, actions, risk, data classes, side effects, taint)\n\
         use the snake_case names from beater-os-core, e.g. file_path, read,\n\
         write, execute, low, medium, high, critical, local_write, code."
    )
}
