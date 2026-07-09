//! Full replay trace bundle export.
//!
//! This module is intentionally separate from [`crate::AuditBundle`]. The audit
//! bundle is redaction-safe and digest-only; this trace bundle is the complete
//! replay artifact shaped like `contracts/schema/trace-bundle.schema.json`.
//! Callers should only expose it across already-authorized audit/control-plane
//! boundaries because manifests, targets, summaries, and journal payloads may
//! contain sensitive data.

use beater_os_core::{
    ActionManifest, AgentSession, ApprovalEvidence, CapabilityGrant, CapabilityReceipt,
    InMemoryJournal, JournalEvent, JournalRecord, JournalSnapshot, MemoryRecord,
    ModelRouteDecisionRecord, PaymentMandate, PolicyDecision, ReceiptLedger, SessionStatus,
    SimulationEvidence,
};
use serde::{Deserialize, Serialize};

use crate::verify::{
    CheckOutcome, CheckResult, snapshot_root_hash, verify_expected_root, verify_snapshot,
};

/// A self-contained trace for one session run plus its hash-linked journal and
/// receipt chains.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceBundle {
    pub bundle_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub policy_version: String,
    pub sessions: Vec<AgentSession>,
    pub grants: Vec<CapabilityGrant>,
    pub payment_mandates: Vec<PaymentMandate>,
    pub approvals: Vec<ApprovalEvidence>,
    pub simulations: Vec<SimulationEvidence>,
    pub manifests: Vec<ActionManifest>,
    pub decisions: Vec<PolicyDecision>,
    #[serde(default)]
    pub model_route_decisions: Vec<ModelRouteDecisionRecord>,
    #[serde(default)]
    pub memory_records: Vec<MemoryRecord>,
    pub receipts: Vec<CapabilityReceipt>,
    pub journal: Vec<JournalRecord>,
}

/// Serialize a full trace bundle to pretty JSON.
pub fn trace_bundle_to_json(bundle: &TraceBundle) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(bundle)
}

/// Options for read-only trace bundle verification.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TraceBundleVerifyOptions<'a> {
    pub expected_journal_root: Option<&'a str>,
}

/// Result of verifying a full trace bundle as a read-only audit artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TraceBundleVerificationReport {
    pub ok: bool,
    pub bundle_id: String,
    pub session_id: Option<String>,
    pub records: usize,
    pub journal_root_hash: String,
    pub receipt_root_hash: String,
    pub grants: usize,
    pub payment_mandates: usize,
    pub approvals: usize,
    pub simulations: usize,
    pub manifests: usize,
    pub decisions: usize,
    pub model_route_decisions: usize,
    pub memory_records: usize,
    pub receipts: usize,
    pub checks: Vec<CheckResult>,
}

#[derive(Default)]
struct ProjectedTrace {
    sessions: Vec<AgentSession>,
    grants: Vec<CapabilityGrant>,
    payment_mandates: Vec<PaymentMandate>,
    approvals: Vec<ApprovalEvidence>,
    simulations: Vec<SimulationEvidence>,
    manifests: Vec<ActionManifest>,
    decisions: Vec<PolicyDecision>,
    model_route_decisions: Vec<ModelRouteDecisionRecord>,
    memory_records: Vec<MemoryRecord>,
    receipts: Vec<CapabilityReceipt>,
}

/// Verify that a trace bundle is a faithful, read-only audit artifact.
///
/// The top-level arrays are treated as redundant evidence. The journal is the
/// only authority source: verification rebuilds projection state from
/// `bundle.journal`, verifies the embedded journal, rebuilds the receipt chain
/// from `ReceiptAppended` events, and rejects any mismatch between the
/// journal-derived projection and exported arrays. This never applies/imports a
/// bundle into daemon state and never re-runs policy admission or tools.
pub fn verify_trace_bundle(bundle: &TraceBundle) -> TraceBundleVerificationReport {
    verify_trace_bundle_with_options(bundle, TraceBundleVerifyOptions::default())
}

pub fn verify_trace_bundle_with_options(
    bundle: &TraceBundle,
    options: TraceBundleVerifyOptions<'_>,
) -> TraceBundleVerificationReport {
    let snapshot = trace_bundle_snapshot(bundle);
    let mut checks = verify_snapshot(&snapshot).checks;
    if bundle.bundle_id.trim().is_empty() {
        checks.push(check_fail(
            "trace_bundle_id",
            "trace bundle id must not be empty",
        ));
    } else {
        checks.push(check_pass(
            "trace_bundle_id",
            format!("trace bundle id {} is present", bundle.bundle_id),
        ));
    }
    let journal = InMemoryJournal::from_records(bundle.journal.clone());
    let core_verification = journal.verify_chain();
    let records = bundle.journal.len();
    let journal_root_hash = snapshot_root_hash(&snapshot);
    match core_verification {
        Ok(report) => checks.push(check_pass(
            "core_journal_causality",
            format!(
                "core journal verifier accepted {} record(s)",
                report.records
            ),
        )),
        Err(err) => checks.push(check_fail(
            "core_journal_causality",
            format!("core journal verifier rejected bundle: {err}"),
        )),
    }
    if let Some(expected_root) = options.expected_journal_root {
        checks.push(verify_expected_root(&snapshot, expected_root));
    }
    let projected = match project_trace_from_journal(&bundle.journal) {
        Ok(projected) => {
            checks.push(check_pass(
                "journal_projection",
                "journal-derived projection completed",
            ));
            projected
        }
        Err(err) => {
            checks.push(check_fail("journal_projection", err));
            ProjectedTrace::default()
        }
    };
    if projected.sessions.len() == 1 {
        checks.push(check_pass(
            "single_session_trace",
            "trace bundle projects exactly one session",
        ));
    } else {
        checks.push(check_fail(
            "single_session_trace",
            format!(
                "trace bundle verifier currently requires exactly one session, found {}",
                projected.sessions.len()
            ),
        ));
    }
    push_section_check(
        &mut checks,
        "sessions",
        &bundle.sessions,
        &projected.sessions,
    );
    push_section_check(&mut checks, "grants", &bundle.grants, &projected.grants);
    push_section_check(
        &mut checks,
        "payment_mandates",
        &bundle.payment_mandates,
        &projected.payment_mandates,
    );
    push_section_check(
        &mut checks,
        "approvals",
        &bundle.approvals,
        &projected.approvals,
    );
    push_section_check(
        &mut checks,
        "simulations",
        &bundle.simulations,
        &projected.simulations,
    );
    push_section_check(
        &mut checks,
        "manifests",
        &bundle.manifests,
        &projected.manifests,
    );
    push_section_check(
        &mut checks,
        "decisions",
        &bundle.decisions,
        &projected.decisions,
    );
    push_section_check(
        &mut checks,
        "model_route_decisions",
        &bundle.model_route_decisions,
        &projected.model_route_decisions,
    );
    push_section_check(
        &mut checks,
        "memory_records",
        &bundle.memory_records,
        &projected.memory_records,
    );
    push_section_check(
        &mut checks,
        "receipts",
        &bundle.receipts,
        &projected.receipts,
    );
    let receipt_ledger = ReceiptLedger::from_receipts(projected.receipts.clone());
    match receipt_ledger.verify_chain() {
        Ok(()) => checks.push(check_pass(
            "receipt_chain",
            "journal-derived receipt chain verified",
        )),
        Err(err) => checks.push(check_fail(
            "receipt_chain",
            format!("journal-derived receipt chain failed verification: {err}"),
        )),
    }
    let ok = checks
        .iter()
        .all(|check| check.outcome == CheckOutcome::Pass);
    TraceBundleVerificationReport {
        ok,
        bundle_id: bundle.bundle_id.clone(),
        session_id: projected
            .sessions
            .first()
            .map(|session| session.session_id.clone()),
        records,
        journal_root_hash,
        receipt_root_hash: receipt_ledger.root_hash(),
        grants: projected.grants.len(),
        payment_mandates: projected.payment_mandates.len(),
        approvals: projected.approvals.len(),
        simulations: projected.simulations.len(),
        manifests: projected.manifests.len(),
        decisions: projected.decisions.len(),
        model_route_decisions: projected.model_route_decisions.len(),
        memory_records: projected.memory_records.len(),
        receipts: projected.receipts.len(),
        checks,
    }
}

pub fn trace_bundle_snapshot(bundle: &TraceBundle) -> JournalSnapshot {
    JournalSnapshot {
        records: bundle.journal.clone(),
    }
}

fn project_trace_from_journal(records: &[JournalRecord]) -> Result<ProjectedTrace, String> {
    let mut projected = ProjectedTrace::default();
    for record in records {
        match &record.event {
            JournalEvent::SessionCreated { session } => projected.sessions.push(session.clone()),
            JournalEvent::SessionStatusChanged { session_id, to, .. } => {
                let Some(session) = projected
                    .sessions
                    .iter_mut()
                    .find(|session| session.session_id == *session_id)
                else {
                    return Err(format!(
                        "session status transition references missing session {session_id}",
                    ));
                };
                session.status = to.clone();
            }
            JournalEvent::CapabilityGranted { grant } => projected.grants.push(grant.clone()),
            JournalEvent::CapabilityRevoked {
                grant_id,
                revocation_handle,
                ..
            } => {
                let Some(_grant) = projected.grants.iter().find(|grant| {
                    grant.grant_id == *grant_id && grant.revocation_handle == *revocation_handle
                }) else {
                    return Err(format!(
                        "grant revocation references missing grant {grant_id}",
                    ));
                };
                // Trace export serializes the live projection's `grants` array
                // without folding `revoked_handles` back into each grant. Keep
                // this verifier byte-contract aligned with that exported shape;
                // the revocation itself remains authoritative evidence in the
                // journal that is independently verified above.
            }
            JournalEvent::PaymentMandateIssued { mandate } => {
                projected.payment_mandates.push(mandate.clone());
            }
            JournalEvent::ActionProposed { manifest } => {
                projected.manifests.push((**manifest).clone());
            }
            JournalEvent::PolicyDecided { decision } => projected.decisions.push(decision.clone()),
            JournalEvent::ExecutionLeaseIssued { .. }
            | JournalEvent::ExecutionLeaseHeartbeated { .. }
            | JournalEvent::ExecutionLeaseReconciled { .. } => {}
            JournalEvent::ApprovalRecorded { approval } => {
                projected.approvals.push(approval.clone());
            }
            JournalEvent::SimulationRecorded { simulation } => {
                projected.simulations.push(simulation.clone());
            }
            JournalEvent::ReceiptAppended { receipt } => projected.receipts.push(receipt.clone()),
            JournalEvent::ModelRouteDecided { decision } => {
                projected.model_route_decisions.push(decision.clone());
            }
            JournalEvent::MemoryWritten { memory } => {
                projected.memory_records.push(memory.clone());
            }
            JournalEvent::ScenarioEvaluated { .. } | JournalEvent::IncidentAnnotated { .. } => {}
        }
    }
    if projected
        .sessions
        .iter()
        .any(|session| session.status != SessionStatus::Running)
    {
        projected
            .sessions
            .sort_by(|a, b| a.session_id.cmp(&b.session_id));
    }
    Ok(projected)
}

fn push_section_check<T: PartialEq>(
    checks: &mut Vec<CheckResult>,
    name: &str,
    exported: &[T],
    projected: &[T],
) {
    if exported == projected {
        checks.push(check_pass(
            &format!("trace_bundle_{name}"),
            format!("{name} section matches journal-derived projection"),
        ));
    } else {
        checks.push(check_fail(
            &format!("trace_bundle_{name}"),
            format!("{name} section does not match journal-derived projection"),
        ));
    }
}

fn check_pass(check: &str, detail: impl Into<String>) -> CheckResult {
    CheckResult {
        check: check.to_string(),
        outcome: CheckOutcome::Pass,
        detail: detail.into(),
    }
}

fn check_fail(check: &str, detail: impl Into<String>) -> CheckResult {
    CheckResult {
        check: check.to_string(),
        outcome: CheckOutcome::Fail,
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    use beater_os_core::{JournalEvent, JournalRecord};
    use chrono::{TimeZone, Utc};

    fn compact_route_decision() -> ModelRouteDecisionRecord {
        ModelRouteDecisionRecord {
            decision_id: "1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            session_id: "session-route".to_string(),
            result: "denied".to_string(),
            selected_route_id: None,
            selected_route_hash: None,
            candidate_route_ids: BTreeSet::new(),
            rejected_route_ids: BTreeSet::new(),
            request_hash: "2222222222222222222222222222222222222222222222222222222222222222"
                .to_string(),
            catalog_hash: "3333333333333333333333333333333333333333333333333333333333333333"
                .to_string(),
            policy_hash: "4444444444444444444444444444444444444444444444444444444444444444"
                .to_string(),
            decision_payload_hash:
                "5555555555555555555555555555555555555555555555555555555555555555".to_string(),
            requested_at: Utc.with_ymd_and_hms(2026, 7, 9, 0, 0, 0).unwrap(),
            recorded_at: Utc.with_ymd_and_hms(2026, 7, 9, 0, 0, 1).unwrap(),
        }
    }

    fn empty_trace_bundle() -> TraceBundle {
        TraceBundle {
            bundle_id: "trace-empty".to_string(),
            description: None,
            policy_version: "policy-test".to_string(),
            sessions: Vec::new(),
            grants: Vec::new(),
            payment_mandates: Vec::new(),
            approvals: Vec::new(),
            simulations: Vec::new(),
            manifests: Vec::new(),
            decisions: Vec::new(),
            model_route_decisions: Vec::new(),
            memory_records: Vec::new(),
            receipts: Vec::new(),
            journal: Vec::new(),
        }
    }

    #[test]
    fn empty_payload_sections_remain_present() {
        let bundle = empty_trace_bundle();
        let json = trace_bundle_to_json(&bundle).unwrap_or_else(|err| err.to_string());
        assert!(json.contains("\"bundle_id\""));
        assert!(json.contains("\"sessions\""));
        assert!(json.contains("\"model_route_decisions\""));
        assert!(json.contains("\"memory_records\""));
        assert!(json.contains("\"journal\""));
        assert!(!json.contains("\"description\""));
    }

    #[test]
    fn old_trace_bundles_default_missing_model_route_decisions() {
        let json = r#"{
          "bundle_id": "old-trace",
          "policy_version": "policy-test",
          "sessions": [],
          "grants": [],
          "payment_mandates": [],
          "approvals": [],
          "simulations": [],
          "manifests": [],
          "decisions": [],
          "receipts": [],
          "journal": []
        }"#;
        let bundle: TraceBundle = serde_json::from_str(json).expect("old bundle shape");
        assert!(bundle.model_route_decisions.is_empty());
        assert!(bundle.memory_records.is_empty());
    }

    #[test]
    fn model_route_decisions_project_from_journal() {
        let decision = compact_route_decision();
        let record = JournalRecord {
            seq: 0,
            created_at: decision.recorded_at,
            event: JournalEvent::ModelRouteDecided {
                decision: decision.clone(),
            },
            prev_hash: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            hash: "6666666666666666666666666666666666666666666666666666666666666666".to_string(),
        };
        let projected = project_trace_from_journal(&[record]).expect("project trace");
        assert_eq!(projected.model_route_decisions, vec![decision]);
    }

    #[test]
    fn forged_model_route_decision_section_fails_verification() {
        let mut bundle = empty_trace_bundle();
        bundle.model_route_decisions.push(compact_route_decision());
        let report = verify_trace_bundle(&bundle);
        assert!(
            report.checks.iter().any(|check| {
                check.check == "trace_bundle_model_route_decisions"
                    && check.outcome == CheckOutcome::Fail
            }),
            "expected model route decision section mismatch, got {report:?}"
        );
    }

    fn memory_record() -> MemoryRecord {
        MemoryRecord {
            memory_id: "mem-route".to_string(),
            source_event_id: "session-route".to_string(),
            source_digest: "sha256:source".to_string(),
            writer: "agent:memory".to_string(),
            created_at: Utc.with_ymd_and_hms(2026, 7, 9, 0, 0, 0).unwrap(),
            scope: Some("scope:trace".to_string()),
            kind: "summary".to_string(),
            content_ref: "memory://mem-route".to_string(),
            summary: "Route memory trace fixture".to_string(),
            confidence_basis_points: 9_000,
            sensitivity: beater_os_core::DataClass::Internal,
            source_taint: BTreeSet::new(),
            source_data_classes: BTreeSet::new(),
            expires_at: None,
            access_policy: "runtime_context".to_string(),
        }
    }

    #[test]
    fn memory_records_project_from_journal() {
        let memory = memory_record();
        let record = JournalRecord {
            seq: 0,
            created_at: memory.created_at,
            event: JournalEvent::MemoryWritten {
                memory: memory.clone(),
            },
            prev_hash: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            hash: "7777777777777777777777777777777777777777777777777777777777777777".to_string(),
        };
        let projected = project_trace_from_journal(&[record]).expect("project trace");
        assert_eq!(projected.memory_records, vec![memory]);
    }

    #[test]
    fn forged_memory_record_section_fails_verification() {
        let mut bundle = empty_trace_bundle();
        bundle.memory_records.push(memory_record());
        let report = verify_trace_bundle(&bundle);
        assert!(
            report.checks.iter().any(|check| {
                check.check == "trace_bundle_memory_records" && check.outcome == CheckOutcome::Fail
            }),
            "expected memory record section mismatch, got {report:?}"
        );
    }
}
