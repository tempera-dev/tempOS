//! Deep tests for the memory projection (`final.md` §25 step 10, §26 provenance).
//!
//! Coverage: rebuild determinism, provenance traceability, expiry fail-closed,
//! the redaction seam (content omitted, provenance retained, journal + its
//! `verify_chain()` untouched), and negative/edge cases (empty journal,
//! last-writer-wins on a re-written id).
//!
//! The workspace denies `unwrap`/`expect`, so these tests unwrap through small
//! panic-on-`None` helpers instead.

use beater_os_core::{
    BeaterOsError, DataClass, InMemoryJournal, JournalEvent, JournalSnapshot, MemoryRecord,
    TaintLabel,
};
use beater_os_memory::{
    JournalRecords, MemoryContextRejectReason, MemoryContextRequest, MemoryContextWarning,
    MemoryProjection, ProjectedMemory, REDACTION_PLACEHOLDER, RedactionDirective, project,
    project_with_redactions,
};
use chrono::{DateTime, Utc};

fn ts(secs: i64) -> DateTime<Utc> {
    // Fixed, deterministic timestamps; falls back to `now` only if `secs` is
    // out of range (it never is for these small values).
    DateTime::from_timestamp(secs, 0).unwrap_or_else(Utc::now)
}

/// Panic-on-`None` accessor so tests fail loudly without tripping the
/// workspace `expect_used` lint.
fn memory_of<'a>(projection: &'a MemoryProjection, id: &str) -> &'a ProjectedMemory {
    match projection.get(id) {
        Some(memory) => memory,
        None => panic!("expected memory {id} in projection"),
    }
}

fn memory(id: &str, source_event: &str, expires_at: Option<DateTime<Utc>>) -> MemoryRecord {
    MemoryRecord {
        memory_id: id.to_string(),
        source_event_id: source_event.to_string(),
        source_digest: format!("digest-of-{source_event}"),
        writer: format!("writer-{id}"),
        created_at: ts(1_000),
        scope: None,
        kind: "note".to_string(),
        content_ref: format!("content://{id}"),
        summary: format!("summary of {id}"),
        confidence_basis_points: 8_000,
        sensitivity: DataClass::Internal,
        source_taint: Default::default(),
        source_data_classes: Default::default(),
        expires_at,
        access_policy: "default".to_string(),
    }
}

fn sensitive_memory(
    id: &str,
    source_event: &str,
    sensitivity: DataClass,
    confidence_basis_points: u16,
    writer: &str,
) -> MemoryRecord {
    let mut record = memory(id, source_event, None);
    record.sensitivity = sensitivity;
    record.confidence_basis_points = confidence_basis_points;
    record.writer = writer.to_string();
    record
}

/// A journal that writes the given memories in order, plus a non-memory event
/// (`IncidentAnnotated`) first to prove non-memory records are ignored.
fn journal_with(memories: Vec<MemoryRecord>) -> InMemoryJournal {
    let mut journal = InMemoryJournal::new();
    if journal
        .append(
            JournalEvent::IncidentAnnotated {
                incident_id: "i-1".to_string(),
                note: "unrelated".to_string(),
            },
            ts(500),
        )
        .is_err()
    {
        panic!("append incident failed");
    }
    for (idx, mem) in memories.into_iter().enumerate() {
        if journal
            .append(
                JournalEvent::IncidentAnnotated {
                    incident_id: mem.source_event_id.clone(),
                    note: format!("source for {}", mem.memory_id),
                },
                ts(750 + idx as i64),
            )
            .is_err()
        {
            panic!("append memory source failed");
        }
        if journal
            .append(
                JournalEvent::MemoryWritten { memory: mem },
                ts(1_000 + idx as i64),
            )
            .is_err()
        {
            panic!("append memory failed");
        }
    }
    journal
}

#[test]
fn empty_journal_projects_to_empty() {
    let journal = InMemoryJournal::new();
    let projection = project(&journal, ts(10_000));
    assert!(projection.is_empty());
    assert_eq!(projection.len(), 0);
    assert_eq!(projection.active_count(), 0);
    assert_eq!(projection.expired_count(), 0);
    assert!(projection.all_traceable()); // vacuously true
    assert!(projection.provenance("missing").is_none());
    assert!(projection.get("missing").is_none());
}

#[test]
fn journal_rejects_unprovenanced_memory_before_projection() {
    let mut journal = InMemoryJournal::new();
    let err = journal
        .append(
            JournalEvent::MemoryWritten {
                memory: memory("m-a", "", None),
            },
            ts(1_000),
        )
        .err();
    let Some(BeaterOsError::JournalCausality { reason, .. }) = err else {
        panic!("expected journal causality error");
    };
    assert!(reason.contains("empty source_event_id"));
    let projection = project(&journal, ts(5_000));
    assert!(projection.is_empty());
}

#[test]
fn non_memory_events_are_ignored() {
    // Only the incident event, no MemoryWritten.
    let journal = journal_with(vec![]);
    let projection = project(&journal, ts(10_000));
    assert!(projection.is_empty());
}

#[test]
fn rebuild_is_deterministic_and_idempotent() {
    let journal = journal_with(vec![
        memory("m-b", "e-2", None),
        memory("m-a", "e-1", None),
        memory("m-c", "e-3", Some(ts(2_000))),
    ]);
    let now = ts(5_000);

    let first = project(&journal, now);
    let second = project(&journal, now);
    assert_eq!(first, second, "projecting twice must be identical");

    // Rebuild from an independent snapshot yields the same projection
    // (§12.6 "derived memory can be rebuilt").
    let snapshot: JournalSnapshot = journal.snapshot();
    let from_snapshot = project(&snapshot, now);
    assert_eq!(first, from_snapshot);

    // Rebuild from a raw record vector, too.
    let from_records = project(&journal.records().to_vec(), now);
    assert_eq!(first, from_records);

    // Deterministic ordering by memory_id.
    let ids: Vec<&str> = first
        .audit_view()
        .map(|m| m.record().memory_id.as_str())
        .collect();
    assert_eq!(ids, vec!["m-a", "m-b", "m-c"]);
}

#[test]
fn provenance_is_traceable_to_source_event_and_writer() {
    let journal = journal_with(vec![memory("m-a", "e-1", None), memory("m-b", "e-2", None)]);
    let projection = project(&journal, ts(5_000));

    assert!(projection.all_traceable());

    let Some(prov) = projection.provenance("m-b") else {
        panic!("m-b provenance missing");
    };
    assert_eq!(prov.memory_id, "m-b");
    assert_eq!(prov.source_event_id, "e-2");
    assert_eq!(prov.source_digest, "digest-of-e-2");
    assert_eq!(prov.writer, "writer-m-b");

    // The provenance seq/hash must point at the actual journal record that wrote it.
    let Some(record) = journal.records().iter().find(
        |r| matches!(&r.event, JournalEvent::MemoryWritten { memory } if memory.memory_id == "m-b"),
    ) else {
        panic!("m-b record missing");
    };
    assert_eq!(prov.journal_seq, record.seq);
    assert_eq!(prov.journal_record_hash, record.hash);

    // Provenance mirrors the record's own source fields.
    let projected = memory_of(&projection, "m-b");
    assert_eq!(projected.record().source_event_id, prov.source_event_id);
    assert_eq!(projected.provenance().writer, "writer-m-b");
}

#[test]
fn expiry_is_fail_closed_excluded_from_active_present_in_audit() {
    let now = ts(5_000);
    let journal = journal_with(vec![
        memory("live", "e-1", Some(ts(9_000))), // expires later -> active
        memory("dead", "e-2", Some(ts(3_000))), // already expired -> audit only
        memory("boundary", "e-3", Some(now)),   // expires_at == now -> expired (<=)
        memory("eternal", "e-4", None),         // no expiry -> active
    ]);
    let projection = project(&journal, now);

    let active: Vec<&str> = projection
        .active()
        .map(|m| m.record().memory_id.as_str())
        .collect();
    assert_eq!(active, vec!["eternal", "live"]);

    let expired: Vec<&str> = projection
        .expired()
        .map(|m| m.record().memory_id.as_str())
        .collect();
    assert_eq!(expired, vec!["boundary", "dead"]);

    assert_eq!(projection.active_count(), 2);
    assert_eq!(projection.expired_count(), 2);

    // Expired memory is still present for audit and still fully traceable.
    let dead = memory_of(&projection, "dead");
    assert!(dead.is_expired());
    assert!(!dead.is_active());
    assert_eq!(dead.provenance().source_event_id, "e-2");
    assert!(projection.all_traceable());

    // Boundary is inclusive: expires_at <= now is expired.
    assert!(memory_of(&projection, "boundary").is_expired());
    assert!(memory_of(&projection, "live").is_active());
}

#[test]
fn last_writer_wins_on_rewritten_memory_id() {
    let mut updated = memory("m-a", "e-2", None);
    updated.summary = "updated summary".to_string();
    updated.content_ref = "content://m-a/v2".to_string();
    updated.confidence_basis_points = 9_500;

    let journal = journal_with(vec![
        memory("m-a", "e-1", None), // seq lower
        updated,                    // seq higher -> wins
    ]);
    let projection = project(&journal, ts(5_000));

    assert_eq!(projection.len(), 1, "same id collapses to one memory");
    let winner = memory_of(&projection, "m-a");
    assert_eq!(winner.record().summary, "updated summary");
    assert_eq!(winner.record().content_ref, "content://m-a/v2");
    assert_eq!(winner.record().confidence_basis_points, 9_500);

    // Provenance tracks the winning (latest) write.
    assert_eq!(winner.provenance().source_event_id, "e-2");
    let Some(last) = journal.records().last() else {
        panic!("journal has no records");
    };
    assert_eq!(winner.provenance().journal_seq, last.seq);
}

#[test]
fn last_writer_wins_by_seq_even_for_out_of_order_record_vectors() {
    let mut updated = memory("m-a", "e-2", None);
    updated.summary = "updated summary".to_string();
    updated.content_ref = "content://m-a/v2".to_string();

    let journal = journal_with(vec![
        memory("m-a", "e-1", None), // lower seq
        updated,                    // higher seq
    ]);
    let mut records = journal.records().to_vec();
    records.reverse();

    let projection = project(&records, ts(5_000));

    assert_eq!(projection.len(), 1);
    let winner = memory_of(&projection, "m-a");
    assert_eq!(winner.record().summary, "updated summary");
    assert_eq!(winner.provenance().source_event_id, "e-2");
}

#[test]
fn redaction_omits_content_but_retains_provenance_and_metadata() {
    let journal = journal_with(vec![
        memory("secret", "e-1", None),
        memory("public", "e-2", None),
    ]);
    let now = ts(5_000);

    let directives = vec![RedactionDirective::new("secret")];
    let projection = project_with_redactions(&journal, now, &directives);

    let secret = memory_of(&projection, "secret");
    assert!(secret.is_redacted());
    // Content omitted / replaced.
    assert_eq!(secret.record().content_ref, REDACTION_PLACEHOLDER);
    assert_eq!(secret.record().summary, REDACTION_PLACEHOLDER);
    // Provenance and metadata retained.
    assert_eq!(secret.provenance().source_event_id, "e-1");
    assert_eq!(secret.provenance().writer, "writer-secret");
    assert_eq!(secret.record().sensitivity, DataClass::Internal);
    assert_eq!(secret.record().memory_id, "secret");
    assert!(projection.all_traceable());

    // A non-redacted memory is untouched.
    let public = memory_of(&projection, "public");
    assert!(!public.is_redacted());
    assert_eq!(public.record().content_ref, "content://public");

    // Custom replacement text is honored.
    let custom = vec![RedactionDirective {
        memory_id: "secret".to_string(),
        replacement: Some("TOMBSTONE".to_string()),
    }];
    let custom_proj = project_with_redactions(&journal, now, &custom);
    assert_eq!(
        memory_of(&custom_proj, "secret").record().content_ref,
        "TOMBSTONE"
    );
}

#[test]
fn redaction_never_mutates_the_journal_or_breaks_the_hash_chain() {
    let journal = journal_with(vec![memory("secret", "e-1", None)]);
    let before = journal.snapshot();
    let before_root = journal.root_hash();
    let Ok(before_report) = journal.verify_chain() else {
        panic!("chain invalid before redaction");
    };

    let directives = vec![RedactionDirective::new("secret")];
    let projection = project_with_redactions(&journal, ts(5_000), &directives);
    assert!(memory_of(&projection, "secret").is_redacted());

    // The journal is byte-for-byte identical and still verifies.
    assert_eq!(journal.snapshot(), before);
    assert_eq!(journal.root_hash(), before_root);
    let Ok(after_report) = journal.verify_chain() else {
        panic!("chain invalid after redaction");
    };
    assert_eq!(before_report, after_report);

    // The journaled memory still carries its real content (redaction is view-only).
    let Some(raw) = journal.records().iter().find_map(|r| match &r.event {
        JournalEvent::MemoryWritten { memory } => Some(memory),
        _ => None,
    }) else {
        panic!("journaled memory missing");
    };
    assert_eq!(raw.content_ref, "content://secret");
}

#[test]
fn redaction_directive_for_unknown_id_is_a_no_op() {
    let journal = journal_with(vec![memory("m-a", "e-1", None)]);
    let directives = vec![RedactionDirective::new("does-not-exist")];
    let projection = project_with_redactions(&journal, ts(5_000), &directives);
    assert_eq!(projection.len(), 1);
    assert!(!memory_of(&projection, "m-a").is_redacted());
}

#[test]
fn context_selection_filters_poison_risks_and_keeps_source_provenance() {
    let mut trusted = sensitive_memory(
        "trusted",
        "e-1",
        DataClass::Internal,
        9_000,
        "writer:trusted",
    );
    trusted.scope = Some("session:alpha".to_string());
    trusted.source_data_classes.insert(DataClass::Internal);

    let mut secret = sensitive_memory("secret", "e-2", DataClass::Secret, 9_500, "writer:trusted");
    secret.scope = Some("session:alpha".to_string());
    secret.source_data_classes.insert(DataClass::Secret);

    let mut low_confidence = sensitive_memory(
        "low-confidence",
        "e-3",
        DataClass::Internal,
        1_000,
        "writer:trusted",
    );
    low_confidence.scope = Some("session:alpha".to_string());

    let mut untrusted_writer = sensitive_memory(
        "untrusted-writer",
        "e-4",
        DataClass::Internal,
        9_000,
        "writer:web",
    );
    untrusted_writer.scope = Some("session:alpha".to_string());
    untrusted_writer
        .source_taint
        .insert(TaintLabel::UntrustedWeb);

    let journal = journal_with(vec![trusted, secret, low_confidence, untrusted_writer]);
    let projection = project(&journal, ts(5_000));
    let request = MemoryContextRequest {
        scope: Some("session:alpha".to_string()),
        min_confidence_basis_points: 5_000,
        allowed_sensitivities: [DataClass::Public, DataClass::Internal]
            .into_iter()
            .collect(),
        denied_source_taint: [TaintLabel::UntrustedWeb].into_iter().collect(),
        denied_source_data_classes: [DataClass::Secret].into_iter().collect(),
        trusted_writers: ["writer:trusted".to_string()].into_iter().collect(),
        ..MemoryContextRequest::default()
    };

    let selection = projection.select_context(&request);
    assert_eq!(selection.selected.len(), 1);
    assert_eq!(selection.selected[0].memory_id, "trusted");
    assert_eq!(
        selection.selected[0].scope.as_deref(),
        Some("session:alpha")
    );
    assert_eq!(
        selection.selected[0].provenance.source_event_id, "e-1",
        "selected context must carry memory source id"
    );
    assert!(
        selection.selected[0]
            .provenance
            .source_journal_seq
            .is_some(),
        "selected context must anchor the source journal record"
    );
    assert!(selection.selected[0].content_ref.is_none());
    assert!(
        selection.selected[0]
            .warnings
            .contains(&MemoryContextWarning::MemoryIsContextNotAuthority)
    );
    assert!(
        selection.selected[0]
            .warnings
            .contains(&MemoryContextWarning::ContentRefOmitted)
    );

    let rejected = selection
        .rejected
        .iter()
        .map(|rejection| {
            (
                rejection.memory_id.as_str(),
                rejection.reasons.as_slice(),
                rejection.provenance.source_event_id.as_str(),
            )
        })
        .collect::<Vec<_>>();
    assert!(rejected.iter().any(|(id, reasons, source)| {
        *id == "secret"
            && *source == "e-2"
            && reasons.contains(&MemoryContextRejectReason::SensitivityNotAllowed)
            && reasons.contains(&MemoryContextRejectReason::SourceDataClassDenied)
    }));
    assert!(rejected.iter().any(|(id, reasons, source)| {
        *id == "low-confidence"
            && *source == "e-3"
            && reasons.contains(&MemoryContextRejectReason::ConfidenceTooLow)
    }));
    assert!(rejected.iter().any(|(id, reasons, source)| {
        *id == "untrusted-writer"
            && *source == "e-4"
            && reasons.contains(&MemoryContextRejectReason::SourceTaintDenied)
            && reasons.contains(&MemoryContextRejectReason::WriterNotTrusted)
    }));
}

#[test]
fn context_selection_is_bounded_and_orders_by_confidence_then_recency() {
    let mut older = sensitive_memory("older", "e-1", DataClass::Internal, 9_000, "writer:trusted");
    older.created_at = ts(900);
    let mut newer = sensitive_memory("newer", "e-2", DataClass::Internal, 9_000, "writer:trusted");
    newer.created_at = ts(1_100);
    let highest = sensitive_memory(
        "highest-confidence",
        "e-3",
        DataClass::Internal,
        9_500,
        "writer:trusted",
    );
    let journal = journal_with(vec![older, newer, highest]);
    let projection = project(&journal, ts(5_000));
    let request = MemoryContextRequest {
        max_items: Some(2),
        allowed_sensitivities: [DataClass::Internal].into_iter().collect(),
        trusted_writers: ["writer:trusted".to_string()].into_iter().collect(),
        ..MemoryContextRequest::default()
    };

    let selection = projection.select_context(&request);
    let selected_ids = selection
        .selected
        .iter()
        .map(|item| item.memory_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(selected_ids, vec!["highest-confidence", "newer"]);
    assert_eq!(selection.truncated, 1);
}

#[test]
fn context_selection_rejects_memory_without_source_record_anchor() {
    let journal = journal_with(vec![memory("m-a", "e-1", None)]);
    let memory_only_records = journal
        .records()
        .iter()
        .filter(|record| matches!(record.event, JournalEvent::MemoryWritten { .. }))
        .cloned()
        .collect::<Vec<_>>();
    let projection = project(&memory_only_records, ts(5_000));

    let selection = projection.select_context(&MemoryContextRequest::default());
    assert!(selection.selected.is_empty());
    assert_eq!(selection.rejected.len(), 1);
    assert!(
        selection.rejected[0]
            .reasons
            .contains(&MemoryContextRejectReason::SourceRecordMissing)
    );
}

#[test]
fn context_selection_bounds_rejections_and_preserves_safe_json_defaults() {
    let mut first = sensitive_memory("first", "e-1", DataClass::Secret, 9_000, "writer:trusted");
    first.source_data_classes.insert(DataClass::Secret);
    let mut second = sensitive_memory("second", "e-2", DataClass::Secret, 9_000, "writer:trusted");
    second.source_data_classes.insert(DataClass::Secret);
    let journal = journal_with(vec![first, second]);
    let projection = project(&journal, ts(5_000));

    let request: MemoryContextRequest = match serde_json::from_value(serde_json::json!({
        "max_rejections": 1
    })) {
        Ok(request) => request,
        Err(err) => panic!("memory context request should deserialize: {err}"),
    };
    assert!(
        request.allowed_sensitivities.contains(&DataClass::Internal),
        "partial JSON must keep the safe public/internal sensitivity default"
    );
    let selection = projection.select_context(&request);
    assert!(selection.selected.is_empty());
    assert_eq!(selection.rejected.len(), 1);
    assert_eq!(selection.truncated_rejections, 1);
}

#[test]
fn journal_records_trait_accepts_journal_snapshot_and_vec_after_context_selection() {
    let journal = journal_with(vec![memory("m-a", "e-1", None)]);
    let snapshot = journal.snapshot();
    let records: Vec<_> = journal.records().to_vec();
    let now = ts(5_000);

    let a: MemoryProjection = project(&journal, now);
    let b: MemoryProjection = project(&snapshot, now);
    let c: MemoryProjection = project(&records, now);

    assert_eq!(a, b);
    assert_eq!(a, c);
    // Trait method is reachable directly.
    assert_eq!(snapshot.journal_records().len(), journal.records().len());
}

#[test]
fn count_by_sensitivity_separates_data_classes_after_context_selection() {
    let mut secret = memory("s", "e-1", None);
    secret.sensitivity = DataClass::Secret;
    let journal = journal_with(vec![secret, memory("i", "e-2", None)]);
    let projection = project(&journal, ts(5_000));
    assert_eq!(projection.count_by_sensitivity(DataClass::Secret), 1);
    assert_eq!(projection.count_by_sensitivity(DataClass::Internal), 1);
    assert_eq!(projection.count_by_sensitivity(DataClass::Financial), 0);
}
