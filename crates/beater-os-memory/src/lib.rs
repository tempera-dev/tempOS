//! Accountable memory projection for tempOS.
//!
//! This crate realizes `final.md` §25 build-order step 10 ("Memory projection
//! from journal") and the §10.8 Memory Service responsibilities of *building
//! projections*, *serving context with provenance*, *enforcing retention*, and
//! *supporting redaction*. It exists to keep the §26 NEVER-compromise invariant
//! **"Memory provenance"** true by construction: memory is a deterministic
//! *fold* over the append-only, hash-chained journal, never a separate mutable
//! store that could drift from the audit trail.
//!
//! Every projected memory originates from a [`JournalEvent::MemoryWritten`]
//! record, so it is always traceable back to a journaled source event, its
//! writer, and the exact journal record (seq + hash) that wrote it. Replaying
//! the same journal always yields the same projection.
//!
//! # Before Coding (per `CLAUDE.md`)
//!
//! - **Critical path.** [`project`] / [`project_with_redactions`] is a single
//!   linear pass over the journal records; provenance and expiry are decided
//!   inline. Provenance/active lookups after projection are `O(log n)`
//!   `BTreeMap` reads. There is no non-critical background path — the projection
//!   is a pure value computed on demand.
//! - **Allocation / copy / syscall.** No syscalls, no I/O, no async. Bounded by
//!   journal size: one [`ProjectedMemory`] per *distinct* `memory_id` (a later
//!   `MemoryWritten` for the same id replaces the earlier one — last-writer-wins),
//!   so memory never grows past the number of live memory ids. Each surviving
//!   record is cloned once into the projection; non-memory records are skipped
//!   without allocation.
//! - **Queue / retry bounds.** None. The projection is synchronous and total; it
//!   cannot block, retry, or fail partway. Determinism comes from folding in
//!   journal (seq) order into an ordered [`std::collections::BTreeMap`].
//! - **Failure mode under overload.** Fails *closed* on the safety-relevant
//!   axes: an expired memory (`expires_at <= now`) is excluded from
//!   [`MemoryProjection::active`] and confers nothing; it survives only in the
//!   audit view for accountability. A redacted memory keeps its provenance but
//!   surrenders its `content_ref`/`summary`. There is no code path that serves a
//!   memory without provenance.
//! - **Security boundary & evidence.** The evidence is the journal itself. This
//!   crate reads a journal/snapshot and *never mutates it* — redaction is a
//!   projection-layer concern (see [`RedactionDirective`]) so the hash chain and
//!   [`beater_os_core::InMemoryJournal::verify_chain`] remain intact. The
//!   accountability chain for any memory is exposed via
//!   [`MemoryProjection::provenance`].
//! - **Language / Rust tie-breaker.** Pure deterministic in-memory fold over
//!   core contracts: idiomatic safe Rust, no FFI, no unsafe (workspace forbids
//!   it). No tie-breaker in play.
//! - **macOS impact.** None. No platform-specific code, I/O, or dependencies
//!   beyond `beater-os-core` and `chrono`.
//! - **Local verification.**
//!   `cargo test -p beater-os-memory && cargo clippy -p beater-os-memory --all-targets -- -D warnings`
//!
//! # Redaction seam (issue #9)
//!
//! The append-only, hash-chained journal must NEVER be mutated; doing so would
//! break §26 integrity. So redaction is modeled here as a *projection input*: a
//! [`RedactionDirective`] omits/replaces a memory's `content_ref` and `summary`
//! in the projected view while keeping its provenance metadata, and the
//! underlying journal record (and its hash) is left untouched. This crate
//! provides the *mechanism/seam* only. The deep policy question of append-only
//! integrity vs. a right-to-be-forgotten is tracked in **issue #9** and is
//! intentionally NOT decided here.
//!
//! ```
//! use beater_os_memory::project;
//! use beater_os_core::InMemoryJournal;
//! use chrono::Utc;
//!
//! let journal = InMemoryJournal::new();
//! let projection = project(&journal, Utc::now());
//! assert!(projection.is_empty());
//! ```

use std::cmp::Reverse;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use beater_os_core::{DataClass, MemoryRecord, TaintLabel};
use beater_os_core::{HashValue, InMemoryJournal, JournalEvent, JournalRecord, JournalSnapshot};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Default replacement text substituted for a redacted memory's `content_ref`
/// and `summary` when a [`RedactionDirective`] supplies no explicit replacement.
pub const REDACTION_PLACEHOLDER: &str = "[redacted]";

/// Anything that exposes a slice of journal records in append order.
///
/// Implemented for [`InMemoryJournal`], [`JournalSnapshot`], and a raw
/// `[JournalRecord]` slice so [`project`] accepts a journal or a snapshot
/// interchangeably (the §12.6 "derived memory can be rebuilt" invariant: a
/// snapshot replays to the same projection as the live journal it came from).
pub trait JournalRecords {
    /// The journal records, in append (seq) order.
    fn journal_records(&self) -> &[JournalRecord];
}

impl JournalRecords for InMemoryJournal {
    fn journal_records(&self) -> &[JournalRecord] {
        self.records()
    }
}

impl JournalRecords for JournalSnapshot {
    fn journal_records(&self) -> &[JournalRecord] {
        &self.records
    }
}

impl JournalRecords for Vec<JournalRecord> {
    fn journal_records(&self) -> &[JournalRecord] {
        self
    }
}

/// A projection-layer directive to redact a memory's content by `memory_id`.
///
/// This does NOT touch the journal (see the crate-level "Redaction seam" note
/// and issue #9). It only tells [`project_with_redactions`] to replace the
/// projected memory's `content_ref`/`summary` while preserving its provenance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedactionDirective {
    /// The memory whose content is to be omitted from the projected view.
    pub memory_id: String,
    /// Replacement text for `content_ref`/`summary`. `None` uses
    /// [`REDACTION_PLACEHOLDER`].
    pub replacement: Option<String>,
}

impl RedactionDirective {
    /// Redact `memory_id` with the default [`REDACTION_PLACEHOLDER`].
    pub fn new(memory_id: impl Into<String>) -> Self {
        Self {
            memory_id: memory_id.into(),
            replacement: None,
        }
    }

    fn replacement_text(&self) -> &str {
        self.replacement.as_deref().unwrap_or(REDACTION_PLACEHOLDER)
    }
}

/// The accountability chain for a single projected memory (§26 "Memory
/// provenance"): where it came from, who wrote it, and the exact journal record
/// that recorded it. Every [`ProjectedMemory`] has one; a memory without a
/// journaled source is impossible by construction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryProvenance {
    /// The memory this provenance describes.
    pub memory_id: String,
    /// The source event that gave rise to the memory (`MemoryRecord::source_event_id`).
    pub source_event_id: String,
    /// Digest of the source material (`MemoryRecord::source_digest`).
    pub source_digest: String,
    /// The principal that wrote the memory (`MemoryRecord::writer`).
    pub writer: String,
    /// `seq` of the journal record whose `MemoryWritten` event wrote this memory.
    pub journal_seq: u64,
    /// Hash of that journal record — anchors the memory into the hash chain.
    pub journal_record_hash: HashValue,
    /// `seq` of the journal event named by `source_event_id`, when present in
    /// the projected record set.
    #[serde(default)]
    pub source_journal_seq: Option<u64>,
    /// Hash of the journal event named by `source_event_id`, when present in
    /// the projected record set.
    #[serde(default)]
    pub source_record_hash: Option<HashValue>,
    /// When the memory was written (`MemoryRecord::created_at`).
    pub created_at: DateTime<Utc>,
}

/// One memory in the projection: the (possibly redacted) record, its
/// provenance, and its expiry/redaction status at the projection's `now`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectedMemory {
    record: MemoryRecord,
    provenance: MemoryProvenance,
    expired: bool,
    redacted: bool,
}

impl ProjectedMemory {
    /// The projected memory record. If [`Self::is_redacted`], `content_ref` and
    /// `summary` are the replacement text; all other fields are as journaled.
    pub fn record(&self) -> &MemoryRecord {
        &self.record
    }

    /// The accountability chain for this memory. Always present.
    pub fn provenance(&self) -> &MemoryProvenance {
        &self.provenance
    }

    /// `true` if `expires_at <= now`. Expired memory is excluded from
    /// [`MemoryProjection::active`] and confers nothing (fail-closed).
    pub fn is_expired(&self) -> bool {
        self.expired
    }

    /// `true` if a [`RedactionDirective`] omitted this memory's content.
    pub fn is_redacted(&self) -> bool {
        self.redacted
    }

    /// `true` if the memory may be served in the active context view (not expired).
    pub fn is_active(&self) -> bool {
        !self.expired
    }
}

/// The current memory state derived from a journal at a fixed `now`.
///
/// Deterministic and idempotent: [`project`]-ing the same records with the same
/// `now` (and redactions) always yields an equal `MemoryProjection`. Ordered by
/// `memory_id` for stable iteration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryProjection {
    projected_at: DateTime<Utc>,
    memories: BTreeMap<String, ProjectedMemory>,
}

impl MemoryProjection {
    /// The `now` this projection was computed at (the expiry cut-off).
    pub fn projected_at(&self) -> DateTime<Utc> {
        self.projected_at
    }

    /// Total number of distinct memories (active + expired).
    pub fn len(&self) -> usize {
        self.memories.len()
    }

    /// `true` if no memory has been written to the projected journal.
    pub fn is_empty(&self) -> bool {
        self.memories.is_empty()
    }

    /// Look up a memory by id, regardless of expiry.
    pub fn get(&self, memory_id: &str) -> Option<&ProjectedMemory> {
        self.memories.get(memory_id)
    }

    /// The accountability chain for a memory id, if it exists (§26 provenance
    /// query).
    pub fn provenance(&self, memory_id: &str) -> Option<&MemoryProvenance> {
        self.memories
            .get(memory_id)
            .map(ProjectedMemory::provenance)
    }

    /// The active context view: memories that are not expired. Redacted memories
    /// are included but carry no content. Ordered by `memory_id`.
    pub fn active(&self) -> impl Iterator<Item = &ProjectedMemory> {
        self.memories.values().filter(|m| m.is_active())
    }

    /// The expired memories, retained for audit only (never served). Ordered by
    /// `memory_id`.
    pub fn expired(&self) -> impl Iterator<Item = &ProjectedMemory> {
        self.memories.values().filter(|m| m.is_expired())
    }

    /// Every projected memory, active and expired, for accountability/audit.
    /// Ordered by `memory_id`.
    pub fn audit_view(&self) -> impl Iterator<Item = &ProjectedMemory> {
        self.memories.values()
    }

    /// Count of memories servable in the active view.
    pub fn active_count(&self) -> usize {
        self.active().count()
    }

    /// Count of expired (audit-only) memories.
    pub fn expired_count(&self) -> usize {
        self.expired().count()
    }

    /// The §26 invariant, checkable: every projected memory is traceable to a
    /// journaled source event. True by construction (projections only ingest
    /// [`JournalEvent::MemoryWritten`] records, each carrying a
    /// `source_event_id`); exposed so callers and tests can assert it.
    pub fn all_traceable(&self) -> bool {
        self.memories
            .values()
            .all(|m| !m.provenance.source_event_id.is_empty())
    }

    /// Count of memories at a given sensitivity class (§10.8 "separate data
    /// classes"). Redaction does not change a memory's sensitivity.
    pub fn count_by_sensitivity(&self, sensitivity: DataClass) -> usize {
        self.memories
            .values()
            .filter(|m| m.record.sensitivity == sensitivity)
            .count()
    }

    /// Select bounded, provenance-carrying memories for model/runtime context.
    ///
    /// This is the policy-facing context view. It never treats memory as
    /// authority: selected items are evidence with provenance and explicit
    /// warnings, while every excluded active/expired item gets a structured
    /// rejection reason for audit and prompt-debugging.
    pub fn select_context(&self, request: &MemoryContextRequest) -> MemoryContextSelection {
        let mut accepted = Vec::new();
        let mut rejected = Vec::new();
        let max_items = request.max_items.unwrap_or(DEFAULT_MEMORY_CONTEXT_LIMIT);
        let max_rejections = request
            .max_rejections
            .unwrap_or(DEFAULT_MEMORY_CONTEXT_REJECTION_LIMIT);
        let mut truncated_rejections = 0;

        for memory in self.audit_view() {
            let reasons = memory_context_rejection_reasons(memory, request);
            if reasons.is_empty() {
                accepted.push(memory);
            } else if rejected.len() < max_rejections {
                rejected.push(MemoryContextRejection {
                    memory_id: memory.record.memory_id.clone(),
                    reasons,
                    provenance: memory.provenance.clone(),
                });
            } else {
                truncated_rejections += 1;
            }
        }

        accepted.sort_by_key(|memory| {
            (
                Reverse(memory.record.confidence_basis_points),
                Reverse(memory.record.created_at.timestamp_millis()),
                memory.record.memory_id.clone(),
            )
        });
        let truncated = accepted.len().saturating_sub(max_items);
        let selected = accepted
            .into_iter()
            .take(max_items)
            .map(|memory| MemoryContextItem {
                memory_id: memory.record.memory_id.clone(),
                scope: memory.record.scope.clone(),
                kind: memory.record.kind.clone(),
                content_ref: if request.include_content_refs {
                    Some(memory.record.content_ref.clone())
                } else {
                    None
                },
                summary: memory.record.summary.clone(),
                confidence_basis_points: memory.record.confidence_basis_points,
                sensitivity: memory.record.sensitivity,
                source_taint: memory.record.source_taint.clone(),
                source_data_classes: memory.record.source_data_classes.clone(),
                access_policy: memory.record.access_policy.clone(),
                provenance: memory.provenance.clone(),
                warnings: memory_context_warnings(memory, request),
            })
            .collect();

        MemoryContextSelection {
            projected_at: self.projected_at,
            selected,
            rejected,
            truncated,
            truncated_rejections,
            selection_policy: request.summary(),
        }
    }
}

/// Default upper bound for context memories when a request does not specify one.
pub const DEFAULT_MEMORY_CONTEXT_LIMIT: usize = 16;
/// Default upper bound for structured context rejections returned to callers.
pub const DEFAULT_MEMORY_CONTEXT_REJECTION_LIMIT: usize = 64;

/// Request for a bounded, policy-filtered memory context view.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryContextRequest {
    /// Optional memory scope. When set, only records with the same
    /// `MemoryRecord::scope` are selectable.
    #[serde(default)]
    pub scope: Option<String>,
    /// Maximum number of selected context items. `None` uses
    /// [`DEFAULT_MEMORY_CONTEXT_LIMIT`].
    #[serde(default)]
    pub max_items: Option<usize>,
    /// Maximum number of structured rejections to retain in the returned
    /// selection. `None` uses [`DEFAULT_MEMORY_CONTEXT_REJECTION_LIMIT`].
    #[serde(default)]
    pub max_rejections: Option<usize>,
    /// Minimum confidence required to select a memory. Defaults to zero.
    #[serde(default)]
    pub min_confidence_basis_points: u16,
    /// Explicit sensitivity allowlist. Empty means all sensitivities are allowed.
    /// This is deliberately not a linear ceiling over `DataClass`.
    #[serde(default = "default_allowed_memory_sensitivities")]
    pub allowed_sensitivities: BTreeSet<DataClass>,
    /// Source taint labels that must be excluded from selected context.
    #[serde(default)]
    pub denied_source_taint: BTreeSet<TaintLabel>,
    /// Source data classes that must be excluded from selected context.
    #[serde(default)]
    pub denied_source_data_classes: BTreeSet<DataClass>,
    /// Optional allowlist of memory `kind` values.
    #[serde(default)]
    pub allowed_kinds: BTreeSet<String>,
    /// Optional allowlist of `access_policy` values.
    #[serde(default)]
    pub allowed_access_policies: BTreeSet<String>,
    /// Optional allowlist of writers trusted for this context use.
    #[serde(default)]
    pub trusted_writers: BTreeSet<String>,
    /// Whether redacted memories may appear as placeholder summaries. Defaults
    /// false because placeholders are usually not useful context.
    #[serde(default)]
    pub include_redacted: bool,
    /// Whether `content_ref` is included in selected items. Defaults false so
    /// model-facing context can carry summaries/provenance without extra
    /// dereference capability.
    #[serde(default)]
    pub include_content_refs: bool,
    /// Require the source event named by `source_event_id` to be present in the
    /// projected record set and anchored by seq/hash. Defaults true so raw,
    /// partial record vectors cannot silently become model context.
    #[serde(default = "default_require_verified_source")]
    pub require_verified_source: bool,
}

impl Default for MemoryContextRequest {
    fn default() -> Self {
        Self {
            max_items: Some(DEFAULT_MEMORY_CONTEXT_LIMIT),
            max_rejections: Some(DEFAULT_MEMORY_CONTEXT_REJECTION_LIMIT),
            min_confidence_basis_points: 0,
            scope: None,
            allowed_sensitivities: default_allowed_memory_sensitivities(),
            denied_source_taint: BTreeSet::new(),
            denied_source_data_classes: BTreeSet::new(),
            allowed_kinds: BTreeSet::new(),
            allowed_access_policies: BTreeSet::new(),
            trusted_writers: BTreeSet::new(),
            include_redacted: false,
            include_content_refs: false,
            require_verified_source: default_require_verified_source(),
        }
    }
}

impl MemoryContextRequest {
    fn summary(&self) -> MemoryContextPolicySummary {
        MemoryContextPolicySummary {
            max_items: self.max_items.unwrap_or(DEFAULT_MEMORY_CONTEXT_LIMIT),
            max_rejections: self
                .max_rejections
                .unwrap_or(DEFAULT_MEMORY_CONTEXT_REJECTION_LIMIT),
            min_confidence_basis_points: self.min_confidence_basis_points,
            scope: self.scope.clone(),
            allowed_sensitivities: self.allowed_sensitivities.clone(),
            denied_source_taint: self.denied_source_taint.clone(),
            denied_source_data_classes: self.denied_source_data_classes.clone(),
            allowed_kinds: self.allowed_kinds.clone(),
            allowed_access_policies: self.allowed_access_policies.clone(),
            trusted_writers: self.trusted_writers.clone(),
            include_redacted: self.include_redacted,
            include_content_refs: self.include_content_refs,
            require_verified_source: self.require_verified_source,
        }
    }
}

fn default_require_verified_source() -> bool {
    true
}

fn default_allowed_memory_sensitivities() -> BTreeSet<DataClass> {
    BTreeSet::from([DataClass::Public, DataClass::Internal])
}

fn default_memory_context_limit_value() -> usize {
    DEFAULT_MEMORY_CONTEXT_LIMIT
}

fn default_memory_context_rejection_limit_value() -> usize {
    DEFAULT_MEMORY_CONTEXT_REJECTION_LIMIT
}

/// Serializable result of selecting memory context.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryContextSelection {
    pub projected_at: DateTime<Utc>,
    pub selected: Vec<MemoryContextItem>,
    pub rejected: Vec<MemoryContextRejection>,
    pub truncated: usize,
    #[serde(default)]
    pub truncated_rejections: usize,
    pub selection_policy: MemoryContextPolicySummary,
}

/// One memory selected for context. This is evidence, not authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryContextItem {
    pub memory_id: String,
    #[serde(default)]
    pub scope: Option<String>,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_ref: Option<String>,
    pub summary: String,
    pub confidence_basis_points: u16,
    pub sensitivity: DataClass,
    #[serde(default)]
    pub source_taint: BTreeSet<TaintLabel>,
    #[serde(default)]
    pub source_data_classes: BTreeSet<DataClass>,
    pub access_policy: String,
    pub provenance: MemoryProvenance,
    #[serde(default)]
    pub warnings: Vec<MemoryContextWarning>,
}

/// A memory excluded from context, with audit-visible reasons.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryContextRejection {
    pub memory_id: String,
    pub reasons: Vec<MemoryContextRejectReason>,
    pub provenance: MemoryProvenance,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryContextPolicySummary {
    #[serde(default = "default_memory_context_limit_value")]
    pub max_items: usize,
    #[serde(default = "default_memory_context_rejection_limit_value")]
    pub max_rejections: usize,
    pub min_confidence_basis_points: u16,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default = "default_allowed_memory_sensitivities")]
    pub allowed_sensitivities: BTreeSet<DataClass>,
    #[serde(default)]
    pub denied_source_taint: BTreeSet<TaintLabel>,
    #[serde(default)]
    pub denied_source_data_classes: BTreeSet<DataClass>,
    #[serde(default)]
    pub allowed_kinds: BTreeSet<String>,
    #[serde(default)]
    pub allowed_access_policies: BTreeSet<String>,
    #[serde(default)]
    pub trusted_writers: BTreeSet<String>,
    pub include_redacted: bool,
    pub include_content_refs: bool,
    #[serde(default = "default_require_verified_source")]
    pub require_verified_source: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryContextRejectReason {
    Expired,
    Redacted,
    ConfidenceTooLow,
    ScopeMismatch,
    SensitivityNotAllowed,
    SourceTaintDenied,
    SourceDataClassDenied,
    KindNotAllowed,
    AccessPolicyNotAllowed,
    WriterNotTrusted,
    SourceRecordMissing,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryContextWarning {
    MemoryIsContextNotAuthority,
    WriterTrustNotConstrained,
    ContentRefOmitted,
}

fn memory_context_rejection_reasons(
    memory: &ProjectedMemory,
    request: &MemoryContextRequest,
) -> Vec<MemoryContextRejectReason> {
    let mut reasons = BTreeSet::new();
    if memory.is_expired() {
        reasons.insert(MemoryContextRejectReason::Expired);
    }
    if memory.is_redacted() && !request.include_redacted {
        reasons.insert(MemoryContextRejectReason::Redacted);
    }
    if request.require_verified_source
        && (memory.provenance.source_journal_seq.is_none()
            || memory.provenance.source_record_hash.is_none())
    {
        reasons.insert(MemoryContextRejectReason::SourceRecordMissing);
    }
    if memory.record.confidence_basis_points < request.min_confidence_basis_points {
        reasons.insert(MemoryContextRejectReason::ConfidenceTooLow);
    }
    if let Some(scope) = request.scope.as_deref()
        && memory.record.scope.as_deref() != Some(scope)
    {
        reasons.insert(MemoryContextRejectReason::ScopeMismatch);
    }
    if !request.allowed_sensitivities.is_empty()
        && !request
            .allowed_sensitivities
            .contains(&memory.record.sensitivity)
    {
        reasons.insert(MemoryContextRejectReason::SensitivityNotAllowed);
    }
    if memory
        .record
        .source_taint
        .iter()
        .any(|taint| request.denied_source_taint.contains(taint))
    {
        reasons.insert(MemoryContextRejectReason::SourceTaintDenied);
    }
    if memory
        .record
        .source_data_classes
        .iter()
        .any(|class| request.denied_source_data_classes.contains(class))
    {
        reasons.insert(MemoryContextRejectReason::SourceDataClassDenied);
    }
    if !request.allowed_kinds.is_empty() && !request.allowed_kinds.contains(&memory.record.kind) {
        reasons.insert(MemoryContextRejectReason::KindNotAllowed);
    }
    if !request.allowed_access_policies.is_empty()
        && !request
            .allowed_access_policies
            .contains(&memory.record.access_policy)
    {
        reasons.insert(MemoryContextRejectReason::AccessPolicyNotAllowed);
    }
    if !request.trusted_writers.is_empty()
        && !request.trusted_writers.contains(&memory.provenance.writer)
    {
        reasons.insert(MemoryContextRejectReason::WriterNotTrusted);
    }
    reasons.into_iter().collect()
}

fn memory_context_warnings(
    memory: &ProjectedMemory,
    request: &MemoryContextRequest,
) -> Vec<MemoryContextWarning> {
    let mut warnings = BTreeSet::from([MemoryContextWarning::MemoryIsContextNotAuthority]);
    if request.trusted_writers.is_empty() {
        warnings.insert(MemoryContextWarning::WriterTrustNotConstrained);
    }
    if !request.include_content_refs && !memory.record.content_ref.is_empty() {
        warnings.insert(MemoryContextWarning::ContentRefOmitted);
    }
    warnings.into_iter().collect()
}

/// Project the current memory state from a journal or snapshot at `now`.
///
/// A deterministic fold over every [`JournalEvent::MemoryWritten`] record.
/// Last-writer-wins: if the same `memory_id` is written more than once, the
/// record with the higher `seq` prevails (memory *can be invalidated* / updated;
/// §12.6). Expiry is fail-closed at `now`. Equivalent to
/// [`project_with_redactions`] with no directives.
pub fn project(source: &impl JournalRecords, now: DateTime<Utc>) -> MemoryProjection {
    project_with_redactions(source, now, &[])
}

/// Like [`project`], but applies projection-layer [`RedactionDirective`]s: a
/// redacted memory keeps its provenance and metadata but its
/// `content_ref`/`summary` are replaced. The journal is never mutated.
pub fn project_with_redactions(
    source: &impl JournalRecords,
    now: DateTime<Utc>,
    redactions: &[RedactionDirective],
) -> MemoryProjection {
    let redaction_by_id: BTreeMap<&str, &RedactionDirective> = redactions
        .iter()
        .map(|directive| (directive.memory_id.as_str(), directive))
        .collect();
    let source_records: BTreeMap<&str, (u64, &HashValue)> = source
        .journal_records()
        .iter()
        .filter_map(|record| {
            memory_source_event_id(&record.event)
                .map(|event_id| (event_id, (record.seq, &record.hash)))
        })
        .collect();

    let mut memories: BTreeMap<String, ProjectedMemory> = BTreeMap::new();

    for record in source.journal_records() {
        let JournalEvent::MemoryWritten { memory } = &record.event else {
            continue;
        };

        let provenance = MemoryProvenance {
            memory_id: memory.memory_id.clone(),
            source_event_id: memory.source_event_id.clone(),
            source_digest: memory.source_digest.clone(),
            writer: memory.writer.clone(),
            journal_seq: record.seq,
            journal_record_hash: record.hash.clone(),
            source_journal_seq: source_records
                .get(memory.source_event_id.as_str())
                .map(|(seq, _hash)| *seq),
            source_record_hash: source_records
                .get(memory.source_event_id.as_str())
                .map(|(_seq, hash)| (*hash).clone()),
            created_at: memory.created_at,
        };

        let expired = memory
            .expires_at
            .is_some_and(|expires_at| expires_at <= now);

        let mut projected_record = memory.clone();
        let redacted = match redaction_by_id.get(memory.memory_id.as_str()) {
            Some(directive) => {
                let replacement = directive.replacement_text().to_string();
                projected_record.content_ref = replacement.clone();
                projected_record.summary = replacement;
                true
            }
            None => false,
        };

        // Last-writer-wins by journal seq, not caller iteration order. This
        // keeps raw record vectors deterministic even if the caller hands us an
        // out-of-order slice.
        let projected = ProjectedMemory {
            record: projected_record,
            provenance,
            expired,
            redacted,
        };
        match memories.entry(memory.memory_id.clone()) {
            Entry::Vacant(slot) => {
                slot.insert(projected);
            }
            Entry::Occupied(mut slot) => {
                if record.seq >= slot.get().provenance.journal_seq {
                    slot.insert(projected);
                }
            }
        }
    }

    MemoryProjection {
        projected_at: now,
        memories,
    }
}

fn memory_source_event_id(event: &JournalEvent) -> Option<&str> {
    match event {
        JournalEvent::SessionCreated { session } => Some(session.session_id.as_str()),
        JournalEvent::SessionStatusChanged { transition_id, .. } => Some(transition_id.as_str()),
        JournalEvent::CapabilityGranted { grant } => Some(grant.grant_id.as_str()),
        JournalEvent::CapabilityRevoked {
            revocation_handle, ..
        } => Some(revocation_handle.as_str()),
        JournalEvent::PaymentMandateIssued { mandate } => Some(mandate.mandate_id.as_str()),
        JournalEvent::ActionProposed { manifest } => Some(manifest.action_id.as_str()),
        JournalEvent::PolicyDecided { decision } => Some(decision.decision_id.as_str()),
        JournalEvent::ExecutionLeaseIssued { lease } => Some(lease.lease_id.as_str()),
        JournalEvent::ExecutionLeaseHeartbeated { heartbeat } => {
            Some(heartbeat.heartbeat_id.as_str())
        }
        JournalEvent::ExecutionLeaseReconciled { reconciliation } => {
            Some(reconciliation.reconciliation_id.as_str())
        }
        JournalEvent::ApprovalRecorded { approval } => Some(approval.review_id.as_str()),
        JournalEvent::SimulationRecorded { simulation } => Some(simulation.simulation_id.as_str()),
        JournalEvent::ReceiptAppended { receipt } => Some(receipt.receipt_id.as_str()),
        JournalEvent::ModelRouteDecided { decision } => Some(decision.decision_id.as_str()),
        JournalEvent::MemoryWritten { .. } => None,
        JournalEvent::ScenarioEvaluated { scenario, .. } => Some(scenario.scenario_id.as_str()),
        JournalEvent::IncidentAnnotated { incident_id, .. } => Some(incident_id.as_str()),
    }
}
