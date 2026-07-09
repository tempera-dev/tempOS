//! Policy-aware model route metadata selector for tempOS.
//!
//! This crate is deliberately not a provider SDK. It is the deterministic
//! authority-adjacent layer that decides whether a model call may use a declared
//! route and records why. The router obeys [`ModelPolicy`]; it does not invent
//! policy. Route metadata must be supplied by trusted configuration or generated
//! client code, then selected here before any provider sees prompt data.
//!
//! Critical path: a single pass over a small route catalog, bounded by route
//! count. No network I/O, no model calls, no async queues, no background
//! retries. Sorting is deterministic by cost, latency, locality, and route id.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use beater_os_core::{DataClass, HashValue, ModelPolicy, TaintLabel, hash_json};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type RouterResult<T> = Result<T, ModelRouterError>;

#[derive(Debug, Error)]
pub enum ModelRouterError {
    #[error("route catalog is empty")]
    EmptyCatalog,
    #[error("route {0} is duplicated")]
    DuplicateRoute(String),
    #[error("route request is invalid: {0}")]
    InvalidRequest(String),
    #[error(transparent)]
    Core(#[from] beater_os_core::BeaterOsError),
}

/// Intent class for a model call. Planner and verifier routes can be kept
/// separate even when they share a provider.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelPurpose {
    Planner,
    Executor,
    Verifier,
    Classifier,
    Summarizer,
    Embedder,
    BrowserUse,
    Code,
    Other(String),
}

/// Provider retention class ordered from strictest to loosest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionClass {
    None,
    NoTraining,
    Limited,
    ProviderDefault,
}

/// Where a model route executes relative to the user/workspace trust boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteLocality {
    Local,
    PrivateCloud,
    PublicCloud,
}

impl RouteLocality {
    pub fn is_local(self) -> bool {
        matches!(self, Self::Local)
    }
}

/// Static metadata for one route. This is the canonical input the router
/// trusts; model-authored text must never mint or weaken these fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRoute {
    pub route_id: String,
    pub provider: String,
    pub model: String,
    pub model_version: String,
    pub locality: RouteLocality,
    pub retention: RetentionClass,
    pub max_data_class: Option<DataClass>,
    #[serde(default)]
    pub allowed_purposes: BTreeSet<ModelPurpose>,
    pub pricing: RoutePricing,
    pub p95_latency_ms: u64,
    pub max_context_tokens: u64,
    pub max_output_tokens: u64,
    #[serde(default)]
    pub supports_tools: bool,
    #[serde(default)]
    pub supports_multimodal: bool,
    #[serde(default = "default_route_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub notes: Option<String>,
}

impl ModelRoute {
    pub fn local(
        route_id: impl Into<String>,
        provider: impl Into<String>,
        model: impl Into<String>,
    ) -> Self {
        Self {
            route_id: route_id.into(),
            provider: provider.into(),
            model: model.into(),
            model_version: "unversioned".to_string(),
            locality: RouteLocality::Local,
            retention: RetentionClass::None,
            max_data_class: None,
            allowed_purposes: BTreeSet::new(),
            pricing: RoutePricing::zero(),
            p95_latency_ms: 1_000,
            max_context_tokens: 8_192,
            max_output_tokens: 2_048,
            supports_tools: false,
            supports_multimodal: false,
            enabled: true,
            notes: None,
        }
    }
}

fn default_route_enabled() -> bool {
    true
}

/// Integer route pricing, avoiding float rounding in admission-adjacent code.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutePricing {
    pub input_cents_per_million_tokens: u64,
    pub output_cents_per_million_tokens: u64,
}

impl RoutePricing {
    pub fn zero() -> Self {
        Self {
            input_cents_per_million_tokens: 0,
            output_cents_per_million_tokens: 0,
        }
    }

    pub fn estimate_cents(&self, input_tokens: u64, output_tokens: u64) -> Option<u64> {
        let input = input_tokens.checked_mul(self.input_cents_per_million_tokens)?;
        let output = output_tokens.checked_mul(self.output_cents_per_million_tokens)?;
        ceil_div(input, 1_000_000)?.checked_add(ceil_div(output, 1_000_000)?)
    }
}

/// Trusted model route catalog.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelRouteCatalog {
    routes: BTreeMap<String, ModelRoute>,
}

impl ModelRouteCatalog {
    pub fn new(routes: impl IntoIterator<Item = ModelRoute>) -> RouterResult<Self> {
        let mut by_id = BTreeMap::new();
        for route in routes {
            if route.route_id.trim().is_empty() {
                return Err(ModelRouterError::InvalidRequest(
                    "route_id must not be empty".to_string(),
                ));
            }
            let route_id = route.route_id.clone();
            let previous = by_id.insert(route_id.clone(), route);
            if previous.is_some() {
                return Err(ModelRouterError::DuplicateRoute(route_id));
            }
        }
        if by_id.is_empty() {
            return Err(ModelRouterError::EmptyCatalog);
        }
        Ok(Self { routes: by_id })
    }

    pub fn iter(&self) -> impl Iterator<Item = &ModelRoute> {
        self.routes.values()
    }

    pub fn get(&self, route_id: &str) -> Option<&ModelRoute> {
        self.routes.get(route_id)
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

/// One proposed model call before prompt data is sent to a provider.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRouteRequest {
    pub session_id: String,
    pub purpose: ModelPurpose,
    #[serde(default)]
    pub data_classes: BTreeSet<DataClass>,
    #[serde(default)]
    pub taint: BTreeSet<TaintLabel>,
    pub estimated_input_tokens: u64,
    pub max_output_tokens: u64,
    #[serde(default)]
    pub latency_budget_ms: Option<u64>,
    #[serde(default)]
    pub max_estimated_cents: Option<u64>,
    #[serde(default)]
    pub required_local: bool,
    #[serde(default)]
    pub required_tools: bool,
    #[serde(default)]
    pub required_multimodal: bool,
    pub max_retention: RetentionClass,
    #[serde(default)]
    pub allowed_routes: BTreeSet<String>,
    #[serde(default)]
    pub denied_routes: BTreeSet<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

impl ModelRouteRequest {
    pub fn new(
        session_id: impl Into<String>,
        purpose: ModelPurpose,
        estimated_input_tokens: u64,
        max_output_tokens: u64,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            purpose,
            data_classes: BTreeSet::new(),
            taint: BTreeSet::new(),
            estimated_input_tokens,
            max_output_tokens,
            latency_budget_ms: None,
            max_estimated_cents: None,
            required_local: false,
            required_tools: false,
            required_multimodal: false,
            max_retention: RetentionClass::NoTraining,
            allowed_routes: BTreeSet::new(),
            denied_routes: BTreeSet::new(),
            reason: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelRouteDecisionResult {
    Allowed,
    Denied,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelRouteDecision {
    pub decision_id: HashValue,
    pub session_id: String,
    pub result: ModelRouteDecisionResult,
    pub selected: Option<ModelRouteSelection>,
    pub rejected_routes: Vec<ModelRouteRejection>,
    pub policy_summary: ModelPolicySummary,
    pub requested_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelRouteSelection {
    pub route_id: String,
    pub provider: String,
    pub model: String,
    pub model_version: String,
    pub locality: RouteLocality,
    pub retention: RetentionClass,
    pub max_data_class: Option<DataClass>,
    pub estimated_cents: u64,
    pub p95_latency_ms: u64,
    pub max_context_tokens: u64,
    pub max_output_tokens: u64,
    pub selection_rank: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelRouteRejection {
    pub route_id: String,
    pub reasons: Vec<ModelRouteRejectReason>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelRouteRejectReason {
    Disabled,
    NotInSessionAllowedRoutes,
    NotInRequestAllowedRoutes,
    RequestDeniedRoute,
    LocalOnlyRequired,
    PurposeNotAllowed,
    DataClassTooHigh,
    RetentionTooWeak,
    ContextTooSmall,
    OutputTooSmall,
    LatencyTooHigh,
    CostTooHigh,
    CostUnknown,
    ToolsUnsupported,
    MultimodalUnsupported,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelPolicySummary {
    pub allowed_routes: BTreeSet<String>,
    pub local_only: bool,
    pub max_data_class: Option<DataClass>,
}

impl From<&ModelPolicy> for ModelPolicySummary {
    fn from(policy: &ModelPolicy) -> Self {
        Self {
            allowed_routes: policy.allowed_routes.clone(),
            local_only: policy.local_only,
            max_data_class: policy.max_data_class,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Candidate<'a> {
    route: &'a ModelRoute,
    estimated_cents: u64,
}

pub fn choose_model_route(
    catalog: &ModelRouteCatalog,
    policy: &ModelPolicy,
    request: &ModelRouteRequest,
) -> RouterResult<ModelRouteDecision> {
    choose_model_route_at(catalog, policy, request, Utc::now())
}

pub fn choose_model_route_at(
    catalog: &ModelRouteCatalog,
    policy: &ModelPolicy,
    request: &ModelRouteRequest,
    requested_at: DateTime<Utc>,
) -> RouterResult<ModelRouteDecision> {
    if catalog.is_empty() {
        return Err(ModelRouterError::EmptyCatalog);
    }
    validate_request(request)?;
    let mut candidates = Vec::new();
    let mut rejected_routes = Vec::new();
    for route in catalog.iter() {
        let estimated_cents = route
            .pricing
            .estimate_cents(request.estimated_input_tokens, request.max_output_tokens);
        let reasons = route_rejection_reasons(route, policy, request, estimated_cents);
        if reasons.is_empty() {
            candidates.push(Candidate {
                route,
                estimated_cents: estimated_cents.unwrap_or(0),
            });
        } else {
            rejected_routes.push(ModelRouteRejection {
                route_id: route.route_id.clone(),
                reasons,
            });
        }
    }
    candidates.sort_by(compare_candidates);
    let selected = candidates.first().map(|candidate| ModelRouteSelection {
        route_id: candidate.route.route_id.clone(),
        provider: candidate.route.provider.clone(),
        model: candidate.route.model.clone(),
        model_version: candidate.route.model_version.clone(),
        locality: candidate.route.locality,
        retention: candidate.route.retention,
        max_data_class: candidate.route.max_data_class,
        estimated_cents: candidate.estimated_cents,
        p95_latency_ms: candidate.route.p95_latency_ms,
        max_context_tokens: candidate.route.max_context_tokens,
        max_output_tokens: candidate.route.max_output_tokens,
        selection_rank: 0,
    });
    let result = if selected.is_some() {
        ModelRouteDecisionResult::Allowed
    } else {
        ModelRouteDecisionResult::Denied
    };
    let policy_summary = ModelPolicySummary::from(policy);
    let decision_id = model_route_decision_id(
        request,
        selected.as_ref(),
        &rejected_routes,
        &policy_summary,
        requested_at,
    )?;
    Ok(ModelRouteDecision {
        decision_id,
        session_id: request.session_id.clone(),
        result,
        selected,
        rejected_routes,
        policy_summary,
        requested_at,
    })
}

fn route_rejection_reasons(
    route: &ModelRoute,
    policy: &ModelPolicy,
    request: &ModelRouteRequest,
    estimated_cents: Option<u64>,
) -> Vec<ModelRouteRejectReason> {
    let mut reasons = BTreeSet::new();
    if !route.enabled {
        reasons.insert(ModelRouteRejectReason::Disabled);
    }
    if !policy.allowed_routes.is_empty() && !policy.allowed_routes.contains(&route.route_id) {
        reasons.insert(ModelRouteRejectReason::NotInSessionAllowedRoutes);
    }
    if !request.allowed_routes.is_empty() && !request.allowed_routes.contains(&route.route_id) {
        reasons.insert(ModelRouteRejectReason::NotInRequestAllowedRoutes);
    }
    if request.denied_routes.contains(&route.route_id) {
        reasons.insert(ModelRouteRejectReason::RequestDeniedRoute);
    }
    if (policy.local_only || request.required_local) && !route.locality.is_local() {
        reasons.insert(ModelRouteRejectReason::LocalOnlyRequired);
    }
    if !route.allowed_purposes.is_empty() && !route.allowed_purposes.contains(&request.purpose) {
        reasons.insert(ModelRouteRejectReason::PurposeNotAllowed);
    }
    if !data_classes_fit(
        route.max_data_class,
        policy.max_data_class,
        &request.data_classes,
    ) {
        reasons.insert(ModelRouteRejectReason::DataClassTooHigh);
    }
    if route.retention > request.max_retention {
        reasons.insert(ModelRouteRejectReason::RetentionTooWeak);
    }
    let context_tokens = request
        .estimated_input_tokens
        .checked_add(request.max_output_tokens);
    if context_tokens.is_none_or(|tokens| tokens > route.max_context_tokens) {
        reasons.insert(ModelRouteRejectReason::ContextTooSmall);
    }
    if request.max_output_tokens > route.max_output_tokens {
        reasons.insert(ModelRouteRejectReason::OutputTooSmall);
    }
    if let Some(latency_budget_ms) = request.latency_budget_ms
        && route.p95_latency_ms > latency_budget_ms
    {
        reasons.insert(ModelRouteRejectReason::LatencyTooHigh);
    }
    match (request.max_estimated_cents, estimated_cents) {
        (_, None) => {
            reasons.insert(ModelRouteRejectReason::CostUnknown);
        }
        (Some(max_estimated_cents), Some(estimated_cents))
            if estimated_cents > max_estimated_cents =>
        {
            reasons.insert(ModelRouteRejectReason::CostTooHigh);
        }
        _ => {}
    }
    if request.required_tools && !route.supports_tools {
        reasons.insert(ModelRouteRejectReason::ToolsUnsupported);
    }
    if request.required_multimodal && !route.supports_multimodal {
        reasons.insert(ModelRouteRejectReason::MultimodalUnsupported);
    }
    reasons.into_iter().collect()
}

fn data_classes_fit(
    route_ceiling: Option<DataClass>,
    policy_ceiling: Option<DataClass>,
    classes: &BTreeSet<DataClass>,
) -> bool {
    let effective_ceiling = min_optional_data_class(route_ceiling, policy_ceiling);
    let Some(ceiling) = effective_ceiling else {
        return true;
    };
    classes
        .iter()
        .all(|class| data_class_allowed_by_ceiling(*class, ceiling))
}

fn min_optional_data_class(left: Option<DataClass>, right: Option<DataClass>) -> Option<DataClass> {
    match (left, right) {
        (Some(left), Some(right)) => Some(if data_class_rank(left) <= data_class_rank(right) {
            left
        } else {
            right
        }),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

fn data_class_allowed_by_ceiling(class: DataClass, ceiling: DataClass) -> bool {
    data_class_rank(class) <= data_class_rank(ceiling)
}

fn data_class_rank(class: DataClass) -> u8 {
    match class {
        DataClass::Public => 0,
        DataClass::Internal
        | DataClass::UntrustedWeb
        | DataClass::UntrustedEmail
        | DataClass::UntrustedDocument
        | DataClass::ToolOutput => 1,
        DataClass::Code | DataClass::Binary => 2,
        DataClass::Personal => 3,
        DataClass::Customer => 4,
        DataClass::Financial => 5,
        DataClass::Secret => 6,
    }
}

fn validate_request(request: &ModelRouteRequest) -> RouterResult<()> {
    if request.session_id.trim().is_empty() {
        return Err(ModelRouterError::InvalidRequest(
            "session_id must not be empty".to_string(),
        ));
    }
    if request.estimated_input_tokens == 0 {
        return Err(ModelRouterError::InvalidRequest(
            "estimated_input_tokens must be greater than zero".to_string(),
        ));
    }
    if request.max_output_tokens == 0 {
        return Err(ModelRouterError::InvalidRequest(
            "max_output_tokens must be greater than zero".to_string(),
        ));
    }
    Ok(())
}

fn compare_candidates(left: &Candidate<'_>, right: &Candidate<'_>) -> Ordering {
    (
        left.estimated_cents,
        left.route.p95_latency_ms,
        locality_rank(left.route.locality),
        left.route.route_id.as_str(),
    )
        .cmp(&(
            right.estimated_cents,
            right.route.p95_latency_ms,
            locality_rank(right.route.locality),
            right.route.route_id.as_str(),
        ))
}

fn locality_rank(locality: RouteLocality) -> u8 {
    match locality {
        RouteLocality::Local => 0,
        RouteLocality::PrivateCloud => 1,
        RouteLocality::PublicCloud => 2,
    }
}

fn model_route_decision_id(
    request: &ModelRouteRequest,
    selected: Option<&ModelRouteSelection>,
    rejected_routes: &[ModelRouteRejection],
    policy_summary: &ModelPolicySummary,
    requested_at: DateTime<Utc>,
) -> RouterResult<HashValue> {
    #[derive(Serialize)]
    struct DecisionIdView<'a> {
        request: &'a ModelRouteRequest,
        selected: Option<&'a ModelRouteSelection>,
        rejected_routes: &'a [ModelRouteRejection],
        policy_summary: &'a ModelPolicySummary,
        requested_at: DateTime<Utc>,
    }
    Ok(hash_json(&DecisionIdView {
        request,
        selected,
        rejected_routes,
        policy_summary,
        requested_at,
    })?)
}

fn ceil_div(value: u64, divisor: u64) -> Option<u64> {
    if divisor == 0 {
        return None;
    }
    if value == 0 {
        Some(0)
    } else {
        Some(((value - 1) / divisor) + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local_route() -> ModelRoute {
        let mut route = ModelRoute::local("local/small", "local", "small");
        route.max_data_class = None;
        route.allowed_purposes = BTreeSet::from([ModelPurpose::Planner, ModelPurpose::Verifier]);
        route.p95_latency_ms = 40;
        route.max_context_tokens = 32_000;
        route.max_output_tokens = 4_096;
        route
    }

    fn cloud_route(route_id: &str, max_data_class: Option<DataClass>) -> ModelRoute {
        ModelRoute {
            route_id: route_id.to_string(),
            provider: "cloud".to_string(),
            model: "frontier".to_string(),
            model_version: "2026-07".to_string(),
            locality: RouteLocality::PublicCloud,
            retention: RetentionClass::NoTraining,
            max_data_class,
            allowed_purposes: BTreeSet::from([ModelPurpose::Planner, ModelPurpose::Executor]),
            pricing: RoutePricing {
                input_cents_per_million_tokens: 300,
                output_cents_per_million_tokens: 1_500,
            },
            p95_latency_ms: 900,
            max_context_tokens: 200_000,
            max_output_tokens: 16_384,
            supports_tools: true,
            supports_multimodal: true,
            enabled: true,
            notes: None,
        }
    }

    #[test]
    fn omitted_optional_route_fields_keep_catalog_usable() {
        let route: ModelRoute = serde_json::from_value(serde_json::json!({
            "route_id": "cloud/default-enabled",
            "provider": "cloud",
            "model": "frontier",
            "model_version": "2026-07",
            "locality": "public_cloud",
            "retention": "no_training",
            "allowed_purposes": ["planner"],
            "pricing": {
                "input_cents_per_million_tokens": 300,
                "output_cents_per_million_tokens": 1500
            },
            "p95_latency_ms": 900,
            "max_context_tokens": 200000,
            "max_output_tokens": 16384
        }))
        .unwrap_or_else(|err| panic!("route should deserialize: {err}"));

        let catalog = ModelRouteCatalog::new([route])
            .unwrap_or_else(|err| panic!("catalog should build: {err}"));
        let request = ModelRouteRequest::new("s1", ModelPurpose::Planner, 1_000, 500);
        let decision = choose_model_route_at(
            &catalog,
            &ModelPolicy::default(),
            &request,
            DateTime::from_timestamp(1, 0).unwrap_or_else(Utc::now),
        )
        .unwrap_or_else(|err| panic!("routing should return decision: {err}"));

        assert_eq!(decision.result, ModelRouteDecisionResult::Allowed);
        assert_eq!(
            decision
                .selected
                .unwrap_or_else(|| panic!("route should be selected"))
                .route_id,
            "cloud/default-enabled"
        );
    }

    #[test]
    fn default_catalog_is_rejected_at_selection_boundary() {
        let request = ModelRouteRequest::new("s1", ModelPurpose::Planner, 1_000, 500);
        let result = choose_model_route_at(
            &ModelRouteCatalog::default(),
            &ModelPolicy::default(),
            &request,
            DateTime::from_timestamp(1, 0).unwrap_or_else(Utc::now),
        );
        assert!(matches!(result, Err(ModelRouterError::EmptyCatalog)));
    }

    #[test]
    fn customer_data_does_not_enter_public_route_with_internal_policy_ceiling() {
        let catalog =
            ModelRouteCatalog::new([cloud_route("cloud/frontier", Some(DataClass::Customer))])
                .unwrap_or_else(|err| panic!("catalog should build: {err}"));
        let mut request = ModelRouteRequest::new("s1", ModelPurpose::Planner, 1_000, 500);
        request.data_classes.insert(DataClass::Customer);
        let decision = choose_model_route_at(
            &catalog,
            &ModelPolicy::default(),
            &request,
            DateTime::from_timestamp(1, 0).unwrap_or_else(Utc::now),
        )
        .unwrap_or_else(|err| panic!("routing should return decision: {err}"));
        assert_eq!(decision.result, ModelRouteDecisionResult::Denied);
        assert_eq!(
            decision.rejected_routes[0].reasons,
            vec![ModelRouteRejectReason::DataClassTooHigh]
        );
    }

    #[test]
    fn local_only_policy_excludes_cloud_routes() {
        let catalog = ModelRouteCatalog::new([local_route(), cloud_route("cloud/frontier", None)])
            .unwrap_or_else(|err| panic!("catalog should build: {err}"));
        let mut policy = ModelPolicy::default();
        policy.local_only = true;
        policy.max_data_class = None;
        let request = ModelRouteRequest::new("s1", ModelPurpose::Verifier, 1_000, 500);
        let decision = choose_model_route_at(
            &catalog,
            &policy,
            &request,
            DateTime::from_timestamp(1, 0).unwrap_or_else(Utc::now),
        )
        .unwrap_or_else(|err| panic!("routing should return decision: {err}"));
        let selected = decision
            .selected
            .unwrap_or_else(|| panic!("local route should be selected"));
        assert_eq!(selected.route_id, "local/small");
        assert!(decision.rejected_routes.iter().any(|rejection| {
            rejection.route_id == "cloud/frontier"
                && rejection
                    .reasons
                    .contains(&ModelRouteRejectReason::LocalOnlyRequired)
        }));
    }

    #[test]
    fn planner_and_verifier_routes_can_differ() {
        let mut verifier = local_route();
        verifier.route_id = "local/verifier".to_string();
        verifier.allowed_purposes = BTreeSet::from([ModelPurpose::Verifier]);
        let mut planner = cloud_route("cloud/planner", Some(DataClass::Internal));
        planner.allowed_purposes = BTreeSet::from([ModelPurpose::Planner]);
        let catalog = ModelRouteCatalog::new([verifier, planner])
            .unwrap_or_else(|err| panic!("catalog should build: {err}"));
        let policy = ModelPolicy::default();
        let planner_decision = choose_model_route_at(
            &catalog,
            &policy,
            &ModelRouteRequest::new("s1", ModelPurpose::Planner, 1_000, 500),
            DateTime::from_timestamp(1, 0).unwrap_or_else(Utc::now),
        )
        .unwrap_or_else(|err| panic!("planner route should decide: {err}"));
        let verifier_decision = choose_model_route_at(
            &catalog,
            &policy,
            &ModelRouteRequest::new("s1", ModelPurpose::Verifier, 1_000, 500),
            DateTime::from_timestamp(1, 0).unwrap_or_else(Utc::now),
        )
        .unwrap_or_else(|err| panic!("verifier route should decide: {err}"));
        assert_eq!(
            planner_decision
                .selected
                .unwrap_or_else(|| panic!("planner selected"))
                .route_id,
            "cloud/planner"
        );
        assert_eq!(
            verifier_decision
                .selected
                .unwrap_or_else(|| panic!("verifier selected"))
                .route_id,
            "local/verifier"
        );
    }

    #[test]
    fn cost_latency_retention_and_tools_are_fail_closed_filters() {
        let catalog = ModelRouteCatalog::new([cloud_route("cloud/frontier", None)])
            .unwrap_or_else(|err| panic!("catalog should build: {err}"));
        let mut request = ModelRouteRequest::new("s1", ModelPurpose::Planner, 10_000, 10_000);
        request.max_estimated_cents = Some(1);
        request.latency_budget_ms = Some(100);
        request.max_retention = RetentionClass::None;
        request.required_tools = true;
        let mut policy = ModelPolicy::default();
        policy.max_data_class = None;
        let decision = choose_model_route_at(
            &catalog,
            &policy,
            &request,
            DateTime::from_timestamp(1, 0).unwrap_or_else(Utc::now),
        )
        .unwrap_or_else(|err| panic!("routing should return decision: {err}"));
        assert_eq!(decision.result, ModelRouteDecisionResult::Denied);
        let reasons = &decision.rejected_routes[0].reasons;
        assert!(reasons.contains(&ModelRouteRejectReason::CostTooHigh));
        assert!(reasons.contains(&ModelRouteRejectReason::LatencyTooHigh));
        assert!(reasons.contains(&ModelRouteRejectReason::RetentionTooWeak));
    }
}
