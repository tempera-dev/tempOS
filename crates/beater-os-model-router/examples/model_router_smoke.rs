use std::collections::BTreeSet;
use std::error::Error;

use beater_os_core::{DataClass, ModelPolicy};
use beater_os_model_router::{
    ModelPurpose, ModelRoute, ModelRouteCatalog, ModelRouteRequest, RetentionClass,
    choose_model_route,
};
use serde_json::json;

fn main() -> Result<(), Box<dyn Error>> {
    let mut as_json = false;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--json" => as_json = true,
            other => return Err(format!("unsupported argument: {other}").into()),
        }
    }

    let mut local = ModelRoute::local("local/verifier", "local", "verifier-small");
    local.allowed_purposes = BTreeSet::from([ModelPurpose::Verifier, ModelPurpose::Classifier]);
    local.max_context_tokens = 32_000;

    let mut cloud = ModelRoute::local("cloud/planner", "frontier-cloud", "planner-large");
    cloud.locality = beater_os_model_router::RouteLocality::PublicCloud;
    cloud.retention = RetentionClass::NoTraining;
    cloud.max_data_class = Some(DataClass::Internal);
    cloud.allowed_purposes = BTreeSet::from([ModelPurpose::Planner]);
    cloud.p95_latency_ms = 900;
    cloud.pricing.input_cents_per_million_tokens = 300;
    cloud.pricing.output_cents_per_million_tokens = 1_500;

    let catalog = ModelRouteCatalog::new([local, cloud])?;
    let mut policy = ModelPolicy::default();
    policy.allowed_routes.insert("local/verifier".to_string());
    policy.allowed_routes.insert("cloud/planner".to_string());

    let mut request =
        ModelRouteRequest::new("router-smoke-session", ModelPurpose::Planner, 2_000, 1_000);
    request.data_classes.insert(DataClass::Internal);
    request.max_estimated_cents = Some(10);
    request.max_retention = RetentionClass::NoTraining;

    let decision = choose_model_route(&catalog, &policy, &request)?;
    let Some(selected) = decision.selected.as_ref() else {
        return Err("router smoke expected one selected route".into());
    };
    if selected.route_id != "cloud/planner" {
        return Err(format!("unexpected selected route: {}", selected.route_id).into());
    }

    let report = json!({
        "status": "ok",
        "session_id": decision.session_id,
        "decision_id": decision.decision_id,
        "selected_route": selected.route_id,
        "estimated_cents": selected.estimated_cents,
        "rejected_routes": decision.rejected_routes.len()
    });

    if as_json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("model router smoke OK");
        println!("  session: {}", report["session_id"]);
        println!("  selected: {}", report["selected_route"]);
        println!("  decision: {}", report["decision_id"]);
    }
    Ok(())
}
