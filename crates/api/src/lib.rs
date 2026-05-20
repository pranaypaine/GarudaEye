pub mod handlers;
pub mod state;

use axum::{
    routing::get,
    Router,
};
use std::sync::Arc;

pub use state::AppState;

/// Build the API router with all endpoint handlers
pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(handlers::health))
        .route("/start", get(handlers::start_collection))
        .route("/enrich", get(handlers::start_enrichment))
        .route("/assets", get(handlers::list_assets))
        .route("/assets/:asset_id", get(handlers::assets::get_asset_by_id))
        .route("/dashboard/dashboard", get(handlers::dashboard::get_dashboard))
        .route("/dashboard/common_ports", get(handlers::dashboard::get_common_ports))
        .route("/dashboard/admin_ports", get(handlers::dashboard::get_admin_ports))
        .route("/relationships", get(handlers::relationships::get_all_relationships))
        .route("/relationships/:asset_id", get(handlers::relationships::get_asset_relationships))
        .route("/graph", get(handlers::relationships::get_asset_graph))
        .route("/attack-paths", get(handlers::attack_paths::get_attack_paths))
        .with_state(state)
}
