pub mod dashboard;
pub mod relationships;
pub mod assets;
pub mod attack_paths;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::state::AppState;
use tracing::{info, error};

/// Health check endpoint
pub async fn health() -> &'static str {
    "OK"
}

/// Trigger Shodan enrichment on all existing public assets
pub async fn start_enrichment(
    State(state): State<Arc<AppState>>,
) -> Result<Json<crate::state::EnrichmentSummary>, StatusCode> {
    info!("Enrichment triggered via API");

    let orchestrator = state.orchestrator.clone();

    match orchestrator.start_enrichment().await {
        Ok(summary) => Ok(Json(summary)),
        Err(e) => {
            error!("Enrichment failed: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Start collection process
pub async fn start_collection(
    State(state): State<Arc<AppState>>,
) -> Result<Json<StartResponse>, StatusCode> {
    info!("Collection started via API");
    
    // Clone the orchestrator for the background task
    let orchestrator = state.orchestrator.clone();
    
    // Spawn collection in background to avoid blocking the API response
    tokio::spawn(async move {
        if let Err(e) = orchestrator.start_collection().await {
            error!("Collection failed: {}", e);
        }
    });
    
    Ok(Json(StartResponse {
        message: "Collection started".to_string(),
        status: "running".to_string(),
    }))
}

#[derive(Debug, Serialize)]
pub struct StartResponse {
    message: String,
    status: String,
}

/// List assets with optional filtering
pub async fn list_assets(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListAssetsQuery>,
) -> Result<Json<Vec<garudaeye_core::Asset>>, StatusCode> {
    let asset_type = params.asset_type.as_deref().and_then(|s| {
        serde_json::from_str(&format!("\"{}\"", s)).ok()
    });

    let provider = params.provider.as_deref().and_then(|s| {
        serde_json::from_str(&format!("\"{}\"", s)).ok()
    });

    let mut assets = match state.asset_store.list(asset_type, provider, params.limit).await {
        Ok(assets) => assets,
        Err(e) => {
            error!("Failed to list assets: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // In-memory filters for fields not in the base list query
    if let Some(search) = &params.search {
        let q = search.to_lowercase();
        assets.retain(|a| {
            a.sk.to_lowercase().contains(&q)
                || a.service.as_deref().unwrap_or("").to_lowercase().contains(&q)
                || a.resource_id.as_deref().unwrap_or("").to_lowercase().contains(&q)
                || a.arn.as_deref().unwrap_or("").to_lowercase().contains(&q)
                || a.dns_name.as_deref().unwrap_or("").to_lowercase().contains(&q)
                || a.vpc_id.as_deref().unwrap_or("").to_lowercase().contains(&q)
        });
    }

    if let Some(region) = &params.region {
        assets.retain(|a| a.region.as_deref() == Some(region.as_str()));
    }

    if let Some(public) = params.public_access {
        assets.retain(|a| a.public_access == Some(public));
    }

    if let Some(encrypted) = params.encryption_enabled {
        assets.retain(|a| a.encryption_enabled == Some(encrypted));
    }

    info!("Retrieved {} assets", assets.len());
    Ok(Json(assets))
}

#[derive(Debug, Deserialize)]
pub struct ListAssetsQuery {
    asset_type: Option<String>,
    provider: Option<String>,
    limit: Option<i64>,
    search: Option<String>,
    region: Option<String>,
    public_access: Option<bool>,
    encryption_enabled: Option<bool>,
}
