use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Serialize;
use std::sync::Arc;
use uuid::Uuid;
use crate::state::AppState;
use tracing::{info, error};

/// Get all relationships for a specific asset
pub async fn get_asset_relationships(
    State(state): State<Arc<AppState>>,
    Path(asset_id): Path<String>,
) -> Result<Json<Vec<garudaeye_core::AssetRelationship>>, StatusCode> {
    let asset_id = Uuid::parse_str(&asset_id)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    
    match state.asset_store.get_relationships(asset_id).await {
        Ok(relationships) => {
            info!("Retrieved {} relationships for asset {}", relationships.len(), asset_id);
            Ok(Json(relationships))
        }
        Err(e) => {
            error!("Failed to get relationships: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Get all relationships in the system
pub async fn get_all_relationships(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<garudaeye_core::AssetRelationship>>, StatusCode> {
    match state.asset_store.get_all_relationships().await {
        Ok(relationships) => {
            info!("Retrieved {} total relationships", relationships.len());
            Ok(Json(relationships))
        }
        Err(e) => {
            error!("Failed to get relationships: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Get asset graph data for visualization
#[derive(Serialize)]
pub struct AssetGraphResponse {
    pub nodes: Vec<AssetNode>,
    pub edges: Vec<AssetEdge>,
}

#[derive(Serialize)]
pub struct AssetNode {
    pub id: String,
    pub label: String,
    pub asset_type: String,
    pub provider: String,
    pub region: Option<String>,
    pub service: Option<String>,
    pub vpc_id: Option<String>,
    pub subnet_id: Option<String>,
    pub public_access: Option<bool>,
    pub encryption_enabled: Option<bool>,
}

#[derive(Serialize)]
pub struct AssetEdge {
    pub id: String,
    pub source: String,
    pub target: String,
    pub relationship_type: String,
    pub metadata: Option<serde_json::Value>,
}

pub async fn get_asset_graph(
    State(state): State<Arc<AppState>>,
) -> Result<Json<AssetGraphResponse>, StatusCode> {
    // Get all assets
    let assets = match state.asset_store.list(None, None, None).await {
        Ok(assets) => assets,
        Err(e) => {
            error!("Failed to list assets: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    
    // Get all relationships
    let relationships = match state.asset_store.get_all_relationships().await {
        Ok(relationships) => relationships,
        Err(e) => {
            error!("Failed to get relationships: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    
    // Convert to graph format
    let nodes: Vec<AssetNode> = assets.into_iter().map(|asset| AssetNode {
        id: asset.id.to_string(),
        label: asset.sk.clone(),
        asset_type: asset.asset_type.to_string(),
        provider: asset.provider.to_string(),
        region: asset.region.clone(),
        service: asset.service.clone(),
        vpc_id: asset.vpc_id.clone(),
        subnet_id: asset.subnet_id.clone(),
        public_access: asset.public_access,
        encryption_enabled: asset.encryption_enabled,
    }).collect();
    
    let edges: Vec<AssetEdge> = relationships.into_iter().map(|rel| AssetEdge {
        id: rel.id.to_string(),
        source: rel.source_asset_id.to_string(),
        target: rel.target_asset_id.to_string(),
        relationship_type: rel.relationship_type.to_string(),
        metadata: rel.metadata,
    }).collect();
    
    info!("Retrieved asset graph: {} nodes, {} edges", nodes.len(), edges.len());
    
    Ok(Json(AssetGraphResponse { nodes, edges }))
}
