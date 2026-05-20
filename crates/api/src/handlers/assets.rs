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

/// Response for single asset with relationships
#[derive(Serialize)]
pub struct AssetDetailResponse {
    pub asset: garudaeye_core::Asset,
    pub relationships: AssetRelationships,
}

#[derive(Serialize)]
pub struct AssetRelationships {
    pub outgoing: Vec<RelatedAsset>,
    pub incoming: Vec<RelatedAsset>,
}

#[derive(Serialize)]
pub struct RelatedAsset {
    pub asset: garudaeye_core::Asset,
    pub relationship_type: String,
    pub relationship_id: String,
}

use infra::traits::AssetStore;

/// Get a single asset by ID with all its relationships
pub async fn get_asset_by_id(
    State(state): State<Arc<AppState>>,
    Path(asset_id): Path<String>,
) -> Result<Json<AssetDetailResponse>, StatusCode> {
    let asset_uuid = Uuid::parse_str(&asset_id)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Fetch the asset directly by ID (fixes H-2: was loading all assets)
    let asset = match state.asset_store.get_by_id(asset_uuid).await {
        Ok(Some(a)) => a,
        Ok(None) => return Err(StatusCode::NOT_FOUND),
        Err(e) => {
            error!("Failed to get asset {}: {}", asset_id, e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Get all assets for relationship resolution (only needed for names)
    let all_assets = match state.asset_store.list(None, None, None).await {
        Ok(assets) => assets,
        Err(e) => {
            error!("Failed to list assets: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    
    // Get all relationships
    let all_relationships = match state.asset_store.get_all_relationships().await {
        Ok(rels) => rels,
        Err(e) => {
            error!("Failed to get relationships: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    
    // Find outgoing relationships (where this asset is the source)
    let mut outgoing = Vec::new();
    for rel in all_relationships.iter() {
        if rel.source_asset_id == asset_uuid {
            if let Some(target) = all_assets.iter().find(|a| a.id == rel.target_asset_id) {
                outgoing.push(RelatedAsset {
                    asset: target.clone(),
                    relationship_type: rel.relationship_type.to_string(),
                    relationship_id: rel.id.to_string(),
                });
            }
        }
    }
    
    // Find incoming relationships (where this asset is the target)
    let mut incoming = Vec::new();
    for rel in all_relationships.iter() {
        if rel.target_asset_id == asset_uuid {
            if let Some(source) = all_assets.iter().find(|a| a.id == rel.source_asset_id) {
                incoming.push(RelatedAsset {
                    asset: source.clone(),
                    relationship_type: rel.relationship_type.to_string(),
                    relationship_id: rel.id.to_string(),
                });
            }
        }
    }
    
    info!(
        "Retrieved asset {} with {} outgoing and {} incoming relationships",
        asset_id,
        outgoing.len(),
        incoming.len()
    );
    
    Ok(Json(AssetDetailResponse {
        asset,
        relationships: AssetRelationships {
            outgoing,
            incoming,
        },
    }))
}
