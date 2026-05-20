use axum::{Router, response::{Response, IntoResponse}, http::{StatusCode, header, Uri}};
use std::sync::Arc;
use tower_http::cors::{CorsLayer, Any};
use tower_http::trace::TraceLayer;
use crate::orchestrator::Orchestrator;
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "../../frontend/dist"]
struct FrontendAssets;

async fn serve_frontend(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    
    // If path is empty, serve index.html
    let path = if path.is_empty() || path == "index.html" {
        "index.html"
    } else {
        path
    };
    
    match FrontendAssets::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, mime.as_ref())
                .body(axum::body::Body::from(content.data))
                .unwrap()
        }
        None => {
            // For SPA routing, return index.html for any unknown path
            if let Some(index) = FrontendAssets::get("index.html") {
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/html")
                    .body(axum::body::Body::from(index.data))
                    .unwrap()
            } else {
                (StatusCode::NOT_FOUND, "404 Not Found").into_response()
            }
        }
    }
}

pub async fn serve(
    addr: String,
    asset_store: Arc<dyn infra::AssetStore + Send + Sync>,
    event_bus: Arc<dyn infra::EventBus + Send + Sync>,
) -> anyhow::Result<()> {
    // Create orchestrator
    let orchestrator: Arc<dyn api::state::OrchestratorTrait> = Arc::new(
        Orchestrator::new(asset_store.clone(), event_bus.clone())
    );
    
    // Create shared application state
    let state = Arc::new(api::AppState {
        asset_store,
        event_bus,
        orchestrator,
    });
    
    // Build router with API routes and frontend
    let app = Router::new()
        .nest("/api", api::build_router(state))
        .fallback(serve_frontend)
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any)
        )
        .layer(TraceLayer::new_for_http());
    
    // Start server
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Server listening on {}", addr);
    
    axum::serve(listener, app)
        .await?;
    
    Ok(())
}
