use std::sync::Arc;

/// Shared application state passed to all handlers
pub struct AppState {
    pub asset_store: Arc<dyn infra::AssetStore + Send + Sync>,
    pub event_bus: Arc<dyn infra::EventBus + Send + Sync>,
    pub orchestrator: Arc<dyn OrchestratorTrait>,
}

/// Trait for orchestrator to avoid circular dependencies
#[async_trait::async_trait]
pub trait OrchestratorTrait: Send + Sync {
    async fn start_collection(&self) -> anyhow::Result<()>;
    async fn start_analysis(&self) -> anyhow::Result<()>;
    async fn start_enrichment(&self) -> anyhow::Result<EnrichmentSummary>;
}

#[derive(Debug, serde::Serialize, Clone)]
pub struct EnrichmentSummary {
    pub queued_ip: usize,
    pub queued_domain: usize,
    pub total_assets_scanned: usize,
}
