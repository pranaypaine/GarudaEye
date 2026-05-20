use async_trait::async_trait;
use garudaeye_core::{Asset, AssetType, CloudProvider, Count, CountCategory, AssetRelationship};

/// Trait for storing and retrieving assets
#[async_trait]
pub trait AssetStore: Send + Sync {
    async fn insert(&self, asset: Asset) -> anyhow::Result<()>;
    async fn update(&self, asset: Asset) -> anyhow::Result<()>;
    async fn get_by_id(&self, id: uuid::Uuid) -> anyhow::Result<Option<Asset>>;
    async fn get_by_sk(&self, asset_type: AssetType, sk: &str) -> anyhow::Result<Option<Asset>>;
    async fn list(
        &self,
        asset_type: Option<AssetType>,
        provider: Option<CloudProvider>,
        limit: Option<i64>,
    ) -> anyhow::Result<Vec<Asset>>;
    async fn count(&self, asset_type: Option<AssetType>) -> anyhow::Result<i64>;
    async fn count_by_field(&self, field: &str, value: &str) -> anyhow::Result<i64>;
    async fn count_with_ports(&self) -> anyhow::Result<i64>;
    async fn count_with_vulnerabilities(&self) -> anyhow::Result<i64>;
    async fn get_port_distribution(&self) -> anyhow::Result<Vec<(u16, i64)>>;
    async fn list_by_risk_score(&self, min_score: i32) -> anyhow::Result<Vec<Asset>>;
    async fn delete(&self, id: uuid::Uuid) -> anyhow::Result<()>;
    
    // Relationship management
    async fn insert_relationship(&self, relationship: AssetRelationship) -> anyhow::Result<()>;
    async fn get_relationships(&self, asset_id: uuid::Uuid) -> anyhow::Result<Vec<AssetRelationship>>;
    async fn get_all_relationships(&self) -> anyhow::Result<Vec<AssetRelationship>>;
    async fn count_relationships(&self) -> anyhow::Result<i64>;
    async fn delete_relationship(&self, id: uuid::Uuid) -> anyhow::Result<()>;
}

/// Trait for storing and retrieving aggregated counts
#[async_trait]
pub trait CountStore: Send + Sync {
    async fn upsert(&self, count: Count) -> anyhow::Result<()>;
    async fn get(
        &self,
        category: CountCategory,
        value: &str,
    ) -> anyhow::Result<Option<Count>>;
    async fn list(&self, category: CountCategory) -> anyhow::Result<Vec<Count>>;
    async fn delete(&self, category: CountCategory, value: &str) -> anyhow::Result<()>;
}

/// Trait for event bus (queue) operations
#[async_trait]
pub trait EventBus: Send + Sync {
    async fn publish(&self, topic: &str, message: &str) -> anyhow::Result<()>;
    async fn subscribe(&self, topic: &str) -> anyhow::Result<Box<dyn EventSubscriber>>;
}

/// Trait for consuming events from a subscription
#[async_trait]
pub trait EventSubscriber: Send {
    async fn next(&mut self) -> anyhow::Result<Option<String>>;
}

/// Trait for object storage (files, blobs)
#[async_trait]
pub trait ObjectStore: Send + Sync {
    async fn put(&self, key: &str, data: &[u8]) -> anyhow::Result<()>;
    async fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>>;
    async fn delete(&self, key: &str) -> anyhow::Result<()>;
    async fn list(&self, prefix: &str) -> anyhow::Result<Vec<String>>;
}
