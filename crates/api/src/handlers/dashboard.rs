use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use serde::Serialize;
use std::sync::Arc;
use crate::state::AppState;
use garudaeye_core::AssetType;
use infra::traits::AssetStore;

/// Dashboard summary endpoint
pub async fn get_dashboard(
    State(state): State<Arc<AppState>>,
) -> Result<Json<DashboardResponse>, StatusCode> {
    let ip_count = state.asset_store.count(Some(AssetType::IpAddress)).await.unwrap_or(0);
    let domain_count = state.asset_store.count(Some(AssetType::Domain)).await.unwrap_or(0);
    let bucket_count = state.asset_store.count(Some(AssetType::S3Bucket)).await.unwrap_or(0);
    let lb_count = state.asset_store.count(Some(AssetType::LoadBalancer)).await.unwrap_or(0);
    let db_count = state.asset_store.count(Some(AssetType::Database)).await.unwrap_or(0);
    let cache_count = state.asset_store.count(Some(AssetType::Cache)).await.unwrap_or(0);
    let cdn_count = state.asset_store.count(Some(AssetType::Cdn)).await.unwrap_or(0);
    let lambda_count = state.asset_store.count(Some(AssetType::Lambda)).await.unwrap_or(0);
    let api_count = state.asset_store.count(Some(AssetType::ApiGateway)).await.unwrap_or(0);
    let queue_count = state.asset_store.count(Some(AssetType::Queue)).await.unwrap_or(0);
    let topic_count = state.asset_store.count(Some(AssetType::Topic)).await.unwrap_or(0);
    let table_count = state.asset_store.count(Some(AssetType::Table)).await.unwrap_or(0);
    let vpc_count = state.asset_store.count(Some(AssetType::Vpc)).await.unwrap_or(0);
    let subnet_count = state.asset_store.count(Some(AssetType::Subnet)).await.unwrap_or(0);
    let sg_count = state.asset_store.count(Some(AssetType::SecurityGroup)).await.unwrap_or(0);
    let container_count = state.asset_store.count(Some(AssetType::Container)).await.unwrap_or(0);
    let cluster_count = state.asset_store.count(Some(AssetType::Cluster)).await.unwrap_or(0);

    let total = ip_count + domain_count + bucket_count + lb_count + db_count +
                cache_count + cdn_count + lambda_count + api_count + queue_count +
                topic_count + table_count + vpc_count + subnet_count + sg_count +
                container_count + cluster_count;

    // Security posture metrics
    let public_assets = state.asset_store.count_by_field("public_access", "1").await.unwrap_or(0);
    let unencrypted_assets = state.asset_store.count_by_field("encryption_enabled", "0").await.unwrap_or(0);
    let total_relationships = state.asset_store.count_relationships().await.unwrap_or(0);

    // Fingerprint-derived metrics
    let assets_with_ports = state.asset_store.count_with_ports().await.unwrap_or(0);
    let assets_with_vulns = state.asset_store.count_with_vulnerabilities().await.unwrap_or(0);
    let high_risk_assets = state.asset_store.list_by_risk_score(70).await
        .map(|v| v.len() as i64).unwrap_or(0);
    let medium_risk_assets = state.asset_store.list_by_risk_score(40).await
        .map(|v| v.len() as i64).unwrap_or(0);

    Ok(Json(DashboardResponse {
        total_assets: total,
        ip_addresses: ip_count,
        domains: domain_count,
        s3_buckets: bucket_count,
        load_balancers: lb_count,
        databases: db_count,
        caches: cache_count,
        cdns: cdn_count,
        lambdas: lambda_count,
        api_gateways: api_count,
        queues: queue_count,
        topics: topic_count,
        tables: table_count,
        vpcs: vpc_count,
        subnets: subnet_count,
        security_groups: sg_count,
        containers: container_count,
        clusters: cluster_count,
        public_assets,
        unencrypted_assets,
        total_relationships,
        assets_with_open_ports: assets_with_ports,
        vulnerabilities: assets_with_vulns,
        high_risk_assets,
        medium_risk_assets,
    }))
}

#[derive(Debug, Serialize)]
pub struct DashboardResponse {
    pub total_assets: i64,
    pub ip_addresses: i64,
    pub domains: i64,
    pub s3_buckets: i64,
    pub load_balancers: i64,
    pub databases: i64,
    pub caches: i64,
    pub cdns: i64,
    pub lambdas: i64,
    pub api_gateways: i64,
    pub queues: i64,
    pub topics: i64,
    pub tables: i64,
    pub vpcs: i64,
    pub subnets: i64,
    pub security_groups: i64,
    pub containers: i64,
    pub clusters: i64,
    pub public_assets: i64,
    pub unencrypted_assets: i64,
    pub total_relationships: i64,
    pub assets_with_open_ports: i64,
    pub vulnerabilities: i64,
    pub high_risk_assets: i64,
    pub medium_risk_assets: i64,
}

/// Common ports statistics (top 20 most seen ports across all assets)
pub async fn get_common_ports(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<PortCount>>, StatusCode> {
    let dist = state.asset_store.get_port_distribution().await
        .unwrap_or_default();

    let result = dist.into_iter()
        .take(20)
        .map(|(port, count)| PortCount { port, count })
        .collect();

    Ok(Json(result))
}

// Admin/sensitive ports to watch for
const ADMIN_PORTS: &[u16] = &[
    22, 23, 21, 3389, 5900, 5901,          // remote access
    3306, 5432, 27017, 6379, 1433, 5984,   // databases
    9200, 9300,                             // Elasticsearch
    8080, 8443, 8888, 9090, 9091,          // admin UIs
    15672, 5672,                            // RabbitMQ
    2181, 2888, 3888,                       // ZooKeeper
    6443,                                   // Kubernetes API
    2375, 2376,                             // Docker
];

/// Admin/sensitive ports that are open
pub async fn get_admin_ports(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<PortCount>>, StatusCode> {
    let dist = state.asset_store.get_port_distribution().await
        .unwrap_or_default();

    let result = dist.into_iter()
        .filter(|(port, _)| ADMIN_PORTS.contains(port))
        .map(|(port, count)| PortCount { port, count })
        .collect();

    Ok(Json(result))
}


#[derive(Debug, Serialize)]
pub struct PortCount {
    pub port: u16,
    pub count: i64,
}
