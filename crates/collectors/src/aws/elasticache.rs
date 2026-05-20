use aws_sdk_elasticache::Client;
use garudaeye_core::{Asset, AssetType, CloudProvider};
use infra::traits::{AssetStore, EventBus};
use tracing::{info, error, debug};

pub struct ElastiCacheCollector {
    client: Client,
    region: String,
}

impl ElastiCacheCollector {
    pub async fn new(config: &aws_config::SdkConfig, region: String) -> Self {
        let client = Client::new(config);
        Self { client, region }
    }

    pub async fn collect(
        &self,
        asset_store: &dyn AssetStore,
        event_bus: &dyn EventBus,
    ) -> anyhow::Result<()> {
        info!("Starting ElastiCache collection...");

        let mut count = 0;

        // show_cache_node_info=true to get primary endpoint for Redis single-node clusters
        let result = self.client
            .describe_cache_clusters()
            .show_cache_node_info(true)
            .send()
            .await;

        match result {
            Ok(output) => {
                for cluster in output.cache_clusters.unwrap_or_default() {
                    let cluster_id = match cluster.cache_cluster_id() {
                        Some(id) => id.to_string(),
                        None => continue,
                    };

                    // Determine endpoint: configuration endpoint (Redis cluster mode / Memcached)
                    // or individual node endpoint (Redis single-node)
                    let endpoint_address = cluster.configuration_endpoint()
                        .and_then(|e| e.address())
                        .map(|s| s.to_string())
                        .or_else(|| {
                            cluster.cache_nodes()
                                .first()
                                .and_then(|n| n.endpoint())
                                .and_then(|e| e.address())
                                .map(|s| s.to_string())
                        });

                    let sk = endpoint_address.clone().unwrap_or_else(|| cluster_id.clone());

                    let mut asset = Asset::new(
                        AssetType::Cache,
                        sk.clone(),
                        CloudProvider::Aws,
                    );

                    asset.service = Some(format!("ElastiCache ({})",
                        cluster.engine().unwrap_or("unknown")));
                    asset.resource_id = Some(cluster_id.clone());
                    asset.region = Some(self.region.clone());
                    asset.encryption_enabled = cluster.at_rest_encryption_enabled();

                    // Security groups
                    let sg_ids: Vec<String> = cluster.security_groups()
                        .iter()
                        .filter_map(|sg| sg.security_group_id().map(|s| s.to_string()))
                        .collect();
                    if !sg_ids.is_empty() {
                        asset.security_groups = Some(sg_ids.clone());
                    }

                    let config_json = serde_json::json!({
                        "cache_cluster_id": cluster_id,
                        "cache_cluster_status": cluster.cache_cluster_status(),
                        "engine": cluster.engine(),
                        "engine_version": cluster.engine_version(),
                        "cache_node_type": cluster.cache_node_type(),
                        "num_cache_nodes": cluster.num_cache_nodes(),
                        "endpoint": endpoint_address,
                        "configuration_endpoint": cluster.configuration_endpoint().and_then(|e| e.address()),
                        "port": cluster.configuration_endpoint()
                            .and_then(|e| e.port())
                            .or_else(|| cluster.cache_nodes().first().and_then(|n| n.endpoint()).and_then(|e| e.port())),
                        "cache_subnet_group_name": cluster.cache_subnet_group_name(),
                        "replication_group_id": cluster.replication_group_id(),
                        "preferred_availability_zone": cluster.preferred_availability_zone(),
                        "preferred_maintenance_window": cluster.preferred_maintenance_window(),
                        "snapshot_retention_limit": cluster.snapshot_retention_limit(),
                        "snapshot_window": cluster.snapshot_window(),
                        "at_rest_encryption_enabled": cluster.at_rest_encryption_enabled(),
                        "transit_encryption_enabled": cluster.transit_encryption_enabled(),
                        "auth_token_enabled": cluster.auth_token_enabled(),
                        "auth_token_last_modified_date": cluster.auth_token_last_modified_date()
                            .map(|t| t.secs().to_string()),
                        "replication_group_id": cluster.replication_group_id(),
                        "auto_minor_version_upgrade": cluster.auto_minor_version_upgrade(),
                        "cache_parameter_group": cluster.cache_parameter_group().map(|pg| serde_json::json!({
                            "cache_parameter_group_name": pg.cache_parameter_group_name(),
                            "parameter_apply_status": pg.parameter_apply_status(),
                        })),
                        "security_groups": sg_ids,
                        "cache_nodes": cluster.cache_nodes()
                            .iter()
                            .map(|n| serde_json::json!({
                                "cache_node_id": n.cache_node_id(),
                                "cache_node_status": n.cache_node_status(),
                                "endpoint": n.endpoint().and_then(|e| e.address()),
                                "port": n.endpoint().and_then(|e| e.port()),
                                "availability_zone": n.customer_availability_zone(),
                            }))
                            .collect::<Vec<_>>(),
                        "ip_discovery": cluster.ip_discovery().map(|i| i.as_str()),
                        "network_type": cluster.network_type().map(|n| n.as_str()),
                        "transit_encryption_mode": cluster.transit_encryption_mode().map(|m| m.as_str()),
                    });

                    asset.configuration = Some(config_json);
                    asset_store.insert(asset.clone()).await?;
                    event_bus.publish("analyze-cache", &asset.sk).await?;

                    count += 1;
                    debug!("Collected ElastiCache cluster: {}", cluster_id);
                }
            }
            Err(e) => {
                error!("Failed to describe ElastiCache clusters: {}", e);
            }
        }

        info!("ElastiCache collection complete. Collected {} clusters", count);
        Ok(())
    }
}

