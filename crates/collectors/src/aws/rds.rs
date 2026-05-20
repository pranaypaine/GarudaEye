use aws_sdk_rds::Client;
use garudaeye_core::{Asset, AssetType, CloudProvider};
use infra::traits::{AssetStore, EventBus};
use tracing::{info, error, debug};

pub struct RdsCollector {
    client: Client,
    region: String,
}

impl RdsCollector {
    pub async fn new(config: &aws_config::SdkConfig, region: String) -> Self {
        let client = Client::new(config);
        Self { client, region }
    }

    pub async fn collect(
        &self,
        asset_store: &dyn AssetStore,
        event_bus: &dyn EventBus,
    ) -> anyhow::Result<()> {
        info!("Starting RDS collection...");

        let mut count = 0;

        let result = self.client.describe_db_instances().send().await;

        match result {
            Ok(output) => {
                for db in output.db_instances.unwrap_or_default() {
                    let db_id = match db.db_instance_identifier() {
                        Some(id) => id.to_string(),
                        None => continue,
                    };

                    let endpoint_address = db.endpoint()
                        .and_then(|e| e.address())
                        .map(|s| s.to_string());

                    let sk = endpoint_address.clone().unwrap_or_else(|| db_id.clone());

                    let mut asset = Asset::new(
                        AssetType::Database,
                        sk.clone(),
                        CloudProvider::Aws,
                    );

                    asset.service = Some(format!("RDS ({})", db.engine().unwrap_or("unknown")));
                    asset.resource_id = Some(db_id.clone());
                    asset.arn = db.db_instance_arn().map(|s| s.to_string());
                    asset.region = Some(self.region.clone());
                    asset.public_access = db.publicly_accessible();
                    asset.encryption_enabled = db.storage_encrypted();

                    // VPC / network
                    if let Some(subnet_group) = db.db_subnet_group() {
                        asset.vpc_id = subnet_group.vpc_id().map(|s| s.to_string());
                    }

                    // Security groups
                    let sg_ids: Vec<String> = db.vpc_security_groups()
                        .iter()
                        .filter_map(|sg| sg.vpc_security_group_id().map(|s| s.to_string()))
                        .collect();
                    if !sg_ids.is_empty() {
                        asset.security_groups = Some(sg_ids.clone());
                    }

                    // Tags
                    let tags = db.tag_list();
                    if !tags.is_empty() {
                        let tags_map: serde_json::Value = tags.iter()
                            .filter_map(|t| {
                                if let (Some(k), Some(v)) = (t.key(), t.value()) {
                                    Some((k.to_string(), serde_json::json!(v)))
                                } else { None }
                            })
                            .collect::<serde_json::Map<String, serde_json::Value>>()
                            .into();
                        asset.tags = Some(tags_map);
                    }

                    let config_json = serde_json::json!({
                        "db_instance_identifier": db_id,
                        "db_instance_class": db.db_instance_class(),
                        "engine": db.engine(),
                        "engine_version": db.engine_version(),
                        "db_instance_status": db.db_instance_status(),
                        "master_username": db.master_username(),
                        "endpoint_address": endpoint_address,
                        "endpoint_port": db.endpoint().and_then(|e| e.port()),
                        "endpoint_hosted_zone_id": db.endpoint().and_then(|e| e.hosted_zone_id()),
                        "allocated_storage": db.allocated_storage(),
                        "storage_type": db.storage_type(),
                        "storage_encrypted": db.storage_encrypted(),
                        "kms_key_id": db.kms_key_id(),
                        "publicly_accessible": db.publicly_accessible(),
                        "multi_az": db.multi_az(),
                        "availability_zone": db.availability_zone(),
                        "secondary_availability_zone": db.secondary_availability_zone(),
                        "db_subnet_group_name": db.db_subnet_group()
                            .and_then(|sg| sg.db_subnet_group_name()),
                        "vpc_id": db.db_subnet_group().and_then(|sg| sg.vpc_id()),
                        "vpc_security_groups": sg_ids,
                        "backup_retention_period": db.backup_retention_period(),
                        "preferred_backup_window": db.preferred_backup_window(),
                        "preferred_maintenance_window": db.preferred_maintenance_window(),
                        "auto_minor_version_upgrade": db.auto_minor_version_upgrade(),
                        "deletion_protection": db.deletion_protection(),
                        "iam_database_authentication_enabled": db.iam_database_authentication_enabled(),
                        "performance_insights_enabled": db.performance_insights_enabled(),
                        "enhanced_monitoring_resource_arn": db.enhanced_monitoring_resource_arn(),
                        "monitoring_interval": db.monitoring_interval(),
                        "ca_certificate_identifier": db.ca_certificate_identifier(),
                        "license_model": db.license_model(),
                        "db_parameter_groups": db.db_parameter_groups()
                            .iter()
                            .map(|pg| serde_json::json!({
                                "name": pg.db_parameter_group_name(),
                                "status": pg.parameter_apply_status(),
                            }))
                            .collect::<Vec<_>>(),
                        "option_group_memberships": db.option_group_memberships()
                            .iter()
                            .map(|og| serde_json::json!({
                                "name": og.option_group_name(),
                                "status": og.status(),
                            }))
                            .collect::<Vec<_>>(),
                        "read_replica_db_instance_identifiers": db.read_replica_db_instance_identifiers(),
                        "read_replica_source_db_instance_identifier": db.read_replica_source_db_instance_identifier(),
                        "copy_tags_to_snapshot": db.copy_tags_to_snapshot(),
                        "timezone": db.timezone(),
                        "character_set_name": db.character_set_name(),
                        "db_cluster_identifier": db.db_cluster_identifier(),
                        "instance_create_time": db.instance_create_time()
                            .map(|t| t.secs().to_string()),
                        "latest_restorable_time": db.latest_restorable_time()
                            .map(|t| t.secs().to_string()),
                    });

                    asset.configuration = Some(config_json);
                    asset_store.insert(asset.clone()).await?;
                    event_bus.publish("analyze-database", &asset.sk).await?;
                    if asset.public_access == Some(true) {
                        event_bus.publish("analyze-domain", &asset.sk).await?;
                    }

                    count += 1;
                    debug!("Collected RDS instance: {}", db_id);
                }
            }
            Err(e) => {
                error!("Failed to describe RDS instances: {}", e);
            }
        }

        info!("RDS collection complete. Collected {} databases", count);
        Ok(())
    }
}

