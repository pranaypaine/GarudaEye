use aws_sdk_elasticsearch::Client;
use garudaeye_core::{Asset, AssetType, CloudProvider};
use infra::traits::{AssetStore, EventBus};
use tracing::{info, error, debug};

pub struct ElasticsearchCollector {
    client: Client,
    region: String,
}

impl ElasticsearchCollector {
    pub async fn new(config: &aws_config::SdkConfig, region: String) -> Self {
        let client = Client::new(config);
        Self { client, region }
    }

    pub async fn collect(
        &self,
        asset_store: &dyn AssetStore,
        event_bus: &dyn EventBus,
    ) -> anyhow::Result<()> {
        info!("Starting Elasticsearch collection...");

        let mut count = 0;

        let result = self.client.list_domain_names().send().await;

        match result {
            Ok(output) => {
                for domain in output.domain_names.unwrap_or_default() {
                    let name = match domain.domain_name() {
                        Some(n) => n.to_string(),
                        None => continue,
                    };

                    let dr = match self.client
                        .describe_elasticsearch_domain()
                        .domain_name(&name)
                        .send()
                        .await
                    {
                        Ok(r) => r,
                        Err(e) => {
                            error!("Failed to describe ES domain {}: {}", name, e);
                            continue;
                        }
                    };

                    let domain_status = match dr.domain_status() {
                        Some(s) => s,
                        None => continue,
                    };

                    // Endpoint: domain can have VPC endpoint or public endpoint
                    let endpoint = domain_status.endpoint()
                        .map(|s| s.to_string())
                        .or_else(|| {
                            domain_status.endpoints()
                                .and_then(|eps| eps.get("vpc"))
                                .map(|s| s.to_string())
                        });

                    let sk = endpoint.clone().unwrap_or_else(|| name.clone());

                    let mut asset = Asset::new(
                        AssetType::Domain,
                        sk.clone(),
                        CloudProvider::Aws,
                    );

                    asset.service = Some("Elasticsearch".to_string());
                    asset.resource_id = Some(name.clone());
                    asset.arn = Some(domain_status.arn().to_string());
                    asset.region = Some(self.region.clone());

                    // VPC — if VPC options present, it's private; otherwise public
                    let is_vpc_deployed = domain_status.vpc_options().is_some();
                    asset.public_access = Some(!is_vpc_deployed);

                    if let Some(vpc_opts) = domain_status.vpc_options() {
                        asset.vpc_id = vpc_opts.vpc_id().map(|s| s.to_string());
                        asset.subnet_id = vpc_opts.subnet_ids()
                            .first()
                            .map(|s| s.to_string());
                        let sg_ids: Vec<String> = vpc_opts.security_group_ids()
                            .iter()
                            .map(|s| s.to_string())
                            .collect();
                        if !sg_ids.is_empty() {
                            asset.security_groups = Some(sg_ids);
                        }
                    }

                    // Encryption
                    asset.encryption_enabled = domain_status.encryption_at_rest_options()
                        .and_then(|e| e.enabled());

                    let config_json = serde_json::json!({
                        "domain_name": name,
                        "domain_id": domain_status.domain_id(),
                        "arn": domain_status.arn(),
                        "elasticsearch_version": domain_status.elasticsearch_version(),
                        "created": domain_status.created(),
                        "deleted": domain_status.deleted(),
                        "endpoint": endpoint,
                        "endpoints": domain_status.endpoints(),
                        "processing": domain_status.processing(),
                        "upgrade_processing": domain_status.upgrade_processing(),
                        "is_vpc_deployed": is_vpc_deployed,
                        "vpc_options": domain_status.vpc_options().map(|v| serde_json::json!({
                            "vpc_id": v.vpc_id(),
                            "subnet_ids": v.subnet_ids(),
                            "security_group_ids": v.security_group_ids(),
                            "availability_zones": v.availability_zones(),
                        })),
                        "cluster_config": domain_status.elasticsearch_cluster_config().map(|c| serde_json::json!({
                            "instance_type": c.instance_type().map(|t| t.as_str()),
                            "instance_count": c.instance_count(),
                            "dedicated_master_enabled": c.dedicated_master_enabled(),
                            "dedicated_master_type": c.dedicated_master_type().map(|t| t.as_str()),
                            "dedicated_master_count": c.dedicated_master_count(),
                            "zone_awareness_enabled": c.zone_awareness_enabled(),
                            "warm_enabled": c.warm_enabled(),
                            "warm_type": c.warm_type().map(|t| t.as_str()),
                            "warm_count": c.warm_count(),
                        })),
                        "ebs_options": domain_status.ebs_options().map(|e| serde_json::json!({
                            "ebs_enabled": e.ebs_enabled(),
                            "volume_type": e.volume_type().map(|t| t.as_str()),
                            "volume_size": e.volume_size(),
                            "iops": e.iops(),
                        })),
                        "encryption_at_rest": domain_status.encryption_at_rest_options().map(|e| serde_json::json!({
                            "enabled": e.enabled(),
                            "kms_key_id": e.kms_key_id(),
                        })),
                        "node_to_node_encryption": domain_status.node_to_node_encryption_options()
                            .and_then(|n| n.enabled()),
                        "domain_endpoint_options": domain_status.domain_endpoint_options().map(|d| serde_json::json!({
                            "enforce_https": d.enforce_https(),
                            "tls_security_policy": d.tls_security_policy().map(|p| p.as_str()),
                            "custom_endpoint_enabled": d.custom_endpoint_enabled(),
                            "custom_endpoint": d.custom_endpoint(),
                            "custom_endpoint_certificate_arn": d.custom_endpoint_certificate_arn(),
                        })),
                        "advanced_security_options": domain_status.advanced_security_options().map(|a| serde_json::json!({
                            "enabled": a.enabled(),
                            "internal_user_database_enabled": a.internal_user_database_enabled(),
                            "saml_options_enabled": a.saml_options().and_then(|s| s.enabled()),
                        })),
                        "cognito_options": domain_status.cognito_options().map(|c| serde_json::json!({
                            "enabled": c.enabled(),
                            "user_pool_id": c.user_pool_id(),
                            "identity_pool_id": c.identity_pool_id(),
                        })),
                        "snapshot_options": domain_status.snapshot_options()
                            .and_then(|s| s.automated_snapshot_start_hour()),
                    });

                    asset.configuration = Some(config_json);
                    asset_store.insert(asset.clone()).await?;
                    if !is_vpc_deployed {
                        event_bus.publish("analyze-domain", &asset.sk).await?;
                    }

                    count += 1;
                    debug!("Collected Elasticsearch domain: {}", name);
                }
            }
            Err(e) => {
                error!("Failed to list Elasticsearch domains: {}", e);
            }
        }

        info!("Elasticsearch collection complete. Collected {} domains", count);
        Ok(())
    }
}

