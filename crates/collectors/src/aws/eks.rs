use aws_sdk_eks::Client;
use garudaeye_core::{Asset, AssetType, CloudProvider};
use infra::traits::{AssetStore, EventBus};
use tracing::{info, error, debug};

pub struct EksCollector {
    client: Client,
    region: String,
}

impl EksCollector {
    pub async fn new(config: &aws_config::SdkConfig, region: String) -> Self {
        let client = Client::new(config);
        Self { client, region }
    }

    pub async fn collect(
        &self,
        asset_store: &dyn AssetStore,
        event_bus: &dyn EventBus,
    ) -> anyhow::Result<()> {
        info!("Starting EKS collection...");

        let mut count = 0;

        let result = self.client.list_clusters().send().await;

        match result {
            Ok(output) => {
                for cluster_name in output.clusters.unwrap_or_default() {
                    let describe_result = self.client
                        .describe_cluster()
                        .name(&cluster_name)
                        .send()
                        .await;

                    if let Ok(dr) = describe_result {
                        if let Some(cluster) = dr.cluster() {
                            let endpoint = cluster.endpoint().unwrap_or("").to_string();
                            let sk = endpoint.trim_start_matches("https://").to_string();
                            let sk = if sk.is_empty() { cluster_name.clone() } else { sk };

                            let mut asset = Asset::new(
                                AssetType::Domain,
                                sk.clone(),
                                CloudProvider::Aws,
                            );

                            asset.service = Some("EKS".to_string());
                            asset.resource_id = Some(cluster_name.clone());
                            asset.arn = cluster.arn().map(|s| s.to_string());
                            asset.region = Some(self.region.clone());
                            asset.iam_role = cluster.role_arn().map(|s| s.to_string());

                            // VPC config
                            if let Some(vpc_config) = cluster.resources_vpc_config() {
                                asset.vpc_id = vpc_config.vpc_id().map(|s| s.to_string());
                                asset.subnet_id = vpc_config.subnet_ids()
                                    .first()
                                    .map(|s| s.to_string());
                                let sg_ids: Vec<String> = vpc_config.security_group_ids()
                                    .iter()
                                    .map(|s| s.to_string())
                                    .collect();
                                if !sg_ids.is_empty() {
                                    asset.security_groups = Some(sg_ids);
                                }

                                let endpoint_public = vpc_config.endpoint_public_access();
                                asset.public_access = Some(endpoint_public);
                            }

                            // Encryption
                            let encryption_configs: Vec<serde_json::Value> = cluster.encryption_config()
                                .iter()
                                .map(|ec| serde_json::json!({
                                    "resources": ec.resources(),
                                    "key_arn": ec.provider().and_then(|p| p.key_arn()),
                                }))
                                .collect();
                            if !encryption_configs.is_empty() {
                                asset.encryption_enabled = Some(true);
                            }

                            // Logging
                            let logging_types: Vec<serde_json::Value> = cluster.logging()
                                .map(|l| l.cluster_logging())
                                .unwrap_or_default()
                                .iter()
                                .map(|lt| serde_json::json!({
                                    "types": lt.types().iter().map(|t| t.as_str()).collect::<Vec<_>>(),
                                    "enabled": lt.enabled(),
                                }))
                                .collect();

                            // Tags
                            if let Some(tags_map) = cluster.tags() {
                                if !tags_map.is_empty() {
                                    let tags_val: serde_json::Value = tags_map.iter()
                                        .map(|(k, v)| (k.clone(), serde_json::json!(v)))
                                        .collect::<serde_json::Map<String, serde_json::Value>>()
                                        .into();
                                    asset.tags = Some(tags_val);
                                }
                            }

                            let config_json = serde_json::json!({
                                "cluster_name": cluster_name,
                                "cluster_arn": cluster.arn(),
                                "kubernetes_version": cluster.version(),
                                "platform_version": cluster.platform_version(),
                                "status": cluster.status().map(|s| s.as_str()),
                                "endpoint": cluster.endpoint(),
                                "role_arn": cluster.role_arn(),
                                "resources_vpc_config": cluster.resources_vpc_config().map(|v| serde_json::json!({
                                    "vpc_id": v.vpc_id(),
                                    "subnet_ids": v.subnet_ids(),
                                    "security_group_ids": v.security_group_ids(),
                                    "cluster_security_group_id": v.cluster_security_group_id(),
                                    "endpoint_public_access": v.endpoint_public_access(),
                                    "endpoint_private_access": v.endpoint_private_access(),
                                    "public_access_cidrs": v.public_access_cidrs(),
                                })),
                                "kubernetes_network_config": cluster.kubernetes_network_config().map(|k| serde_json::json!({
                                    "service_ipv4_cidr": k.service_ipv4_cidr(),
                                    "service_ipv6_cidr": k.service_ipv6_cidr(),
                                    "ip_family": k.ip_family().map(|f| f.as_str()),
                                })),
                                "logging": logging_types,
                                "identity_oidc_issuer": cluster.identity()
                                    .and_then(|i| i.oidc())
                                    .and_then(|o| o.issuer()),
                                "certificate_authority": cluster.certificate_authority()
                                    .and_then(|ca| ca.data()),
                                "encryption_config": encryption_configs,
                                "created_at": cluster.created_at().map(|t| t.secs().to_string()),
                                "client_request_token": cluster.client_request_token(),
                                "connector_config": cluster.connector_config().map(|c| serde_json::json!({
                                    "activation_id": c.activation_id(),
                                    "activation_expiry": c.activation_expiry().map(|t| t.secs().to_string()),
                                    "provider": c.provider(),
                                    "role_arn": c.role_arn(),
                                })),
                            });

                            asset.configuration = Some(config_json);
                            asset_store.insert(asset.clone()).await?;

                            if !sk.is_empty() {
                                event_bus.publish("analyze-domain", &asset.sk).await?;
                            }

                            count += 1;
                            debug!("Collected EKS cluster: {}", cluster_name);
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to list EKS clusters: {}", e);
            }
        }

        info!("EKS collection complete. Collected {} clusters", count);
        Ok(())
    }
}

