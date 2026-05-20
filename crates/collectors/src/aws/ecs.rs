use aws_sdk_ecs::Client;
use garudaeye_core::{Asset, AssetType, CloudProvider};
use infra::traits::{AssetStore, EventBus};
use tracing::{info, error, debug};

pub struct EcsCollector {
    client: Client,
    region: String,
}

impl EcsCollector {
    pub async fn new(config: &aws_config::SdkConfig, region: String) -> Self {
        let client = Client::new(config);
        Self { client, region }
    }

    pub async fn collect(
        &self,
        asset_store: &dyn AssetStore,
        _event_bus: &dyn EventBus,
    ) -> anyhow::Result<()> {
        info!("Starting ECS collection...");

        let mut cluster_count = 0;
        let mut service_count = 0;

        let clusters_result = self.client.list_clusters().send().await;

        match clusters_result {
            Ok(output) => {
                let cluster_arns = output.cluster_arns.unwrap_or_default();

                for cluster_arn in &cluster_arns {
                    let describe_result = self.client
                        .describe_clusters()
                        .clusters(cluster_arn)
                        .include(aws_sdk_ecs::types::ClusterField::Tags)
                        .include(aws_sdk_ecs::types::ClusterField::Statistics)
                        .include(aws_sdk_ecs::types::ClusterField::Settings)
                        .send()
                        .await;

                    if let Ok(describe_output) = describe_result {
                        for cluster in describe_output.clusters.unwrap_or_default() {
                            let cluster_name = match cluster.cluster_name() {
                                Some(n) => n.to_string(),
                                None => continue,
                            };

                            let mut asset = Asset::new(
                                AssetType::Cluster,
                                cluster_name.clone(),
                                CloudProvider::Aws,
                            );

                            asset.service = Some("ECS".to_string());
                            asset.resource_id = Some(cluster_name.clone());
                            asset.arn = cluster.cluster_arn.clone();
                            asset.region = Some(self.region.clone());

                            // Tags
                            let tags = cluster.tags();
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

                            // Settings
                            let settings: Vec<serde_json::Value> = cluster.settings()
                                .iter()
                                .map(|s| serde_json::json!({
                                    "name": s.name().map(|n| n.as_str()),
                                    "value": s.value(),
                                }))
                                .collect();

                            // Capacity providers
                            let capacity_providers: Vec<&str> = cluster.capacity_providers()
                                .iter()
                                .map(|s| s.as_str())
                                .collect();

                            let config_json = serde_json::json!({
                                "cluster_name": cluster_name,
                                "cluster_arn": cluster.cluster_arn,
                                "status": cluster.status,
                                "running_tasks_count": cluster.running_tasks_count,
                                "pending_tasks_count": cluster.pending_tasks_count,
                                "active_services_count": cluster.active_services_count,
                                "registered_container_instances_count": cluster.registered_container_instances_count,
                                "statistics": cluster.statistics()
                                    .iter()
                                    .map(|s| serde_json::json!({ "name": s.name(), "value": s.value() }))
                                    .collect::<Vec<_>>(),
                                "settings": settings,
                                "capacity_providers": capacity_providers,
                                "default_capacity_provider_strategy": cluster.default_capacity_provider_strategy()
                                    .iter()
                                    .map(|s| serde_json::json!({
                                        "capacity_provider": s.capacity_provider(),
                                        "weight": s.weight(),
                                        "base": s.base(),
                                    }))
                                    .collect::<Vec<_>>(),
                            });

                            asset.configuration = Some(config_json);
                            asset_store.insert(asset.clone()).await?;
                            cluster_count += 1;
                            debug!("Collected ECS cluster: {}", cluster_name);

                            // List and describe services in this cluster
                            let mut next_token: Option<String> = None;
                            loop {
                                let mut list_req = self.client
                                    .list_services()
                                    .cluster(cluster_arn);
                                if let Some(ref token) = next_token {
                                    list_req = list_req.next_token(token);
                                }
                                let services_result = list_req.send().await;

                                let (service_arns, token) = match services_result {
                                    Ok(o) => (o.service_arns.unwrap_or_default(), o.next_token),
                                    Err(_) => break,
                                };

                                if service_arns.is_empty() {
                                    break;
                                }

                                // Describe services in batches of 10
                                for chunk in service_arns.chunks(10) {
                                    let mut describe_req = self.client.describe_services()
                                        .cluster(cluster_arn)
                                        .include(aws_sdk_ecs::types::ServiceField::Tags);
                                    for arn in chunk {
                                        describe_req = describe_req.services(arn);
                                    }

                                    if let Ok(svc_output) = describe_req.send().await {
                                        for svc in svc_output.services.unwrap_or_default() {
                                            let svc_name = svc.service_name()
                                                .unwrap_or("")
                                                .to_string();
                                            let svc_arn = svc.service_arn()
                                                .unwrap_or("")
                                                .to_string();

                                            let mut svc_asset = Asset::new(
                                                AssetType::Container,
                                                svc_name.clone(),
                                                CloudProvider::Aws,
                                            );

                                            svc_asset.service = Some("ECS/Service".to_string());
                                            svc_asset.resource_id = Some(svc_arn.clone());
                                            svc_asset.arn = Some(svc_arn.clone());
                                            svc_asset.region = Some(self.region.clone());

                                            // Load balancers attached to service
                                            let load_balancers: Vec<serde_json::Value> = svc.load_balancers()
                                                .iter()
                                                .map(|lb| serde_json::json!({
                                                    "target_group_arn": lb.target_group_arn(),
                                                    "load_balancer_name": lb.load_balancer_name(),
                                                    "container_name": lb.container_name(),
                                                    "container_port": lb.container_port(),
                                                }))
                                                .collect();

                                            // Network config
                                            let network_config = svc.network_configuration().map(|nc| {
                                                nc.awsvpc_configuration().map(|awsvpc| {
                                                    svc_asset.vpc_id = None; // VPC inferred from subnets
                                                    let sg_ids: Vec<String> = awsvpc.security_groups()
                                                        .iter()
                                                        .map(|s| s.to_string())
                                                        .collect();
                                                    if !sg_ids.is_empty() {
                                                        svc_asset.security_groups = Some(sg_ids.clone());
                                                    }
                                                    svc_asset.public_access = awsvpc.assign_public_ip()
                                                        .map(|a| a.as_str() == "ENABLED");
                                                    serde_json::json!({
                                                        "subnets": awsvpc.subnets(),
                                                        "security_groups": sg_ids,
                                                        "assign_public_ip": awsvpc.assign_public_ip().map(|a| a.as_str()),
                                                    })
                                                })
                                            }).flatten();

                                            // Tags
                                            let tags = svc.tags();
                                            if !tags.is_empty() {
                                                let tags_map: serde_json::Value = tags.iter()
                                                    .filter_map(|t| {
                                                        if let (Some(k), Some(v)) = (t.key(), t.value()) {
                                                            Some((k.to_string(), serde_json::json!(v)))
                                                        } else { None }
                                                    })
                                                    .collect::<serde_json::Map<String, serde_json::Value>>()
                                                    .into();
                                                svc_asset.tags = Some(tags_map);
                                            }

                                            let svc_config = serde_json::json!({
                                                "service_name": svc_name,
                                                "service_arn": svc_arn,
                                                "cluster_arn": cluster_arn,
                                                "cluster_name": cluster_name,
                                                "status": svc.status(),
                                                "task_definition": svc.task_definition(),
                                                "desired_count": svc.desired_count(),
                                                "running_count": svc.running_count(),
                                                "pending_count": svc.pending_count(),
                                                "launch_type": svc.launch_type().map(|l| l.as_str()),
                                                "platform_version": svc.platform_version(),
                                                "platform_family": svc.platform_family(),
                                                "scheduling_strategy": svc.scheduling_strategy().map(|s| s.as_str()),
                                                "deployment_controller": svc.deployment_controller()
                                                    .map(|d| d.r#type().as_str()),
                                                "created_at": svc.created_at().map(|t| t.secs().to_string()),
                                                "health_check_grace_period_seconds": svc.health_check_grace_period_seconds(),
                                                "propagate_tags": svc.propagate_tags().map(|p| p.as_str()),
                                                "role_arn": svc.role_arn(),
                                                "load_balancers": load_balancers,
                                                "network_configuration": network_config,
                                                "deployment_configuration": svc.deployment_configuration().map(|dc| serde_json::json!({
                                                    "maximum_percent": dc.maximum_percent(),
                                                    "minimum_healthy_percent": dc.minimum_healthy_percent(),
                                                })),
                                                "capacity_provider_strategy": svc.capacity_provider_strategy()
                                                    .iter()
                                                    .map(|s| serde_json::json!({
                                                        "capacity_provider": s.capacity_provider(),
                                                        "weight": s.weight(),
                                                        "base": s.base(),
                                                    }))
                                                    .collect::<Vec<_>>(),
                                            });

                                            svc_asset.configuration = Some(svc_config);
                                            asset_store.insert(svc_asset).await?;
                                            service_count += 1;
                                            debug!("Collected ECS service: {}", svc_name);
                                        }
                                    }
                                }

                                next_token = token;
                                if next_token.is_none() {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to list ECS clusters: {}", e);
            }
        }

        info!("ECS collection complete. Collected {} clusters, {} services",
              cluster_count, service_count);
        Ok(())
    }
}

