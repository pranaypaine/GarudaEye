use aws_sdk_elasticloadbalancingv2::Client;
use garudaeye_core::{Asset, AssetType, CloudProvider};
use infra::traits::{AssetStore, EventBus};
use tracing::{info, error, debug};

pub struct ElbCollector {
    client: Client,
    region: String,
}

impl ElbCollector {
    pub async fn new(config: &aws_config::SdkConfig, region: String) -> Self {
        let client = Client::new(config);
        Self { client, region }
    }

    pub async fn collect(
        &self,
        asset_store: &dyn AssetStore,
        event_bus: &dyn EventBus,
    ) -> anyhow::Result<()> {
        info!("Starting ELB collection...");

        let mut count = 0;

        let result = self.client.describe_load_balancers().send().await;

        match result {
            Ok(output) => {
                for lb in output.load_balancers.unwrap_or_default() {
                    let dns_name = match lb.dns_name() {
                        Some(d) => d.to_string(),
                        None => continue,
                    };
                    let lb_arn = lb.load_balancer_arn().unwrap_or("").to_string();
                    let lb_type = lb.r#type().map(|t| t.as_str()).unwrap_or("unknown").to_string();
                    let scheme = lb.scheme().map(|s| s.as_str()).unwrap_or("unknown").to_string();
                    let is_internet_facing = scheme == "internet-facing";

                    let mut asset = Asset::new(
                        AssetType::LoadBalancer,
                        dns_name.clone(),
                        CloudProvider::Aws,
                    );

                    asset.service = Some(format!("ELB ({})", lb_type));
                    asset.resource_id = Some(lb_arn.clone());
                    asset.arn = Some(lb_arn.clone());
                    asset.dns_name = Some(dns_name.clone());
                    asset.region = Some(self.region.clone());
                    asset.public_access = Some(is_internet_facing);

                    // Security groups (ALB only)
                    let sg_ids: Vec<String> = lb.security_groups()
                        .iter()
                        .map(|s| s.to_string())
                        .collect();
                    if !sg_ids.is_empty() {
                        asset.security_groups = Some(sg_ids.clone());
                    }

                    // Availability zones
                    let azs: Vec<serde_json::Value> = lb.availability_zones()
                        .iter()
                        .map(|az| serde_json::json!({
                            "zone_name": az.zone_name(),
                            "subnet_id": az.subnet_id(),
                        }))
                        .collect();

                    // Fetch listeners
                    let listeners: Vec<serde_json::Value> = match self.client
                        .describe_listeners()
                        .load_balancer_arn(&lb_arn)
                        .send()
                        .await
                    {
                        Ok(lr) => lr.listeners.unwrap_or_default()
                            .iter()
                            .map(|l| serde_json::json!({
                                "listener_arn": l.listener_arn(),
                                "port": l.port(),
                                "protocol": l.protocol().map(|p| p.as_str()),
                                "ssl_policy": l.ssl_policy(),
                                "certificates": l.certificates()
                                    .iter()
                                    .map(|c| serde_json::json!({
                                        "certificate_arn": c.certificate_arn(),
                                        "is_default": c.is_default(),
                                    }))
                                    .collect::<Vec<_>>(),
                            }))
                            .collect(),
                        Err(_) => vec![],
                    };

                    // Tags
                    if let Ok(tags_resp) = self.client
                        .describe_tags()
                        .resource_arns(&lb_arn)
                        .send()
                        .await
                    {
                        for td in tags_resp.tag_descriptions.unwrap_or_default() {
                            let tag_list = td.tags();
                            if !tag_list.is_empty() {
                                let tags_map: serde_json::Value = tag_list.iter()
                                    .filter_map(|t| {
                                        if let (Some(k), Some(v)) = (t.key(), t.value()) {
                                            Some((k.to_string(), serde_json::json!(v)))
                                        } else { None }
                                    })
                                    .collect::<serde_json::Map<String, serde_json::Value>>()
                                    .into();
                                asset.tags = Some(tags_map);
                            }
                        }
                    }

                    let config_json = serde_json::json!({
                        "load_balancer_name": lb.load_balancer_name(),
                        "load_balancer_arn": lb_arn,
                        "dns_name": dns_name,
                        "type": lb_type,
                        "scheme": scheme,
                        "is_internet_facing": is_internet_facing,
                        "state": lb.state().and_then(|s| s.code()).map(|c| c.as_str()),
                        "vpc_id": lb.vpc_id(),
                        "ip_address_type": lb.ip_address_type().map(|t| t.as_str()),
                        "security_groups": sg_ids,
                        "availability_zones": azs,
                        "listeners": listeners,
                        "created_time": lb.created_time().map(|t| t.secs().to_string()),
                        "customer_owned_ipv4_pool": lb.customer_owned_ipv4_pool(),
                        "enforce_security_group_inbound_rules_on_private_link_traffic":
                            lb.enforce_security_group_inbound_rules_on_private_link_traffic(),
                    });

                    asset.configuration = Some(config_json);
                    asset_store.insert(asset.clone()).await?;
                    if is_internet_facing {
                        event_bus.publish("analyze-domain", &asset.sk).await?;
                    }

                    count += 1;
                    debug!("Collected ELB: {}", dns_name);
                }
            }
            Err(e) => {
                error!("Failed to describe load balancers: {}", e);
            }
        }

        info!("ELB collection complete. Collected {} load balancers", count);
        Ok(())
    }
}

