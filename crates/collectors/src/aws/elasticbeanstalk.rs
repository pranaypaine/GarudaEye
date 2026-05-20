use aws_sdk_elasticbeanstalk::Client;
use garudaeye_core::{Asset, AssetType, CloudProvider};
use infra::traits::{AssetStore, EventBus};
use tracing::{info, error, debug};

pub struct ElasticBeanstalkCollector {
    client: Client,
    region: String,
}

impl ElasticBeanstalkCollector {
    pub async fn new(config: &aws_config::SdkConfig, region: String) -> Self {
        let client = Client::new(config);
        Self { client, region }
    }

    pub async fn collect(
        &self,
        asset_store: &dyn AssetStore,
        event_bus: &dyn EventBus,
    ) -> anyhow::Result<()> {
        info!("Starting Elastic Beanstalk collection...");

        let mut count = 0;

        let result = self.client.describe_environments().send().await;

        match result {
            Ok(output) => {
                for env in output.environments.unwrap_or_default() {
                    let env_id = env.environment_id().unwrap_or("").to_string();
                    let env_name = env.environment_name().unwrap_or("").to_string();

                    let cname = env.cname().map(|s| s.to_string());
                    let endpoint = env.endpoint_url().map(|s| s.to_string());
                    let sk = cname.clone()
                        .or_else(|| endpoint.clone())
                        .unwrap_or_else(|| env_name.clone());

                    let mut asset = Asset::new(
                        AssetType::Domain,
                        sk.clone(),
                        CloudProvider::Aws,
                    );

                    asset.service = Some("Elastic Beanstalk".to_string());
                    asset.resource_id = Some(env_id.clone());
                    asset.region = Some(self.region.clone());
                    // WebServer tier with a CNAME is internet-facing; Worker tier is internal
                    let is_public = cname.is_some()
                        && env.tier().and_then(|t| t.name()) != Some("Worker");
                    asset.public_access = Some(is_public);

                    // Extract region from CNAME (env-name.region.elasticbeanstalk.com)
                    if let Some(ref cname_str) = cname {
                        let parts: Vec<&str> = cname_str.split('.').collect();
                        if parts.len() >= 3 {
                            asset.region = Some(parts[1].to_string());
                        }
                    }

                    let config_json = serde_json::json!({
                        "environment_id": env_id,
                        "environment_name": env_name,
                        "application_name": env.application_name(),
                        "version_label": env.version_label(),
                        "solution_stack_name": env.solution_stack_name(),
                        "platform_arn": env.platform_arn(),
                        "cname": cname,
                        "endpoint_url": endpoint,
                        "status": env.status().map(|s| s.as_str()),
                        "health": env.health().map(|h| h.as_str()),
                        "health_status": env.health_status().map(|h| h.as_str()),
                        "tier_name": env.tier().and_then(|t| t.name()),
                        "tier_type": env.tier().and_then(|t| t.r#type()),
                        "tier_version": env.tier().and_then(|t| t.version()),
                        "description": env.description(),
                        "date_created": env.date_created().map(|t| t.secs().to_string()),
                        "date_updated": env.date_updated().map(|t| t.secs().to_string()),
                        "is_web_server_tier": env.tier()
                            .and_then(|t| t.name())
                            .map(|n| n == "WebServer"),
                        "is_worker_tier": env.tier()
                            .and_then(|t| t.name())
                            .map(|n| n == "Worker"),
                        "abortable_operation_in_progress": env.abortable_operation_in_progress(),
                    });

                    asset.configuration = Some(config_json);
                    asset_store.insert(asset.clone()).await?;
                    if is_public {
                        event_bus.publish("analyze-domain", &asset.sk).await?;
                    }

                    count += 1;
                    debug!("Collected Elastic Beanstalk environment: {}", env_name);
                }
            }
            Err(e) => {
                error!("Failed to describe Elastic Beanstalk environments: {}", e);
            }
        }

        info!("Elastic Beanstalk collection complete. Collected {} environments", count);
        Ok(())
    }
}

