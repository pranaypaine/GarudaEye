use aws_sdk_apigateway::Client;
use garudaeye_core::{Asset, AssetType, CloudProvider};
use infra::traits::{AssetStore, EventBus};
use tracing::{info, error, debug};

pub struct ApiGatewayCollector {
    client: Client,
    region: String,
}

impl ApiGatewayCollector {
    pub async fn new(config: &aws_config::SdkConfig, region: String) -> Self {
        let client = Client::new(config);
        Self { client, region }
    }

    pub async fn collect(
        &self,
        asset_store: &dyn AssetStore,
        event_bus: &dyn EventBus,
    ) -> anyhow::Result<()> {
        info!("Starting API Gateway collection...");

        let mut count = 0;

        let result = self.client.get_rest_apis().send().await;

        match result {
            Ok(output) => {
                for api in output.items.unwrap_or_default() {
                    let api_id = match api.id() {
                        Some(id) => id.to_string(),
                        None => continue,
                    };
                    let api_name = api.name().unwrap_or("").to_string();

                    // Endpoint types
                    let endpoint_types: Vec<String> = api.endpoint_configuration()
                        .map(|ec| ec.types())
                        .unwrap_or_default()
                        .iter()
                        .map(|t| t.as_str().to_string())
                        .collect();
                    let is_private = endpoint_types.iter().any(|t| t == "PRIVATE");
                    let is_edge = endpoint_types.iter().any(|t| t == "EDGE");

                    // Get stages
                    let stages = match self.client
                        .get_stages()
                        .rest_api_id(&api_id)
                        .send()
                        .await
                    {
                        Ok(sr) => sr.item.unwrap_or_default(),
                        Err(_) => vec![],
                    };

                    // Get resources count
                    let resources_count = match self.client
                        .get_resources()
                        .rest_api_id(&api_id)
                        .send()
                        .await
                    {
                        Ok(rr) => rr.items.as_ref().map(|v| v.len()).unwrap_or(0),
                        Err(_) => 0,
                    };

                    let stages_detail: Vec<serde_json::Value> = stages.iter().map(|stage| {
                        let stage_name = stage.stage_name().unwrap_or("");
                        serde_json::json!({
                            "stage_name": stage_name,
                            "description": stage.description(),
                            "deployment_id": stage.deployment_id(),
                            "created_date": stage.created_date().map(|t| t.secs().to_string()),
                            "last_updated_date": stage.last_updated_date().map(|t| t.secs().to_string()),
                            "tracing_enabled": stage.tracing_enabled(),
                            "cache_cluster_enabled": stage.cache_cluster_enabled(),
                            "cache_cluster_status": stage.cache_cluster_status().map(|s| s.as_str()),
                            "cache_cluster_size": stage.cache_cluster_size().map(|s| s.as_str()),
                            "client_certificate_id": stage.client_certificate_id(),
                            "web_acl_arn": stage.web_acl_arn(),
                            "variables": stage.variables(),
                        })
                    }).collect();

                    // For each stage, create an asset with the full endpoint URL
                    for stage in &stages {
                        let stage_name = match stage.stage_name() {
                            Some(n) => n.to_string(),
                            None => continue,
                        };

                        // Proper regional endpoint
                        let endpoint = format!(
                            "{}.execute-api.{}.amazonaws.com",
                            api_id, self.region
                        );
                        let full_url = format!("https://{}/{}", endpoint, stage_name);

                        let mut asset = Asset::new(
                            AssetType::ApiGateway,
                            endpoint.clone(),
                            CloudProvider::Aws,
                        );

                        asset.service = Some(format!("API Gateway ({}/{})", api_name, stage_name));
                        asset.resource_id = Some(format!("{}/{}", api_id, stage_name));
                        asset.region = Some(self.region.clone());
                        asset.public_access = Some(!is_private);
                        asset.dns_name = Some(endpoint.clone());

                        let config_json = serde_json::json!({
                            "api_id": api_id,
                            "api_name": api_name,
                            "description": api.description(),
                            "version": api.version(),
                            "created_date": api.created_date().map(|t| t.secs().to_string()),
                            "stage_name": stage_name,
                            "full_url": full_url,
                            "endpoint_types": endpoint_types,
                            "is_private": is_private,
                            "is_edge": is_edge,
                            "resources_count": resources_count,
                            "policy": api.policy(),
                            "api_key_source": api.api_key_source().map(|s| s.as_str()),
                            "minimum_compression_size": api.minimum_compression_size(),
                            "binary_media_types": api.binary_media_types(),
                            "warnings": api.warnings(),
                            "stages": stages_detail,
                            "tags": api.tags(),
                        });

                        asset.configuration = Some(config_json);
                        asset_store.insert(asset.clone()).await?;
                        event_bus.publish("analyze-domain", &endpoint).await?;

                        count += 1;
                        debug!("Collected API Gateway: {} (stage: {})", api_name, stage_name);
                    }

                    // If no stages, still record the API
                    if stages.is_empty() {
                        let endpoint = format!(
                            "{}.execute-api.{}.amazonaws.com",
                            api_id, self.region
                        );

                        let mut asset = Asset::new(
                            AssetType::ApiGateway,
                            endpoint.clone(),
                            CloudProvider::Aws,
                        );

                        asset.service = Some(format!("API Gateway ({})", api_name));
                        asset.resource_id = Some(api_id.clone());
                        asset.region = Some(self.region.clone());
                        asset.public_access = Some(!is_private);

                        let config_json = serde_json::json!({
                            "api_id": api_id,
                            "api_name": api_name,
                            "description": api.description(),
                            "version": api.version(),
                            "endpoint_types": endpoint_types,
                            "is_private": is_private,
                            "resources_count": resources_count,
                            "policy": api.policy(),
                            "stages": [],
                        });

                        asset.configuration = Some(config_json);
                        asset_store.insert(asset.clone()).await?;
                        if !is_private {
                            event_bus.publish("analyze-domain", &endpoint).await?;
                        }

                        count += 1;
                    }
                }
            }
            Err(e) => {
                error!("Failed to get REST APIs: {}", e);
            }
        }

        info!("API Gateway collection complete. Collected {} APIs", count);
        Ok(())
    }
}

