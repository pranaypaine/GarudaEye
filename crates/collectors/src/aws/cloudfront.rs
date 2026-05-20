use aws_sdk_cloudfront::Client;
use garudaeye_core::{Asset, AssetType, CloudProvider};
use infra::traits::{AssetStore, EventBus};
use tracing::{info, error, debug};

pub struct CloudFrontCollector {
    client: Client,
    #[allow(dead_code)]
    region: String,
}

impl CloudFrontCollector {
    pub async fn new(config: &aws_config::SdkConfig, region: String) -> Self {
        let client = Client::new(config);
        Self { client, region }
    }

    pub async fn collect(
        &self,
        asset_store: &dyn AssetStore,
        event_bus: &dyn EventBus,
    ) -> anyhow::Result<()> {
        info!("Starting CloudFront collection...");

        let mut count = 0;

        let result = self.client.list_distributions().send().await;

        match result {
            Ok(output) => {
                if let Some(dist_list) = output.distribution_list {
                    for dist in dist_list.items.unwrap_or_default() {
                        let domain_name = dist.domain_name().to_string();
                        let dist_id = dist.id().to_string();

                        let mut asset = Asset::new(
                            AssetType::Cdn,
                            domain_name.clone(),
                            CloudProvider::Aws,
                        );

                        asset.service = Some("CloudFront".to_string());
                        asset.resource_id = Some(dist_id.clone());
                        asset.arn = Some(dist.arn().to_string());
                        asset.dns_name = Some(domain_name.clone());
                        asset.region = Some("global".to_string());
                        asset.public_access = Some(dist.enabled());

                        // Origins — what the distribution points to
                        let origins: Vec<serde_json::Value> = dist.origins()
                            .map(|o| o.items())
                            .unwrap_or_default()
                            .iter()
                            .map(|origin| serde_json::json!({
                                "id": origin.id(),
                                "domain_name": origin.domain_name(),
                                "origin_path": origin.origin_path(),
                                "connection_attempts": origin.connection_attempts(),
                                "connection_timeout": origin.connection_timeout(),
                                "protocol_policy": origin.custom_origin_config()
                                    .map(|c| c.origin_protocol_policy().as_str()),
                                "s3_origin_access": origin.s3_origin_config()
                                    .map(|s| !s.origin_access_identity().is_empty()),
                                "origin_access_control_id": origin.origin_access_control_id(),
                            }))
                            .collect();

                        // Aliases (custom domains)
                        let aliases: Vec<String> = dist.aliases()
                            .map(|a| a.items())
                            .unwrap_or_default()
                            .iter()
                            .map(|s| s.to_string())
                            .collect();

                        // Default cache behavior
                        let default_cache_behavior = dist.default_cache_behavior().map(|dcb| {
                            serde_json::json!({
                                "target_origin_id": dcb.target_origin_id(),
                                "viewer_protocol_policy": dcb.viewer_protocol_policy().as_str(),
                                "compress": dcb.compress(),
                                "allowed_methods": dcb.allowed_methods().map(|m| m.items().iter().map(|i| i.as_str()).collect::<Vec<_>>()),
                                "cached_methods": dcb.allowed_methods().and_then(|m| m.cached_methods()).map(|cm| cm.items().iter().map(|i| i.as_str()).collect::<Vec<_>>()),
                                "cache_policy_id": dcb.cache_policy_id(),
                                "origin_request_policy_id": dcb.origin_request_policy_id(),
                                "field_level_encryption_id": dcb.field_level_encryption_id(),
                                "realtime_log_config_arn": dcb.realtime_log_config_arn(),
                            })
                        });

                        // SSL / viewer certificate
                        let viewer_cert = dist.viewer_certificate().map(|vc| serde_json::json!({
                            "ssl_support_method": vc.ssl_support_method().map(|m| m.as_str()),
                            "minimum_protocol_version": vc.minimum_protocol_version().map(|v| v.as_str()),
                            "acm_certificate_arn": vc.acm_certificate_arn(),
                            "iam_certificate_id": vc.iam_certificate_id(),
                            "cloudfront_default_certificate": vc.cloud_front_default_certificate(),
                        }));

                        // Geo restriction
                        let geo_restriction = dist.restrictions()
                            .and_then(|r| r.geo_restriction())
                            .map(|gr| serde_json::json!({
                                "restriction_type": gr.restriction_type().as_str(),
                                "quantity": gr.quantity(),
                                "locations": gr.items(),
                            }));

                        let config_json = serde_json::json!({
                            "distribution_id": dist_id,
                            "domain_name": domain_name,
                            "arn": dist.arn(),
                            "status": dist.status(),
                            "enabled": dist.enabled(),
                            "is_ipv6_enabled": dist.is_ipv6_enabled(),
                            "http_version": dist.http_version().as_str(),
                            "price_class": dist.price_class().as_str(),
                            "comment": dist.comment(),
                            "web_acl_id": dist.web_acl_id(),
                            "aliases": aliases,
                            "origins": origins,
                            "default_cache_behavior": default_cache_behavior,
                            "viewer_certificate": viewer_cert,
                            "geo_restriction": geo_restriction,
                            "custom_error_responses": dist.custom_error_responses()
                                .map(|c| c.items())
                                .unwrap_or_default()
                                .iter()
                                .map(|er| serde_json::json!({
                                    "error_code": er.error_code(),
                                    "response_code": er.response_code(),
                                    "response_page_path": er.response_page_path(),
                                    "error_caching_min_ttl": er.error_caching_min_ttl(),
                                }))
                                .collect::<Vec<_>>(),
                            "last_modified_time": dist.last_modified_time().secs().to_string(),
                        });

                        asset.configuration = Some(config_json);
                        asset_store.insert(asset.clone()).await?;
                        event_bus.publish("analyze-domain", &domain_name).await?;

                        count += 1;
                        debug!("Collected CloudFront distribution: {}", domain_name);
                    }
                }
            }
            Err(e) => {
                error!("Failed to list CloudFront distributions: {}", e);
            }
        }

        info!("CloudFront collection complete. Collected {} distributions", count);
        Ok(())
    }
}

