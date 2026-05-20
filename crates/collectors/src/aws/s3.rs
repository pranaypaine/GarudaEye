use aws_sdk_s3::Client;
use garudaeye_core::{Asset, AssetType, CloudProvider};
use infra::traits::{AssetStore, EventBus};
use tracing::{info, error, debug};

pub struct S3Collector {
    client: Client,
    region: String,
}

impl S3Collector {
    pub async fn new(config: &aws_config::SdkConfig, region: String) -> Self {
        let client = Client::new(config);
        Self { client, region }
    }

    pub async fn collect(
        &self,
        asset_store: &dyn AssetStore,
        event_bus: &dyn EventBus,
    ) -> anyhow::Result<()> {
        info!("Starting S3 collection...");

        let mut count = 0;

        let result = self.client.list_buckets().send().await;

        match result {
            Ok(output) => {
                for bucket in output.buckets.unwrap_or_default() {
                    let name = match bucket.name() {
                        Some(n) => n.to_string(),
                        None => continue,
                    };

                    let mut asset = Asset::new(
                        AssetType::S3Bucket,
                        name.clone(),
                        CloudProvider::Aws,
                    );

                    asset.service = Some("S3".to_string());
                    asset.resource_id = Some(name.clone());
                    asset.region = Some(self.region.clone());

                    let mut config_json = serde_json::json!({
                        "bucket_name": name,
                        "creation_date": bucket.creation_date().map(|d| d.secs().to_string()),
                    });

                    // Region / location
                    if let Ok(location) = self.client
                        .get_bucket_location()
                        .bucket(&name)
                        .send()
                        .await
                    {
                        if let Some(constraint) = location.location_constraint() {
                            let region_str = constraint.as_str().to_string();
                            asset.region = Some(if region_str.is_empty() { "us-east-1".to_string() } else { region_str.clone() });
                            config_json["region"] = serde_json::json!(region_str);
                        }
                    }

                    // Public access block
                    let public_access_blocked = match self.client
                        .get_public_access_block()
                        .bucket(&name)
                        .send()
                        .await
                    {
                        Ok(resp) => {
                            if let Some(config) = resp.public_access_block_configuration() {
                                let block_public_acls = config.block_public_acls().unwrap_or(false);
                                let ignore_public_acls = config.ignore_public_acls().unwrap_or(false);
                                let block_public_policy = config.block_public_policy().unwrap_or(false);
                                let restrict_public_buckets = config.restrict_public_buckets().unwrap_or(false);
                                config_json["public_access_block"] = serde_json::json!({
                                    "block_public_acls": block_public_acls,
                                    "ignore_public_acls": ignore_public_acls,
                                    "block_public_policy": block_public_policy,
                                    "restrict_public_buckets": restrict_public_buckets,
                                });
                                block_public_acls && ignore_public_acls && block_public_policy && restrict_public_buckets
                            } else {
                                false
                            }
                        }
                        Err(_) => false,
                    };
                    asset.public_access = Some(!public_access_blocked);

                    // Versioning
                    if let Ok(versioning) = self.client
                        .get_bucket_versioning()
                        .bucket(&name)
                        .send()
                        .await
                    {
                        config_json["versioning"] = serde_json::json!(
                            versioning.status().map(|s| s.as_str()).unwrap_or("Disabled")
                        );
                        config_json["mfa_delete"] = serde_json::json!(
                            versioning.mfa_delete().map(|s| s.as_str()).unwrap_or("Disabled")
                        );
                    }

                    // Encryption
                    match self.client
                        .get_bucket_encryption()
                        .bucket(&name)
                        .send()
                        .await
                    {
                        Ok(enc) => {
                            if let Some(config) = enc.server_side_encryption_configuration() {
                                let rules: Vec<serde_json::Value> = config.rules()
                                    .iter()
                                    .map(|r| serde_json::json!({
                                        "sse_algorithm": r.apply_server_side_encryption_by_default()
                                            .and_then(|d| Some(d.sse_algorithm().as_str().to_string())),
                                        "kms_master_key_id": r.apply_server_side_encryption_by_default()
                                            .and_then(|d| d.kms_master_key_id()),
                                        "bucket_key_enabled": r.bucket_key_enabled(),
                                    }))
                                    .collect();
                                config_json["encryption"] = serde_json::json!(rules);
                                asset.encryption_enabled = Some(true);
                            }
                        }
                        Err(_) => {
                            config_json["encryption"] = serde_json::json!(null);
                            asset.encryption_enabled = Some(false);
                        }
                    }

                    // Logging
                    if let Ok(logging) = self.client
                        .get_bucket_logging()
                        .bucket(&name)
                        .send()
                        .await
                    {
                        let logging_enabled = logging.logging_enabled().is_some();
                        config_json["logging_enabled"] = serde_json::json!(logging_enabled);
                        if let Some(log) = logging.logging_enabled() {
                            config_json["logging_target_bucket"] = serde_json::json!(log.target_bucket());
                            config_json["logging_target_prefix"] = serde_json::json!(log.target_prefix());
                        }
                    }

                    // Website hosting
                    match self.client
                        .get_bucket_website()
                        .bucket(&name)
                        .send()
                        .await
                    {
                        Ok(website) => {
                            config_json["website_hosting"] = serde_json::json!({
                                "enabled": true,
                                "index_document": website.index_document().map(|d| d.suffix()),
                                "error_document": website.error_document().map(|d| d.key()),
                            });
                        }
                        Err(_) => {
                            config_json["website_hosting"] = serde_json::json!(false);
                        }
                    }

                    // ACL — detect public grants
                    if let Ok(acl) = self.client
                        .get_bucket_acl()
                        .bucket(&name)
                        .send()
                        .await
                    {
                        let public_grants: Vec<serde_json::Value> = acl.grants()
                            .iter()
                            .filter_map(|g| {
                                let grantee = g.grantee()?;
                                let uri = grantee.uri()?;
                                if uri.contains("AllUsers") || uri.contains("AuthenticatedUsers") {
                                    Some(serde_json::json!({
                                        "grantee_uri": uri,
                                        "permission": g.permission().map(|p| p.as_str()),
                                    }))
                                } else {
                                    None
                                }
                            })
                            .collect();
                        if !public_grants.is_empty() {
                            config_json["public_acl_grants"] = serde_json::json!(public_grants);
                            asset.public_access = Some(true);
                        }
                        config_json["owner"] = serde_json::json!(
                            acl.owner().and_then(|o| o.display_name())
                        );
                    }

                    // Tags
                    if let Ok(tags_resp) = self.client
                        .get_bucket_tagging()
                        .bucket(&name)
                        .send()
                        .await
                    {
                        let tag_set = tags_resp.tag_set();
                        if !tag_set.is_empty() {
                            let tags_map: serde_json::Value = tag_set.iter()
                                .map(|t| (t.key().to_string(), serde_json::json!(t.value())))
                                .collect::<serde_json::Map<String, serde_json::Value>>()
                                .into();
                            asset.tags = Some(tags_map);
                        }
                    }

                    asset.configuration = Some(config_json);
                    asset_store.insert(asset.clone()).await?;
                    event_bus.publish("analyze-bucket", &asset.sk).await?;

                    count += 1;
                    debug!("Collected S3 bucket: {}", name);
                }
            }
            Err(e) => {
                error!("Failed to list S3 buckets: {}", e);
            }
        }

        info!("S3 collection complete. Collected {} buckets", count);
        Ok(())
    }
}
