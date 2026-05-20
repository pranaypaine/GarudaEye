use aws_sdk_sns::Client;
use garudaeye_core::{Asset, AssetType, CloudProvider};
use infra::traits::{AssetStore, EventBus};
use tracing::{info, error, debug};

pub struct SnsCollector {
    client: Client,
    region: String,
}

impl SnsCollector {
    pub async fn new(config: &aws_config::SdkConfig, region: String) -> Self {
        let client = Client::new(config);
        Self { client, region }
    }

    pub async fn collect(
        &self,
        asset_store: &dyn AssetStore,
        _event_bus: &dyn EventBus,
    ) -> anyhow::Result<()> {
        info!("Starting SNS collection...");

        let mut count = 0;
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.list_topics();
            if let Some(ref tok) = next_token {
                req = req.next_token(tok);
            }
            let output = match req.send().await {
                Ok(o) => o,
                Err(e) => { error!("Failed to list SNS topics: {}", e); break; }
            };

            let topics = output.topics.unwrap_or_default();
            let more = output.next_token.clone();

            for topic in topics {
                let topic_arn = match topic.topic_arn() {
                    Some(a) => a.to_string(),
                    None => continue,
                };

                let topic_name = topic_arn.split(':').last().unwrap_or(&topic_arn).to_string();

                let mut asset = Asset::new(AssetType::Topic, topic_name.clone(), CloudProvider::Aws);
                asset.service = Some("SNS".to_string());
                asset.resource_id = Some(topic_arn.clone());
                asset.arn = Some(topic_arn.clone());
                asset.region = Some(self.region.clone());

                // FIFO detection from ARN suffix
                let is_fifo = topic_name.ends_with(".fifo");

                // Get all topic attributes
                match self.client.get_topic_attributes()
                    .topic_arn(&topic_arn).send().await
                {
                    Ok(attrs_out) => {
                        let attrs = attrs_out.attributes.unwrap_or_default();

                        let display_name = attrs.get("DisplayName").cloned();
                        let owner = attrs.get("Owner").cloned();
                        let subscriptions_confirmed = attrs.get("SubscriptionsConfirmed")
                            .and_then(|s| s.parse::<u64>().ok());
                        let subscriptions_pending = attrs.get("SubscriptionsPending")
                            .and_then(|s| s.parse::<u64>().ok());
                        let subscriptions_deleted = attrs.get("SubscriptionsDeleted")
                            .and_then(|s| s.parse::<u64>().ok());
                        let kms_key_id = attrs.get("KmsMasterKeyId").cloned();
                        let content_based_dedup = attrs.get("ContentBasedDeduplication")
                            .map(|s| s == "true");
                        let fifo_topic = attrs.get("FifoTopic")
                            .map(|s| s == "true")
                            .unwrap_or(is_fifo);
                        let policy = attrs.get("Policy").cloned();
                        let delivery_policy = attrs.get("DeliveryPolicy").cloned();
                        let effective_delivery_policy = attrs.get("EffectiveDeliveryPolicy").cloned();
                        let https_failure_feedback_role = attrs.get("HTTPSFailureFeedbackRoleArn").cloned();
                        let https_success_feedback_role = attrs.get("HTTPSSuccessFeedbackRoleArn").cloned();
                        let https_success_feedback_sample_rate = attrs.get("HTTPSSuccessFeedbackSampleRate").cloned();

                        // Encryption
                        asset.encryption_enabled = Some(kms_key_id.as_ref().map(|k| !k.is_empty()).unwrap_or(false));

                        // Public access detection: parse policy for wildcard principal
                        let is_public = policy.as_ref().map(|p| {
                            is_policy_public(p)
                        }).unwrap_or(false);
                        asset.public_access = Some(is_public);

                        // Parse delivery policy as JSON
                        let delivery_policy_json = delivery_policy.as_ref()
                            .and_then(|p| serde_json::from_str::<serde_json::Value>(p).ok());
                        let effective_delivery_policy_json = effective_delivery_policy.as_ref()
                            .and_then(|p| serde_json::from_str::<serde_json::Value>(p).ok());

                        let config_json = serde_json::json!({
                            "topic_arn": topic_arn,
                            "topic_name": topic_name,
                            "display_name": display_name,
                            "owner": owner,
                            "is_fifo": fifo_topic,
                            "subscriptions_confirmed": subscriptions_confirmed,
                            "subscriptions_pending": subscriptions_pending,
                            "subscriptions_deleted": subscriptions_deleted,
                            "kms_master_key_id": kms_key_id,
                            "content_based_deduplication": content_based_dedup,
                            "is_public": is_public,
                            "delivery_policy": delivery_policy_json,
                            "effective_delivery_policy": effective_delivery_policy_json,
                            "https_failure_feedback_role_arn": https_failure_feedback_role,
                            "https_success_feedback_role_arn": https_success_feedback_role,
                            "https_success_feedback_sample_rate": https_success_feedback_sample_rate,
                        });

                        asset.configuration = Some(config_json);
                    }
                    Err(e) => {
                        error!("Failed to get SNS topic attributes for {}: {}", topic_arn, e);
                        asset.configuration = Some(serde_json::json!({
                            "topic_arn": topic_arn,
                            "is_fifo": is_fifo,
                        }));
                    }
                }

                asset_store.insert(asset.clone()).await?;
                count += 1;
                debug!("Collected SNS topic: {}", topic_arn);
            }

            match more {
                Some(tok) => next_token = Some(tok),
                None => break,
            }
        }

        info!("SNS collection complete. Collected {} topics", count);
        Ok(())
    }
}

/// Returns true if the IAM policy has a statement that allows any principal (public access).
fn is_policy_public(policy_json: &str) -> bool {
    if let Ok(policy) = serde_json::from_str::<serde_json::Value>(policy_json) {
        if let Some(statements) = policy.get("Statement").and_then(|s| s.as_array()) {
            for stmt in statements {
                let effect = stmt.get("Effect").and_then(|e| e.as_str()).unwrap_or("");
                if effect != "Allow" {
                    continue;
                }
                let principal = stmt.get("Principal");
                if let Some(p) = principal {
                    if p == "*" {
                        return true;
                    }
                    if let Some(aws) = p.get("AWS") {
                        if aws == "*" {
                            return true;
                        }
                        if let Some(arr) = aws.as_array() {
                            if arr.iter().any(|v| v == "*") {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

