use aws_sdk_sqs::Client;
use aws_sdk_sqs::types::QueueAttributeName;
use garudaeye_core::{Asset, AssetType, CloudProvider};
use infra::traits::{AssetStore, EventBus};
use tracing::{info, error, debug};

pub struct SqsCollector {
    client: Client,
    region: String,
}

impl SqsCollector {
    pub async fn new(config: &aws_config::SdkConfig, region: String) -> Self {
        let client = Client::new(config);
        Self { client, region }
    }

    pub async fn collect(
        &self,
        asset_store: &dyn AssetStore,
        _event_bus: &dyn EventBus,
    ) -> anyhow::Result<()> {
        info!("Starting SQS collection...");

        let mut count = 0;
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.list_queues();
            if let Some(ref tok) = next_token {
                req = req.next_token(tok);
            }
            let output = match req.send().await {
                Ok(o) => o,
                Err(e) => { error!("Failed to list SQS queues: {}", e); break; }
            };

            let queue_urls = output.queue_urls.unwrap_or_default();
            let more = output.next_token.clone();

            for queue_url in queue_urls {
                let queue_name = queue_url.split('/').last().unwrap_or(&queue_url).to_string();

                let mut asset = Asset::new(AssetType::Queue, queue_name.clone(), CloudProvider::Aws);
                asset.service = Some("SQS".to_string());
                asset.resource_id = Some(queue_url.clone());
                asset.region = Some(self.region.clone());

                match self.client.get_queue_attributes()
                    .queue_url(&queue_url)
                    .attribute_names(QueueAttributeName::All)
                    .send().await
                {
                    Ok(attrs_out) => {
                        let attrs = attrs_out.attributes.unwrap_or_default();

                        // Helper closure
                        let get = |k: &QueueAttributeName| attrs.get(k).map(|s| s.as_str());

                        // ARN
                        if let Some(arn) = get(&QueueAttributeName::QueueArn) {
                            asset.arn = Some(arn.to_string());
                        }

                        // Encryption
                        let kms_key = get(&QueueAttributeName::KmsMasterKeyId).map(|s| s.to_string());
                        let sqs_sse = get(&QueueAttributeName::SqsManagedSseEnabled)
                            .map(|s| s == "true")
                            .unwrap_or(false);
                        asset.encryption_enabled = Some(
                            kms_key.as_ref().map(|k| !k.is_empty()).unwrap_or(false) || sqs_sse
                        );

                        // FIFO
                        let is_fifo = get(&QueueAttributeName::FifoQueue)
                            .map(|s| s == "true")
                            .unwrap_or_else(|| queue_name.ends_with(".fifo"));

                        // Deduplication
                        let content_based_dedup = get(&QueueAttributeName::ContentBasedDeduplication)
                            .map(|s| s == "true");

                        // DLQ / redrive policy
                        let redrive_policy = attrs.get(&QueueAttributeName::RedrivePolicy).cloned();
                        let redrive_json = redrive_policy.as_ref()
                            .and_then(|p| serde_json::from_str::<serde_json::Value>(p).ok());
                        let dlq_arn = redrive_json.as_ref()
                            .and_then(|j| j.get("deadLetterTargetArn"))
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        let max_receive_count = redrive_json.as_ref()
                            .and_then(|j| j.get("maxReceiveCount"))
                            .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())));

                        // Public access detection
                        let policy = attrs.get(&QueueAttributeName::Policy).map(|s| s.as_str());
                        let is_public = policy.map(is_policy_public).unwrap_or(false);
                        asset.public_access = Some(is_public);

                        let config_json = serde_json::json!({
                            "queue_url": queue_url,
                            "queue_name": queue_name,
                            "queue_arn": get(&QueueAttributeName::QueueArn),
                            "is_fifo": is_fifo,
                            "content_based_deduplication": content_based_dedup,
                            "is_public": is_public,
                            "approximate_number_of_messages": get(&QueueAttributeName::ApproximateNumberOfMessages),
                            "approximate_number_of_messages_not_visible": get(&QueueAttributeName::ApproximateNumberOfMessagesNotVisible),
                            "approximate_number_of_messages_delayed": get(&QueueAttributeName::ApproximateNumberOfMessagesDelayed),
                            "visibility_timeout_seconds": get(&QueueAttributeName::VisibilityTimeout),
                            "maximum_message_size": get(&QueueAttributeName::MaximumMessageSize),
                            "message_retention_period_seconds": get(&QueueAttributeName::MessageRetentionPeriod),
                            "delay_seconds": get(&QueueAttributeName::DelaySeconds),
                            "receive_message_wait_time_seconds": get(&QueueAttributeName::ReceiveMessageWaitTimeSeconds),
                            "created_timestamp": get(&QueueAttributeName::CreatedTimestamp),
                            "last_modified_timestamp": get(&QueueAttributeName::LastModifiedTimestamp),
                            "kms_master_key_id": kms_key,
                            "kms_data_key_reuse_period_seconds": get(&QueueAttributeName::KmsDataKeyReusePeriodSeconds),
                            "sqs_managed_sse_enabled": sqs_sse,
                            "deduplication_scope": get(&QueueAttributeName::DeduplicationScope),
                            "fifo_throughput_limit": get(&QueueAttributeName::FifoThroughputLimit),
                            "dead_letter_target_arn": dlq_arn,
                            "max_receive_count": max_receive_count,
                            "has_dead_letter_queue": redrive_policy.is_some(),
                        });

                        asset.configuration = Some(config_json);
                    }
                    Err(e) => {
                        error!("Failed to get SQS queue attributes for {}: {}", queue_url, e);
                        asset.configuration = Some(serde_json::json!({"queue_url": queue_url}));
                    }
                }

                asset_store.insert(asset.clone()).await?;
                count += 1;
                debug!("Collected SQS queue: {}", queue_name);
            }

            match more {
                Some(tok) => next_token = Some(tok),
                None => break,
            }
        }

        info!("SQS collection complete. Collected {} queues", count);
        Ok(())
    }
}

/// Returns true if the IAM resource policy allows any principal (public access).
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

