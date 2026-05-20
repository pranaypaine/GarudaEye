use aws_sdk_dynamodb::Client;
use garudaeye_core::{Asset, AssetType, CloudProvider};
use infra::traits::{AssetStore, EventBus};
use tracing::{info, error, debug};

pub struct DynamoDbCollector {
    client: Client,
    region: String,
}

impl DynamoDbCollector {
    pub async fn new(config: &aws_config::SdkConfig, region: String) -> Self {
        let client = Client::new(config);
        Self { client, region }
    }

    pub async fn collect(
        &self,
        asset_store: &dyn AssetStore,
        _event_bus: &dyn EventBus,
    ) -> anyhow::Result<()> {
        info!("Starting DynamoDB collection...");

        let mut count = 0;

        let mut last_evaluated_table: Option<String> = None;
        loop {
            let mut req = self.client.list_tables();
            if let Some(ref last) = last_evaluated_table {
                req = req.exclusive_start_table_name(last);
            }
            let output = match req.send().await {
                Ok(o) => o,
                Err(e) => { error!("Failed to list DynamoDB tables: {}", e); break; }
            };

            let table_names = output.table_names.unwrap_or_default();
            let more = output.last_evaluated_table_name.clone();

            for table_name in table_names {
                // Describe table
                let desc = match self.client.describe_table()
                    .table_name(&table_name).send().await
                {
                    Ok(o) => o,
                    Err(e) => { error!("Failed to describe table {}: {}", table_name, e); continue; }
                };

                let table = match desc.table {
                    Some(t) => t,
                    None => continue,
                };

                let mut asset = Asset::new(AssetType::Table, table_name.clone(), CloudProvider::Aws);
                asset.service = Some("DynamoDB".to_string());
                asset.resource_id = Some(table_name.clone());
                asset.arn = table.table_arn().map(|s| s.to_string());
                asset.region = Some(self.region.clone());

                // Encryption
                let encryption_enabled = table.sse_description()
                    .and_then(|s| s.status())
                    .map(|s| s.as_str() == "ENABLED")
                    .unwrap_or(false);
                asset.encryption_enabled = Some(encryption_enabled);

                // Tags
                if let Some(arn) = asset.arn.as_ref() {
                    match self.client.list_tags_of_resource()
                        .resource_arn(arn).send().await
                    {
                        Ok(tags_out) => {
                            let tags = tags_out.tags.unwrap_or_default();
                            if !tags.is_empty() {
                                let tags_map: serde_json::Value = tags.iter()
                                    .map(|t| (t.key.clone(), serde_json::json!(t.value)))
                                    .collect::<serde_json::Map<String, serde_json::Value>>()
                                    .into();
                                asset.tags = Some(tags_map);
                            }
                        }
                        Err(_) => {}
                    }
                }

                // Key schema
                let key_schema: Vec<serde_json::Value> = table.key_schema()
                    .iter()
                    .map(|k| serde_json::json!({
                        "attribute_name": k.attribute_name(),
                        "key_type": k.key_type().as_str(),
                    }))
                    .collect();

                // Attribute definitions
                let attribute_definitions: Vec<serde_json::Value> = table.attribute_definitions()
                    .iter()
                    .map(|a| serde_json::json!({
                        "attribute_name": a.attribute_name(),
                        "attribute_type": a.attribute_type().as_str(),
                    }))
                    .collect();

                // Global secondary indexes
                let gsi_list: Vec<serde_json::Value> = table.global_secondary_indexes()
                    .iter()
                    .map(|gsi| serde_json::json!({
                        "index_name": gsi.index_name(),
                        "index_status": gsi.index_status().map(|s| s.as_str()),
                        "item_count": gsi.item_count(),
                        "index_size_bytes": gsi.index_size_bytes(),
                        "key_schema": gsi.key_schema().iter().map(|k| serde_json::json!({
                            "attribute_name": k.attribute_name(),
                            "key_type": k.key_type().as_str(),
                        })).collect::<Vec<_>>(),
                        "projection": gsi.projection().map(|p| serde_json::json!({
                            "projection_type": p.projection_type().map(|t| t.as_str()),
                            "non_key_attributes": p.non_key_attributes(),
                        })),
                        "provisioned_throughput": gsi.provisioned_throughput().map(|t| serde_json::json!({
                            "read_capacity_units": t.read_capacity_units(),
                            "write_capacity_units": t.write_capacity_units(),
                        })),
                    }))
                    .collect();

                // Local secondary indexes
                let lsi_list: Vec<serde_json::Value> = table.local_secondary_indexes()
                    .iter()
                    .map(|lsi| serde_json::json!({
                        "index_name": lsi.index_name(),
                        "item_count": lsi.item_count(),
                        "index_size_bytes": lsi.index_size_bytes(),
                        "key_schema": lsi.key_schema().iter().map(|k| serde_json::json!({
                            "attribute_name": k.attribute_name(),
                            "key_type": k.key_type().as_str(),
                        })).collect::<Vec<_>>(),
                        "projection": lsi.projection().map(|p| serde_json::json!({
                            "projection_type": p.projection_type().map(|t| t.as_str()),
                            "non_key_attributes": p.non_key_attributes(),
                        })),
                    }))
                    .collect();

                // Replicas (global table)
                let replicas: Vec<serde_json::Value> = table.replicas()
                    .iter()
                    .map(|r| serde_json::json!({
                        "region_name": r.region_name(),
                        "replica_status": r.replica_status().map(|s| s.as_str()),
                        "kms_master_key_id": r.kms_master_key_id(),
                    }))
                    .collect();

                // Provisioned throughput
                let throughput_json = table.provisioned_throughput().map(|t| serde_json::json!({
                    "read_capacity_units": t.read_capacity_units(),
                    "write_capacity_units": t.write_capacity_units(),
                    "number_of_decreases_today": t.number_of_decreases_today(),
                }));

                // Stream specification
                let stream_json = table.stream_specification().map(|s| serde_json::json!({
                    "stream_enabled": s.stream_enabled(),
                    "stream_view_type": s.stream_view_type().map(|t| t.as_str()),
                }));

                // Billing mode
                let billing_json = table.billing_mode_summary().map(|b| serde_json::json!({
                    "billing_mode": b.billing_mode().map(|m| m.as_str()),
                }));

                // Encryption detail
                let sse_json = table.sse_description().map(|s| serde_json::json!({
                    "status": s.status().map(|st| st.as_str()),
                    "sse_type": s.sse_type().map(|t| t.as_str()),
                    "kms_master_key_arn": s.kms_master_key_arn(),
                }));

                // Point-in-time recovery
                let pitr_enabled = match self.client.describe_continuous_backups()
                    .table_name(&table_name).send().await
                {
                    Ok(pitr_out) => {
                        pitr_out.continuous_backups_description
                            .and_then(|d| d.point_in_time_recovery_description)
                            .and_then(|p| p.point_in_time_recovery_status)
                            .map(|s| s.as_str() == "ENABLED")
                            .unwrap_or(false)
                    }
                    Err(_) => false,
                };

                let config_json = serde_json::json!({
                    "table_name": table_name,
                    "table_id": table.table_id(),
                    "table_arn": table.table_arn(),
                    "table_status": table.table_status().map(|s| s.as_str()),
                    "item_count": table.item_count(),
                    "table_size_bytes": table.table_size_bytes(),
                    "creation_date_time": table.creation_date_time().map(|t| t.secs()),
                    "table_class": table.table_class_summary().and_then(|c| c.table_class()).map(|c| c.as_str()),
                    "key_schema": key_schema,
                    "attribute_definitions": attribute_definitions,
                    "global_secondary_indexes": gsi_list,
                    "local_secondary_indexes": lsi_list,
                    "replicas": replicas,
                    "is_global_table": !table.replicas().is_empty(),
                    "provisioned_throughput": throughput_json,
                    "stream_specification": stream_json,
                    "billing_mode": billing_json,
                    "sse_description": sse_json,
                    "point_in_time_recovery_enabled": pitr_enabled,
                    "latest_stream_arn": table.latest_stream_arn(),
                    "latest_stream_label": table.latest_stream_label(),
                });

                asset.configuration = Some(config_json);
                asset_store.insert(asset.clone()).await?;
                count += 1;
                debug!("Collected DynamoDB table: {}", table_name);
            }

            match more {
                Some(last) => last_evaluated_table = Some(last),
                None => break,
            }
        }

        info!("DynamoDB collection complete. Collected {} tables", count);
        Ok(())
    }
}

