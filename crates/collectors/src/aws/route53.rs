use aws_sdk_route53::Client;
use garudaeye_core::{Asset, AssetType, CloudProvider};
use infra::traits::{AssetStore, EventBus};
use tracing::{info, error, debug};

pub struct Route53Collector {
    client: Client,
    #[allow(dead_code)]
    region: String,
}

impl Route53Collector {
    pub async fn new(config: &aws_config::SdkConfig, region: String) -> Self {
        let client = Client::new(config);
        Self { client, region }
    }

    pub async fn collect(
        &self,
        asset_store: &dyn AssetStore,
        event_bus: &dyn EventBus,
    ) -> anyhow::Result<()> {
        info!("Starting Route53 collection...");

        let mut zone_count = 0;
        let mut record_count = 0;

        let zones_result = self.client.list_hosted_zones().send().await;

        match zones_result {
            Ok(output) => {
                for zone in output.hosted_zones {
                    let zone_id = zone.id.clone();
                    let zone_name_raw = zone.name.clone();
                    let domain_name = zone_name_raw.trim_end_matches('.').to_string();
                    let is_private = zone.config.as_ref().map(|c| c.private_zone).unwrap_or(false);

                    // DNSSEC status
                    let dnssec_status = match self.client
                        .get_dnssec()
                        .hosted_zone_id(&zone_id)
                        .send()
                        .await
                    {
                        Ok(ds) => {
                            let status = ds.status().and_then(|s| s.serve_signature())
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| "NOT_SIGNING".to_string());
                            Some(status)
                        }
                        Err(_) => None,
                    };

                    let mut asset = Asset::new(
                        AssetType::Domain,
                        domain_name.clone(),
                        CloudProvider::Aws,
                    );

                    asset.service = Some("Route53".to_string());
                    asset.resource_id = Some(zone_id.clone());
                    asset.region = Some("global".to_string());

                    let config_json = serde_json::json!({
                        "zone_id": zone_id,
                        "zone_name": domain_name,
                        "private_zone": is_private,
                        "resource_record_set_count": zone.resource_record_set_count,
                        "caller_reference": zone.caller_reference,
                        "comment": zone.config.as_ref().and_then(|c| c.comment.as_deref()),
                        "linked_service_principal": zone.linked_service.as_ref()
                            .and_then(|ls| ls.service_principal.as_deref()),
                        "dnssec_status": dnssec_status,
                    });

                    asset.configuration = Some(config_json);
                    asset_store.insert(asset.clone()).await?;

                    if !is_private {
                        event_bus.publish("analyze-domain", &domain_name).await?;
                    }

                    zone_count += 1;
                    debug!("Collected Route53 zone: {}", domain_name);

                    // Collect all record sets for this zone
                    let mut list_token: Option<String> = None;
                    loop {
                        let mut list_req = self.client
                            .list_resource_record_sets()
                            .hosted_zone_id(&zone_id);
                        if let Some(ref token) = list_token {
                            list_req = list_req.start_record_identifier(token);
                        }

                        match list_req.send().await {
                            Ok(records_output) => {
                                for record in &records_output.resource_record_sets {
                                    let record_name = record.name.trim_end_matches('.').to_string();
                                    let record_type = record.r#type.as_str().to_string();

                                    // Get all record values
                                    let values: Vec<String> = record.resource_records()
                                        .iter()
                                        .map(|rr| rr.value().to_string())
                                        .collect();

                                    // Alias target
                                    let alias_target = record.alias_target().map(|at| serde_json::json!({
                                        "dns_name": at.dns_name(),
                                        "hosted_zone_id": at.hosted_zone_id(),
                                        "evaluate_target_health": at.evaluate_target_health(),
                                    }));

                                    // Routing policy
                                    let routing_policy = if record.weight().is_some() {
                                        "WEIGHTED"
                                    } else if record.region().is_some() {
                                        "LATENCY"
                                    } else if record.failover().is_some() {
                                        "FAILOVER"
                                    } else if record.geo_location().is_some() {
                                        "GEOLOCATION"
                                    } else if record.multi_value_answer().is_some() {
                                        "MULTIVALUE"
                                    } else {
                                        "SIMPLE"
                                    };

                                    let record_config = serde_json::json!({
                                        "zone_id": zone_id,
                                        "zone_name": domain_name,
                                        "name": record_name,
                                        "type": record_type,
                                        "ttl": record.ttl,
                                        "values": values,
                                        "alias_target": alias_target,
                                        "routing_policy": routing_policy,
                                        "weight": record.weight(),
                                        "set_identifier": record.set_identifier(),
                                        "failover": record.failover().map(|f| f.as_str()),
                                        "health_check_id": record.health_check_id(),
                                        "geo_location": record.geo_location().map(|g| serde_json::json!({
                                            "continent_code": g.continent_code(),
                                            "country_code": g.country_code(),
                                            "subdivision_code": g.subdivision_code(),
                                        })),
                                        "region": record.region().map(|r| r.as_str()),
                                        "multi_value_answer": record.multi_value_answer(),
                                    });

                                    // Collect subdomains and A/AAAA/CNAME as domain assets
                                    let is_apex = record_name == domain_name;
                                    let should_collect = matches!(
                                        record_type.as_str(),
                                        "A" | "AAAA" | "CNAME" | "MX" | "TXT" | "NS" | "CAA" | "SRV" | "PTR"
                                    );

                                    if should_collect && !is_apex {
                                        let mut sub_asset = Asset::new(
                                            AssetType::Domain,
                                            record_name.clone(),
                                            CloudProvider::Aws,
                                        );
                                        sub_asset.service = Some("Route53".to_string());
                                        sub_asset.resource_id = Some(
                                            format!("{}:{}", zone_id, record_name)
                                        );
                                        sub_asset.region = Some("global".to_string());
                                        sub_asset.configuration = Some(record_config);

                                        asset_store.insert(sub_asset.clone()).await?;

                                        if !is_private && matches!(record_type.as_str(), "A" | "AAAA" | "CNAME") {
                                            event_bus.publish("analyze-domain", &record_name).await?;
                                        }

                                        record_count += 1;
                                        debug!("Collected Route53 record: {} ({})", record_name, record_type);
                                    } else if should_collect && is_apex {
                                        // Update the zone asset config to include record details
                                        record_count += 1;
                                    }
                                }

                                if !records_output.is_truncated {
                                    break;
                                }
                                list_token = records_output.next_record_identifier;
                                if list_token.is_none() {
                                    break;
                                }
                            }
                            Err(e) => {
                                error!("Failed to list records for zone {}: {}", zone_id, e);
                                break;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to list Route53 hosted zones: {}", e);
            }
        }

        info!("Route53 collection complete. Collected {} zones with {} records",
              zone_count, record_count);
        Ok(())
    }
}

