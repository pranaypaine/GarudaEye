use aws_sdk_ec2::Client;
use garudaeye_core::{Asset, AssetType, CloudProvider};
use infra::traits::{AssetStore, EventBus};
use tracing::{info, error, debug};

pub struct Ec2Collector {
    client: Client,
    region: String,
}

impl Ec2Collector {
    pub async fn new(config: &aws_config::SdkConfig, region: String) -> Self {
        let client = Client::new(config);
        Self { client, region }
    }

    pub async fn collect(
        &self,
        asset_store: &dyn AssetStore,
        event_bus: &dyn EventBus,
    ) -> anyhow::Result<()> {
        info!("Starting EC2 collection...");

        let mut count = 0;

        let result = self.client.describe_instances().send().await;

        match result {
            Ok(output) => {
                for reservation in output.reservations.unwrap_or_default() {
                    for instance in reservation.instances.unwrap_or_default() {
                        let instance_id = match instance.instance_id() {
                            Some(id) => id.to_string(),
                            None => continue,
                        };

                        // Use public IP if available, otherwise private
                        let is_public = instance.public_ip_address().is_some();
                        let ip_str = match instance.public_ip_address()
                            .or_else(|| instance.private_ip_address())
                        {
                            Some(ip) => ip.to_string(),
                            None => continue,
                        };

                        let mut asset = Asset::new(
                            AssetType::IpAddress,
                            ip_str.clone(),
                            CloudProvider::Aws,
                        );

                        asset.region = Some(self.region.clone());
                        asset.service = Some(if is_public { "EC2".to_string() } else { "EC2 (private)".to_string() });
                        asset.resource_id = Some(instance_id.clone());
                        asset.public_access = Some(is_public);
                        asset.vpc_id = instance.vpc_id().map(|s| s.to_string());
                        asset.subnet_id = instance.subnet_id().map(|s| s.to_string());
                        asset.dns_name = instance.public_dns_name()
                            .filter(|s| !s.is_empty())
                            .map(|s| s.to_string());
                        asset.iam_role = instance.iam_instance_profile()
                            .and_then(|p| p.arn())
                            .map(|s| s.to_string());

                        // Security groups
                        let sg_ids: Vec<String> = instance.security_groups()
                            .iter()
                            .filter_map(|sg| sg.group_id().map(|s| s.to_string()))
                            .collect();
                        if !sg_ids.is_empty() {
                            asset.security_groups = Some(sg_ids.clone());
                        }

                        // Tags
                        let tags = instance.tags();
                        let name_tag = tags.iter()
                            .find(|t| t.key() == Some("Name"))
                            .and_then(|t| t.value())
                            .map(|s| s.to_string());
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

                        // Block device mappings
                        let volumes: Vec<serde_json::Value> = instance.block_device_mappings()
                            .iter()
                            .map(|bdm| serde_json::json!({
                                "device_name": bdm.device_name(),
                                "volume_id": bdm.ebs().and_then(|e| e.volume_id()),
                                "delete_on_termination": bdm.ebs().and_then(|e| e.delete_on_termination()),
                                "status": bdm.ebs().and_then(|e| e.status()).map(|s| s.as_str()),
                            }))
                            .collect();

                        // Network interfaces
                        let network_interfaces: Vec<serde_json::Value> = instance.network_interfaces()
                            .iter()
                            .map(|ni| serde_json::json!({
                                "network_interface_id": ni.network_interface_id(),
                                "private_ip": ni.private_ip_address(),
                                "public_ip": ni.association().and_then(|a| a.public_ip()),
                                "subnet_id": ni.subnet_id(),
                                "vpc_id": ni.vpc_id(),
                                "status": ni.status().map(|s| s.as_str()),
                                "source_dest_check": ni.source_dest_check(),
                                "security_groups": ni.groups().iter()
                                    .filter_map(|sg| sg.group_id())
                                    .collect::<Vec<_>>(),
                            }))
                            .collect();

                        asset.network_interfaces = Some(network_interfaces.clone());

                        let config_json = serde_json::json!({
                            "instance_id": instance_id,
                            "name": name_tag,
                            "instance_type": instance.instance_type().map(|t| t.as_str()),
                            "state": instance.state().and_then(|s| s.name()).map(|n| n.as_str()),
                            "ami_id": instance.image_id(),
                            "key_name": instance.key_name(),
                            "architecture": instance.architecture().map(|a| a.as_str()),
                            "platform": instance.platform().map(|p| p.as_str()),
                            "platform_details": instance.platform_details(),
                            "virtualization_type": instance.virtualization_type().map(|v| v.as_str()),
                            "hypervisor": instance.hypervisor().map(|h| h.as_str()),
                            "root_device_type": instance.root_device_type().map(|r| r.as_str()),
                            "root_device_name": instance.root_device_name(),
                            "is_public": is_public,
                            "public_ip": instance.public_ip_address(),
                            "private_ip": instance.private_ip_address(),
                            "public_dns": instance.public_dns_name(),
                            "private_dns": instance.private_dns_name(),
                            "vpc_id": instance.vpc_id(),
                            "subnet_id": instance.subnet_id(),
                            "source_dest_check": instance.source_dest_check(),
                            "ebs_optimized": instance.ebs_optimized(),
                            "monitoring_state": instance.monitoring()
                                .and_then(|m| m.state())
                                .map(|s| s.as_str()),
                            "tenancy": instance.placement()
                                .and_then(|p| p.tenancy())
                                .map(|t| t.as_str()),
                            "availability_zone": instance.placement()
                                .and_then(|p| p.availability_zone()),
                            "placement_group": instance.placement()
                                .and_then(|p| p.group_name()),
                            "launch_time": instance.launch_time().map(|t| t.secs().to_string()),
                            "iam_instance_profile": instance.iam_instance_profile()
                                .and_then(|p| p.arn()),
                            "capacity_reservation_id": instance.capacity_reservation_id(),
                            "security_groups": sg_ids,
                            "block_device_mappings": volumes,
                            "network_interfaces": network_interfaces,
                            "state_transition_reason": instance.state_transition_reason(),
                            "hibernation_configured": instance.hibernation_options()
                                .and_then(|h| h.configured),
                            "nitro_enclave_enabled": instance.enclave_options()
                                .and_then(|e| e.enabled),
                            "metadata_options": {
                                "http_endpoint": instance.metadata_options()
                                    .and_then(|m| m.http_endpoint())
                                    .map(|e| e.as_str()),
                                "http_tokens": instance.metadata_options()
                                    .and_then(|m| m.http_tokens())
                                    .map(|t| t.as_str()),
                                "imdsv2_required": instance.metadata_options()
                                    .and_then(|m| m.http_tokens())
                                    .map(|t| t.as_str() == "required"),
                            },
                        });

                        asset.configuration = Some(config_json);
                        asset_store.insert(asset.clone()).await?;

                        if is_public {
                            event_bus.publish("analyze-ip", &asset.sk).await?;
                        }

                        count += 1;
                        debug!("Collected EC2 instance: {} ({})", instance_id, ip_str);
                    }
                }
            }
            Err(e) => {
                error!("Failed to describe EC2 instances: {}", e);
            }
        }

        info!("EC2 collection complete. Collected {} instances", count);
        Ok(())
    }
}
