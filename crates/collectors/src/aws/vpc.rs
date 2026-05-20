use aws_sdk_ec2::Client;
use garudaeye_core::{Asset, AssetType, CloudProvider};
use infra::traits::{AssetStore, EventBus};
use tracing::{info, error, debug};

pub struct VpcCollector {
    client: Client,
    region: String,
}

impl VpcCollector {
    pub async fn new(config: &aws_config::SdkConfig, region: String) -> Self {
        let client = Client::new(config);
        Self { client, region }
    }

    pub async fn collect(
        &self,
        asset_store: &dyn AssetStore,
        _event_bus: &dyn EventBus,
    ) -> anyhow::Result<()> {
        info!("Starting VPC collection...");

        let mut vpc_count = 0;
        let mut subnet_count = 0;
        let mut sg_count = 0;

        // ── VPCs ────────────────────────────────────────────────────────────────
        match self.client.describe_vpcs().send().await {
            Ok(output) => {
                for vpc in output.vpcs.unwrap_or_default() {
                    let vpc_id = match vpc.vpc_id() {
                        Some(id) => id.to_string(),
                        None => continue,
                    };

                    let mut asset = Asset::new(AssetType::Vpc, vpc_id.clone(), CloudProvider::Aws);
                    asset.service = Some("VPC".to_string());
                    asset.resource_id = Some(vpc_id.clone());
                    asset.region = Some(self.region.clone());

                    // IPv4 CIDR associations
                    let ipv4_cidrs: Vec<serde_json::Value> = vpc.cidr_block_association_set()
                        .iter()
                        .map(|a| serde_json::json!({
                            "cidr": a.cidr_block(),
                            "state": a.cidr_block_state().and_then(|s| s.state()).map(|s| s.as_str()),
                        }))
                        .collect();

                    // IPv6 CIDR associations
                    let ipv6_cidrs: Vec<serde_json::Value> = vpc.ipv6_cidr_block_association_set()
                        .iter()
                        .map(|a| serde_json::json!({
                            "cidr": a.ipv6_cidr_block(),
                            "state": a.ipv6_cidr_block_state().and_then(|s| s.state()).map(|s| s.as_str()),
                            "ipv6_pool": a.ipv6_pool(),
                            "network_border_group": a.network_border_group(),
                        }))
                        .collect();

                    // Tags
                    let tags = vpc.tags();
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

                    let config_json = serde_json::json!({
                        "vpc_id": vpc_id,
                        "name": name_tag,
                        "cidr_block": vpc.cidr_block(),
                        "ipv4_cidr_associations": ipv4_cidrs,
                        "ipv6_cidr_associations": ipv6_cidrs,
                        "is_default": vpc.is_default(),
                        "state": vpc.state().map(|s| s.as_str()),
                        "dhcp_options_id": vpc.dhcp_options_id(),
                        "instance_tenancy": vpc.instance_tenancy().map(|t| t.as_str()),
                        "owner_id": vpc.owner_id(),
                    });

                    asset.configuration = Some(config_json);
                    asset_store.insert(asset.clone()).await?;
                    vpc_count += 1;
                    debug!("Collected VPC: {}", vpc_id);
                }
            }
            Err(e) => error!("Failed to describe VPCs: {}", e),
        }

        // ── Subnets ─────────────────────────────────────────────────────────────
        match self.client.describe_subnets().send().await {
            Ok(output) => {
                for subnet in output.subnets.unwrap_or_default() {
                    let subnet_id = match subnet.subnet_id() {
                        Some(id) => id.to_string(),
                        None => continue,
                    };

                    let mut asset = Asset::new(
                        AssetType::Subnet, subnet_id.clone(), CloudProvider::Aws,
                    );
                    asset.service = Some("VPC/Subnet".to_string());
                    asset.resource_id = Some(subnet_id.clone());
                    asset.vpc_id = subnet.vpc_id().map(|s| s.to_string());
                    asset.region = Some(self.region.clone());
                    asset.public_access = subnet.map_public_ip_on_launch();

                    // IPv6 CIDR associations
                    let ipv6_cidrs: Vec<serde_json::Value> = subnet.ipv6_cidr_block_association_set()
                        .iter()
                        .map(|a| serde_json::json!({
                            "cidr": a.ipv6_cidr_block(),
                            "state": a.ipv6_cidr_block_state().and_then(|s| s.state()).map(|s| s.as_str()),
                        }))
                        .collect();

                    // Tags
                    let tags = subnet.tags();
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

                    let config_json = serde_json::json!({
                        "subnet_id": subnet_id,
                        "name": name_tag,
                        "vpc_id": subnet.vpc_id(),
                        "cidr_block": subnet.cidr_block(),
                        "ipv6_cidr_associations": ipv6_cidrs,
                        "availability_zone": subnet.availability_zone(),
                        "availability_zone_id": subnet.availability_zone_id(),
                        "available_ip_address_count": subnet.available_ip_address_count(),
                        "map_public_ip_on_launch": subnet.map_public_ip_on_launch(),
                        "map_customer_owned_ip_on_launch": subnet.map_customer_owned_ip_on_launch(),
                        "customer_owned_ipv4_pool": subnet.customer_owned_ipv4_pool(),
                        "default_for_az": subnet.default_for_az(),
                        "assign_ipv6_address_on_creation": subnet.assign_ipv6_address_on_creation(),
                        "state": subnet.state().map(|s| s.as_str()),
                        "subnet_arn": subnet.subnet_arn(),
                        "outpost_arn": subnet.outpost_arn(),
                        "owner_id": subnet.owner_id(),
                        "enable_dns64": subnet.enable_dns64(),
                        "ipv6_native": subnet.ipv6_native(),
                    });

                    asset.configuration = Some(config_json);
                    asset_store.insert(asset.clone()).await?;
                    subnet_count += 1;
                    debug!("Collected Subnet: {}", subnet_id);
                }
            }
            Err(e) => error!("Failed to describe Subnets: {}", e),
        }

        // ── Security Groups ──────────────────────────────────────────────────────
        match self.client.describe_security_groups().send().await {
            Ok(output) => {
                for sg in output.security_groups.unwrap_or_default() {
                    let sg_id = match sg.group_id() {
                        Some(id) => id.to_string(),
                        None => continue,
                    };

                    let mut asset = Asset::new(
                        AssetType::SecurityGroup, sg_id.clone(), CloudProvider::Aws,
                    );
                    asset.service = Some("VPC/SecurityGroup".to_string());
                    asset.resource_id = Some(sg_id.clone());
                    asset.vpc_id = sg.vpc_id().map(|s| s.to_string());
                    asset.region = Some(self.region.clone());

                    // Ingress rules — detect open-to-world
                    let ingress_rules: Vec<serde_json::Value> = sg.ip_permissions()
                        .iter()
                        .map(|rule| {
                            let ipv4_ranges: Vec<serde_json::Value> = rule.ip_ranges()
                                .iter()
                                .map(|r| serde_json::json!({
                                    "cidr": r.cidr_ip(),
                                    "description": r.description(),
                                }))
                                .collect();
                            let ipv6_ranges: Vec<serde_json::Value> = rule.ipv6_ranges()
                                .iter()
                                .map(|r| serde_json::json!({
                                    "cidr": r.cidr_ipv6(),
                                    "description": r.description(),
                                }))
                                .collect();
                            let sg_refs: Vec<serde_json::Value> = rule.user_id_group_pairs()
                                .iter()
                                .map(|p| serde_json::json!({
                                    "group_id": p.group_id(),
                                    "group_name": p.group_name(),
                                    "user_id": p.user_id(),
                                    "peering_status": p.peering_status(),
                                }))
                                .collect();
                            serde_json::json!({
                                "from_port": rule.from_port(),
                                "to_port": rule.to_port(),
                                "protocol": rule.ip_protocol(),
                                "ipv4_ranges": ipv4_ranges,
                                "ipv6_ranges": ipv6_ranges,
                                "security_group_refs": sg_refs,
                            })
                        })
                        .collect();

                    // Egress rules
                    let egress_rules: Vec<serde_json::Value> = sg.ip_permissions_egress()
                        .iter()
                        .map(|rule| {
                            let ipv4_ranges: Vec<serde_json::Value> = rule.ip_ranges()
                                .iter()
                                .map(|r| serde_json::json!({
                                    "cidr": r.cidr_ip(),
                                    "description": r.description(),
                                }))
                                .collect();
                            let ipv6_ranges: Vec<serde_json::Value> = rule.ipv6_ranges()
                                .iter()
                                .map(|r| serde_json::json!({
                                    "cidr": r.cidr_ipv6(),
                                    "description": r.description(),
                                }))
                                .collect();
                            serde_json::json!({
                                "from_port": rule.from_port(),
                                "to_port": rule.to_port(),
                                "protocol": rule.ip_protocol(),
                                "ipv4_ranges": ipv4_ranges,
                                "ipv6_ranges": ipv6_ranges,
                            })
                        })
                        .collect();

                    // Detect if any ingress rule is open to world (0.0.0.0/0 or ::/0)
                    let open_to_world = sg.ip_permissions().iter().any(|rule| {
                        rule.ip_ranges().iter().any(|r| r.cidr_ip() == Some("0.0.0.0/0"))
                            || rule.ipv6_ranges().iter().any(|r| r.cidr_ipv6() == Some("::/0"))
                    });
                    asset.public_access = Some(open_to_world);

                    // Tags
                    let tags = sg.tags();
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

                    let config_json = serde_json::json!({
                        "group_id": sg_id,
                        "group_name": sg.group_name(),
                        "name": name_tag,
                        "description": sg.description(),
                        "vpc_id": sg.vpc_id(),
                        "owner_id": sg.owner_id(),
                        "open_to_world": open_to_world,
                        "ingress_rules": ingress_rules,
                        "egress_rules": egress_rules,
                    });

                    asset.configuration = Some(config_json);
                    asset_store.insert(asset.clone()).await?;
                    sg_count += 1;
                    debug!("Collected Security Group: {} (open_to_world={})", sg_id, open_to_world);
                }
            }
            Err(e) => error!("Failed to describe Security Groups: {}", e),
        }

        info!("VPC collection complete. Collected {} VPCs, {} subnets, {} security groups",
              vpc_count, subnet_count, sg_count);
        Ok(())
    }
}

