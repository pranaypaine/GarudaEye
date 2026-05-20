use std::sync::Arc;
use std::collections::HashMap;
use tracing::{info, debug};
use uuid::Uuid;
use garudaeye_core::{AssetType, AssetRelationship, RelationshipType};
use infra::traits::AssetStore;

/// Builds relationships between assets based on their metadata
pub struct RelationshipBuilder {
    asset_store: Arc<dyn AssetStore>,
}

impl RelationshipBuilder {
    pub fn new(asset_store: Arc<dyn AssetStore>) -> Self {
        Self { asset_store }
    }

    pub async fn build_relationships(&self) -> anyhow::Result<()> {
        info!("Starting relationship building...");

        let assets = self.asset_store.list(None, None, None).await?;

        // ── Lookup indexes ───────────────────────────────────────────────────────
        let mut vpc_assets: HashMap<String, Uuid> = HashMap::new();       // vpc_id → asset UUID
        let mut subnet_assets: HashMap<String, Uuid> = HashMap::new();    // subnet_id → asset UUID
        let mut sg_assets: HashMap<String, Uuid> = HashMap::new();        // sg_id → asset UUID
        let mut s3_assets: HashMap<String, Uuid> = HashMap::new();        // bucket_name → asset UUID
        let mut elb_by_dns: HashMap<String, Uuid> = HashMap::new();       // elb dns_name → asset UUID
        let mut elb_by_name: HashMap<String, Uuid> = HashMap::new();      // lb name (sk) → asset UUID
        let mut cf_by_domain: HashMap<String, Uuid> = HashMap::new();     // cloudfront domain → asset UUID
        let mut apigw_by_dns: HashMap<String, Uuid> = HashMap::new();     // api gw dns_name prefix → asset UUID
        let mut sqs_by_arn: HashMap<String, Uuid> = HashMap::new();       // SQS ARN → asset UUID
        let mut sns_by_arn: HashMap<String, Uuid> = HashMap::new();       // SNS topic ARN → asset UUID

        for asset in &assets {
            match asset.asset_type {
                AssetType::Vpc => {
                    if let Some(ref id) = asset.resource_id {
                        vpc_assets.insert(id.clone(), asset.id);
                    }
                }
                AssetType::Subnet => {
                    if let Some(ref id) = asset.resource_id {
                        subnet_assets.insert(id.clone(), asset.id);
                    }
                }
                AssetType::SecurityGroup => {
                    if let Some(ref id) = asset.resource_id {
                        sg_assets.insert(id.clone(), asset.id);
                    }
                }
                AssetType::S3Bucket => {
                    s3_assets.insert(asset.sk.clone(), asset.id);
                }
                AssetType::LoadBalancer => {
                    if let Some(ref dns) = asset.dns_name {
                        elb_by_dns.insert(dns.to_lowercase(), asset.id);
                    }
                    elb_by_name.insert(asset.sk.clone(), asset.id);
                }
                AssetType::Cdn => {
                    if let Some(ref dns) = asset.dns_name {
                        cf_by_domain.insert(dns.to_lowercase(), asset.id);
                    }
                }
                AssetType::ApiGateway => {
                    if let Some(ref dns) = asset.dns_name {
                        apigw_by_dns.insert(dns.to_lowercase(), asset.id);
                    }
                }
                AssetType::Queue => {
                    if let Some(ref arn) = asset.arn {
                        sqs_by_arn.insert(arn.clone(), asset.id);
                    }
                }
                AssetType::Topic => {
                    if let Some(ref arn) = asset.arn {
                        sns_by_arn.insert(arn.clone(), asset.id);
                    }
                }
                _ => {}
            }
        }

        let mut rel_count = 0;

        // ── Relationship pass ────────────────────────────────────────────────────
        for asset in &assets {

            // ── 1. VPC membership ────────────────────────────────────────────────
            if let Some(ref vpc_id) = asset.vpc_id {
                if let Some(&vpc_uuid) = vpc_assets.get(vpc_id) {
                    if vpc_uuid != asset.id {
                        self.insert_rel(asset.id, vpc_uuid, RelationshipType::MemberOf).await?;
                        rel_count += 1;
                    }
                }
            }

            // ── 2. Subnet membership ─────────────────────────────────────────────
            if let Some(ref subnet_id) = asset.subnet_id {
                if let Some(&subnet_uuid) = subnet_assets.get(subnet_id) {
                    if subnet_uuid != asset.id {
                        self.insert_rel(asset.id, subnet_uuid, RelationshipType::MemberOf).await?;
                        rel_count += 1;

                        // Subnet → VPC (via subnet asset's vpc_id)
                        let subnet_asset = assets.iter().find(|a| a.id == subnet_uuid);
                        if let Some(sa) = subnet_asset {
                            if let Some(ref sv) = sa.vpc_id {
                                if let Some(&vpc_uuid) = vpc_assets.get(sv) {
                                    self.insert_rel(subnet_uuid, vpc_uuid, RelationshipType::MemberOf).await?;
                                    rel_count += 1;
                                }
                            }
                        }
                    }
                }
            }

            // ── 3. Security group authorization ──────────────────────────────────
            if let Some(ref sgs) = asset.security_groups {
                for sg_id in sgs {
                    if let Some(&sg_uuid) = sg_assets.get(sg_id) {
                        if sg_uuid != asset.id {
                            self.insert_rel(asset.id, sg_uuid, RelationshipType::AuthorizedBy).await?;
                            rel_count += 1;
                        }
                    }
                }
            }

            // ── 4. SecurityGroup → SecurityGroup via ingress rules ───────────────
            if asset.asset_type == AssetType::SecurityGroup {
                if let Some(ref config) = asset.configuration {
                    if let Some(rules) = config.get("ingress_rules").and_then(|v| v.as_array()) {
                        for rule in rules {
                            if let Some(refs) = rule.get("security_group_refs").and_then(|v| v.as_array()) {
                                for sg_ref in refs {
                                    if let Some(src_sg_id) = sg_ref.get("group_id").and_then(|v| v.as_str()) {
                                        if let Some(&src_uuid) = sg_assets.get(src_sg_id) {
                                            if src_uuid != asset.id {
                                                self.insert_rel(src_uuid, asset.id, RelationshipType::ConnectedTo).await?;
                                                rel_count += 1;
                                                debug!("SG {} connected to SG {}", src_sg_id, asset.sk);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // ── 5. Lambda relationships ──────────────────────────────────────────
            if asset.asset_type == AssetType::Lambda {
                if let Some(ref config) = asset.configuration {
                    // Lambda → DynamoDB via env var TABLE names
                    if let Some(env_vars) = config.get("environment_variable_keys").and_then(|v| v.as_array()) {
                        // env_variable_keys is just key names (no values for security)
                        // We can't resolve to table names without the values themselves
                        let _ = env_vars;
                    }
                    // Also check older format with env var object
                    if let Some(env_obj) = config.get("environment_variables").and_then(|v| v.as_object()) {
                        for (key, value) in env_obj {
                            if key.to_uppercase().contains("TABLE") || key.to_uppercase().contains("DYNAMODB") {
                                if let Some(table_name) = value.as_str() {
                                    if let Some(table_asset) = assets.iter().find(|a|
                                        a.asset_type == AssetType::Table && a.sk.contains(table_name)
                                    ) {
                                        self.insert_rel(asset.id, table_asset.id, RelationshipType::Uses).await?;
                                        rel_count += 1;
                                        debug!("Lambda {} uses DynamoDB table {}", asset.sk, table_name);
                                    }
                                }
                            }
                        }
                    }

                    // Lambda → SQS/SNS via DLQ target ARN
                    if let Some(dlq_arn) = config.get("dlq_config")
                        .and_then(|d| d.get("target_arn"))
                        .and_then(|v| v.as_str())
                    {
                        if let Some(&target_uuid) = sqs_by_arn.get(dlq_arn) {
                            self.insert_rel(asset.id, target_uuid, RelationshipType::DependsOn).await?;
                            rel_count += 1;
                            debug!("Lambda {} DLQ → SQS {}", asset.sk, dlq_arn);
                        } else if let Some(&target_uuid) = sns_by_arn.get(dlq_arn) {
                            self.insert_rel(asset.id, target_uuid, RelationshipType::DependsOn).await?;
                            rel_count += 1;
                            debug!("Lambda {} DLQ → SNS {}", asset.sk, dlq_arn);
                        }
                    }
                }
            }

            // ── 6. CloudFront relationships ──────────────────────────────────────
            if asset.asset_type == AssetType::Cdn {
                if let Some(ref config) = asset.configuration {
                    if let Some(origins) = config.get("origins").and_then(|v| v.as_array()) {
                        for origin in origins {
                            if let Some(domain) = origin.get("domain_name").and_then(|v| v.as_str()) {
                                let domain_lower = domain.to_lowercase();

                                // CloudFront → S3
                                if domain_lower.contains(".s3.") || domain_lower.contains(".s3-") {
                                    let bucket = domain.split('.').next().unwrap_or("");
                                    if let Some(&s3_uuid) = s3_assets.get(bucket) {
                                        self.insert_rel(asset.id, s3_uuid, RelationshipType::BackedBy).await?;
                                        rel_count += 1;
                                        debug!("CloudFront {} backed by S3 {}", asset.sk, bucket);
                                    }
                                }

                                // CloudFront → ELB
                                if domain_lower.contains(".elb.amazonaws.com") {
                                    let trimmed = domain_lower.trim_end_matches('.');
                                    if let Some(&elb_uuid) = elb_by_dns.get(trimmed) {
                                        self.insert_rel(asset.id, elb_uuid, RelationshipType::RoutesTo).await?;
                                        rel_count += 1;
                                        debug!("CloudFront {} routes to ELB {}", asset.sk, domain);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // ── 7. Route53 domain → target assets ───────────────────────────────
            if asset.asset_type == AssetType::Domain {
                if let Some(ref config) = asset.configuration {
                    // Check alias target
                    let alias_dns = config.get("alias_target")
                        .and_then(|a| a.get("dns_name"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim_end_matches('.').to_lowercase());

                    // Check CNAME/A values
                    let cname_values: Vec<String> = config.get("values")
                        .and_then(|v| v.as_array())
                        .map(|arr| arr.iter()
                            .filter_map(|v| v.as_str())
                            .map(|s| s.trim_end_matches('.').to_lowercase())
                            .collect())
                        .unwrap_or_default();

                    let candidates: Vec<String> = alias_dns.into_iter().chain(cname_values).collect();

                    for candidate in &candidates {
                        // → ELB
                        if candidate.contains(".elb.amazonaws.com") {
                            if let Some(&elb_uuid) = elb_by_dns.get(candidate.as_str()) {
                                self.insert_rel(asset.id, elb_uuid, RelationshipType::RoutesTo).await?;
                                rel_count += 1;
                                debug!("Route53 {} routes to ELB", asset.sk);
                            }
                        }
                        // → CloudFront
                        if candidate.contains(".cloudfront.net") {
                            if let Some(&cf_uuid) = cf_by_domain.get(candidate.as_str()) {
                                self.insert_rel(asset.id, cf_uuid, RelationshipType::RoutesTo).await?;
                                rel_count += 1;
                                debug!("Route53 {} routes to CloudFront", asset.sk);
                            }
                        }
                        // → API Gateway
                        if candidate.contains(".execute-api.") {
                            // Match by prefix since stage is appended
                            for (apigw_dns, &apigw_uuid) in &apigw_by_dns {
                                if candidate.starts_with(apigw_dns.as_str()) || apigw_dns.starts_with(candidate.as_str()) {
                                    self.insert_rel(asset.id, apigw_uuid, RelationshipType::RoutesTo).await?;
                                    rel_count += 1;
                                    debug!("Route53 {} routes to API Gateway", asset.sk);
                                    break;
                                }
                            }
                        }
                        // → S3 website
                        if candidate.contains(".s3-website") || candidate.contains(".s3.amazonaws.com") {
                            let bucket = candidate.split('.').next().unwrap_or("");
                            if let Some(&s3_uuid) = s3_assets.get(bucket) {
                                self.insert_rel(asset.id, s3_uuid, RelationshipType::RoutesTo).await?;
                                rel_count += 1;
                                debug!("Route53 {} routes to S3 bucket {}", asset.sk, bucket);
                            }
                        }
                    }
                }
            }

            // ── 8. ECS service → ELB ─────────────────────────────────────────────
            if asset.asset_type == AssetType::Container {
                if let Some(ref config) = asset.configuration {
                    if let Some(lbs) = config.get("load_balancers").and_then(|v| v.as_array()) {
                        for lb in lbs {
                            // Try by load_balancer_name
                            if let Some(lb_name) = lb.get("load_balancer_name").and_then(|v| v.as_str()) {
                                if let Some(&lb_uuid) = elb_by_name.get(lb_name) {
                                    self.insert_rel(asset.id, lb_uuid, RelationshipType::RoutesTo).await?;
                                    rel_count += 1;
                                    debug!("ECS service {} routed via ELB {}", asset.sk, lb_name);
                                }
                            }
                            // Try by target_group_arn prefix (ARN contains lb name)
                            if let Some(tg_arn) = lb.get("target_group_arn").and_then(|v| v.as_str()) {
                                if tg_arn.contains(":targetgroup/") {
                                    for (lb_name, &lb_uuid) in &elb_by_name {
                                        if tg_arn.contains(lb_name.as_str()) {
                                            self.insert_rel(asset.id, lb_uuid, RelationshipType::RoutesTo).await?;
                                            rel_count += 1;
                                            debug!("ECS service {} matched ELB {} via target group ARN", asset.sk, lb_name);
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // ── 9. SQS → SQS DLQ ────────────────────────────────────────────────
            if asset.asset_type == AssetType::Queue {
                if let Some(ref config) = asset.configuration {
                    if let Some(dlq_arn) = config.get("dead_letter_target_arn").and_then(|v| v.as_str()) {
                        if let Some(&dlq_uuid) = sqs_by_arn.get(dlq_arn) {
                            if dlq_uuid != asset.id {
                                self.insert_rel(asset.id, dlq_uuid, RelationshipType::DependsOn).await?;
                                rel_count += 1;
                                debug!("SQS {} has DLQ {}", asset.sk, dlq_arn);
                            }
                        }
                    }
                }
            }

            // ── 10. ElastiCache replication group sibling ───────────────────────
            // Individual Cache assets that share the same replication_group_id are
            // siblings — but we'd need a second ElastiCache asset type for groups.
            // Skipping for now; handled by shared security_groups / vpc_id membership.
        }

        info!("Relationship building complete. Created {} relationships", rel_count);
        Ok(())
    }

    async fn insert_rel(
        &self,
        source: Uuid,
        target: Uuid,
        rel_type: RelationshipType,
    ) -> anyhow::Result<()> {
        let rel = AssetRelationship::new(source, target, rel_type);
        self.asset_store.insert_relationship(rel).await
    }
}