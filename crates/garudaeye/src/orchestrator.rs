use std::sync::Arc;
use tracing::{info, error};
use infra::traits::{AssetStore, EventBus};
use garudaeye_core::Result;
use crate::relationship_builder::RelationshipBuilder;
use aws_sdk_ec2::Client as Ec2Client;

/// Orchestrates collection and analysis workflows
pub struct Orchestrator {
    asset_store: Arc<dyn AssetStore>,
    event_bus: Arc<dyn EventBus>,
}

impl Orchestrator {
    pub fn new(asset_store: Arc<dyn AssetStore>, event_bus: Arc<dyn EventBus>) -> Self {
        Self {
            asset_store,
            event_bus,
        }
    }
    
    pub async fn start_collection(&self) -> Result<()> {
        info!("Starting collection...");
        
        // Get AWS regions to scan from environment or use default
        let regions_str = std::env::var("AWS_REGIONS")
            .unwrap_or_else(|_| "us-east-1,us-west-2,eu-west-1".to_string());
        
        let regions: Vec<String> = if regions_str.trim().eq_ignore_ascii_case("all") {
            info!("Fetching all available AWS regions...");
            // Fetch all available AWS regions
            let temp_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                .region(aws_config::Region::new("us-east-1".to_string()))
                .load()
                .await;
            let ec2_client = Ec2Client::new(&temp_config);
            
            match ec2_client.describe_regions().send().await {
                Ok(output) => {
                    let regions_vec: Vec<aws_sdk_ec2::types::Region> = output.regions.unwrap_or_default();
                    let all_regions: Vec<String> = regions_vec
                        .into_iter()
                        .filter_map(|r| r.region_name)
                        .collect();
                    info!("Found {} AWS regions", all_regions.len());
                    all_regions
                },
                Err(e) => {
                    error!("Failed to fetch AWS regions: {}. Using default regions.", e);
                    vec!["us-east-1".to_string(), "us-west-2".to_string(), "eu-west-1".to_string()]
                }
            }
        } else {
            regions_str
                .split(',')
                .map(|s| s.trim().to_string())
                .collect()
        };
        
        info!("Scanning AWS regions: {:?}", regions);
        
        for region in regions {
            info!("Starting collection for region: {}", region);
            
            // Load AWS config for this region
            let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                .region(aws_config::Region::new(region.clone()))
                .load()
                .await;
            
            // Initialize all AWS collectors for this region, passing region name
            let ec2 = collectors::aws::Ec2Collector::new(&aws_config, region.clone()).await;
            let s3 = collectors::aws::S3Collector::new(&aws_config, region.clone()).await;
            let elb = collectors::aws::ElbCollector::new(&aws_config, region.clone()).await;
            let rds = collectors::aws::RdsCollector::new(&aws_config, region.clone()).await;
            let elasticache = collectors::aws::ElastiCacheCollector::new(&aws_config, region.clone()).await;
            let elasticsearch = collectors::aws::ElasticsearchCollector::new(&aws_config, region.clone()).await;
            let eks = collectors::aws::EksCollector::new(&aws_config, region.clone()).await;
            let elasticbeanstalk = collectors::aws::ElasticBeanstalkCollector::new(&aws_config, region.clone()).await;
            let apigateway = collectors::aws::ApiGatewayCollector::new(&aws_config, region.clone()).await;
            let lambda = collectors::aws::LambdaCollector::new(&aws_config, region.clone()).await;
            let vpc = collectors::aws::VpcCollector::new(&aws_config, region.clone()).await;
            let dynamodb = collectors::aws::DynamoDbCollector::new(&aws_config, region.clone()).await;
            let sns = collectors::aws::SnsCollector::new(&aws_config, region.clone()).await;
            let sqs = collectors::aws::SqsCollector::new(&aws_config, region.clone()).await;
            let ecs = collectors::aws::EcsCollector::new(&aws_config, region.clone()).await;
            let route53 = collectors::aws::Route53Collector::new(&aws_config, region.clone()).await;
            
            // CloudFront is global, only collect once
            let cloudfront = if region == "us-east-1" {
                Some(collectors::aws::CloudFrontCollector::new(&aws_config, "global".to_string()).await)
            } else {
                None
            };
            
            // Run all collectors for this region
            let store = self.asset_store.as_ref();
            let bus = self.event_bus.as_ref();
            
            // Core infrastructure collectors first (VPC, Subnets, Security Groups)
            if let Err(e) = vpc.collect(store, bus).await {
                error!("VPC collection failed in {}: {}", region, e);
            }
            
            // Compute resources
            if let Err(e) = ec2.collect(store, bus).await {
                error!("EC2 collection failed in {}: {}", region, e);
            }
            
            if let Err(e) = lambda.collect(store, bus).await {
                error!("Lambda collection failed in {}: {}", region, e);
            }
            
            if let Err(e) = eks.collect(store, bus).await {
                error!("EKS collection failed in {}: {}", region, e);
            }
            
            if let Err(e) = ecs.collect(store, bus).await {
                error!("ECS collection failed in {}: {}", region, e);
            }
            
            if let Err(e) = elasticbeanstalk.collect(store, bus).await {
                error!("Elastic Beanstalk collection failed in {}: {}", region, e);
            }
            
            // Storage resources
            if let Err(e) = s3.collect(store, bus).await {
                error!("S3 collection failed in {}: {}", region, e);
            }
            
            // Database resources
            if let Err(e) = rds.collect(store, bus).await {
                error!("RDS collection failed in {}: {}", region, e);
            }
            
            if let Err(e) = dynamodb.collect(store, bus).await {
                error!("DynamoDB collection failed in {}: {}", region, e);
            }
            
            if let Err(e) = elasticache.collect(store, bus).await {
                error!("ElastiCache collection failed in {}: {}", region, e);
            }
            
            if let Err(e) = elasticsearch.collect(store, bus).await {
                error!("Elasticsearch collection failed in {}: {}", region, e);
            }
            
            // Networking resources
            if let Err(e) = elb.collect(store, bus).await {
                error!("ELB collection failed in {}: {}", region, e);
            }
            
            // CloudFront (global service, only in us-east-1)
            if let Some(cf) = cloudfront {
                if let Err(e) = cf.collect(store, bus).await {
                    error!("CloudFront collection failed: {}", e);
                }
            }
            
            if let Err(e) = apigateway.collect(store, bus).await {
                error!("API Gateway collection failed in {}: {}", region, e);
            }
            
            // Messaging resources
            if let Err(e) = sns.collect(store, bus).await {
                error!("SNS collection failed in {}: {}", region, e);
            }
            
            if let Err(e) = sqs.collect(store, bus).await {
                error!("SQS collection failed in {}: {}", region, e);
            }
            
            // DNS resources (Route53 is global but region-aware)
            if region == "us-east-1" {
                if let Err(e) = route53.collect(store, bus).await {
                    error!("Route53 collection failed: {}", e);
                }
            }
            
            info!("Collection complete for region: {}", region);
        }
        
        // Build relationships between collected assets
        info!("Building relationships between assets...");
        let relationship_builder = RelationshipBuilder::new(self.asset_store.clone());
        if let Err(e) = relationship_builder.build_relationships().await {
            error!("Relationship building failed: {}", e);
        }
        
        info!("Collection complete for all regions!");
        Ok(())
    }
    
    pub async fn start_analysis(&self) -> Result<()> {
        info!("Starting analysis...");
        // Phase 3: Will trigger all analyzers
        Ok(())
    }

    /// Re-queue all existing public assets for fingerprint enrichment.
    pub async fn start_enrichment(&self) -> anyhow::Result<api::state::EnrichmentSummary> {
        use garudaeye_core::AssetType;

        info!("Starting fingerprint enrichment on existing assets...");

        // Fetch every asset (no limit)
        let all_assets = self.asset_store.list(None, None, None).await?;
        let total = all_assets.len();

        let mut queued_ip = 0usize;
        let mut queued_domain = 0usize;

        for asset in &all_assets {
            // Only enrich assets flagged as publicly accessible
            if asset.public_access != Some(true) {
                continue;
            }

            match asset.asset_type {
                AssetType::IpAddress => {
                    if let Err(e) = self.event_bus.publish("analyze-ip", &asset.sk).await {
                        error!("Failed to queue IP {} for enrichment: {}", asset.sk, e);
                    } else {
                        queued_ip += 1;
                    }
                }
                AssetType::LoadBalancer
                | AssetType::Domain
                | AssetType::ApiGateway
                | AssetType::Database
                | AssetType::Cdn => {
                    if let Err(e) = self.event_bus.publish("analyze-domain", &asset.sk).await {
                        error!("Failed to queue domain {} for enrichment: {}", asset.sk, e);
                    } else {
                        queued_domain += 1;
                    }
                }
                _ => {}
            }
        }

        info!(
            "Enrichment queued: {} IPs, {} domains (out of {} total assets)",
            queued_ip, queued_domain, total
        );

        Ok(api::state::EnrichmentSummary {
            queued_ip,
            queued_domain,
            total_assets_scanned: total,
        })
    }
}

// Implement the trait from the API crate to avoid circular dependencies
#[async_trait::async_trait]
impl api::state::OrchestratorTrait for Orchestrator {
    async fn start_collection(&self) -> anyhow::Result<()> {
        Orchestrator::start_collection(self).await.map_err(Into::into)
    }
    
    async fn start_analysis(&self) -> anyhow::Result<()> {
        Orchestrator::start_analysis(self).await.map_err(Into::into)
    }

    async fn start_enrichment(&self) -> anyhow::Result<api::state::EnrichmentSummary> {
        Orchestrator::start_enrichment(self).await.map_err(Into::into)
    }
}
