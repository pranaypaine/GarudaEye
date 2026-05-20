use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Main asset representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub id: Uuid,
    pub asset_type: AssetType,
    pub sk: String,  // Sort key - the actual value (IP, domain, etc.)
    pub provider: CloudProvider,
    pub region: Option<String>,
    pub service: Option<String>,
    pub resource_id: Option<String>,
    
    // Enrichment data from analyzers
    pub ports: Option<Vec<u16>>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub organization: Option<String>,
    pub isp: Option<String>,
    pub asn: Option<String>,
    pub vulnerabilities: Option<Vec<String>>,
    pub http_title: Option<String>,
    pub http_server: Option<String>,
    pub ssl_cert: Option<String>,
    pub last_seen: Option<chrono::DateTime<chrono::Utc>>,
    pub shodan_data: Option<serde_json::Value>,
    pub virustotal_score: Option<f64>,
    pub observatory_grade: Option<String>,
    pub observatory_score: Option<i32>,
    pub nmap_results: Option<Vec<NmapResult>>,
    
    // AWS-specific metadata for relationship mapping
    pub tags: Option<serde_json::Value>,
    pub vpc_id: Option<String>,
    pub subnet_id: Option<String>,
    pub security_groups: Option<Vec<String>>,
    pub iam_role: Option<String>,
    pub network_interfaces: Option<Vec<serde_json::Value>>,
    pub public_access: Option<bool>,
    pub encryption_enabled: Option<bool>,
    pub compliance_status: Option<String>,
    pub configuration: Option<serde_json::Value>,
    pub dns_name: Option<String>,
    pub arn: Option<String>,
    
    // Fingerprint-derived fields
    pub risk_score: i32,
    pub os_guess: Option<String>,
    
    // Metadata
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl Asset {
    pub fn new(asset_type: AssetType, sk: String, provider: CloudProvider) -> Self {
        let now = chrono::Utc::now();
        Self {
            id: Uuid::new_v4(),
            asset_type,
            sk,
            provider,
            region: None,
            service: None,
            resource_id: None,
            ports: None,
            country: None,
            city: None,
            organization: None,
            isp: None,
            asn: None,
            vulnerabilities: None,
            http_title: None,
            http_server: None,
            ssl_cert: None,
            last_seen: None,
            shodan_data: None,
            virustotal_score: None,
            observatory_grade: None,
            observatory_score: None,
            nmap_results: None,
            tags: None,
            vpc_id: None,
            subnet_id: None,
            security_groups: None,
            iam_role: None,
            network_interfaces: None,
            public_access: None,
            encryption_enabled: None,
            compliance_status: None,
            configuration: None,
            dns_name: None,
            arn: None,
            risk_score: 0,
            os_guess: None,
            created_at: now,
            updated_at: now,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "TEXT", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum AssetType {
    IpAddress,
    Domain,
    S3Bucket,
    LoadBalancer,
    Database,
    Cache,
    Cdn,
    Lambda,
    ApiGateway,
    Queue,
    Topic,
    Table,
    Vpc,
    Subnet,
    SecurityGroup,
    Container,
    Cluster,
}

impl std::fmt::Display for AssetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssetType::IpAddress => write!(f, "ip_address"),
            AssetType::Domain => write!(f, "domain"),
            AssetType::S3Bucket => write!(f, "s3_bucket"),
            AssetType::LoadBalancer => write!(f, "load_balancer"),
            AssetType::Database => write!(f, "database"),
            AssetType::Cache => write!(f, "cache"),
            AssetType::Cdn => write!(f, "cdn"),
            AssetType::Lambda => write!(f, "lambda"),
            AssetType::ApiGateway => write!(f, "api_gateway"),
            AssetType::Queue => write!(f, "queue"),
            AssetType::Topic => write!(f, "topic"),
            AssetType::Table => write!(f, "table"),
            AssetType::Vpc => write!(f, "vpc"),
            AssetType::Subnet => write!(f, "subnet"),
            AssetType::SecurityGroup => write!(f, "security_group"),
            AssetType::Container => write!(f, "container"),
            AssetType::Cluster => write!(f, "cluster"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "TEXT", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum CloudProvider {
    Aws,
    Azure,
    Gcp,
    Digitalocean,
    Oracle,
}

impl std::fmt::Display for CloudProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CloudProvider::Aws => write!(f, "aws"),
            CloudProvider::Azure => write!(f, "azure"),
            CloudProvider::Gcp => write!(f, "gcp"),
            CloudProvider::Digitalocean => write!(f, "digitalocean"),
            CloudProvider::Oracle => write!(f, "oracle"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NmapResult {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service: Option<String>,
    pub version: Option<String>,
    pub scripts: Option<Vec<NmapScript>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NmapScript {
    pub id: String,
    pub output: String,
}

/// Represents a relationship/connection between two assets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetRelationship {
    pub id: Uuid,
    pub source_asset_id: Uuid,
    pub target_asset_id: Uuid,
    pub relationship_type: RelationshipType,
    pub metadata: Option<serde_json::Value>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl AssetRelationship {
    pub fn new(
        source_asset_id: Uuid,
        target_asset_id: Uuid,
        relationship_type: RelationshipType,
    ) -> Self {
        let now = chrono::Utc::now();
        Self {
            id: Uuid::new_v4(),
            source_asset_id,
            target_asset_id,
            relationship_type,
            metadata: None,
            created_at: now,
            updated_at: now,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "TEXT", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum RelationshipType {
    Uses,              // e.g., Lambda uses S3 bucket
    AttachedTo,        // e.g., ENI attached to EC2
    MemberOf,          // e.g., EC2 member of VPC
    RoutesTo,          // e.g., ALB routes to EC2
    Triggers,          // e.g., API Gateway triggers Lambda
    ConnectedTo,       // e.g., RDS connected to subnet
    DependsOn,         // General dependency
    BackedBy,          // e.g., CloudFront backed by S3
    AuthorizedBy,      // e.g., Resource authorized by IAM role
    MonitoredBy,       // e.g., Resource monitored by CloudWatch
    EncryptedBy,       // e.g., Resource encrypted by KMS key
}

impl std::fmt::Display for RelationshipType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelationshipType::Uses => write!(f, "uses"),
            RelationshipType::AttachedTo => write!(f, "attached_to"),
            RelationshipType::MemberOf => write!(f, "member_of"),
            RelationshipType::RoutesTo => write!(f, "routes_to"),
            RelationshipType::Triggers => write!(f, "triggers"),
            RelationshipType::ConnectedTo => write!(f, "connected_to"),
            RelationshipType::DependsOn => write!(f, "depends_on"),
            RelationshipType::BackedBy => write!(f, "backed_by"),
            RelationshipType::AuthorizedBy => write!(f, "authorized_by"),
            RelationshipType::MonitoredBy => write!(f, "monitored_by"),
            RelationshipType::EncryptedBy => write!(f, "encrypted_by"),
        }
    }
}
