use async_trait::async_trait;
use garudaeye_core::{Asset, AssetType, CloudProvider, Count, CountCategory, AssetRelationship};
use sqlx::{SqlitePool, Row};
use tracing::{debug, info};

pub struct SqliteAssetStore {
    pool: SqlitePool,
}

impl SqliteAssetStore {
    pub async fn new(database_url: &str) -> anyhow::Result<Self> {
        // Create data directory if it doesn't exist
        if database_url.starts_with("sqlite://") {
            let path = database_url.strip_prefix("sqlite://").unwrap();
            if let Some(parent) = std::path::Path::new(path).parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
        }
        
        // Connect with options to create database if it doesn't exist
        let pool = SqlitePool::connect_with(
            database_url.parse::<sqlx::sqlite::SqliteConnectOptions>()?
                .create_if_missing(true)
        ).await?;
        
        // Run migrations
        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await?;
        
        info!("SQLite asset store initialized");
        Ok(Self { pool })
    }
}

#[async_trait]
impl crate::traits::AssetStore for SqliteAssetStore {
    async fn insert(&self, asset: Asset) -> anyhow::Result<()> {
        let asset_type = asset.asset_type.to_string();
        let provider = asset.provider.to_string();
        let ports = asset.ports.as_ref().map(|p| serde_json::to_string(p).unwrap());
        let vulnerabilities = asset.vulnerabilities.as_ref().map(|v| serde_json::to_string(v).unwrap());
        let shodan_data = asset.shodan_data.as_ref().map(|d| serde_json::to_string(d).unwrap());
        let nmap_results = asset.nmap_results.as_ref().map(|n| serde_json::to_string(n).unwrap());
        let tags = asset.tags.as_ref().map(|t| serde_json::to_string(t).unwrap());
        let security_groups = asset.security_groups.as_ref().map(|sg| serde_json::to_string(sg).unwrap());
        let network_interfaces = asset.network_interfaces.as_ref().map(|ni| serde_json::to_string(ni).unwrap());
        let configuration = asset.configuration.as_ref().map(|c| serde_json::to_string(c).unwrap());
        
        sqlx::query(
            r#"
            INSERT INTO assets (
                id, asset_type, sk, provider, region, service, resource_id,
                ports, country, city, organization, isp, asn,
                vulnerabilities, http_title, http_server, ssl_cert, last_seen,
                shodan_data, virustotal_score, observatory_grade, observatory_score,
                nmap_results, tags, vpc_id, subnet_id, security_groups, iam_role,
                network_interfaces, public_access, encryption_enabled, compliance_status,
                configuration, dns_name, arn, risk_score, os_guess, created_at, updated_at
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24,
                ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33, ?34, ?35, ?36, ?37, ?38, ?39
            )
            ON CONFLICT(asset_type, sk) DO UPDATE SET
                updated_at = ?39,
                region = COALESCE(?5, region),
                service = COALESCE(?6, service),
                resource_id = COALESCE(?7, resource_id),
                tags = COALESCE(?24, tags),
                vpc_id = COALESCE(?25, vpc_id),
                subnet_id = COALESCE(?26, subnet_id),
                security_groups = COALESCE(?27, security_groups),
                iam_role = COALESCE(?28, iam_role),
                network_interfaces = COALESCE(?29, network_interfaces),
                public_access = COALESCE(?30, public_access),
                encryption_enabled = COALESCE(?31, encryption_enabled),
                configuration = COALESCE(?33, configuration),
                dns_name = COALESCE(?34, dns_name),
                arn = COALESCE(?35, arn),
                risk_score = ?36,
                os_guess = COALESCE(?37, os_guess)
            "#
        )
        .bind(asset.id.to_string())
        .bind(&asset_type)
        .bind(&asset.sk)
        .bind(&provider)
        .bind(&asset.region)
        .bind(&asset.service)
        .bind(&asset.resource_id)
        .bind(&ports)
        .bind(&asset.country)
        .bind(&asset.city)
        .bind(&asset.organization)
        .bind(&asset.isp)
        .bind(&asset.asn)
        .bind(&vulnerabilities)
        .bind(&asset.http_title)
        .bind(&asset.http_server)
        .bind(&asset.ssl_cert)
        .bind(&asset.last_seen)
        .bind(&shodan_data)
        .bind(&asset.virustotal_score)
        .bind(&asset.observatory_grade)
        .bind(&asset.observatory_score)
        .bind(&nmap_results)
        .bind(&tags)
        .bind(&asset.vpc_id)
        .bind(&asset.subnet_id)
        .bind(&security_groups)
        .bind(&asset.iam_role)
        .bind(&network_interfaces)
        .bind(&asset.public_access)
        .bind(&asset.encryption_enabled)
        .bind(&asset.compliance_status)
        .bind(&configuration)
        .bind(&asset.dns_name)
        .bind(&asset.arn)
        .bind(asset.risk_score)
        .bind(&asset.os_guess)
        .bind(&asset.created_at)
        .bind(&asset.updated_at)
        .execute(&self.pool)
        .await?;
        
        debug!("Inserted/updated asset: {} ({})", asset.sk, asset_type);
        Ok(())
    }
    
    async fn update(&self, asset: Asset) -> anyhow::Result<()> {
        let ports = asset.ports.as_ref().map(|p| serde_json::to_string(p).unwrap());
        let vulnerabilities = asset.vulnerabilities.as_ref().map(|v| serde_json::to_string(v).unwrap());
        let shodan_data = asset.shodan_data.as_ref().map(|d| serde_json::to_string(d).unwrap());
        let nmap_results = asset.nmap_results.as_ref().map(|n| serde_json::to_string(n).unwrap());
        
        sqlx::query(
            r#"
            UPDATE assets SET
                region = ?1, service = ?2, resource_id = ?3,
                ports = ?4, country = ?5, city = ?6, organization = ?7,
                isp = ?8, asn = ?9, vulnerabilities = ?10, http_title = ?11,
                http_server = ?12, ssl_cert = ?13, last_seen = ?14,
                shodan_data = ?15, virustotal_score = ?16,
                observatory_grade = ?17, observatory_score = ?18,
                nmap_results = ?19, risk_score = ?20, os_guess = ?21,
                updated_at = ?22
            WHERE id = ?23
            "#
        )
        .bind(&asset.region)
        .bind(&asset.service)
        .bind(&asset.resource_id)
        .bind(&ports)
        .bind(&asset.country)
        .bind(&asset.city)
        .bind(&asset.organization)
        .bind(&asset.isp)
        .bind(&asset.asn)
        .bind(&vulnerabilities)
        .bind(&asset.http_title)
        .bind(&asset.http_server)
        .bind(&asset.ssl_cert)
        .bind(&asset.last_seen)
        .bind(&shodan_data)
        .bind(&asset.virustotal_score)
        .bind(&asset.observatory_grade)
        .bind(&asset.observatory_score)
        .bind(&nmap_results)
        .bind(asset.risk_score)
        .bind(&asset.os_guess)
        .bind(&asset.updated_at)
        .bind(asset.id.to_string())
        .execute(&self.pool)
        .await?;
        
        debug!("Updated asset: {}", asset.id);
        Ok(())
    }
    
    async fn get_by_id(&self, id: uuid::Uuid) -> anyhow::Result<Option<Asset>> {
        let row = sqlx::query(
            "SELECT * FROM assets WHERE id = ?1"
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(row.map(|r| self.row_to_asset(r)).transpose()?)
    }
    
    async fn get_by_sk(&self, asset_type: AssetType, sk: &str) -> anyhow::Result<Option<Asset>> {
        let asset_type_str = asset_type.to_string();
        let row = sqlx::query(
            "SELECT * FROM assets WHERE asset_type = ?1 AND sk = ?2"
        )
        .bind(&asset_type_str)
        .bind(sk)
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(row.map(|r| self.row_to_asset(r)).transpose()?)
    }
    
    async fn list(
        &self,
        asset_type: Option<AssetType>,
        provider: Option<CloudProvider>,
        limit: Option<i64>,
    ) -> anyhow::Result<Vec<Asset>> {
        let mut query = "SELECT * FROM assets WHERE 1=1".to_string();
        
        if let Some(at) = asset_type {
            query.push_str(&format!(" AND asset_type = '{}'", at));
        }
        
        if let Some(p) = provider {
            query.push_str(&format!(" AND provider = '{}'", p));
        }
        
        query.push_str(" ORDER BY created_at DESC");
        
        if let Some(l) = limit {
            query.push_str(&format!(" LIMIT {}", l));
        }
        
        let rows = sqlx::query(&query)
            .fetch_all(&self.pool)
            .await?;
        
        rows.into_iter()
            .map(|r| self.row_to_asset(r))
            .collect()
    }
    
    async fn count(&self, asset_type: Option<AssetType>) -> anyhow::Result<i64> {
        let mut query = "SELECT COUNT(*) as count FROM assets WHERE 1=1".to_string();
        
        if let Some(at) = asset_type {
            query.push_str(&format!(" AND asset_type = '{}'", at));
        }
        
        let row = sqlx::query(&query)
            .fetch_one(&self.pool)
            .await?;
        
        Ok(row.try_get("count")?)
    }
    
    async fn count_by_field(&self, field: &str, value: &str) -> anyhow::Result<i64> {
        // Whitelist allowed field names to prevent SQL injection
        let allowed_fields = ["public_access", "encryption_enabled", "provider", "region", "service", "asset_type"];
        if !allowed_fields.contains(&field) {
            return Err(anyhow::anyhow!("Field '{}' is not allowed for count_by_field", field));
        }
        let query = format!("SELECT COUNT(*) as count FROM assets WHERE {} = ?1", field);
        let row = sqlx::query(&query)
            .bind(value)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get("count")?)
    }

    async fn count_with_ports(&self) -> anyhow::Result<i64> {
        let row = sqlx::query(
            "SELECT COUNT(*) as count FROM assets WHERE ports IS NOT NULL AND ports != 'null' AND ports != '[]'"
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(row.try_get("count")?)
    }

    async fn count_with_vulnerabilities(&self) -> anyhow::Result<i64> {
        let row = sqlx::query(
            "SELECT COUNT(*) as count FROM assets WHERE vulnerabilities IS NOT NULL AND vulnerabilities != 'null' AND vulnerabilities != '[]'"
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(row.try_get("count")?)
    }

    async fn get_port_distribution(&self) -> anyhow::Result<Vec<(u16, i64)>> {
        let rows = sqlx::query(
            "SELECT ports FROM assets WHERE ports IS NOT NULL AND ports != 'null' AND ports != '[]'"
        )
        .fetch_all(&self.pool)
        .await?;

        let mut counts: std::collections::HashMap<u16, i64> = std::collections::HashMap::new();
        for row in rows {
            let ports_str: Option<String> = row.try_get("ports").ok().flatten();
            if let Some(ps) = ports_str {
                if let Ok(ports) = serde_json::from_str::<Vec<u16>>(&ps) {
                    for port in ports {
                        *counts.entry(port).or_insert(0) += 1;
                    }
                }
            }
        }
        let mut dist: Vec<(u16, i64)> = counts.into_iter().collect();
        dist.sort_by(|a, b| b.1.cmp(&a.1));
        Ok(dist)
    }

    async fn list_by_risk_score(&self, min_score: i32) -> anyhow::Result<Vec<Asset>> {
        let rows = sqlx::query(
            "SELECT * FROM assets WHERE risk_score >= ?1 ORDER BY risk_score DESC"
        )
        .bind(min_score)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|r| self.row_to_asset(r))
            .collect()
    }

    async fn delete(&self, id: uuid::Uuid) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM assets WHERE id = ?1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        
        debug!("Deleted asset: {}", id);
        Ok(())
    }
    
    async fn insert_relationship(&self, relationship: AssetRelationship) -> anyhow::Result<()> {
        let relationship_type = relationship.relationship_type.to_string();
        let metadata = relationship.metadata.as_ref().map(|m| serde_json::to_string(m).unwrap());
        
        sqlx::query(
            r#"
            INSERT INTO asset_relationships (
                id, source_asset_id, target_asset_id, relationship_type, metadata, created_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(source_asset_id, target_asset_id, relationship_type) DO UPDATE SET
                updated_at = ?7,
                metadata = COALESCE(?5, metadata)
            "#
        )
        .bind(relationship.id.to_string())
        .bind(relationship.source_asset_id.to_string())
        .bind(relationship.target_asset_id.to_string())
        .bind(&relationship_type)
        .bind(&metadata)
        .bind(&relationship.created_at)
        .bind(&relationship.updated_at)
        .execute(&self.pool)
        .await?;
        
        debug!("Inserted/updated relationship: {} -> {}", relationship.source_asset_id, relationship.target_asset_id);
        Ok(())
    }
    
    async fn get_relationships(&self, asset_id: uuid::Uuid) -> anyhow::Result<Vec<AssetRelationship>> {
        let rows = sqlx::query(
            r#"
            SELECT * FROM asset_relationships 
            WHERE source_asset_id = ?1 OR target_asset_id = ?1
            ORDER BY created_at DESC
            "#
        )
        .bind(asset_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        
        rows.into_iter()
            .map(|r| self.row_to_relationship(r))
            .collect()
    }
    
    async fn get_all_relationships(&self) -> anyhow::Result<Vec<AssetRelationship>> {
        let rows = sqlx::query("SELECT * FROM asset_relationships ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await?;
        
        rows.into_iter()
            .map(|r| self.row_to_relationship(r))
            .collect()
    }
    
    async fn count_relationships(&self) -> anyhow::Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) as count FROM asset_relationships")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get("count")?)
    }
    
    async fn delete_relationship(&self, id: uuid::Uuid) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM asset_relationships WHERE id = ?1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        
        debug!("Deleted relationship: {}", id);
        Ok(())
    }
}

impl SqliteAssetStore {
    fn row_to_asset(&self, row: sqlx::sqlite::SqliteRow) -> anyhow::Result<Asset> {
        let id: String = row.try_get("id")?;
        let asset_type: String = row.try_get("asset_type")?;
        let provider: String = row.try_get("provider")?;
        let ports: Option<String> = row.try_get("ports")?;
        let vulnerabilities: Option<String> = row.try_get("vulnerabilities")?;
        let shodan_data: Option<String> = row.try_get("shodan_data")?;
        let nmap_results: Option<String> = row.try_get("nmap_results")?;
        let tags: Option<String> = row.try_get("tags").ok().flatten();
        let security_groups: Option<String> = row.try_get("security_groups").ok().flatten();
        let network_interfaces: Option<String> = row.try_get("network_interfaces").ok().flatten();
        let configuration: Option<String> = row.try_get("configuration").ok().flatten();
        
        Ok(Asset {
            id: uuid::Uuid::parse_str(&id)?,
            asset_type: serde_json::from_str(&format!("\"{}\"", asset_type))?,
            sk: row.try_get("sk")?,
            provider: serde_json::from_str(&format!("\"{}\"", provider))?,
            region: row.try_get("region")?,
            service: row.try_get("service")?,
            resource_id: row.try_get("resource_id")?,
            ports: ports.as_ref().and_then(|p| serde_json::from_str(p).ok()),
            country: row.try_get("country")?,
            city: row.try_get("city")?,
            organization: row.try_get("organization")?,
            isp: row.try_get("isp")?,
            asn: row.try_get("asn")?,
            vulnerabilities: vulnerabilities.as_ref().and_then(|v| serde_json::from_str(v).ok()),
            http_title: row.try_get("http_title")?,
            http_server: row.try_get("http_server")?,
            ssl_cert: row.try_get("ssl_cert")?,
            last_seen: row.try_get("last_seen")?,
            shodan_data: shodan_data.as_ref().and_then(|d| serde_json::from_str(d).ok()),
            virustotal_score: row.try_get("virustotal_score")?,
            observatory_grade: row.try_get("observatory_grade")?,
            observatory_score: row.try_get("observatory_score")?,
            nmap_results: nmap_results.as_ref().and_then(|n| serde_json::from_str(n).ok()),
            tags: tags.as_ref().and_then(|t| serde_json::from_str(t).ok()),
            vpc_id: row.try_get("vpc_id").ok().flatten(),
            subnet_id: row.try_get("subnet_id").ok().flatten(),
            security_groups: security_groups.as_ref().and_then(|sg| serde_json::from_str(sg).ok()),
            iam_role: row.try_get("iam_role").ok().flatten(),
            network_interfaces: network_interfaces.as_ref().and_then(|ni| serde_json::from_str(ni).ok()),
            public_access: row.try_get("public_access").ok().flatten(),
            encryption_enabled: row.try_get("encryption_enabled").ok().flatten(),
            compliance_status: row.try_get("compliance_status").ok().flatten(),
            configuration: configuration.as_ref().and_then(|c| serde_json::from_str(c).ok()),
            dns_name: row.try_get("dns_name").ok().flatten(),
            arn: row.try_get("arn").ok().flatten(),
            risk_score: row.try_get("risk_score").unwrap_or(0),
            os_guess: row.try_get("os_guess").ok().flatten(),
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
    
    fn row_to_relationship(&self, row: sqlx::sqlite::SqliteRow) -> anyhow::Result<AssetRelationship> {
        let id: String = row.try_get("id")?;
        let source_asset_id: String = row.try_get("source_asset_id")?;
        let target_asset_id: String = row.try_get("target_asset_id")?;
        let relationship_type: String = row.try_get("relationship_type")?;
        let metadata: Option<String> = row.try_get("metadata")?;
        
        Ok(AssetRelationship {
            id: uuid::Uuid::parse_str(&id)?,
            source_asset_id: uuid::Uuid::parse_str(&source_asset_id)?,
            target_asset_id: uuid::Uuid::parse_str(&target_asset_id)?,
            relationship_type: serde_json::from_str(&format!("\"{}\"", relationship_type))?,
            metadata: metadata.as_ref().and_then(|m| serde_json::from_str(m).ok()),
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

pub struct SqliteCountStore {
    pool: SqlitePool,
}

impl SqliteCountStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl crate::traits::CountStore for SqliteCountStore {
    async fn upsert(&self, count: Count) -> anyhow::Result<()> {
        let category = count.category.to_string();
        
        sqlx::query(
            r#"
            INSERT INTO counts (category, value, count)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(category, value) DO UPDATE SET count = ?3
            "#
        )
        .bind(&category)
        .bind(&count.value)
        .bind(count.count)
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
    
    async fn get(
        &self,
        category: CountCategory,
        value: &str,
    ) -> anyhow::Result<Option<Count>> {
        let category_str = category.to_string();
        let row = sqlx::query(
            "SELECT * FROM counts WHERE category = ?1 AND value = ?2"
        )
        .bind(&category_str)
        .bind(value)
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(row.map(|r| {
            let category_str: String = r.try_get("category")?;
            Ok::<Count, anyhow::Error>(Count {
                category: serde_json::from_str(&format!("\"{}\"", category_str))?,
                value: r.try_get("value")?,
                count: r.try_get("count")?,
            })
        }).transpose()?)
    }
    
    async fn list(&self, category: CountCategory) -> anyhow::Result<Vec<Count>> {
        let category_str = category.to_string();
        let rows = sqlx::query(
            "SELECT * FROM counts WHERE category = ?1 ORDER BY count DESC"
        )
        .bind(&category_str)
        .fetch_all(&self.pool)
        .await?;
        
        rows.into_iter()
            .map(|r| {
                let category_str: String = r.try_get("category")?;
                Ok(Count {
                    category: serde_json::from_str(&format!("\"{}\"", category_str))?,
                    value: r.try_get("value")?,
                    count: r.try_get("count")?,
                })
            })
            .collect()
    }
    
    async fn delete(&self, category: CountCategory, value: &str) -> anyhow::Result<()> {
        let category_str = category.to_string();
        sqlx::query("DELETE FROM counts WHERE category = ?1 AND value = ?2")
            .bind(&category_str)
            .bind(value)
            .execute(&self.pool)
            .await?;
        
        Ok(())
    }
}
