use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{info, error, warn, debug};
use garudaeye_core::Asset;
use infra::traits::AssetStore;

pub struct ShodanAnalyzer {
    api_key: String,
    client: Client,
    base_url: String,
}

impl ShodanAnalyzer {
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            client: Client::new(),
            base_url: "https://api.shodan.io".to_string(),
        }
    }
    
    /// Analyze a single IP address using Shodan API
    pub async fn analyze_ip(&self, ip: &str) -> anyhow::Result<ShodanHostInfo> {
        let url = format!("{}/shodan/host/{}?key={}", self.base_url, ip, self.api_key);
        
        debug!("Querying Shodan for IP: {}", ip);
        
        let response = self.client
            .get(&url)
            .send()
            .await?;
            
        if response.status().is_success() {
            let host_info: ShodanHostInfo = response.json().await?;
            info!("Successfully retrieved Shodan data for {}", ip);
            Ok(host_info)
        } else if response.status().as_u16() == 404 {
            warn!("No Shodan data found for IP: {}", ip);
            Err(anyhow::anyhow!("No data found for IP"))
        } else {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            error!("Shodan API error {}: {}", status, error_text);
            Err(anyhow::anyhow!("Shodan API error: {} - {}", status, error_text))
        }
    }
    
    /// Enrich an asset with Shodan data
    pub async fn enrich_asset(
        &self,
        asset: &mut Asset,
        asset_store: &dyn AssetStore,
    ) -> anyhow::Result<()> {
        match self.analyze_ip(&asset.sk).await {
            Ok(host_info) => {
                // Update asset with Shodan data
                asset.ports = Some(host_info.ports.clone());
                asset.country = host_info.country_name.clone();
                asset.city = host_info.city.clone();
                asset.organization = host_info.org.clone();
                asset.isp = host_info.isp.clone();
                asset.asn = host_info.asn.clone();
                asset.vulnerabilities = host_info.vulns.clone();
                asset.last_seen = host_info.last_update.as_ref().and_then(|s| {
                    chrono::DateTime::parse_from_rfc3339(s)
                        .ok()
                        .map(|dt| dt.with_timezone(&chrono::Utc))
                });
                
                // Store full Shodan response as JSON
                asset.shodan_data = Some(serde_json::to_value(&host_info)?);
                
                // Update the asset in storage
                asset_store.update(asset.clone()).await?;
                
                info!("Enriched asset {} with Shodan data: {} ports, {} vulns", 
                    asset.sk,
                    asset.ports.as_ref().map(|p| p.len()).unwrap_or(0),
                    asset.vulnerabilities.as_ref().map(|v| v.len()).unwrap_or(0)
                );
                
                Ok(())
            },
            Err(e) => {
                warn!("Failed to enrich asset {} with Shodan: {}", asset.sk, e);
                Err(e)
            }
        }
    }
    
    /// Resolve a hostname to IP addresses using the local system DNS resolver.
    /// This avoids Shodan's `/dns/resolve` endpoint which requires a paid membership.
    pub async fn resolve_hostname(&self, hostname: &str) -> anyhow::Result<Vec<String>> {
        debug!("Resolving hostname via system DNS: {}", hostname);

        // lookup_host requires a host:port pair; port 0 is a dummy
        let addrs = tokio::net::lookup_host(format!("{}:0", hostname))
            .await
            .map_err(|e| anyhow::anyhow!("DNS lookup failed for {}: {}", hostname, e))?;

        let ips: Vec<String> = addrs
            .filter_map(|addr| {
                let ip = addr.ip();
                // Skip link-local and loopback — not useful for Shodan
                if ip.is_loopback() || ip.is_unspecified() {
                    None
                } else {
                    Some(ip.to_string())
                }
            })
            .collect::<std::collections::HashSet<_>>() // deduplicate
            .into_iter()
            .collect();

        if ips.is_empty() {
            warn!("System DNS returned no usable IPs for {}", hostname);
            return Err(anyhow::anyhow!("No usable IPs resolved for {}", hostname));
        }

        info!("Resolved {} → {:?}", hostname, ips);
        Ok(ips)
    }

    /// Enrich a domain-named asset via Shodan: resolve hostname → query each IP
    pub async fn enrich_domain_asset(
        &self,
        asset: &mut Asset,
        asset_store: &dyn AssetStore,
    ) -> anyhow::Result<()> {
        let hostname = asset.sk.clone();

        let ips = match self.resolve_hostname(&hostname).await {
            Ok(ips) if !ips.is_empty() => ips,
            Ok(_) => {
                warn!("No IPs resolved for hostname: {}", hostname);
                return Err(anyhow::anyhow!("No IPs resolved for {}", hostname));
            }
            Err(e) => {
                warn!("Failed to resolve hostname {}: {}", hostname, e);
                return Err(e);
            }
        };

        // Query Shodan for each resolved IP; use the first successful result
        let mut enriched = false;
        for ip in &ips {
            // Rate limiting: 1 req/s for free tier
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

            match self.analyze_ip(ip).await {
                Ok(host_info) => {
                    // Merge Shodan data onto the domain asset
                    asset.ports = Some(host_info.ports.clone());
                    asset.country = host_info.country_name.clone();
                    asset.city = host_info.city.clone();
                    asset.organization = host_info.org.clone();
                    asset.isp = host_info.isp.clone();
                    asset.asn = host_info.asn.clone();
                    asset.vulnerabilities = host_info.vulns.clone();

                    // Store resolved IPs alongside the full Shodan response
                    asset.shodan_data = Some(serde_json::json!({
                        "resolved_ips": ips,
                        "queried_ip": ip,
                        "host_info": serde_json::to_value(&host_info)?,
                    }));

                    asset_store.update(asset.clone()).await?;

                    info!(
                        "Enriched domain asset {} (resolved to {}) with Shodan data: {} ports, {} vulns",
                        hostname,
                        ip,
                        asset.ports.as_ref().map(|p| p.len()).unwrap_or(0),
                        asset.vulnerabilities.as_ref().map(|v| v.len()).unwrap_or(0),
                    );
                    enriched = true;
                    break; // one successful Shodan result is enough
                }
                Err(e) => {
                    warn!("Shodan lookup failed for {} ({}): {}", hostname, ip, e);
                }
            }
        }

        if enriched {
            Ok(())
        } else {
            Err(anyhow::anyhow!("No Shodan data found for any IP of {}", hostname))
        }
    }

    /// Bulk analyze multiple IPs (respects rate limits)
    pub async fn analyze_batch(
        &self,
        assets: &mut [Asset],
        asset_store: &dyn AssetStore,
    ) -> anyhow::Result<usize> {
        let mut enriched_count = 0;
        
        for asset in assets.iter_mut() {
            // Rate limiting: Shodan free tier allows 1 request/second
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            
            if let Ok(_) = self.enrich_asset(asset, asset_store).await {
                enriched_count += 1;
            }
        }
        
        info!("Enriched {}/{} assets with Shodan data", enriched_count, assets.len());
        Ok(enriched_count)
    }
}

/// Shodan host information response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanHostInfo {
    pub ip_str: String,
    pub ports: Vec<u16>,
    pub country_name: Option<String>,
    pub city: Option<String>,
    pub org: Option<String>,
    pub isp: Option<String>,
    pub asn: Option<String>,
    pub hostnames: Vec<String>,
    pub domains: Vec<String>,
    pub os: Option<String>,
    pub last_update: Option<String>,
    pub vulns: Option<Vec<String>>,
    pub data: Vec<ShodanService>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanService {
    pub port: u16,
    pub transport: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub data: String,
    pub timestamp: String,
}
