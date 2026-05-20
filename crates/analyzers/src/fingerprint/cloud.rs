use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;
use tracing::{debug, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudInfo {
    pub provider: String,
    pub region: Option<String>,
    pub service: Option<String>,
    pub network_border_group: Option<String>,
}

/// In-memory index of cloud provider IP prefixes, loaded once at startup.
pub struct CloudRanges {
    entries: Vec<CloudEntry>,
}

struct CloudEntry {
    net: IpNet,
    provider: &'static str,
    region: Option<String>,
    service: Option<String>,
    network_border_group: Option<String>,
}

// ── AWS JSON shapes ───────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct AwsRangesFile {
    prefixes: Vec<AwsPrefix>,
    #[serde(default)]
    ipv6_prefixes: Vec<AwsIpv6Prefix>,
}

#[derive(serde::Deserialize)]
struct AwsPrefix {
    ip_prefix: String,
    region: String,
    service: String,
    network_border_group: String,
}

#[derive(serde::Deserialize)]
struct AwsIpv6Prefix {
    ipv6_prefix: String,
    region: String,
    service: String,
    network_border_group: String,
}

// ── GCP JSON shapes ───────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct GcpRangesFile {
    prefixes: Vec<GcpPrefix>,
}

#[derive(serde::Deserialize)]
struct GcpPrefix {
    #[serde(rename = "ipv4Prefix")]
    ipv4_prefix: Option<String>,
    #[serde(rename = "ipv6Prefix")]
    ipv6_prefix: Option<String>,
    #[serde(rename = "scope")]
    scope: Option<String>,
    service: Option<String>,
}

impl CloudRanges {
    /// Download and parse all cloud provider IP ranges.
    /// On failure for any provider, logs a warning and continues with partial data.
    pub async fn load() -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .expect("HTTP client build failed");

        let mut entries: Vec<CloudEntry> = Vec::new();

        // AWS
        match fetch_aws(&client).await {
            Ok(aws_entries) => {
                let count = aws_entries.len();
                entries.extend(aws_entries);
                debug!("Loaded {} AWS IP ranges", count);
            }
            Err(e) => warn!("Failed to load AWS IP ranges: {}", e),
        }

        // GCP
        match fetch_gcp(&client).await {
            Ok(gcp_entries) => {
                let count = gcp_entries.len();
                entries.extend(gcp_entries);
                debug!("Loaded {} GCP IP ranges", count);
            }
            Err(e) => warn!("Failed to load GCP IP ranges: {}", e),
        }

        // Cloudflare
        match fetch_cloudflare(&client).await {
            Ok(cf_entries) => {
                let count = cf_entries.len();
                entries.extend(cf_entries);
                debug!("Loaded {} Cloudflare IP ranges", count);
            }
            Err(e) => warn!("Failed to load Cloudflare IP ranges: {}", e),
        }

        // Fastly
        match fetch_fastly(&client).await {
            Ok(fastly_entries) => {
                let count = fastly_entries.len();
                entries.extend(fastly_entries);
                debug!("Loaded {} Fastly IP ranges", count);
            }
            Err(e) => warn!("Failed to load Fastly IP ranges: {}", e),
        }

        Self { entries }
    }

    /// Look up a single IP address against all known cloud ranges.
    /// Returns the most specific match (smallest prefix).
    pub fn lookup(&self, ip_str: &str) -> Option<CloudInfo> {
        let ip: IpAddr = ip_str.parse().ok()?;

        // Find all matching entries, then pick the one with the longest prefix (most specific)
        let mut best: Option<(&CloudEntry, u8)> = None;
        for entry in &self.entries {
            if entry.net.contains(&ip) {
                let prefix_len = match entry.net {
                    IpNet::V4(ref n) => n.prefix_len(),
                    IpNet::V6(ref n) => n.prefix_len(),
                };
                if best.map(|(_, l)| prefix_len > l).unwrap_or(true) {
                    best = Some((entry, prefix_len));
                }
            }
        }

        best.map(|(e, _)| CloudInfo {
            provider: e.provider.to_string(),
            region: e.region.clone(),
            service: e.service.clone(),
            network_border_group: e.network_border_group.clone(),
        })
    }
}

// ── Fetch helpers ─────────────────────────────────────────────────────────────

async fn fetch_aws(client: &reqwest::Client) -> anyhow::Result<Vec<CloudEntry>> {
    let body = client
        .get("https://ip-ranges.amazonaws.com/ip-ranges.json")
        .send()
        .await?
        .text()
        .await?;

    let file: AwsRangesFile = serde_json::from_str(&body)?;
    let mut entries = Vec::with_capacity(file.prefixes.len() + file.ipv6_prefixes.len());

    for p in file.prefixes {
        if let Ok(net) = IpNet::from_str(&p.ip_prefix) {
            entries.push(CloudEntry {
                net,
                provider: "AWS",
                region: Some(p.region),
                service: Some(p.service),
                network_border_group: Some(p.network_border_group),
            });
        }
    }
    for p in file.ipv6_prefixes {
        if let Ok(net) = IpNet::from_str(&p.ipv6_prefix) {
            entries.push(CloudEntry {
                net,
                provider: "AWS",
                region: Some(p.region),
                service: Some(p.service),
                network_border_group: Some(p.network_border_group),
            });
        }
    }

    Ok(entries)
}

async fn fetch_gcp(client: &reqwest::Client) -> anyhow::Result<Vec<CloudEntry>> {
    let body = client
        .get("https://www.gstatic.com/ipranges/cloud.json")
        .send()
        .await?
        .text()
        .await?;

    let file: GcpRangesFile = serde_json::from_str(&body)?;
    let mut entries = Vec::with_capacity(file.prefixes.len());

    for p in file.prefixes {
        let cidr = p.ipv4_prefix.or(p.ipv6_prefix);
        if let Some(cidr) = cidr {
            if let Ok(net) = IpNet::from_str(&cidr) {
                entries.push(CloudEntry {
                    net,
                    provider: "GCP",
                    region: p.scope,
                    service: p.service,
                    network_border_group: None,
                });
            }
        }
    }

    Ok(entries)
}

async fn fetch_cloudflare(client: &reqwest::Client) -> anyhow::Result<Vec<CloudEntry>> {
    let mut entries = Vec::new();

    for url in &[
        "https://www.cloudflare.com/ips-v4",
        "https://www.cloudflare.com/ips-v6",
    ] {
        let body = client.get(*url).send().await?.text().await?;
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Ok(net) = IpNet::from_str(line) {
                entries.push(CloudEntry {
                    net,
                    provider: "Cloudflare",
                    region: None,
                    service: Some("Cloudflare CDN/Proxy".to_string()),
                    network_border_group: None,
                });
            }
        }
    }

    Ok(entries)
}

async fn fetch_fastly(client: &reqwest::Client) -> anyhow::Result<Vec<CloudEntry>> {
    #[derive(serde::Deserialize)]
    struct FastlyResponse {
        addresses: Vec<String>,
        ipv6_addresses: Vec<String>,
    }

    let body = client
        .get("https://api.fastly.com/public-ip-list")
        .send()
        .await?
        .text()
        .await?;

    let resp: FastlyResponse = serde_json::from_str(&body)?;
    let mut entries = Vec::new();

    for cidr in resp.addresses.iter().chain(resp.ipv6_addresses.iter()) {
        if let Ok(net) = IpNet::from_str(cidr) {
            entries.push(CloudEntry {
                net,
                provider: "Fastly",
                region: None,
                service: Some("Fastly CDN".to_string()),
                network_border_group: None,
            });
        }
    }

    Ok(entries)
}
