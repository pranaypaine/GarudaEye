use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use tracing::debug;

use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};

/// ASN ownership information for an IP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsnInfo {
    pub asn: u32,
    pub asn_string: String,     // "AS15169"
    pub prefix: String,          // "8.8.8.0/24"
    pub country: String,         // "US"
    pub registry: String,        // "arin" | "ripe" | "apnic" | "lacnic" | "afrinic"
    pub allocation_date: Option<String>,
    /// Organisation name (second Team Cymru query)
    pub org_name: Option<String>,
    /// True if this ASN belongs to a well-known cloud/hosting provider
    pub is_hosting: bool,
    /// True if this ASN belongs to a well-known CDN
    pub is_cdn: bool,
}

/// Look up the ASN for an IP using Team Cymru's free DNS-based whois service.
///
/// Protocol:
///   IPv4 `1.2.3.4` → TXT query `4.3.2.1.origin.asn.cymru.com`
///   IPv6            → TXT query `<reversed-nibbles>.origin6.asn.cymru.com`
///   Response:        `"15169 | 8.8.8.0/24 | US | arin | 2000-03-30"`
///
///   Then: `AS15169.asn.cymru.com` → `"15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"`
///
/// This is a free public service — no API key, no registration.
pub async fn lookup(ip: &str) -> anyhow::Result<AsnInfo> {
    let addr: IpAddr = ip.parse().map_err(|_| anyhow::anyhow!("Invalid IP: {}", ip))?;

    let query_name = build_cymru_query(&addr);

    let resolver = build_resolver();

    // First query: origin lookup
    let txt = resolver
        .txt_lookup(query_name.as_str())
        .await
        .map_err(|e| anyhow::anyhow!("ASN lookup failed for {}: {}", ip, e))?;

    let record = txt
        .iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No ASN TXT record for {}", ip))?;

    let raw: String = record
        .txt_data()
        .iter()
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join("");

    let mut info = parse_origin_record(&raw)?;

    // Second query: org name lookup (AS{n}.asn.cymru.com)
    let asn_query = format!("AS{}.asn.cymru.com.", info.asn);
    if let Ok(txt2) = resolver.txt_lookup(asn_query.as_str()).await {
        if let Some(record2) = txt2.iter().next() {
            let raw2: String = record2
                .txt_data()
                .iter()
                .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
                .collect::<Vec<_>>()
                .join("");
            info.org_name = parse_org_name(&raw2);
        }
    }

    // Tag well-known hosting / CDN ASNs
    let asn_str = info.asn_string.as_str();
    info.is_hosting = is_hosting_asn(info.asn);
    info.is_cdn = is_cdn_asn(info.asn);

    debug!(
        ip = ip,
        asn = asn_str,
        org = ?info.org_name,
        "ASN lookup complete"
    );

    Ok(info)
}

// ── Parsing helpers ───────────────────────────────────────────────────────────

/// `"15169 | 8.8.8.0/24 | US | arin | 2000-03-30"`
fn parse_origin_record(raw: &str) -> anyhow::Result<AsnInfo> {
    let parts: Vec<&str> = raw.splitn(5, '|').map(str::trim).collect();
    if parts.len() < 4 {
        return Err(anyhow::anyhow!("Unexpected ASN record format: {}", raw));
    }

    let asn: u32 = parts[0]
        .split_whitespace()
        .next()
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);

    Ok(AsnInfo {
        asn,
        asn_string: format!("AS{}", asn),
        prefix: parts[1].to_string(),
        country: parts[2].to_string(),
        registry: parts[3].to_string(),
        allocation_date: parts.get(4).map(|s| s.to_string()),
        org_name: None,
        is_hosting: false,
        is_cdn: false,
    })
}

/// `"15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"`
fn parse_org_name(raw: &str) -> Option<String> {
    let parts: Vec<&str> = raw.splitn(5, '|').map(str::trim).collect();
    parts.get(4).map(|s| s.to_string())
}

fn build_cymru_query(addr: &IpAddr) -> String {
    match addr {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // Reverse the octets: 1.2.3.4 → 4.3.2.1.origin.asn.cymru.com
            format!(
                "{}.{}.{}.{}.origin.asn.cymru.com.",
                octets[3], octets[2], octets[1], octets[0]
            )
        }
        IpAddr::V6(v6) => {
            // Expand IPv6 to full nibble form, reverse, append origin6.asn.cymru.com
            let segments = v6.segments();
            let nibbles: String = segments
                .iter()
                .rev()
                .flat_map(|seg| {
                    format!("{:04x}", seg)
                        .chars()
                        .rev()
                        .collect::<Vec<_>>()
                })
                .map(|c| format!("{}.", c))
                .collect();
            format!("{}origin6.asn.cymru.com.", nibbles)
        }
    }
}

fn build_resolver() -> TokioAsyncResolver {
    let mut opts = ResolverOpts::default();
    opts.timeout = std::time::Duration::from_secs(5);
    opts.attempts = 2;
    TokioAsyncResolver::tokio(ResolverConfig::default(), opts)
}

// ── Well-known ASN classification ─────────────────────────────────────────────
// These are based on publicly known ASN assignments. Kept small and curated.

fn is_hosting_asn(asn: u32) -> bool {
    matches!(
        asn,
        // AWS
        16509 | 14618 | 38895 |
        // GCP
        15169 | 396982 |
        // Azure
        8075 | 8068 | 8069 |
        // Alibaba Cloud
        45102 | 37963 |
        // OVH
        16276 |
        // Hetzner
        24940 |
        // DigitalOcean
        14061 | 397627 |
        // Linode
        63949 |
        // Vultr
        20473 |
        // Scaleway
        12876 |
        // Oracle Cloud
        31898 | 31898
    )
}

fn is_cdn_asn(asn: u32) -> bool {
    matches!(
        asn,
        // Cloudflare
        13335 |
        // Fastly
        54113 |
        // Akamai
        20940 | 16625 |
        // Amazon CloudFront
        16509 |
        // Imperva / Incapsula
        19551 |
        // Sucuri
        30148 |
        // Limelight
        22822
    )
}
