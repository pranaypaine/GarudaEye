use serde::{Deserialize, Serialize};
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use std::net::IpAddr;
use tracing::debug;

use super::signatures;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsInfo {
    /// IPv4 addresses (A records)
    pub a_records: Vec<String>,
    /// IPv6 addresses (AAAA records)
    pub aaaa_records: Vec<String>,
    /// CNAME target (if domain is an alias)
    pub cname: Option<String>,
    /// MX (mail exchange) records
    pub mx_records: Vec<MxRecord>,
    /// NS (name server) records
    pub ns_records: Vec<String>,
    /// Raw TXT records
    pub txt_records: Vec<String>,
    /// PTR (reverse DNS) — populated for IP targets
    pub ptr: Option<String>,

    // Email security posture
    pub has_spf: bool,
    pub spf_record: Option<String>,
    pub has_dmarc: bool,
    pub dmarc_record: Option<String>,
    pub has_dkim_hint: bool, // heuristic: selector._domainkey TXT present

    // Infrastructure inferences
    pub dns_provider: Option<String>,
    pub mail_provider: Option<String>,
    /// Cloud hint inferred from PTR or A record patterns
    pub cloud_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MxRecord {
    pub exchange: String,
    pub preference: u16,
}

/// Full DNS enumeration for a domain name.
pub async fn lookup_domain(domain: &str) -> anyhow::Result<DnsInfo> {
    let resolver = build_resolver();
    let mut info = DnsInfo::default();

    // A records
    if let Ok(resp) = resolver.ipv4_lookup(domain).await {
        info.a_records = resp.iter().map(|ip| ip.to_string()).collect();
    }

    // AAAA records
    if let Ok(resp) = resolver.ipv6_lookup(domain).await {
        info.aaaa_records = resp.iter().map(|ip| ip.to_string()).collect();
    }

    // CNAME — check if the lookup had a chain; take the first CNAME
    if let Ok(resp) = resolver.lookup(domain, hickory_resolver::proto::rr::RecordType::CNAME).await {
        let cname = resp
            .iter()
            .next()
            .map(|rdata| rdata.to_string().trim_end_matches('.').to_string());
        if cname.as_deref() != Some(domain) {
            info.cname = cname;
        }
    }

    // MX records
    if let Ok(resp) = resolver.mx_lookup(domain).await {
        for mx in resp.iter() {
            info.mx_records.push(MxRecord {
                exchange: mx.exchange().to_string().trim_end_matches('.').to_string(),
                preference: mx.preference(),
            });
        }
        info.mx_records.sort_by_key(|m| m.preference);
    }

    // NS records
    if let Ok(resp) = resolver.ns_lookup(domain).await {
        info.ns_records = resp
            .iter()
            .map(|ns| ns.0.to_string().trim_end_matches('.').to_string())
            .collect();
    }

    // TXT records — all of them
    if let Ok(resp) = resolver.txt_lookup(domain).await {
        for txt in resp.iter() {
            let value: String = txt
                .txt_data()
                .iter()
                .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
                .collect::<Vec<_>>()
                .join("");
            info.txt_records.push(value);
        }
    }

    // DMARC — query _dmarc.domain
    let dmarc_name = format!("_dmarc.{}", domain);
    if let Ok(resp) = resolver.txt_lookup(dmarc_name.as_str()).await {
        for txt in resp.iter() {
            let value: String = txt
                .txt_data()
                .iter()
                .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
                .collect::<Vec<_>>()
                .join("");
            if value.starts_with("v=DMARC1") {
                info.has_dmarc = true;
                info.dmarc_record = Some(value);
                break;
            }
        }
    }

    // Parse TXT records for SPF and DKIM hints
    for txt in &info.txt_records {
        let lower = txt.to_lowercase();
        if lower.starts_with("v=spf1") {
            info.has_spf = true;
            info.spf_record = Some(txt.clone());
        }
        if lower.contains("v=dkim1") {
            info.has_dkim_hint = true;
        }
    }

    // Infrastructure detection from NS records
    info.dns_provider = signatures::detect_dns_provider(&info.ns_records);

    // Mail provider from MX records
    let mx_exchanges: Vec<String> = info.mx_records.iter().map(|m| m.exchange.clone()).collect();
    info.mail_provider = signatures::detect_mail_provider(&mx_exchanges);

    // Cloud hint from A records and CNAME
    info.cloud_hint = infer_cloud_from_domain(domain, &info);

    debug!(
        domain = domain,
        a = info.a_records.len(),
        mx = info.mx_records.len(),
        ns = info.ns_records.len(),
        "DNS enumeration complete"
    );

    Ok(info)
}

/// Reverse DNS lookup (PTR record) for an IP address.
pub async fn lookup_ptr(ip: &str) -> anyhow::Result<DnsInfo> {
    let resolver = build_resolver();
    let mut info = DnsInfo::default();

    let addr: IpAddr = ip.parse().map_err(|_| anyhow::anyhow!("Invalid IP: {}", ip))?;

    match resolver.reverse_lookup(addr).await {
        Ok(resp) => {
            if let Some(name) = resp.iter().next() {
                let ptr = name.to_string().trim_end_matches('.').to_string();
                info.cloud_hint = Some(infer_cloud_from_ptr(&ptr));
                info.ptr = Some(ptr);
            }
        }
        Err(e) => {
            debug!("PTR lookup failed for {}: {}", ip, e);
        }
    }

    Ok(info)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn build_resolver() -> TokioAsyncResolver {
    let mut opts = ResolverOpts::default();
    opts.timeout = std::time::Duration::from_secs(5);
    opts.attempts = 2;
    TokioAsyncResolver::tokio(ResolverConfig::default(), opts)
}

fn infer_cloud_from_ptr(ptr: &str) -> String {
    let lower = ptr.to_lowercase();
    if lower.contains("amazonaws.com") {
        extract_aws_info_from_ptr(&lower)
    } else if lower.contains("compute.internal") || lower.contains("ec2.internal") {
        "AWS EC2 (private)".to_string()
    } else if lower.contains("googleusercontent.com") || lower.contains("google.internal") {
        "Google Cloud".to_string()
    } else if lower.contains("cloudfront.net") {
        "AWS CloudFront".to_string()
    } else if lower.contains("elb.amazonaws.com") {
        "AWS Elastic Load Balancer".to_string()
    } else if lower.contains("s3.amazonaws.com") {
        "AWS S3".to_string()
    } else if lower.contains("azure") || lower.contains("microsoft.com") {
        "Microsoft Azure".to_string()
    } else if lower.contains("cloudflare") {
        "Cloudflare".to_string()
    } else if lower.contains("fastly") {
        "Fastly CDN".to_string()
    } else if lower.contains("akamai") || lower.contains("akamaitechnologies") {
        "Akamai CDN".to_string()
    } else if lower.contains("digitalocean") {
        "DigitalOcean".to_string()
    } else if lower.contains("linode") || lower.contains("akamai.net") {
        "Linode/Akamai Cloud".to_string()
    } else if lower.contains("vultr") {
        "Vultr".to_string()
    } else if lower.contains("hetzner") {
        "Hetzner Cloud".to_string()
    } else {
        lower
    }
}

fn extract_aws_info_from_ptr(ptr: &str) -> String {
    // ec2-{ip}.compute-1.amazonaws.com  → us-east-1
    // ec2-{ip}.{region}.compute.amazonaws.com
    if let Some(region) = extract_aws_region(ptr) {
        format!("AWS EC2 ({})", region)
    } else if ptr.contains("elb") {
        "AWS ELB".to_string()
    } else if ptr.contains("rds") {
        "AWS RDS".to_string()
    } else {
        "AWS".to_string()
    }
}

fn extract_aws_region(ptr: &str) -> Option<String> {
    // Patterns: compute-1 = us-east-1, {region}.compute = other regions
    if ptr.contains("compute-1.") {
        return Some("us-east-1".to_string());
    }
    // Try to extract from ec2-ip.REGION.compute.amazonaws.com
    let parts: Vec<&str> = ptr.split('.').collect();
    for (i, part) in parts.iter().enumerate() {
        if *part == "compute" && i > 0 {
            return Some(parts[i - 1].to_string());
        }
    }
    None
}

fn infer_cloud_from_domain(domain: &str, info: &DnsInfo) -> Option<String> {
    let lower = domain.to_lowercase();

    // Explicit cloud hosting patterns
    if lower.ends_with(".amazonaws.com") { return Some("AWS".to_string()); }
    if lower.ends_with(".cloudfront.net") { return Some("AWS CloudFront".to_string()); }
    if lower.ends_with(".elb.amazonaws.com") { return Some("AWS ELB".to_string()); }
    if lower.ends_with(".s3.amazonaws.com") || lower.ends_with(".s3-website") {
        return Some("AWS S3".to_string());
    }
    if lower.ends_with(".execute-api.amazonaws.com") { return Some("AWS API Gateway".to_string()); }
    if lower.ends_with(".lambda-url.") { return Some("AWS Lambda URL".to_string()); }
    if lower.ends_with(".azurewebsites.net") { return Some("Azure App Service".to_string()); }
    if lower.ends_with(".azure.com") { return Some("Azure".to_string()); }
    if lower.ends_with(".azurefd.net") { return Some("Azure Front Door".to_string()); }
    if lower.ends_with(".blob.core.windows.net") { return Some("Azure Blob Storage".to_string()); }
    if lower.ends_with(".appspot.com") { return Some("Google App Engine".to_string()); }
    if lower.ends_with(".run.app") { return Some("Google Cloud Run".to_string()); }
    if lower.ends_with(".cloudfunctions.net") { return Some("Google Cloud Functions".to_string()); }
    if lower.ends_with(".storage.googleapis.com") { return Some("Google Cloud Storage".to_string()); }
    if lower.ends_with(".netlify.app") || lower.ends_with(".netlify.com") {
        return Some("Netlify".to_string());
    }
    if lower.ends_with(".vercel.app") { return Some("Vercel".to_string()); }
    if lower.ends_with(".pages.dev") { return Some("Cloudflare Pages".to_string()); }
    if lower.ends_with(".workers.dev") { return Some("Cloudflare Workers".to_string()); }
    if lower.ends_with(".ondigitalocean.app") { return Some("DigitalOcean App Platform".to_string()); }
    if lower.ends_with(".fly.dev") { return Some("Fly.io".to_string()); }
    if lower.ends_with(".render.com") { return Some("Render.com".to_string()); }
    if lower.ends_with(".railway.app") { return Some("Railway".to_string()); }
    if lower.ends_with(".herokussl.com") || lower.ends_with(".herokudns.com") {
        return Some("Heroku".to_string());
    }

    // Infer from NS (Route53 → likely AWS hosted)
    if let Some(ref provider) = info.dns_provider {
        if provider.contains("Route 53") {
            return Some("AWS (Route 53 DNS)".to_string());
        }
    }

    None
}
