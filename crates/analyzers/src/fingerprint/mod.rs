pub mod asn;
pub mod banner;
pub mod cloud;
pub mod dns;
pub mod http;
pub mod signatures;
pub mod tls;

pub use asn::AsnInfo;
pub use banner::BannerInfo;
pub use cloud::{CloudInfo, CloudRanges};
pub use dns::DnsInfo;
pub use http::HttpInfo;
pub use tls::TlsInfo;

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn};

// ── Fingerprint result ────────────────────────────────────────────────────────

/// Complete fingerprint for a single IP address or domain.
/// Every field is optional — partial results are valid when some probes fail.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Fingerprint {
    pub target: String,

    /// DNS records (PTR for IPs, full enumeration for domains)
    pub dns: Option<DnsInfo>,
    /// TLS certificate analysis (port 443)
    pub tls: Option<TlsInfo>,
    /// HTTP response analysis (port 80)
    pub http: Option<HttpInfo>,
    /// HTTPS response analysis (port 443)
    pub https: Option<HttpInfo>,
    /// TCP banner results for all probed ports
    pub banners: Vec<BannerInfo>,
    /// Cloud provider match from IP range databases
    pub cloud: Option<CloudInfo>,
    /// ASN ownership (Team Cymru DNS-based)
    pub asn: Option<AsnInfo>,

    // ── Aggregated findings ───────────────────────────────────────────────

    /// Best guess at the operating system
    pub os_guess: Option<String>,
    /// Deduplicated list of identified products/technologies
    pub detected_technologies: Vec<String>,
    /// Security warnings collected from all modules
    pub security_warnings: Vec<String>,
    /// CVE hints collected from signature matches and TLS analysis
    pub cve_hints: Vec<String>,
    /// Open ports that were found to be listening
    pub open_ports: Vec<u16>,
    /// Risk score: 0 (no issues) to 100 (critical exposure)
    pub risk_score: u8,
}

// ── Fingerprint analyser ──────────────────────────────────────────────────────

pub struct FingerprintAnalyzer {
    cloud_ranges: Arc<CloudRanges>,
    http_client: reqwest::Client,
}

impl FingerprintAnalyzer {
    /// Initialise the analyser. Downloads cloud IP range files at startup.
    pub async fn new() -> Self {
        info!("Loading cloud IP ranges for fingerprinting...");
        let cloud_ranges = Arc::new(CloudRanges::load().await);

        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(12))
            .danger_accept_invalid_certs(true)
            .user_agent("Mozilla/5.0 (compatible; GarudaEye/0.1; +https://github.com/yourusername/GarudaEye)")
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .expect("HTTP client build should not fail");

        Self { cloud_ranges, http_client }
    }

    /// Full fingerprint for a raw IP address.
    pub async fn fingerprint_ip(&self, ip: &str) -> Fingerprint {
        info!(ip = ip, "Starting IP fingerprint");

        // DNS (PTR only for IPs)
        let dns_fut = dns::lookup_ptr(ip);
        // TLS cert on port 443 (SNI = IP — most servers accept this)
        let tls_fut = tls::grab_cert(ip, ip, 443);
        // HTTP probes
        let http_fut = http::probe(&self.http_client, ip, 80, false);
        let https_fut = http::probe(&self.http_client, ip, 443, true);
        // Cloud + ASN
        let cloud_result = self.cloud_ranges.lookup(ip);
        let asn_fut = asn::lookup(ip);

        // Run all network probes concurrently
        let (dns_r, tls_r, http_r, https_r, asn_r) =
            tokio::join!(dns_fut, tls_fut, http_fut, https_fut, asn_fut);

        // Banner grab all common ports
        let banners = banner::probe_common_ports(ip).await;

        let mut fp = Fingerprint {
            target: ip.to_string(),
            ..Default::default()
        };

        if let Ok(d) = dns_r    { fp.dns   = Some(d); }
        if let Ok(t) = tls_r    { fp.tls   = Some(t); }
        if let Ok(Some(h)) = http_r  { fp.http  = Some(h); }
        if let Ok(Some(h)) = https_r { fp.https = Some(h); }
        if let Ok(a) = asn_r    { fp.asn   = Some(a); }
        fp.cloud   = cloud_result;
        fp.banners = banners;

        fp.aggregate();

        info!(
            ip = ip,
            os = ?fp.os_guess,
            techs = fp.detected_technologies.len(),
            ports = fp.open_ports.len(),
            risk = fp.risk_score,
            "IP fingerprint complete"
        );

        fp
    }

    /// Full fingerprint for a domain name.
    pub async fn fingerprint_domain(&self, domain: &str) -> Fingerprint {
        info!(domain = domain, "Starting domain fingerprint");

        // Full DNS enumeration for domains
        let dns_fut = dns::lookup_domain(domain);
        let tls_fut = tls::grab_cert(domain, domain, 443);
        let http_fut = http::probe(&self.http_client, domain, 80, false);
        let https_fut = http::probe(&self.http_client, domain, 443, true);

        let (dns_r, tls_r, http_r, https_r) =
            tokio::join!(dns_fut, tls_fut, http_fut, https_fut);

        let mut fp = Fingerprint {
            target: domain.to_string(),
            ..Default::default()
        };

        if let Ok(d) = tls_r    { fp.tls   = Some(d); }
        if let Ok(Some(h)) = http_r  { fp.http  = Some(h); }
        if let Ok(Some(h)) = https_r { fp.https = Some(h); }

        if let Ok(dns) = dns_r {
            // Use first resolved IP for cloud/ASN/banner lookup
            if let Some(first_ip) = dns.a_records.first().cloned() {
                let (cloud_r, asn_r) = tokio::join!(
                    async { self.cloud_ranges.lookup(&first_ip) },
                    asn::lookup(&first_ip),
                );
                let banners = banner::probe_common_ports(&first_ip).await;

                fp.cloud   = cloud_r;
                if let Ok(a) = asn_r { fp.asn = Some(a); }
                fp.banners = banners;
            }
            fp.dns = Some(dns);
        }

        fp.aggregate();

        info!(
            domain = domain,
            os = ?fp.os_guess,
            techs = fp.detected_technologies.len(),
            risk = fp.risk_score,
            "Domain fingerprint complete"
        );

        fp
    }
}

// ── Aggregation logic ─────────────────────────────────────────────────────────

impl Fingerprint {
    fn aggregate(&mut self) {
        let mut techs: Vec<String> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();
        let mut cves: Vec<String> = Vec::new();
        let mut ports: Vec<u16> = Vec::new();

        // ── Technologies from HTTP/HTTPS ──────────────────────────────────
        for h in self.https.iter().chain(self.http.iter()) {
            techs.extend_from_slice(&h.technologies);
            warnings.extend_from_slice(&h.security_issues);
        }

        // ── Findings from TLS ─────────────────────────────────────────────
        if let Some(ref t) = self.tls {
            cves.extend_from_slice(&t.known_vuln_hints);
            warnings.extend_from_slice(&t.warnings);
        }

        // ── Findings from banners ─────────────────────────────────────────
        for b in &self.banners {
            ports.push(b.port);
            if let Some(ref p) = b.identified_product {
                techs.push(p.clone());
            }
            cves.extend(b.cve_hints.iter().cloned());

            // OS hint: prefer SSH banner (most reliable)
            if self.os_guess.is_none() {
                if let Some(ref os) = b.os_hint {
                    self.os_guess = Some(os.clone());
                }
            }

            // Flag insecure protocols
            if b.is_plaintext_sensitive && !b.raw_banner.is_empty() {
                warnings.push(format!(
                    "Plaintext sensitive protocol on port {} ({})",
                    b.port,
                    b.protocol.as_deref().unwrap_or("unknown")
                ));
            }
        }

        // ── Cloud context ─────────────────────────────────────────────────
        if let Some(ref c) = self.cloud {
            let cloud_tech = match c.service.as_deref() {
                Some(s) => format!("{} / {}", c.provider, s),
                None => c.provider.clone(),
            };
            techs.push(cloud_tech);
        }

        // ── ASN context ───────────────────────────────────────────────────
        if let Some(ref a) = self.asn {
            if a.is_cdn {
                if let Some(ref org) = a.org_name {
                    techs.push(format!("CDN: {}", org));
                }
            }
            if a.is_hosting {
                if let Some(ref org) = a.org_name {
                    techs.push(format!("Hosting: {}", org));
                }
            }
        }

        // ── DNS-derived context ───────────────────────────────────────────
        if let Some(ref d) = self.dns {
            if !d.has_spf {
                warnings.push("No SPF record — email spoofing possible".to_string());
            }
            if !d.has_dmarc {
                warnings.push("No DMARC record — email spoofing possible".to_string());
            }
            if let Some(ref provider) = d.dns_provider {
                techs.push(format!("DNS: {}", provider));
            }
            if let Some(ref provider) = d.mail_provider {
                techs.push(format!("Mail: {}", provider));
            }
            if let Some(ref cloud) = d.cloud_hint {
                if !techs.iter().any(|t| t.contains(cloud.as_str())) {
                    techs.push(cloud.clone());
                }
            }
        }

        // ── Dedup ──────────────────────────────────────────────────────────
        techs.sort();
        techs.dedup();
        warnings.sort();
        warnings.dedup();
        cves.sort();
        cves.dedup();
        ports.sort();
        ports.dedup();

        self.detected_technologies = techs;
        self.security_warnings = warnings;
        self.cve_hints = cves;
        self.open_ports = ports;

        // ── Risk scoring ───────────────────────────────────────────────────
        self.risk_score = self.compute_risk();
    }

    fn compute_risk(&self) -> u8 {
        let mut score: u32 = 0;

        // TLS issues
        if self.tls.as_ref().map(|t| t.self_signed).unwrap_or(false) { score += 15; }
        if self.tls.as_ref().map(|t| t.expired).unwrap_or(false)    { score += 25; }
        if self.tls.as_ref()
            .and_then(|t| t.days_until_expiry)
            .map(|d| d < 14 && d >= 0)
            .unwrap_or(false)                                        { score += 10; }

        // Insecure protocols open
        let has_telnet = self.banners.iter().any(|b| b.port == 23 && !b.raw_banner.is_empty());
        let has_ftp    = self.banners.iter().any(|b| b.port == 21 && !b.raw_banner.is_empty());
        if has_telnet  { score += 25; }
        if has_ftp     { score += 15; }

        // Exposed databases (should not be internet-facing)
        let exposed_db = self.banners.iter().any(|b| {
            matches!(b.port, 3306 | 5432 | 27017 | 6379 | 11211 | 9200)
                && !b.raw_banner.is_empty()
        });
        if exposed_db { score += 30; }

        // Missing security headers
        let no_hsts = !self.https.as_ref().map(|h| h.hsts).unwrap_or(false);
        let no_csp  = !self.https.as_ref().map(|h| h.csp).unwrap_or(false);
        if no_hsts  { score += 5; }
        if no_csp   { score += 5; }

        // CVE hints
        if !self.cve_hints.is_empty() { score += 20; }

        // Version disclosure
        let version_disclosure = self
            .https.as_ref().or(self.http.as_ref())
            .and_then(|h| h.server.as_ref())
            .map(|s| s.contains('/'))
            .unwrap_or(false);
        if version_disclosure { score += 5; }

        (score as u8).min(100)
    }
}
