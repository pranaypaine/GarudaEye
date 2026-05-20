use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

use super::signatures;

/// Result of probing a single port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BannerInfo {
    pub port: u16,
    /// Raw banner bytes decoded as lossy UTF-8
    pub raw_banner: String,
    /// Protocol layer identified (SSH, FTP, SMTP, etc.)
    pub protocol: Option<String>,
    /// Human-readable product name
    pub identified_product: Option<String>,
    /// Version string parsed from the banner
    pub identified_version: Option<String>,
    /// OS inferred from the banner
    pub os_hint: Option<String>,
    /// CVE hints for this product
    pub cve_hints: Vec<String>,
    /// True if this is a plaintext protocol that should be encrypted
    pub is_plaintext_sensitive: bool,
}

/// Ports to probe — common service ports that yield useful banners.
/// Excludes 80/443 (handled by HTTP module).
const PROBE_PORTS: &[u16] = &[
    21,    // FTP
    22,    // SSH
    23,    // Telnet (insecure — flag it)
    25,    // SMTP
    110,   // POP3
    143,   // IMAP
    389,   // LDAP
    443,   // HTTPS (banner)
    465,   // SMTPS
    587,   // SMTP submission
    993,   // IMAPS
    995,   // POP3S
    1433,  // MSSQL
    1521,  // Oracle DB
    3306,  // MySQL/MariaDB
    3389,  // RDP
    5432,  // PostgreSQL
    5672,  // AMQP (RabbitMQ)
    5900,  // VNC
    6379,  // Redis
    8080,  // HTTP alternate
    8443,  // HTTPS alternate
    8888,  // HTTP alternate (Jupyter, etc.)
    9000,  // PHP-FPM / SonarQube
    9200,  // Elasticsearch HTTP
    9300,  // Elasticsearch transport
    11211, // Memcached
    15672, // RabbitMQ management
    27017, // MongoDB
    27018, // MongoDB secondary
    50070, // Hadoop NameNode
];

/// Probe for a service-specific payload to send before reading the banner.
/// Most services send a banner on connect; some need a prompt first.
fn initial_probe(port: u16) -> Option<&'static [u8]> {
    match port {
        3306 => None,      // MySQL sends greeting immediately
        5432 => None,      // PostgreSQL sends auth request immediately
        6379 => Some(b"PING\r\n"),           // Redis
        11211 => Some(b"version\r\n"),       // Memcached
        9200 | 9300 => Some(b"GET / HTTP/1.0\r\n\r\n"), // Elasticsearch
        27017 => None,     // MongoDB sends wire protocol greeting
        3389 => None,      // RDP — don't probe, just check open
        1433 => None,      // MSSQL
        389 => None,       // LDAP
        _ => None,
    }
}

/// Probe all common ports on `host` concurrently and collect banners.
pub async fn probe_common_ports(host: &str) -> Vec<BannerInfo> {
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(20)); // max 20 concurrent
    let host = host.to_string();

    let tasks: Vec<_> = PROBE_PORTS
        .iter()
        .map(|&port| {
            let host = host.clone();
            let sem = semaphore.clone();
            tokio::spawn(async move {
                let _permit = sem.acquire().await.ok()?;
                grab_banner(&host, port).await.ok()
            })
        })
        .collect();

    let mut results = Vec::new();
    for task in tasks {
        if let Ok(Some(Some(info))) = task.await {
            results.push(info);
        }
    }
    results
}

/// Connect to a single port, optionally send a probe, read the banner, classify it.
pub async fn grab_banner(host: &str, port: u16) -> anyhow::Result<Option<BannerInfo>> {
    // Attempt TCP connection with a short timeout
    let stream = tokio::time::timeout(
        Duration::from_secs(3),
        TcpStream::connect(format!("{}:{}", host, port)),
    )
    .await;

    let mut stream = match stream {
        Ok(Ok(s)) => s,
        Ok(Err(_)) | Err(_) => return Ok(None), // port closed or timeout
    };

    // Send probe payload if needed
    if let Some(probe) = initial_probe(port) {
        let _ = tokio::time::timeout(Duration::from_secs(2), stream.write_all(probe)).await;
    }

    // Read banner — wait up to 2 seconds for data
    let mut buf = vec![0u8; 2048];
    let n = match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {
            // Port is open but sent nothing — still record the open port
            return Ok(Some(BannerInfo {
                port,
                raw_banner: String::new(),
                protocol: classify_protocol_by_port(port),
                identified_product: None,
                identified_version: None,
                os_hint: None,
                cve_hints: vec![],
                is_plaintext_sensitive: is_plaintext_sensitive(port),
            }));
        }
        Ok(Ok(n)) => n,
    };

    let _ = stream.shutdown().await;

    let raw = String::from_utf8_lossy(&buf[..n]).into_owned();
    let lower = raw.to_lowercase();

    // Match against all banner signatures
    let (product, os_hint, cve_hints, protocol, version) = classify_banner(&raw, &lower, port);

    let info = BannerInfo {
        port,
        raw_banner: raw.chars().take(512).collect(), // cap stored banner at 512 chars
        protocol,
        identified_product: product,
        identified_version: version,
        os_hint,
        cve_hints: cve_hints.iter().map(|s| s.to_string()).collect(),
        is_plaintext_sensitive: is_plaintext_sensitive(port),
    };

    debug!(
        host = host,
        port = port,
        product = ?info.identified_product,
        "Banner captured"
    );

    Ok(Some(info))
}

// ── Classification helpers ────────────────────────────────────────────────────

fn classify_banner(
    raw: &str,
    lower: &str,
    port: u16,
) -> (
    Option<String>,              // product
    Option<String>,              // os_hint
    &'static [&'static str],     // cve_hints
    Option<String>,              // protocol
    Option<String>,              // version
) {
    if let Some((product, os, cves)) = signatures::match_banner(lower, signatures::BANNER_SIGS) {
        let version = extract_version(raw, product);
        let protocol = infer_protocol_from_product(product)
            .or_else(|| classify_protocol_by_port(port));
        return (
            Some(product.to_string()),
            os.map(String::from),
            cves,
            protocol,
            version,
        );
    }

    // Fallback: classify by port if banner didn't match
    (None, None, &[], classify_protocol_by_port(port), None)
}

fn extract_version(raw: &str, product: &str) -> Option<String> {
    // Try to find a version number (digits.digits) near the product name
    let lower_raw = raw.to_lowercase();
    let lower_product = product.to_lowercase();

    // Find position of product mention
    let pos = lower_raw.find(lower_product.split_whitespace().next()?)?;
    let after = &raw[pos..];

    // Look for a version-like token: word starting with digit(s) after whitespace or '_' or '/'
    for token in after.split_whitespace().chain(after.split('/')) {
        let t = token.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.');
        if t.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) && t.contains('.') {
            let clean: String = t
                .chars()
                .take_while(|&c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
                .collect();
            if !clean.is_empty() {
                return Some(clean);
            }
        }
    }
    None
}

fn infer_protocol_from_product(product: &str) -> Option<String> {
    let lower = product.to_lowercase();
    if lower.contains("ssh") { return Some("SSH".to_string()); }
    if lower.contains("ftp") { return Some("FTP".to_string()); }
    if lower.contains("smtp") { return Some("SMTP".to_string()); }
    if lower.contains("imap") { return Some("IMAP".to_string()); }
    if lower.contains("pop3") { return Some("POP3".to_string()); }
    if lower.contains("redis") { return Some("Redis".to_string()); }
    if lower.contains("mysql") || lower.contains("mariadb") { return Some("MySQL".to_string()); }
    if lower.contains("postgresql") { return Some("PostgreSQL".to_string()); }
    if lower.contains("mongodb") { return Some("MongoDB".to_string()); }
    if lower.contains("vnc") || lower.contains("rfb") { return Some("VNC".to_string()); }
    if lower.contains("memcached") { return Some("Memcached".to_string()); }
    if lower.contains("elasticsearch") { return Some("Elasticsearch".to_string()); }
    if lower.contains("amqp") || lower.contains("rabbitmq") { return Some("AMQP".to_string()); }
    if lower.contains("telnet") { return Some("Telnet".to_string()); }
    None
}

fn classify_protocol_by_port(port: u16) -> Option<String> {
    Some(match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 | 587 => "SMTP",
        110 => "POP3",
        143 => "IMAP",
        389 => "LDAP",
        443 | 8443 => "HTTPS",
        465 => "SMTPS",
        993 => "IMAPS",
        995 => "POP3S",
        1433 => "MSSQL",
        1521 => "OracleDB",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        5672 => "AMQP",
        5900 => "VNC",
        6379 => "Redis",
        8080 | 8888 | 9000 => "HTTP",
        9200 | 9300 => "Elasticsearch",
        11211 => "Memcached",
        15672 => "RabbitMQ-Management",
        27017 | 27018 => "MongoDB",
        50070 => "Hadoop-HDFS",
        _ => return None,
    }
    .to_string())
}

/// Ports that transmit credentials in plaintext — flag as a security issue.
fn is_plaintext_sensitive(port: u16) -> bool {
    matches!(port, 21 | 23 | 25 | 110 | 143 | 389 | 8080 | 8888)
}
