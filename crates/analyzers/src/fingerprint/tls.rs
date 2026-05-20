use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tracing::debug;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;

use super::signatures;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsInfo {
    /// Subject Common Name (CN)
    pub subject_cn: Option<String>,
    /// Subject Organisation (O)
    pub subject_org: Option<String>,
    /// Issuer Common Name
    pub issuer_cn: Option<String>,
    /// Issuer Organisation — used to classify cert type
    pub issuer_org: Option<String>,
    /// Issuer classification (Let's Encrypt, DigiCert, etc.)
    pub issuer_type: Option<String>,
    /// DNS SANs
    pub san_dns: Vec<String>,
    /// IP SANs
    pub san_ips: Vec<String>,
    /// Certificate validity start
    pub not_before: Option<chrono::DateTime<chrono::Utc>>,
    /// Certificate validity end
    pub not_after: Option<chrono::DateTime<chrono::Utc>>,
    /// Days until expiry (negative = already expired)
    pub days_until_expiry: Option<i64>,
    /// True if the cert is expired
    pub expired: bool,
    /// True if subject == issuer (no CA signed it)
    pub self_signed: bool,
    /// Public key algorithm and size, e.g. "RSA-2048", "ECDSA-P256"
    pub key_type: Option<String>,
    /// Negotiated TLS protocol version, e.g. "TLSv1.3"
    pub tls_version: Option<String>,
    /// Hex serial number
    pub serial: String,
    /// Signature algorithm OID string
    pub signature_algorithm: String,
    /// Depth of the certificate chain received
    pub chain_depth: usize,
    /// Wildcard certificate flag
    pub is_wildcard: bool,
    /// Security warnings derived purely from cert content
    pub warnings: Vec<String>,
    /// Hints from issuer / TLS version analysis
    pub known_vuln_hints: Vec<String>,
}

/// Connect to host:port, perform a TLS handshake, and analyse the certificate.
/// `sni` is the hostname to put in the SNI extension (usually same as host for domains,
/// the domain name for IPs when you know what name to expect).
pub async fn grab_cert(host: &str, sni: &str, port: u16) -> anyhow::Result<TlsInfo> {
    // Build a client config that accepts ANY certificate — we want to inspect
    // certs that may be expired, self-signed, or have wrong hostnames.
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    // TCP connect with timeout
    let tcp = tokio::time::timeout(
        Duration::from_secs(8),
        tokio::net::TcpStream::connect(format!("{}:{}", host, port)),
    )
    .await
    .map_err(|_| anyhow::anyhow!("TCP connect timeout to {}:{}", host, port))??;

    // TLS handshake with timeout
    let server_name = ServerName::try_from(sni.to_owned())
        .map_err(|e| anyhow::anyhow!("Invalid SNI hostname '{}': {}", sni, e))?;

    let mut tls_stream = tokio::time::timeout(
        Duration::from_secs(8),
        connector.connect(server_name, tcp),
    )
    .await
    .map_err(|_| anyhow::anyhow!("TLS handshake timeout to {}:{}", host, port))??;

    // Flush/close gracefully (we don't need to send data)
    let _ = tls_stream.shutdown().await;

    let (_, client_conn) = tls_stream.get_ref();

    // Extract negotiated TLS version
    let tls_version = client_conn
        .protocol_version()
        .map(|v| format!("{:?}", v).replace("TLSv", "TLS "));

    // Extract certificate chain
    let certs: Vec<CertificateDer<'static>> = client_conn
        .peer_certificates()
        .map(|chain| chain.iter().map(|c| c.clone().into_owned()).collect())
        .unwrap_or_default();

    let chain_depth = certs.len();
    if chain_depth == 0 {
        return Err(anyhow::anyhow!("Server sent no certificates"));
    }

    // Parse the leaf (end-entity) certificate
    let mut info = parse_cert(certs[0].as_ref())?;
    info.tls_version = tls_version.clone();
    info.chain_depth = chain_depth;

    // TLS version security check
    if let Some(ref ver) = tls_version {
        let lower = ver.to_lowercase();
        if lower.contains("1.0") {
            info.warnings.push("TLS 1.0 is deprecated (RFC 8996)".to_string());
            info.known_vuln_hints.push("TLS-1.0-POODLE-BEAST".to_string());
        } else if lower.contains("1.1") {
            info.warnings.push("TLS 1.1 is deprecated (RFC 8996)".to_string());
        }
    }

    debug!(
        host = host,
        port = port,
        cn = ?info.subject_cn,
        san_count = info.san_dns.len(),
        expired = info.expired,
        self_signed = info.self_signed,
        "TLS certificate analysis complete"
    );

    Ok(info)
}

// ── Certificate parser ───────────────────────────────────────────────────────

fn parse_cert(der: &[u8]) -> anyhow::Result<TlsInfo> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| anyhow::anyhow!("Failed to parse certificate: {:?}", e))?;

    let mut info = TlsInfo::default();

    // Subject fields
    info.subject_cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|av| av.as_str().ok())
        .map(String::from);

    info.subject_org = cert
        .subject()
        .iter_organization()
        .next()
        .and_then(|av| av.as_str().ok())
        .map(String::from);

    // Issuer fields
    info.issuer_cn = cert
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|av| av.as_str().ok())
        .map(String::from);

    info.issuer_org = cert
        .issuer()
        .iter_organization()
        .next()
        .and_then(|av| av.as_str().ok())
        .map(String::from);

    // Classify issuer
    let issuer_lower = format!(
        "{} {}",
        info.issuer_cn.as_deref().unwrap_or(""),
        info.issuer_org.as_deref().unwrap_or("")
    )
    .to_lowercase();
    info.issuer_type = signatures::TLS_ISSUER_SIGS
        .iter()
        .find(|(pat, _)| issuer_lower.contains(pat))
        .map(|(_, name)| name.to_string());

    // Self-signed check
    info.self_signed = cert.subject() == cert.issuer();
    if info.self_signed {
        info.warnings.push("Self-signed certificate".to_string());
        info.issuer_type = Some("Self-signed".to_string());
    }

    // Serial number
    info.serial = cert.raw_serial_as_string();

    // Signature algorithm
    info.signature_algorithm = cert.signature_algorithm.algorithm.to_string();

    // Validity window
    let not_before_ts = cert.validity().not_before.timestamp();
    let not_after_ts = cert.validity().not_after.timestamp();

    info.not_before = chrono::DateTime::from_timestamp(not_before_ts, 0);
    info.not_after = chrono::DateTime::from_timestamp(not_after_ts, 0);

    let now = chrono::Utc::now();
    if let Some(expiry) = info.not_after {
        let diff = expiry.signed_duration_since(now);
        let days = diff.num_days();
        info.days_until_expiry = Some(days);
        info.expired = days < 0;
        if info.expired {
            info.warnings.push(format!("Certificate expired {} days ago", -days));
        } else if days < 30 {
            info.warnings.push(format!("Certificate expires in {} days", days));
        }
    }

    // Public key type
    let pk = cert.public_key();
    let key_oid = pk.algorithm.algorithm.to_string();
    info.key_type = Some(match key_oid.as_str() {
        "1.2.840.113549.1.1.1" => {
            // RSA — attempt to get bit size from key data length
            let bits = estimate_rsa_bits(pk.subject_public_key.data.as_ref());
            if bits > 0 {
                format!("RSA-{}", bits)
            } else {
                "RSA".to_string()
            }
        }
        "1.2.840.10045.2.1" => {
            // EC — determine curve from parameters
            let curve = extract_ec_curve(&pk.algorithm);
            format!("ECDSA-{}", curve)
        }
        "1.3.101.112" => "Ed25519".to_string(),
        "1.3.101.113" => "Ed448".to_string(),
        "1.2.840.10040.4.1" => "DSA (legacy)".to_string(),
        other => format!("Unknown({})", other),
    });

    // Weak key warning
    if let Some(ref kt) = info.key_type {
        if kt.starts_with("RSA-") {
            let bits: u32 = kt
                .trim_start_matches("RSA-")
                .parse()
                .unwrap_or(0);
            if bits > 0 && bits < 2048 {
                info.warnings.push(format!("Weak RSA key: {} bits (minimum 2048 recommended)", bits));
                info.known_vuln_hints.push("WEAK-RSA-KEY".to_string());
            }
        }
        if kt.contains("DSA") {
            info.warnings.push("DSA keys are deprecated".to_string());
        }
    }

    // SAN extension
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for gn in &san.general_names {
                match gn {
                    GeneralName::DNSName(name) => {
                        let s = name.to_string();
                        if s.starts_with("*.") {
                            info.is_wildcard = true;
                        }
                        info.san_dns.push(s);
                    }
                    GeneralName::IPAddress(bytes) => {
                        let ip_str = bytes_to_ip_string(bytes);
                        if let Some(s) = ip_str {
                            info.san_ips.push(s);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(info)
}

// ── Utilities ────────────────────────────────────────────────────────────────

fn estimate_rsa_bits(spki_data: &[u8]) -> u32 {
    // The DER-encoded RSA public key is a SEQUENCE of (modulus INTEGER, exponent INTEGER)
    // The modulus length in bytes ≈ key size in bits / 8
    // We do a rough estimate by looking at the DER header of the outer SEQUENCE
    // then finding the first INTEGER's length
    if spki_data.len() < 6 {
        return 0;
    }
    // Skip outer SEQUENCE tag+length, inner BIT STRING wrapper
    // A rough heuristic: find 0x02 (INTEGER tag) and read its length
    for i in 0..spki_data.len().saturating_sub(4) {
        if spki_data[i] == 0x02 {
            let len = if spki_data[i + 1] & 0x80 == 0 {
                spki_data[i + 1] as usize
            } else {
                let len_bytes = (spki_data[i + 1] & 0x7f) as usize;
                if i + 2 + len_bytes > spki_data.len() {
                    continue;
                }
                let mut l = 0usize;
                for &b in &spki_data[i + 2..i + 2 + len_bytes] {
                    l = (l << 8) | (b as usize);
                }
                l
            };
            // A valid RSA modulus is 128–1024 bytes (1024–8192 bits)
            if (128..=1024).contains(&len) {
                return (len as u32) * 8;
            }
        }
    }
    0
}

fn extract_ec_curve(alg: &x509_parser::x509::AlgorithmIdentifier) -> String {
    let params = alg.parameters().and_then(|p| p.as_oid().ok());
    match params.map(|o| o.to_string()).as_deref() {
        Some("1.2.840.10045.3.1.7") => "P-256".to_string(),
        Some("1.3.132.0.34") => "P-384".to_string(),
        Some("1.3.132.0.35") => "P-521".to_string(),
        Some("1.3.132.0.10") => "secp256k1".to_string(),
        Some(other) => format!("curve({})", other),
        None => "unknown-curve".to_string(),
    }
}

fn bytes_to_ip_string(bytes: &[u8]) -> Option<String> {
    match bytes.len() {
        4 => {
            let ip = std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
            Some(ip.to_string())
        }
        16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(bytes);
            Some(std::net::Ipv6Addr::from(octets).to_string())
        }
        _ => None,
    }
}

// ── Accept-any certificate verifier (for inspection only) ───────────────────

#[derive(Debug)]
struct AcceptAnyCert;

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}
