use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use serde::Serialize;
use std::sync::Arc;
use crate::state::AppState;
use garudaeye_core::{Asset, AssetType};
use infra::traits::AssetStore;

/// Sensitive ports that indicate risk when exposed
const DB_PORTS: &[u16] = &[3306, 5432, 27017, 6379, 1433, 5984, 9200, 9300, 2181];
const INSECURE_PROTO_PORTS: &[u16] = &[21, 23, 69, 161, 162];
const ADMIN_PORTS: &[u16] = &[
    3389, 5900, 5901, 8080, 8443, 8888, 9090, 9091,
    15672, 5672, 2375, 2376, 6443,
];

#[derive(Debug, Serialize)]
pub struct AttackPath {
    pub id: String,
    pub path_type: String,
    pub severity: String,
    pub description: String,
    pub entry_asset_id: String,
    pub entry_asset_name: String,
    pub affected_ports: Vec<u16>,
    pub evidence: Vec<String>,
    pub remediation: String,
    /// Downstream assets reachable via relationships (lateral movement)
    pub downstream_assets: Vec<String>,
}

/// Compute attack paths from stored asset + relationship data.
pub async fn get_attack_paths(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<AttackPath>>, StatusCode> {
    let assets = state.asset_store.list(None, None, None).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let relationships = state.asset_store.get_all_relationships().await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut paths: Vec<AttackPath> = Vec::new();

    for asset in &assets {
        let ports = asset.ports.as_deref().unwrap_or(&[]);
        let vulns = asset.vulnerabilities.as_deref().unwrap_or(&[]);
        let is_public = asset.public_access.unwrap_or(false);

        // Derive downstream assets via relationships
        let downstream: Vec<String> = relationships.iter()
            .filter(|r| r.source_asset_id == asset.id)
            .filter_map(|r| {
                assets.iter()
                    .find(|a| a.id == r.target_asset_id)
                    .map(|a| a.sk.clone())
            })
            .collect();

        // 1. Exposed Database
        let exposed_db_ports: Vec<u16> = ports.iter()
            .copied()
            .filter(|p| DB_PORTS.contains(p))
            .collect();

        let is_db_type = matches!(
            asset.asset_type,
            AssetType::Database | AssetType::Cache | AssetType::Table
        );

        if !exposed_db_ports.is_empty() || (is_public && is_db_type) {
            let mut evidence = vec![];
            if !exposed_db_ports.is_empty() {
                evidence.push(format!("Database ports open: {:?}", exposed_db_ports));
            }
            if is_public {
                evidence.push("Asset is publicly accessible".to_string());
            }
            if is_db_type {
                evidence.push(format!("Asset type is {:?}", asset.asset_type));
            }

            paths.push(AttackPath {
                id: format!("db-{}", asset.id),
                path_type: "ExposedDatabase".to_string(),
                severity: "Critical".to_string(),
                description: format!(
                    "Database asset '{}' is exposed with open DB ports or public access",
                    asset.sk
                ),
                entry_asset_id: asset.id.to_string(),
                entry_asset_name: asset.sk.clone(),
                affected_ports: exposed_db_ports,
                evidence,
                remediation: "Restrict database access to private networks only. Use VPC private subnets and security groups. Disable public access.".to_string(),
                downstream_assets: downstream.clone(),
            });
        }

        // 2. Insecure Protocol (Telnet, FTP, TFTP, SNMP)
        let insecure_ports: Vec<u16> = ports.iter()
            .copied()
            .filter(|p| INSECURE_PROTO_PORTS.contains(p))
            .collect();

        if !insecure_ports.is_empty() {
            let proto_names: Vec<&str> = insecure_ports.iter().map(|p| match p {
                21 => "FTP",
                23 => "Telnet",
                69 => "TFTP",
                161 | 162 => "SNMP",
                _ => "Unknown",
            }).collect();
            paths.push(AttackPath {
                id: format!("proto-{}", asset.id),
                path_type: "InsecureProtocol".to_string(),
                severity: "Critical".to_string(),
                description: format!(
                    "'{}' exposes insecure plaintext protocols: {}",
                    asset.sk,
                    proto_names.join(", ")
                ),
                entry_asset_id: asset.id.to_string(),
                entry_asset_name: asset.sk.clone(),
                affected_ports: insecure_ports,
                evidence: vec![
                    format!("Insecure protocol ports detected: {:?}", proto_names),
                    "Credentials transmitted in plaintext".to_string(),
                ],
                remediation: "Disable Telnet/FTP. Use SSH (port 22) and SFTP instead. Enable SNMPv3 with authentication if SNMP is required.".to_string(),
                downstream_assets: downstream.clone(),
            });
        }

        // 3. Weak TLS (self-signed or expired cert)
        if is_public {
            if let Some(cfg) = &asset.configuration {
                let self_signed = cfg.get("tls")
                    .and_then(|t| t.get("self_signed"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let is_expired = cfg.get("tls")
                    .and_then(|t| t.get("is_expired"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let days_left = cfg.get("tls")
                    .and_then(|t| t.get("days_until_expiry"))
                    .and_then(|v| v.as_i64())
                    .unwrap_or(999);

                if self_signed || is_expired || days_left < 14 {
                    let mut evidence = vec![];
                    if self_signed { evidence.push("Self-signed TLS certificate".to_string()); }
                    if is_expired { evidence.push("TLS certificate is expired".to_string()); }
                    if days_left < 14 && days_left >= 0 {
                        evidence.push(format!("Certificate expires in {} days", days_left));
                    }
                    let severity = if self_signed || is_expired { "High" } else { "Medium" };
                    paths.push(AttackPath {
                        id: format!("tls-{}", asset.id),
                        path_type: "WeakTLS".to_string(),
                        severity: severity.to_string(),
                        description: format!("'{}' has a weak or untrusted TLS configuration", asset.sk),
                        entry_asset_id: asset.id.to_string(),
                        entry_asset_name: asset.sk.clone(),
                        affected_ports: vec![443],
                        evidence,
                        remediation: "Replace self-signed certificates with CA-signed ones. Set up automated certificate renewal (Let's Encrypt / ACM).".to_string(),
                        downstream_assets: downstream.clone(),
                    });
                }
            }
        }

        // 4. Exposed Admin Interface
        let admin_ports_open: Vec<u16> = ports.iter()
            .copied()
            .filter(|p| ADMIN_PORTS.contains(p))
            .collect();

        if !admin_ports_open.is_empty() && is_public {
            paths.push(AttackPath {
                id: format!("admin-{}", asset.id),
                path_type: "ExposedAdminInterface".to_string(),
                severity: "High".to_string(),
                description: format!("'{}' exposes admin interfaces publicly", asset.sk),
                entry_asset_id: asset.id.to_string(),
                entry_asset_name: asset.sk.clone(),
                affected_ports: admin_ports_open.clone(),
                evidence: vec![
                    format!("Admin ports exposed: {:?}", admin_ports_open),
                    "Asset is publicly accessible (internet-facing)".to_string(),
                ],
                remediation: "Restrict admin interface access to trusted IP ranges or a VPN. Use bastion hosts for remote access.".to_string(),
                downstream_assets: downstream.clone(),
            });
        }

        // 5. CVE Vector
        if !vulns.is_empty() && is_public {
            let severity = if vulns.len() >= 3 { "Critical" } else { "High" };
            paths.push(AttackPath {
                id: format!("cve-{}", asset.id),
                path_type: "CVEVector".to_string(),
                severity: severity.to_string(),
                description: format!(
                    "'{}' is internet-facing with {} known CVE hint(s)",
                    asset.sk, vulns.len()
                ),
                entry_asset_id: asset.id.to_string(),
                entry_asset_name: asset.sk.clone(),
                affected_ports: ports.to_vec(),
                evidence: vulns.iter().map(|v| format!("CVE hint: {}", v)).collect(),
                remediation: "Patch or update vulnerable software. Apply vendor security advisories. Consider WAF protection for internet-facing services.".to_string(),
                downstream_assets: downstream.clone(),
            });
        }

        // 6. Lateral Movement: public asset → downstream sensitive asset
        let has_sensitive_downstream = downstream.iter().any(|_name| {
            relationships.iter()
                .filter(|r| r.source_asset_id == asset.id)
                .any(|r| {
                    assets.iter()
                        .find(|a| a.id == r.target_asset_id)
                        .map(|a| matches!(
                            a.asset_type,
                            AssetType::Database | AssetType::Cache | AssetType::Lambda |
                            AssetType::S3Bucket | AssetType::Table
                        ))
                        .unwrap_or(false)
                })
        });

        if is_public && has_sensitive_downstream && !downstream.is_empty() {
            paths.push(AttackPath {
                id: format!("lateral-{}", asset.id),
                path_type: "LateralMovement".to_string(),
                severity: "High".to_string(),
                description: format!(
                    "'{}' is internet-facing and has relationships to sensitive backend resources",
                    asset.sk
                ),
                entry_asset_id: asset.id.to_string(),
                entry_asset_name: asset.sk.clone(),
                affected_ports: ports.to_vec(),
                evidence: vec![
                    "Public entry point connects to sensitive internal resources".to_string(),
                    format!("Downstream resources: {}", downstream.join(", ")),
                ],
                remediation: "Apply network segmentation between public-facing tiers and backend data stores. Use VPC security groups and NACLs to restrict east-west traffic.".to_string(),
                downstream_assets: downstream,
            });
        }

        // 7. Missing security headers on public HTTP assets
        if is_public {
            if let Some(cfg) = &asset.configuration {
                let no_hsts = cfg.get("https")
                    .and_then(|h| h.get("hsts"))
                    .and_then(|v| v.as_bool())
                    .map(|v| !v)
                    .unwrap_or(false);
                let no_csp = cfg.get("https")
                    .and_then(|h| h.get("csp"))
                    .and_then(|v| v.as_bool())
                    .map(|v| !v)
                    .unwrap_or(false);

                if no_hsts || no_csp {
                    let mut evidence = vec![];
                    if no_hsts { evidence.push("Missing Strict-Transport-Security header".to_string()); }
                    if no_csp { evidence.push("Missing Content-Security-Policy header".to_string()); }

                    paths.push(AttackPath {
                        id: format!("headers-{}", asset.id),
                        path_type: "MissingSecurityHeaders".to_string(),
                        severity: "Medium".to_string(),
                        description: format!(
                            "'{}' is missing security headers that prevent common web attacks",
                            asset.sk
                        ),
                        entry_asset_id: asset.id.to_string(),
                        entry_asset_name: asset.sk.clone(),
                        affected_ports: vec![443, 80],
                        evidence,
                        remediation: "Add HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy headers to all HTTP responses.".to_string(),
                        downstream_assets: vec![],
                    });
                }
            }
        }
    }

    // Sort by severity: Critical > High > Medium
    paths.sort_by(|a, b| {
        severity_order(&b.severity).cmp(&severity_order(&a.severity))
    });

    Ok(Json(paths))
}

fn severity_order(s: &str) -> u8 {
    match s {
        "Critical" => 3,
        "High" => 2,
        "Medium" => 1,
        _ => 0,
    }
}
