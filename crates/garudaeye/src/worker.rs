use std::sync::Arc;
use tracing::{info, error, debug, warn};
use infra::traits::{AssetStore, EventBus};
use analyzers::fingerprint::FingerprintAnalyzer;
use garudaeye_core::AssetType;

/// Run background workers for collection and analysis
pub async fn run_workers(
    worker_count: usize,
    asset_store: Arc<dyn AssetStore + Send + Sync>,
    event_bus: Arc<dyn EventBus + Send + Sync>,
) -> anyhow::Result<()> {
    info!("Initializing {} background workers", worker_count);

    // Build the fingerprint analyser once (downloads cloud IP ranges at startup)
    let analyzer = Arc::new(FingerprintAnalyzer::new().await);
    
    // Spawn analyzer workers
    let mut handles = vec![];
    
    for worker_id in 0..worker_count {
        let store = asset_store.clone();
        let bus = event_bus.clone();
        let fp = analyzer.clone();
        
        let handle = tokio::spawn(async move {
            info!("Worker {} started", worker_id);
            
            // Subscribe to analysis topics
            let mut ip_subscriber = match bus.subscribe("analyze-ip").await {
                Ok(sub) => sub,
                Err(e) => {
                    error!("Worker {} failed to subscribe to analyze-ip: {}", worker_id, e);
                    return;
                }
            };
            
            let mut domain_subscriber = match bus.subscribe("analyze-domain").await {
                Ok(sub) => sub,
                Err(e) => {
                    error!("Worker {} failed to subscribe to analyze-domain: {}", worker_id, e);
                    return;
                }
            };
            
            loop {
                tokio::select! {
                    result = ip_subscriber.next() => {
                        match result {
                            Ok(Some(message)) => {
                                debug!("Worker {} received analyze-ip task: {}", worker_id, message);
                                match store.get_by_sk(AssetType::IpAddress, &message).await {
                                    Ok(Some(mut asset)) => {
                                        let fingerprint = fp.fingerprint_ip(&message).await;
                                        apply_fingerprint_to_asset(&mut asset, fingerprint);
                                        if let Err(e) = store.update(asset).await {
                                            error!("Worker {} failed to update asset {}: {}", worker_id, message, e);
                                        }
                                    }
                                    Ok(None) => {
                                        warn!("Worker {} could not find IP asset: {}", worker_id, message);
                                    }
                                    Err(e) => {
                                        error!("Worker {} database error: {}", worker_id, e);
                                    }
                                }
                            }
                            Ok(None) => { error!("Worker {} IP channel closed", worker_id); break; }
                            Err(e) => { error!("Worker {} error receiving IP task: {}", worker_id, e); }
                        }
                    },
                    result = domain_subscriber.next() => {
                        match result {
                            Ok(Some(message)) => {
                                debug!("Worker {} received analyze-domain task: {}", worker_id, message);

                                // Search across all domain-bearing asset types (including Cdn — fixes H-1)
                                let mut found_asset = None;
                                for at in &[
                                    AssetType::LoadBalancer,
                                    AssetType::Domain,
                                    AssetType::ApiGateway,
                                    AssetType::Database,
                                    AssetType::Cdn,
                                ] {
                                    match store.get_by_sk(*at, &message).await {
                                        Ok(Some(a)) => { found_asset = Some(a); break; }
                                        Ok(None) => {}
                                        Err(e) => {
                                            warn!("Worker {} DB error looking up {}: {}", worker_id, message, e);
                                        }
                                    }
                                }

                                match found_asset {
                                    Some(mut asset) => {
                                        let fingerprint = fp.fingerprint_domain(&message).await;
                                        apply_fingerprint_to_asset(&mut asset, fingerprint);
                                        if let Err(e) = store.update(asset).await {
                                            error!("Worker {} failed to update domain asset {}: {}", worker_id, message, e);
                                        }
                                    }
                                    None => {
                                        warn!("Worker {} could not find domain asset: {}", worker_id, message);
                                    }
                                }
                            }
                            Ok(None) => { error!("Worker {} domain channel closed", worker_id); break; }
                            Err(e) => { error!("Worker {} error receiving domain task: {}", worker_id, e); }
                        }
                    }
                }
            }
        });
        
        handles.push(handle);
    }
    
    // Wait for all workers (they run forever)
    for handle in handles {
        let _ = handle.await;
    }
    
    Ok(())
}

/// Map a `Fingerprint` result back onto the `Asset` fields that the rest of
/// the system (dashboard, API, frontend) already understands.
fn apply_fingerprint_to_asset(
    asset: &mut garudaeye_core::Asset,
    fp: analyzers::fingerprint::Fingerprint,
) {
    // Ports
    if !fp.open_ports.is_empty() {
        asset.ports = Some(fp.open_ports.clone());
    }

    // Geo / network — from ASN
    if let Some(ref asn) = fp.asn {
        asset.asn = Some(asn.asn_string.clone());
        asset.organization = asn.org_name.clone();
        // country comes from ASN record
        if !asn.country.is_empty() {
            asset.country = Some(asn.country.clone());
        }
    }

    // OS hint → store in configuration JSON
    if let Some(ref os) = fp.os_guess {
        let mut cfg = asset.configuration.clone().unwrap_or(serde_json::Value::Object(Default::default()));
        if let serde_json::Value::Object(ref mut map) = cfg {
            map.insert("os_guess".to_string(), serde_json::Value::String(os.clone()));
        }
        asset.configuration = Some(cfg);
    }

    // Technologies → http_server (first HTTP server hit) + full list in configuration
    if let Some(ref h) = fp.https.as_ref().or(fp.http.as_ref()) {
        if let Some(ref server) = h.server {
            asset.http_server = Some(server.clone());
        }
        if let Some(ref title) = h.title {
            asset.http_title = Some(title.clone());
        }
    }

    // Store full fingerprint JSON in configuration for the frontend
    if let Ok(fp_json) = serde_json::to_value(&fp) {
        asset.configuration = Some(fp_json);
    }

    // CVEs / vulnerabilities
    if !fp.cve_hints.is_empty() {
        asset.vulnerabilities = Some(fp.cve_hints.clone());
    }

    // Cloud provider context
    if let Some(ref cloud) = fp.cloud {
        let mut cfg = asset.configuration.clone().unwrap_or(serde_json::Value::Object(Default::default()));
        if let serde_json::Value::Object(ref mut map) = cfg {
            map.insert("cloud_provider".to_string(), serde_json::Value::String(cloud.provider.clone()));
            if let Some(ref region) = cloud.region {
                map.insert("cloud_region".to_string(), serde_json::Value::String(region.clone()));
            }
        }
        // Don't overwrite the full fingerprint — it's already set above
    }

    // TLS cert: extract SSL cert info
    if let Some(ref t) = fp.tls {
        if let Some(ref cn) = t.subject_cn {
            asset.ssl_cert = Some(format!(
                "CN={}, issuer={}, expires={}, self_signed={}",
                cn,
                t.issuer_cn.as_deref().unwrap_or("unknown"),
                t.not_after.map(|d| d.format("%Y-%m-%d").to_string()).as_deref().unwrap_or("unknown"),
                t.self_signed
            ));
        }
    }

    // Risk score and OS guess
    asset.risk_score = fp.risk_score as i32;
    if fp.os_guess.is_some() {
        asset.os_guess = fp.os_guess.clone();
    }

    asset.last_seen = Some(chrono::Utc::now());
}
