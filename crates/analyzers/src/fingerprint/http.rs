use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tracing::debug;

use super::signatures;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HttpInfo {
    pub status_code: u16,
    pub http_version: Option<String>,

    // Server identity headers
    pub server: Option<String>,
    pub x_powered_by: Option<String>,
    pub x_aspnet_version: Option<String>,
    pub x_generator: Option<String>,

    // Routing / CDN
    pub via: Option<String>,
    pub x_forwarded_by: Option<String>,
    pub cdn: Option<String>,

    // Security headers
    pub hsts: bool,
    pub hsts_max_age: Option<u64>,
    pub hsts_include_subdomains: bool,
    pub csp: bool,
    pub x_frame_options: Option<String>,
    pub x_content_type_options: bool,
    pub referrer_policy: Option<String>,
    pub permissions_policy: bool,

    // Content
    pub content_type: Option<String>,
    pub title: Option<String>,

    // Cookie security
    pub cookies: Vec<CookieInfo>,
    pub insecure_cookies: bool,

    // Redirect chain
    pub redirect_url: Option<String>,

    // All raw headers (lowercase name → value)
    pub all_headers: HashMap<String, String>,

    // Detected technologies from headers + body
    pub technologies: Vec<String>,

    // Security observations
    pub security_issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieInfo {
    pub name: String,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<String>,
}

/// Probe a single HTTP/HTTPS endpoint and extract all fingerprinting signals.
pub async fn probe(
    client: &reqwest::Client,
    host: &str,
    port: u16,
    tls: bool,
) -> anyhow::Result<Option<HttpInfo>> {
    let scheme = if tls { "https" } else { "http" };
    let url = if (tls && port == 443) || (!tls && port == 80) {
        format!("{}://{}/", scheme, host)
    } else {
        format!("{}://{}:{}/", scheme, host, port)
    };

    let response = tokio::time::timeout(
        Duration::from_secs(12),
        client.get(&url).send(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("HTTP probe timeout for {}", url))??;

    let mut info = HttpInfo::default();
    info.status_code = response.status().as_u16();
    info.http_version = Some(format!("{:?}", response.version()));

    // Collect all headers
    for (name, value) in response.headers() {
        let key = name.as_str().to_lowercase();
        let val = value.to_str().unwrap_or("").to_string();
        info.all_headers.insert(key.clone(), val.clone());

        match key.as_str() {
            "server" => info.server = Some(val.clone()),
            "x-powered-by" => info.x_powered_by = Some(val.clone()),
            "x-aspnet-version" => info.x_aspnet_version = Some(val.clone()),
            "x-generator" => info.x_generator = Some(val.clone()),
            "via" => info.via = Some(val.clone()),
            "x-forwarded-by" => info.x_forwarded_by = Some(val.clone()),
            "content-type" => info.content_type = Some(val.clone()),
            "location" => info.redirect_url = Some(val.clone()),
            "x-frame-options" => info.x_frame_options = Some(val.clone()),
            "referrer-policy" => info.referrer_policy = Some(val.clone()),
            "x-content-type-options" => {
                info.x_content_type_options = val.to_lowercase().contains("nosniff")
            }
            "permissions-policy" => info.permissions_policy = true,
            "content-security-policy" => info.csp = !val.is_empty(),
            "strict-transport-security" => {
                info.hsts = true;
                info.hsts_max_age = parse_hsts_max_age(&val);
                info.hsts_include_subdomains = val.to_lowercase().contains("includesubdomains");
            }
            "set-cookie" => {
                let cookie = parse_set_cookie(&val);
                if !cookie.secure {
                    info.insecure_cookies = true;
                }
                info.cookies.push(cookie);
            }
            _ => {}
        }
    }

    // CDN detection from header names
    let header_names: Vec<String> = info.all_headers.keys().cloned().collect();
    info.cdn = signatures::detect_cdn_from_headers(&header_names);

    // Technology fingerprinting
    let mut techs: Vec<String> = Vec::new();

    if let Some(ref server) = info.server.clone() {
        let lower = server.to_lowercase();
        if let Some((product, _, _)) = signatures::match_banner(&lower, signatures::HTTP_SERVER_SIGS) {
            techs.push(product.to_string());
        }
    }

    if let Some(ref px) = info.x_powered_by.clone() {
        let lower = px.to_lowercase();
        if let Some((product, _, _)) = signatures::match_banner(&lower, signatures::POWERED_BY_SIGS) {
            techs.push(product.to_string());
        } else {
            // Include raw value if no signature matched — still useful
            techs.push(format!("X-Powered-By: {}", px));
        }
    }

    if let Some(ref gen) = info.x_generator.clone() {
        techs.push(format!("Generator: {}", gen));
    }

    if let Some(ref cdn) = info.cdn.clone() {
        if !techs.contains(cdn) {
            techs.push(cdn.clone());
        }
    }

    if let Some(ref via) = info.via.clone() {
        techs.push(format!("Via: {}", via));
    }

    // Identify ASP.NET from version header
    if info.x_aspnet_version.is_some() {
        if !techs.iter().any(|t| t.contains("ASP.NET")) {
            techs.push("ASP.NET".to_string());
        }
    }

    // Read body (limited to 64 KB) for HTML title + meta-tag tech detection
    let final_url = response.url().clone();
    let ct = info.content_type.clone().unwrap_or_default();
    if ct.contains("text/html") {
        if let Ok(bytes) = tokio::time::timeout(Duration::from_secs(8), response.bytes()).await {
            if let Ok(bytes) = bytes {
                let html = String::from_utf8_lossy(&bytes[..bytes.len().min(65536)]);
                info.title = extract_title(&html);
                detect_html_technologies(&html, &mut techs);
            }
        }
    }

    // Security issues
    if !tls {
        info.security_issues.push("Plaintext HTTP (no TLS)".to_string());
    }
    if !info.hsts && tls {
        info.security_issues.push("Missing HSTS header".to_string());
    }
    if !info.csp {
        info.security_issues.push("Missing Content-Security-Policy".to_string());
    }
    if !info.x_content_type_options {
        info.security_issues.push("Missing X-Content-Type-Options: nosniff".to_string());
    }
    if info.x_frame_options.is_none() && !info.csp {
        info.security_issues.push("Missing clickjacking protection (X-Frame-Options or CSP)".to_string());
    }
    if info.insecure_cookies {
        info.security_issues.push("Cookie without Secure flag (sent over HTTP)".to_string());
    }
    if let Some(ref server) = info.server {
        // Server header disclosing version info
        if server.contains('/') {
            info.security_issues.push(format!("Server version disclosure: {}", server));
        }
    }
    if info.x_powered_by.is_some() {
        info.security_issues.push("X-Powered-By header exposes technology stack".to_string());
    }
    if info.x_aspnet_version.is_some() {
        info.security_issues.push("X-AspNet-Version header exposes framework version".to_string());
    }

    techs.dedup();
    info.technologies = techs;

    debug!(
        url = %final_url,
        status = info.status_code,
        techs = ?info.technologies,
        "HTTP probe complete"
    );

    Ok(Some(info))
}

// ── HTML parsing utilities ───────────────────────────────────────────────────

fn extract_title(html: &str) -> Option<String> {
    let lower = html.to_lowercase();
    let tag_start = lower.find("<title")?;
    let content_start = html[tag_start..].find('>')? + tag_start + 1;
    let content_end = lower[content_start..].find("</title>")? + content_start;
    let title = html[content_start..content_end].trim();
    if title.is_empty() { None } else { Some(decode_html_entities(title)) }
}

fn decode_html_entities(s: &str) -> String {
    s.replace("&amp;", "&")
     .replace("&lt;", "<")
     .replace("&gt;", ">")
     .replace("&quot;", "\"")
     .replace("&#39;", "'")
     .replace("&nbsp;", " ")
}

fn detect_html_technologies(html: &str, techs: &mut Vec<String>) {
    let lower = html.to_lowercase();

    // Meta generator tag: <meta name="generator" content="WordPress 6.x">
    if let Some(gen) = extract_meta_content(&lower, "generator") {
        techs.push(format!("Generator: {}", gen));
    }

    // Common JS framework signals from script src / body text
    let framework_signals: &[(&str, &str)] = &[
        ("wp-content/",             "WordPress"),
        ("wp-includes/",            "WordPress"),
        ("/drupal.js",              "Drupal"),
        ("drupal.settings",         "Drupal"),
        ("/sites/default/files",    "Drupal"),
        ("joomla",                  "Joomla"),
        ("react",                   "React"),
        ("vue.js",                  "Vue.js"),
        ("angular",                 "Angular"),
        ("ember.js",                "Ember.js"),
        ("backbone.js",             "Backbone.js"),
        ("jquery",                  "jQuery"),
        ("bootstrap",               "Bootstrap CSS"),
        ("tailwindcss",             "Tailwind CSS"),
        ("shopify",                 "Shopify"),
        ("magento",                 "Magento"),
        ("woocommerce",             "WooCommerce"),
        ("next.js",                 "Next.js"),
        ("nuxt",                    "Nuxt.js"),
        ("gatsby",                  "Gatsby"),
        ("svelte",                  "Svelte"),
        ("htmx",                    "HTMX"),
    ];

    for (pattern, name) in framework_signals {
        if lower.contains(pattern) && !techs.iter().any(|t| t == name) {
            techs.push(name.to_string());
        }
    }
}

fn extract_meta_content<'a>(html_lower: &'a str, name_attr: &str) -> Option<String> {
    let search = format!("name=\"{}\"", name_attr);
    let pos = html_lower.find(&search)?;
    let after = &html_lower[pos..];
    let content_pos = after.find("content=\"")? + "content=\"".len();
    let content = &after[content_pos..];
    let end = content.find('"')?;
    if end == 0 { None } else { Some(content[..end].to_string()) }
}

fn parse_hsts_max_age(header_value: &str) -> Option<u64> {
    for part in header_value.split(';') {
        let part = part.trim().to_lowercase();
        if part.starts_with("max-age=") {
            return part["max-age=".len()..].trim().parse().ok();
        }
    }
    None
}

fn parse_set_cookie(value: &str) -> CookieInfo {
    let parts: Vec<&str> = value.split(';').collect();
    let name = parts
        .first()
        .and_then(|p| p.split('=').next())
        .unwrap_or("")
        .trim()
        .to_string();

    let lower_parts: Vec<String> = parts.iter().map(|p| p.trim().to_lowercase()).collect();

    let secure = lower_parts.iter().any(|p| p == "secure");
    let http_only = lower_parts.iter().any(|p| p == "httponly");
    let same_site = lower_parts
        .iter()
        .find(|p| p.starts_with("samesite="))
        .map(|p| p["samesite=".len()..].to_string());

    CookieInfo { name, secure, http_only, same_site }
}
