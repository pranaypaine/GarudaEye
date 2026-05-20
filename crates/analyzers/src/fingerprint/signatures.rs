/// A single detection signature
pub struct Signature {
    /// Substring to match (case-insensitive)
    pub pattern: &'static str,
    /// Human-readable product name
    pub product: &'static str,
    /// Inferred OS if applicable
    pub os_hint: Option<&'static str>,
    /// Known CVE hints for this product/pattern (e.g., old versions)
    pub cve_hints: &'static [&'static str],
}

// ── HTTP Server header ──────────────────────────────────────────────────────

pub static HTTP_SERVER_SIGS: &[Signature] = &[
    Signature { pattern: "apache/2.4",       product: "Apache httpd 2.4",         os_hint: None,                      cve_hints: &[] },
    Signature { pattern: "apache/2.2",       product: "Apache httpd 2.2",         os_hint: None,                      cve_hints: &["CVE-2017-7679", "CVE-2017-7668"] },
    Signature { pattern: "apache/1.",        product: "Apache httpd 1.x (EOL)",   os_hint: None,                      cve_hints: &["multiple-EOL-CVEs"] },
    Signature { pattern: "nginx/",           product: "nginx",                    os_hint: None,                      cve_hints: &[] },
    Signature { pattern: "openresty/",       product: "OpenResty (nginx+Lua)",    os_hint: None,                      cve_hints: &[] },
    Signature { pattern: "microsoft-iis/10", product: "Microsoft IIS 10",         os_hint: Some("Windows Server 2016/2019/2022"), cve_hints: &[] },
    Signature { pattern: "microsoft-iis/8",  product: "Microsoft IIS 8.x",        os_hint: Some("Windows Server 2012"), cve_hints: &["CVE-2015-1635"] },
    Signature { pattern: "microsoft-iis/7",  product: "Microsoft IIS 7.x",        os_hint: Some("Windows Server 2008"), cve_hints: &["CVE-2010-3972"] },
    Signature { pattern: "litespeed",        product: "LiteSpeed Web Server",     os_hint: None,                      cve_hints: &[] },
    Signature { pattern: "cloudflare",       product: "Cloudflare CDN",           os_hint: None,                      cve_hints: &[] },
    Signature { pattern: "amazons3",         product: "AWS S3 Static Hosting",    os_hint: None,                      cve_hints: &[] },
    Signature { pattern: "awselb/",          product: "AWS Elastic Load Balancer",os_hint: None,                      cve_hints: &[] },
    Signature { pattern: "awsalb",           product: "AWS Application Load Balancer", os_hint: None,                 cve_hints: &[] },
    Signature { pattern: "gunicorn/",        product: "Gunicorn (Python WSGI)",   os_hint: None,                      cve_hints: &[] },
    Signature { pattern: "kestrel",          product: "Kestrel (.NET/ASP.NET Core)", os_hint: None,                   cve_hints: &[] },
    Signature { pattern: "jetty/",           product: "Eclipse Jetty (Java)",     os_hint: None,                      cve_hints: &[] },
    Signature { pattern: "apache-coyote",    product: "Apache Tomcat",            os_hint: None,                      cve_hints: &[] },
    Signature { pattern: "tomcat/",          product: "Apache Tomcat",            os_hint: None,                      cve_hints: &[] },
    Signature { pattern: "gws",              product: "Google Web Server",        os_hint: None,                      cve_hints: &[] },
    Signature { pattern: "envoy/",           product: "Envoy Proxy",              os_hint: None,                      cve_hints: &[] },
    Signature { pattern: "traefik/",         product: "Traefik Proxy",            os_hint: None,                      cve_hints: &[] },
    Signature { pattern: "caddy/",           product: "Caddy Web Server",         os_hint: None,                      cve_hints: &[] },
    Signature { pattern: "nginx-quic",       product: "nginx (HTTP/3 QUIC)",      os_hint: None,                      cve_hints: &[] },
    Signature { pattern: "tengine/",         product: "Tengine (Alibaba nginx)",  os_hint: None,                      cve_hints: &[] },
    Signature { pattern: "fasthttp/",        product: "FastHTTP (Go)",            os_hint: None,                      cve_hints: &[] },
    Signature { pattern: "cowboy",           product: "Cowboy (Erlang/Elixir)",   os_hint: None,                      cve_hints: &[] },
    Signature { pattern: "werkzeug/",        product: "Werkzeug/Flask (Python dev)", os_hint: None,                   cve_hints: &[] },
    Signature { pattern: "python/",          product: "Python HTTP server",       os_hint: None,                      cve_hints: &[] },
    Signature { pattern: "tornado/",         product: "Tornado (Python)",         os_hint: None,                      cve_hints: &[] },
    Signature { pattern: "thin",             product: "Thin (Ruby)",              os_hint: None,                      cve_hints: &[] },
    Signature { pattern: "unicorn",          product: "Unicorn (Ruby)",           os_hint: None,                      cve_hints: &[] },
    Signature { pattern: "puma",             product: "Puma (Ruby)",              os_hint: None,                      cve_hints: &[] },
    Signature { pattern: "phusion passenger",product: "Phusion Passenger (Ruby/Python)", os_hint: None,              cve_hints: &[] },
];

// ── X-Powered-By header ─────────────────────────────────────────────────────

pub static POWERED_BY_SIGS: &[Signature] = &[
    Signature { pattern: "php/",             product: "PHP",                  os_hint: None,  cve_hints: &[] },
    Signature { pattern: "asp.net",          product: "ASP.NET",              os_hint: Some("Windows"), cve_hints: &[] },
    Signature { pattern: "express",          product: "Express (Node.js)",    os_hint: None,  cve_hints: &[] },
    Signature { pattern: "next.js",          product: "Next.js",              os_hint: None,  cve_hints: &[] },
    Signature { pattern: "nuxt",             product: "Nuxt.js",              os_hint: None,  cve_hints: &[] },
    Signature { pattern: "laravel",          product: "Laravel (PHP)",        os_hint: None,  cve_hints: &[] },
    Signature { pattern: "django",           product: "Django (Python)",      os_hint: None,  cve_hints: &[] },
    Signature { pattern: "rails",            product: "Ruby on Rails",        os_hint: None,  cve_hints: &[] },
    Signature { pattern: "servlet/",         product: "Java Servlet",         os_hint: None,  cve_hints: &[] },
    Signature { pattern: "wix",              product: "Wix (SaaS)",           os_hint: None,  cve_hints: &[] },
    Signature { pattern: "shopify",          product: "Shopify",              os_hint: None,  cve_hints: &[] },
    Signature { pattern: "strapi",           product: "Strapi CMS",           os_hint: None,  cve_hints: &[] },
    Signature { pattern: "wordpress",        product: "WordPress",            os_hint: None,  cve_hints: &[] },
    Signature { pattern: "drupal",           product: "Drupal",               os_hint: None,  cve_hints: &[] },
    Signature { pattern: "joomla",           product: "Joomla",               os_hint: None,  cve_hints: &[] },
];

// ── TCP / service banners ───────────────────────────────────────────────────

pub static BANNER_SIGS: &[Signature] = &[
    // SSH
    Signature { pattern: "ssh-2.0-openssh",                 product: "OpenSSH",                  os_hint: None,                         cve_hints: &[] },
    Signature { pattern: "openssh_9.",                      product: "OpenSSH 9.x",               os_hint: None,                         cve_hints: &[] },
    Signature { pattern: "openssh_8.",                      product: "OpenSSH 8.x",               os_hint: None,                         cve_hints: &[] },
    Signature { pattern: "openssh_7.",                      product: "OpenSSH 7.x",               os_hint: None,                         cve_hints: &["CVE-2018-15473"] },
    Signature { pattern: "openssh_6.",                      product: "OpenSSH 6.x (EOL)",         os_hint: None,                         cve_hints: &["CVE-2016-0777"] },
    Signature { pattern: "ubuntu",                          product: "OpenSSH (Ubuntu)",          os_hint: Some("Ubuntu Linux"),         cve_hints: &[] },
    Signature { pattern: "debian",                          product: "OpenSSH (Debian)",          os_hint: Some("Debian Linux"),         cve_hints: &[] },
    Signature { pattern: "raspbian",                        product: "OpenSSH (Raspbian)",        os_hint: Some("Raspberry Pi OS"),      cve_hints: &[] },
    Signature { pattern: "freebsd",                         product: "OpenSSH (FreeBSD)",         os_hint: Some("FreeBSD"),              cve_hints: &[] },
    Signature { pattern: "centos",                          product: "OpenSSH (CentOS)",          os_hint: Some("CentOS/RHEL Linux"),    cve_hints: &[] },
    Signature { pattern: "amzn",                            product: "OpenSSH (Amazon Linux)",    os_hint: Some("Amazon Linux"),         cve_hints: &[] },
    Signature { pattern: "ssh-2.0-dropbear",                product: "Dropbear SSH",              os_hint: Some("Embedded/Router OS"),   cve_hints: &[] },
    Signature { pattern: "ssh-2.0-libssh2",                 product: "libssh2",                   os_hint: None,                         cve_hints: &[] },
    Signature { pattern: "ssh-2.0-cisco",                   product: "Cisco SSH",                 os_hint: Some("Cisco IOS/NX-OS"),      cve_hints: &[] },
    Signature { pattern: "ssh-2.0-huawei",                  product: "Huawei SSH",                os_hint: Some("Huawei VRP"),           cve_hints: &[] },
    Signature { pattern: "ssh-1.",                          product: "SSH v1 (insecure, EOL)",    os_hint: None,                         cve_hints: &["CVE-2001-0572"] },

    // FTP
    Signature { pattern: "220 proftpd",                     product: "ProFTPD",                   os_hint: None,                         cve_hints: &[] },
    Signature { pattern: "220 vsftpd",                      product: "vsftpd",                    os_hint: None,                         cve_hints: &[] },
    Signature { pattern: "220 filezilla server",            product: "FileZilla FTP Server",      os_hint: Some("Windows"),              cve_hints: &[] },
    Signature { pattern: "220 pure-ftpd",                   product: "Pure-FTPd",                 os_hint: None,                         cve_hints: &[] },
    Signature { pattern: "220 microsoftftpservice",         product: "Microsoft IIS FTP",         os_hint: Some("Windows Server"),       cve_hints: &[] },
    Signature { pattern: "220 ftpdaemon",                   product: "ftpdaemon",                 os_hint: None,                         cve_hints: &[] },

    // SMTP
    Signature { pattern: "220 postfix",                     product: "Postfix SMTP",              os_hint: None,                         cve_hints: &[] },
    Signature { pattern: "postfix smtp",                    product: "Postfix SMTP",              os_hint: None,                         cve_hints: &[] },
    Signature { pattern: "220 sendmail",                    product: "Sendmail",                  os_hint: None,                         cve_hints: &[] },
    Signature { pattern: "microsoft smtp server",           product: "Microsoft Exchange SMTP",   os_hint: Some("Windows Server"),       cve_hints: &[] },
    Signature { pattern: "esmtp exim",                      product: "Exim MTA",                  os_hint: None,                         cve_hints: &["CVE-2019-10149"] },
    Signature { pattern: "220 haraka",                      product: "Haraka SMTP (Node.js)",     os_hint: None,                         cve_hints: &[] },
    Signature { pattern: "220 maildrop",                    product: "Maildrop SMTP",             os_hint: None,                         cve_hints: &[] },

    // POP3 / IMAP
    Signature { pattern: "dovecot",                         product: "Dovecot IMAP/POP3",         os_hint: None,                         cve_hints: &[] },
    Signature { pattern: "cyrus imap",                      product: "Cyrus IMAP",                os_hint: None,                         cve_hints: &[] },
    Signature { pattern: "courier imap",                    product: "Courier IMAP",              os_hint: None,                         cve_hints: &[] },

    // Databases
    Signature { pattern: "mysql",                           product: "MySQL",                     os_hint: None,                         cve_hints: &[] },
    Signature { pattern: "mariadb",                         product: "MariaDB",                   os_hint: None,                         cve_hints: &[] },
    Signature { pattern: "postgresql",                      product: "PostgreSQL",                os_hint: None,                         cve_hints: &[] },
    Signature { pattern: "+pong",                           product: "Redis",                     os_hint: None,                         cve_hints: &["CVE-2022-0543"] },
    Signature { pattern: "-err unknown command",            product: "Redis",                     os_hint: None,                         cve_hints: &[] },
    Signature { pattern: "mongodb",                         product: "MongoDB",                   os_hint: None,                         cve_hints: &[] },
    Signature { pattern: "elastic",                         product: "Elasticsearch",             os_hint: None,                         cve_hints: &[] },
    Signature { pattern: "memcached",                       product: "Memcached",                 os_hint: None,                         cve_hints: &[] },
    Signature { pattern: "cassandra",                       product: "Apache Cassandra",          os_hint: None,                         cve_hints: &[] },
    Signature { pattern: "cqlprotocol",                     product: "Apache Cassandra (CQL)",    os_hint: None,                         cve_hints: &[] },

    // Remote access / legacy protocols
    Signature { pattern: "rfb 003",                         product: "VNC (RFB protocol)",        os_hint: None,                         cve_hints: &[] },
    Signature { pattern: "rfb 004",                         product: "VNC (RFB protocol)",        os_hint: None,                         cve_hints: &[] },
    Signature { pattern: "220 ftp",                         product: "Generic FTP",               os_hint: None,                         cve_hints: &[] },
    Signature { pattern: "telnet",                          product: "Telnet (insecure)",         os_hint: None,                         cve_hints: &["plaintext-protocol"] },

    // Message queues
    Signature { pattern: "rabbitmq",                        product: "RabbitMQ AMQP",             os_hint: None,                         cve_hints: &[] },
    Signature { pattern: "activemq",                        product: "Apache ActiveMQ",           os_hint: None,                         cve_hints: &["CVE-2023-46604"] },
    Signature { pattern: "nats",                            product: "NATS Messaging",            os_hint: None,                         cve_hints: &[] },

    // Kubernetes / Container
    Signature { pattern: "kubernetes",                      product: "Kubernetes API Server",     os_hint: None,                         cve_hints: &[] },
    Signature { pattern: "docker",                          product: "Docker Daemon API",         os_hint: None,                         cve_hints: &[] },

    // Network devices
    Signature { pattern: "cisco ios",                       product: "Cisco IOS",                 os_hint: Some("Cisco Router/Switch"),  cve_hints: &[] },
    Signature { pattern: "junos",                           product: "Juniper JunOS",             os_hint: Some("Juniper Network Device"), cve_hints: &[] },
    Signature { pattern: "fortios",                         product: "Fortinet FortiOS",          os_hint: Some("Fortinet"),             cve_hints: &[] },
    Signature { pattern: "panos",                           product: "Palo Alto PAN-OS",          os_hint: Some("Palo Alto Firewall"),   cve_hints: &[] },

    // Web admin panels
    Signature { pattern: "cpanel",                          product: "cPanel",                    os_hint: None,                         cve_hints: &[] },
    Signature { pattern: "plesk",                           product: "Plesk",                     os_hint: None,                         cve_hints: &[] },
    Signature { pattern: "webmin",                          product: "Webmin",                    os_hint: None,                         cve_hints: &[] },
];

// ── NS record → DNS provider ─────────────────────────────────────────────────

/// Maps NS hostname substring → DNS provider name
pub static DNS_PROVIDER_SIGS: &[(&str, &str)] = &[
    ("cloudflare.com",          "Cloudflare DNS"),
    ("awsdns",                  "Amazon Route 53"),
    ("azure-dns",               "Azure DNS"),
    ("domaincontrol.com",       "GoDaddy DNS"),
    ("googledomains.com",       "Google Domains DNS"),
    ("google.com",              "Google Cloud DNS"),
    ("ns.cloudns.net",          "ClouDNS"),
    ("dynect.net",              "Dyn DNS"),
    ("ultradns",                "UltraDNS"),
    ("nsone.net",               "NS1 DNS"),
    ("dnsimple.com",            "DNSimple"),
    ("dnsmadeeasy.com",         "DNS Made Easy"),
    ("easydns.com",             "EasyDNS"),
    ("name.com",                "Name.com DNS"),
    ("hetzner.com",             "Hetzner DNS"),
    ("netlify.com",             "Netlify DNS"),
    ("vercel-dns.com",          "Vercel DNS"),
    ("fastly.com",              "Fastly DNS"),
    ("akamai",                  "Akamai DNS"),
    ("registrar-servers.com",   "Namecheap DNS"),
    ("hover.com",               "Hover DNS"),
];

// ── MX record → mail provider ────────────────────────────────────────────────

/// Maps MX hostname substring → mail provider name
pub static MAIL_PROVIDER_SIGS: &[(&str, &str)] = &[
    ("google.com",              "Google Workspace"),
    ("googlemail.com",          "Gmail"),
    ("outlook.com",             "Microsoft 365"),
    ("mail.protection.outlook", "Microsoft 365"),
    ("pphosted.com",            "Proofpoint Email Security"),
    ("mimecast.com",            "Mimecast"),
    ("barracudanetworks.com",   "Barracuda Email Security"),
    ("mailgun.org",             "Mailgun"),
    ("sendgrid.net",            "SendGrid"),
    ("amazonses.com",           "Amazon SES"),
    ("zoho.com",                "Zoho Mail"),
    ("fastmail.com",            "Fastmail"),
    ("protonmail.ch",           "ProtonMail"),
    ("messagelabs.com",         "Symantec Email Security"),
    ("spamhero.com",            "SpamHero"),
    ("mcafee.com",              "McAfee Email Security"),
];

// ── TLS certificate issuer → hosting / service hints ────────────────────────

pub static TLS_ISSUER_SIGS: &[(&str, &str)] = &[
    ("let's encrypt",           "Let's Encrypt (automated/DevOps)"),
    ("letsencrypt",             "Let's Encrypt (automated/DevOps)"),
    ("zerossl",                 "ZeroSSL (automated)"),
    ("amazon",                  "AWS Certificate Manager"),
    ("digicert",                "DigiCert (Enterprise)"),
    ("sectigo",                 "Sectigo/Comodo"),
    ("comodo",                  "Comodo/Sectigo"),
    ("globalsign",              "GlobalSign"),
    ("entrust",                 "Entrust"),
    ("godaddy",                 "GoDaddy"),
    ("network solutions",       "Network Solutions"),
    ("thawte",                  "Thawte/DigiCert"),
    ("verisign",                "VeriSign (legacy)"),
    ("self-signed",             "Self-signed (development/misconfiguration)"),
    ("cloudflare",              "Cloudflare-managed TLS"),
    ("google trust services",   "Google Trust Services"),
    ("microsoft corporation",   "Microsoft"),
    ("apple inc",               "Apple"),
];

// ── HTTP response header sets → CDN / WAF ───────────────────────────────────

/// Identifies CDN/WAF from response header names (header name substring)
pub static CDN_HEADER_SIGS: &[(&str, &str)] = &[
    ("cf-ray",                  "Cloudflare CDN"),
    ("x-served-by",             "Fastly CDN"),
    ("x-cache",                 "Varnish/CDN Cache"),
    ("x-amz-cf-id",             "AWS CloudFront"),
    ("x-amz-request-id",       "AWS Service"),
    ("x-ms-request-id",        "Azure Service"),
    ("x-goog-",                 "Google Cloud"),
    ("x-akamai-",               "Akamai CDN"),
    ("x-cdn",                   "CDN-accelerated"),
    ("x-sucuri-id",             "Sucuri WAF"),
    ("x-waf-",                  "Web Application Firewall"),
    ("x-fw-server",             "Firewall-protected"),
    ("nel",                     "Network Error Logging (Cloudflare/enterprise)"),
];

// ── Utility functions ────────────────────────────────────────────────────────

/// Match a lowercase banner/header against a signature list.
/// Returns (product, os_hint, cve_hints) of first match.
pub fn match_banner(lower_banner: &str, sigs: &[Signature]) -> Option<(&'static str, Option<&'static str>, &'static [&'static str])> {
    for sig in sigs {
        if lower_banner.contains(sig.pattern) {
            return Some((sig.product, sig.os_hint, sig.cve_hints));
        }
    }
    None
}

/// Extract a version string after a known product token (e.g., "nginx/1.24.0").
/// Returns None if no '/' is present.
pub fn extract_version_after_slash(banner: &str, product_token: &str) -> Option<String> {
    let lower = banner.to_lowercase();
    let pos = lower.find(product_token)?;
    let after = &banner[pos + product_token.len()..];
    let slash_pos = after.find('/')?;
    let version_start = &after[slash_pos + 1..];
    let end = version_start.find(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '-')
        .unwrap_or(version_start.len());
    if end == 0 { None } else { Some(version_start[..end].to_string()) }
}

/// Identify DNS provider from a list of NS hostnames.
pub fn detect_dns_provider(ns_records: &[String]) -> Option<String> {
    for ns in ns_records {
        let lower = ns.to_lowercase();
        for (pattern, provider) in DNS_PROVIDER_SIGS {
            if lower.contains(pattern) {
                return Some(provider.to_string());
            }
        }
    }
    None
}

/// Identify mail provider from a list of MX exchange hostnames.
pub fn detect_mail_provider(mx_records: &[String]) -> Option<String> {
    for mx in mx_records {
        let lower = mx.to_lowercase();
        for (pattern, provider) in MAIL_PROVIDER_SIGS {
            if lower.contains(pattern) {
                return Some(provider.to_string());
            }
        }
    }
    None
}

/// Identify CDN/WAF from response header names.
pub fn detect_cdn_from_headers(header_names: &[String]) -> Option<String> {
    for name in header_names {
        let lower = name.to_lowercase();
        for (pattern, cdn) in CDN_HEADER_SIGS {
            if lower.contains(pattern) {
                return Some(cdn.to_string());
            }
        }
    }
    None
}
