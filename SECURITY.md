# Security Policy

GarudaEye is a security-focused tool for cloud attack surface discovery. We take the security of the project itself seriously and are committed to handling vulnerability reports responsibly.

---

## Supported Versions

Only the latest release on the `master` branch receives security fixes. We do not backport patches to older releases.

| Version | Supported |
|---|---|
| Latest (`master`) | ✅ Yes |
| Older releases | ❌ No |

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report vulnerabilities through one of the following private channels:

1. **GitHub Private Security Advisory** (preferred): [Report a vulnerability](https://github.com/pranaypaine/GarudaEye/security/advisories/new) using GitHub's built-in private disclosure flow.
2. **Email:** Send a report to the maintainers at the address pranaykumarpaine@gmail.com. Encrypt your message with our PGP key if the information is sensitive.

### What to Include

A useful report includes:

- A description of the vulnerability and its potential impact
- The affected component (crate name and file path if known)
- Steps to reproduce or a proof-of-concept
- Any suggested remediation

Redact real credentials, API keys, or production data from your report.

---

## Response Timeline

| Stage | Target |
|---|---|
| Acknowledgement of report | Within 3 business days |
| Initial triage and severity assessment | Within 7 business days |
| Fix developed and reviewed | Within 30 days for Critical/High; 90 days for Medium/Low |
| Public disclosure | Coordinated with the reporter after the fix is released |

We follow responsible disclosure. We will credit reporters in the release notes unless they prefer to remain anonymous.

---

## Severity Classification

We use the [CVSS v3.1](https://www.first.org/cvss/v3-1/) scoring system for severity assessment and align with the following labels:

| Severity | CVSS Score |
|---|---|
| Critical | 9.0 – 10.0 |
| High | 7.0 – 8.9 |
| Medium | 4.0 – 6.9 |
| Low | 0.1 – 3.9 |

---

## Security Design Principles

GarudaEye is built with the following security expectations:

- **No credentials are stored by the tool.** AWS credentials and API keys are consumed at runtime from environment variables or the standard AWS credential chain and are never persisted to disk.
- **API keys must not appear in logs.** All external API integrations (e.g., Shodan) must pass credentials in request headers or the request body — never as URL query parameters.
- **All database queries must use parameterised statements.** String interpolation into SQL is prohibited.
- **The local API server binds to `127.0.0.1` by default.** It must not be exposed to untrusted networks without authentication and TLS in place.
- **Authentication is required on all API endpoints** that trigger actions (e.g., `/start`, `/enrich`).

---

## Known Security Issues

The following issues have been identified and are being actively worked on. They are documented here in the spirit of transparency and responsible disclosure.

| ID | Severity | Component | Description | Status |
|---|---|---|---|---|
| C-1 | **Critical** | `crates/analyzers/src/shodan.rs` | Shodan API key passed as a URL query parameter, exposing it in HTTP logs and server access logs | In progress |
| C-2 | **Critical** | `crates/infra/src/cloud/` | Cloud mode (Postgres/Redis) panics on first use due to unimplemented methods | In progress |
| C-3 | **High** | `crates/infra/src/local/sqlite.rs` | SQL filter clauses constructed with runtime string formatting, creating SQL injection risk | In progress |
| H-6 | **High** | `crates/api/src/lib.rs` | No authentication on any HTTP endpoint, including write-action endpoints `/start` and `/enrich` | In progress |

If you have found a new issue not listed above, please report it via the private channel described in this document.

---

## Out of Scope

The following are considered out of scope for this security policy:

- Vulnerabilities in third-party dependencies (report those directly to the respective upstream projects; we will update our dependency tree as fixes are released)
- Issues that require physical access to the machine running GarudaEye
- Social engineering attacks
- Denial-of-service attacks against the local development server
- Issues in the `target/` build output directory

---

## Security Acknowledgements

We thank the following individuals for responsibly disclosing security issues:

*(No disclosures yet — your name could be first.)*
