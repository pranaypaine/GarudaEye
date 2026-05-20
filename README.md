![GarudaEye Logo](./images/logo.png)

![License](https://img.shields.io/github/license/riskprofiler/Cloud-Frontier)
![Supports AWS](https://img.shields.io/badge/Supports-AWS-orange)
![Supports GCP](https://img.shields.io/badge/Supports-GCP-1a73e8)
![Supports Azure](https://img.shields.io/badge/Supports-Azure-89c402)
![Supports DigitalOcean](https://img.shields.io/badge/Supports-DigitalOcean-0069ff)
![Supports Oracle Cloud](https://img.shields.io/badge/Supports-Oracle_Cloud-e55844)

> The Eye That Misses Nothing, Single-binary cloud asset discovery and security analysis tool built in Rust.

GarudaEye scans your cloud infrastructure, builds a live inventory of all assets, maps their relationships, and enriches public-facing resources with a built-in passive fingerprinting engine — all from one self-contained binary with an embedded web dashboard. No external API keys required.

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Installation on a New System](#installation-on-a-new-system)
- [Configuration](#configuration)
- [Running](#running)
- [API Reference](#api-reference)
- [Web Dashboard](#web-dashboard)
- [AWS Setup](#aws-setup)
- [Architecture](#architecture)
- [Development](#development)
- [Roadmap](#roadmap)

---

## Features

- **17 AWS resource types** — EC2, S3, RDS, ELB, Lambda, EKS, ECS, ElastiCache, Elasticsearch, Elastic Beanstalk, API Gateway, CloudFront, Route53, DynamoDB, SQS, SNS, VPC/Subnets/Security Groups
- **Multi-region scanning** — scan all regions simultaneously or specify a list
- **Relationship mapping** — automatically links VPCs → subnets → instances → security groups → load balancers
- **Passive fingerprinting engine** — built-in, no API key required; resolves DNS, negotiates TLS, probes HTTP/HTTPS, grabs service banners, identifies cloud providers and ASN, detects OS and technologies, scores risk 0–100
- **Attack path analysis** — detects 7 classes of attack vectors: exposed databases, insecure protocols, weak/expired TLS, exposed admin interfaces, CVE vectors, lateral movement paths, and missing security headers
- **Risk scoring** — every asset scored 0–100; Critical (≥70), High (40–69), Medium (10–39)
- **Embedded Vue.js dashboard** — interactive asset inventory, attack surface view, relationship graph, fingerprint detail panels, and security posture metrics
- **Two runtime modes** — local (SQLite + in-memory queue, zero dependencies) and cloud (Postgres + Redis)
- **Single static binary** — compiled to x86\_64 MUSL, no runtime dependencies

---

## Quick Start

If Rust and Node.js are already installed:

```bash
git clone https://github.com/pranaypaine/GarudaEye
cd GarudaEye
cp .env.example .env
cd frontend && npm install && cd ..
cargo run -- --open
```

The dashboard opens at `http://127.0.0.1:8080`. For a fresh machine, see [Installation on a New System](#installation-on-a-new-system) first.

---

## Installation on a New System

### 1. System Packages

**Ubuntu / Debian**

```bash
sudo apt update
sudo apt install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    libsqlite3-dev \
    musl-tools \
    curl \
    git
```

**Fedora / RHEL / Amazon Linux 2023**

```bash
sudo dnf install -y \
    gcc make pkg-config \
    openssl-devel sqlite-devel \
    musl-gcc curl git
```

**macOS** (Homebrew)

```bash
brew install pkg-config openssl sqlite
```

> `musl-tools` / `musl-gcc` is only required for the static release build. Debug builds use the host toolchain.

---

### 2. Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

The project's `rust-toolchain.toml` pins the `stable` channel and automatically installs the required components (`rustfmt`, `clippy`) and the `x86_64-unknown-linux-musl` target on first use.

```bash
rustc --version   # rustc 1.78+ expected
cargo --version
```

---

### 3. Install Node.js 18+

Node.js is only needed to build the embedded frontend. It is **not** required to run the release binary.

**Ubuntu / Debian**

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
```

**macOS**

```bash
brew install node
```

**Fedora / RHEL**

```bash
sudo dnf install -y nodejs npm
```

```bash
node --version   # v18+ required
npm --version
```

---

### 4. Clone and Build

```bash
git clone https://github.com/pranaypaine/GarudaEye
cd GarudaEye

# Copy environment template
cp .env.example .env

# Install frontend dependencies (required — cargo build embeds the UI)
cd frontend && npm install && cd ..

# Development build
cargo build

# Or release build (static MUSL binary, ~20 MB)
./scripts/release.sh
```

`cargo build` runs `build.rs` which automatically calls `npm run build` inside `frontend/` and embeds the compiled assets — no separate web server needed in production.

---

### 5. Run

```bash
# Debug binary (fast compile)
./target/debug/garudaeye --open

# Release binary (optimised, static)
./target/x86_64-unknown-linux-musl/release/garudaeye --open
```

---

### Complete One-Liner Walkthrough (Ubuntu/Debian)

```bash
# System packages
sudo apt update && sudo apt install -y \
    build-essential pkg-config libssl-dev libsqlite3-dev musl-tools curl git

# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# Build and run
git clone https://github.com/pranaypaine/GarudaEye && cd GarudaEye
cp .env.example .env
cd frontend && npm install && cd ..
cargo build
./target/debug/garudaeye --open
```

### Pre-built Binaries

Download from the [Releases](https://github.com/pranaypaine/GarudaEye/releases) page. The binary is fully static — copy and run:

```bash
chmod +x garudaeye
./garudaeye --open
```

---

## Configuration

Configuration is loaded in priority order: **CLI flags → environment variables → `garudaeye.toml` → defaults**.

### Environment Variables

Copy `.env.example` to `.env` and edit:

```bash
cp .env.example .env
```

#### Core

| Variable | Default | Description |
|---|---|---|
| `MODE` | `local` | Runtime mode: `local` or `cloud` |
| `SERVER_HOST` | `127.0.0.1` | Bind address |
| `SERVER_PORT` | `8080` | HTTP port |
| `LOG_LEVEL` | `info` | One of: `trace`, `debug`, `info`, `warn`, `error` |
| `LOG_FORMAT` | `pretty` | `pretty` (human-readable) or `json` (structured) |

#### Database

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `sqlite://./data/garudaeye.db` | SQLite path (local mode) or Postgres URL (cloud mode) |

Cloud mode Postgres example:
```
DATABASE_URL=postgres://user:password@localhost:5432/garudaeye
```

#### Redis (cloud mode only)

| Variable | Default | Description |
|---|---|---|
| `REDIS_URL` | — | Required in cloud mode. Example: `redis://localhost:6379` |

#### AWS

| Variable | Default | Description |
|---|---|---|
| `AWS_ACCESS_KEY_ID` | — | IAM access key |
| `AWS_SECRET_ACCESS_KEY` | — | IAM secret key |
| `AWS_DEFAULT_REGION` | — | Fallback region if `AWS_REGIONS` is not set |
| `AWS_REGIONS` | `us-east-1,us-west-2,eu-west-1` | Comma-separated list of regions to scan. Set to `all` to scan every available region |

> Global services (CloudFront, Route53) are always collected once from `us-east-1` regardless of region list.

#### Security Analyzers

| Variable | Default | Description |
|---|---|---|
| `SHODAN_API_KEY` | — | Shodan API key for IP/domain enrichment. Free tier supported |
| `VIRUSTOTAL_API_KEY` | — | VirusTotal API key (Phase 6) |

#### Workers

| Variable | Default | Description |
|---|---|---|
| `WORKER_COUNT` | `4` | Number of background analysis workers |
| `COLLECTOR_TIMEOUT_SECS` | `300` | Per-collector timeout in seconds |
| `ANALYZER_TIMEOUT_SECS` | `60` | Per-analysis timeout in seconds |

### Config File (`garudaeye.toml`)

Alternatively, create a `garudaeye.toml` in the working directory:

```toml
mode = "local"
server_host = "0.0.0.0"
server_port = 8080
log_level = "info"
log_format = "pretty"
database_url = "sqlite://./data/garudaeye.db"
worker_count = 4
collector_timeout_secs = 300
analyzer_timeout_secs = 60
```

### CLI Flags

All options can be passed directly:

```
USAGE:
    garudaeye [OPTIONS]

OPTIONS:
    -m, --mode <MODE>               Runtime mode: local or cloud [env: MODE] [default: local]
        --host <HOST>               Bind address [env: SERVER_HOST] [default: 127.0.0.1]
    -p, --port <PORT>               HTTP port [env: SERVER_PORT] [default: 8080]
        --database-url <URL>        Database URL [env: DATABASE_URL]
        --redis-url <URL>           Redis URL — required in cloud mode [env: REDIS_URL]
        --log-level <LEVEL>         Log level [env: LOG_LEVEL] [default: info]
        --log-format <FORMAT>       Log format: pretty or json [env: LOG_FORMAT] [default: pretty]
    -w, --workers <N>               Background worker count [env: WORKER_COUNT] [default: 4]
        --open                      Open the dashboard in a browser after startup
    -h, --help                      Print help
    -V, --version                   Print version
```

---

## Running

### Local Mode (default)

Uses SQLite and in-memory event queues. No external dependencies.

```bash
# Quickstart
./garudaeye --open

# Custom port
./garudaeye --port 9090 --open

# With Shodan enrichment
SHODAN_API_KEY=your_key ./garudaeye --open

# Scan all AWS regions
AWS_REGIONS=all ./garudaeye --open

# Scan specific regions
AWS_REGIONS=us-east-1,eu-west-1,ap-south-1 ./garudaeye --open
```

### Cloud Mode

Uses Postgres for persistence and Redis for the worker event bus. Suitable for long-running server deployments.

```bash
export MODE=cloud
export DATABASE_URL=postgres://user:password@localhost:5432/garudaeye
export REDIS_URL=redis://localhost:6379
./garudaeye --mode cloud
```

### Development (with hot reload)

```bash
./scripts/dev.sh
```

Requires `cargo-watch` for auto-reload on file changes:
```bash
cargo install cargo-watch
```

### Docker

```bash
docker build -t garudaeye:latest .

docker run -p 8080:8080 \
  -e MODE=cloud \
  -e DATABASE_URL=postgres://user:pass@db:5432/garudaeye \
  -e REDIS_URL=redis://redis:6379 \
  -e AWS_ACCESS_KEY_ID=... \
  -e AWS_SECRET_ACCESS_KEY=... \
  garudaeye:latest
```

---

## API Reference

All endpoints are under the `/api` prefix. The dashboard at `/` is served by the embedded frontend.

### Health

```http
GET /api/health
→ 200 OK
```

### Start Collection

Triggers a full AWS asset scan in the background. Returns immediately.

```http
GET /api/start
→ { "message": "Collection started", "status": "running" }
```

### List Assets

```http
GET /api/assets
  ?asset_type=ip_address     # Filter by type (ip_address, load_balancer, database, …)
  &provider=aws              # Filter by provider
  &region=us-east-1          # Filter by region
  &search=my-bucket          # Full-text search on sk / resource_id / service
  &public_access=true        # true or false
  &encryption_enabled=false  # true or false
  &limit=100                 # Max results (default: all)
```

### Get Asset Detail

```http
GET /api/assets/:asset_id
```

### Dashboard Summary

```http
GET /api/dashboard/dashboard
→ {
    "total_assets": 247,
    "public_assets": 18,
    "unencrypted_assets": 5,
    "assets_with_open_ports": 34,
    "vulnerabilities": 12,
    "total_relationships": 412,
    "high_risk_assets": 7,
    "medium_risk_assets": 23,
    "by_type": { "ip_address": 12, "database": 8, … }
  }
```

### Port Statistics

```http
GET /api/dashboard/common_ports     # Top 20 ports by prevalence
GET /api/dashboard/admin_ports      # Admin/sensitive ports only
```

### Attack Paths

```http
GET /api/attack-paths
→ [
    {
      "id": "...",
      "path_type": "ExposedDatabase",
      "severity": "Critical",
      "description": "...",
      "entry_asset_id": "...",
      "entry_asset_name": "prod-rds",
      "affected_ports": [3306],
      "evidence": ["Port 3306 open", "Public access enabled"],
      "remediation": "...",
      "downstream_assets": ["..."]
    }
  ]
```

### Relationships

```http
GET /api/relationships                  # All relationships
GET /api/relationships/:asset_id        # Relationships for one asset
GET /api/graph                          # Graph data (nodes + edges) for the map view
```

---

## Web Dashboard

The Vue.js frontend is compiled and embedded into the binary at build time. No separate web server or Node.js runtime is required in production.

| Page | URL | Description |
|---|---|---|
| Dashboard | `/` | Security posture summary, asset counts, risk distribution |
| Assets | `/assets` | Filterable table with security badges and CVE counts |
| Asset Detail | `/assets/:id` | Full fingerprint panel: TLS cert, DNS, HTTP headers, banners, ASN/geo, CVE hints, risk meter |
| Assets Map | `/assets-map` | Force-directed relationship graph with zoom, pan, and type filtering |
| Attack Surface | `/attack-surface` | 3×3 stat grid, calculated attack paths with severity and remediation guidance |

The **Start Scan** button in the navbar triggers a collection and shows live progress. Click any attack path entry asset to jump directly to its detail page.

---

## AWS Setup

### Required IAM Permissions

GarudaEye only needs read-only access. Attach the following policy to your IAM user or role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketEncryption",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging",
        "s3:GetBucketTagging",
        "elasticloadbalancing:Describe*",
        "rds:DescribeDBInstances",
        "rds:ListTagsForResource",
        "elasticache:DescribeCacheClusters",
        "es:ListDomainNames",
        "es:DescribeElasticsearchDomain",
        "eks:ListClusters",
        "eks:DescribeCluster",
        "ecs:ListClusters",
        "ecs:DescribeClusters",
        "ecs:ListServices",
        "ecs:DescribeServices",
        "lambda:ListFunctions",
        "lambda:GetFunctionConfiguration",
        "elasticbeanstalk:DescribeEnvironments",
        "apigateway:GET",
        "cloudfront:ListDistributions",
        "route53:ListHostedZones",
        "route53:ListResourceRecordSets",
        "dynamodb:ListTables",
        "dynamodb:DescribeTable",
        "sqs:ListQueues",
        "sqs:GetQueueAttributes",
        "sns:ListTopics",
        "sns:GetTopicAttributes"
      ],
      "Resource": "*"
    }
  ]
}
```

### Authentication Methods

GarudaEye uses the standard AWS SDK credential chain — any of these methods work:

**1. Environment variables (recommended for CI/local)**
```bash
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1
```

**2. AWS credentials file**
```ini
# ~/.aws/credentials
[default]
aws_access_key_id = AKIA...
aws_secret_access_key = ...
```

**3. IAM instance profile / ECS task role**  
No configuration needed — the SDK picks up the attached role automatically when running on EC2, ECS, or Lambda.

**4. AWS SSO / named profile**
```bash
export AWS_PROFILE=my-profile
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                         garudaeye                            │
│                                                              │
│  ┌─────────┐   ┌────────────┐   ┌──────────┐   ┌────────┐  │
│  │   CLI   │   │ HTTP Server│   │  Workers │   │Frontend│  │
│  │ (clap)  │   │  (axum)    │   │  (tokio) │   │ (Vue3) │  │
│  └─────────┘   └─────┬──────┘   └────┬─────┘   └────────┘  │
│                       │               │                      │
│              ┌────────▼───────────────▼────────┐            │
│              │         Orchestrator              │            │
│              └────────┬───────────────┬─────────┘            │
│                       │               │                      │
│              ┌────────▼──────┐  ┌────▼──────────┐           │
│              │  Collectors   │  │   Analyzers          │     │
│              │  (17 AWS)     │  │  Fingerprint Engine  │     │
│              └────────┬──────┘  │  DNS·TLS·HTTP·Banners│     │
│                       │         │  ASN·OS·Risk Score   │     │
│                       │         └─────────────────────┘     │
│                       │                                      │
│              ┌────────▼──────────────────┐                  │
│              │       Infrastructure       │                  │
│              │  AssetStore  │  EventBus   │                  │
│              │  SQLite/PG   │  Mem/Redis  │                  │
│              └───────────────────────────┘                  │
└──────────────────────────────────────────────────────────────┘
```

### Crate Overview

| Crate | Purpose |
|---|---|
| `garudaeye` | Binary entry point, CLI, HTTP server, orchestrator, background workers |
| `garudaeye_core` | Domain types: `Asset`, `Config`, `AssetType`, error types |
| `infra` | `AssetStore` and `EventBus` traits + SQLite, Postgres, in-memory, Redis implementations |
| `collectors` | AWS asset collectors — one module per service type |
| `analyzers` | Passive fingerprinting engine: DNS, TLS, HTTP/HTTPS, banner grabbing, cloud/ASN detection, OS/tech detection, risk scoring |
| `api` | Axum route handlers: assets, dashboard, attack paths, relationships, graph |

### Fingerprinting Engine

Sub-modules in `crates/analyzers/src/fingerprint/`:

| Module | What it does |
|---|---|
| `dns` | Resolves A/AAAA/MX/TXT/SOA, detects SPF/DMARC/DNSSEC, identifies DNS provider |
| `tls` | Fetches TLS certificate, extracts subject/issuer/SANs/expiry, detects self-signed |
| `http` | HTTP GET — status, server header, title, content length, security issues |
| `https` | HTTPS GET — same as HTTP plus HSTS, CSP, technology detection |
| `banner` | TCP banner grab on common ports, maps to product/version/CVE hints |
| `cloud` | Detects AWS/Azure/GCP/Cloudflare hosting from rDNS, headers, and ASN |
| `asn` | ASN and geolocation lookup |
| `signatures` | Technology signature matching from HTTP responses |

### Attack Path Types

| Type | Severity | Detection |
|---|---|---|
| `ExposedDatabase` | Critical | Database-type asset or DB ports (3306, 5432, 27017, etc.) open to internet |
| `InsecureProtocol` | Critical | FTP (21), Telnet (23), TFTP (69), or SNMP (161/162) ports open |
| `WeakTLS` | High/Medium | Self-signed cert, expired cert, or expiring within 14 days on a public asset |
| `ExposedAdminInterface` | High | Admin ports (22, 3389, 8080, 8443, 9200, etc.) open with public access enabled |
| `CVEVector` | Critical/High | Non-empty CVE hints on a public asset |
| `LateralMovement` | High | Public asset with relationships to internal databases, caches, or queues |
| `MissingSecurityHeaders` | Medium | Missing HSTS or CSP on a public HTTPS asset |

### Data Flow

1. **Collection** — Orchestrator iterates regions, runs all collectors in sequence. Each collector calls the AWS SDK, maps responses to `Asset` structs, persists to `AssetStore`, and publishes IP/domain events to the `EventBus`.
2. **Fingerprinting** — Worker pool consumes events. For each public asset, all fingerprint sub-modules run in sequence. Results are merged into a `Fingerprint` struct, serialised to JSON, and stored in `asset.configuration`. `risk_score` and `os_guess` are written directly to the asset row.
3. **Relationships** — After all collectors finish, `RelationshipBuilder` queries the asset store and creates edges between related assets (EC2 → VPC, ELB → EC2, Lambda → SQS).
4. **API** — Axum handlers read from `AssetStore`. `/api/attack-paths` computes attack paths on-the-fly from assets and relationships. The embedded Vue frontend consumes all endpoints.

---

## Development

### Running Tests

```bash
cargo test --workspace
```

### Code Quality

```bash
cargo fmt --all
cargo clippy --workspace -- -D warnings
cargo audit        # requires: cargo install cargo-audit
```

### Database Migrations

Migrations run automatically on startup. To add a new migration:

```bash
cargo install sqlx-cli --no-default-features --features sqlite,postgres
sqlx migrate add migration_description
# Edit the generated file in migrations/
sqlx migrate run --database-url sqlite://./data/garudaeye.db
```

### Frontend Development

The frontend is a standard Vite + Vue 3 project in `frontend/`. It is automatically compiled and embedded into the binary via `build.rs`.

```bash
cd frontend
npm install
npm run dev          # Standalone dev server (proxies /api to localhost:8080)
npm run build        # Build for embedding (done automatically by cargo build)
```

---

## License

MIT — see [LICENSE](LICENSE) for details.

---
