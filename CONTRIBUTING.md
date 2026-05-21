# Contributing to GarudaEye

Thank you for your interest in contributing to GarudaEye — a cloud-native attack surface discovery and security analysis tool. We welcome all contributions, from bug fixes to new cloud provider collectors.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Project Structure](#project-structure)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Reporting Bugs](#reporting-bugs)
- [Requesting Features](#requesting-features)
- [Coding Standards](#coding-standards)

---


## Getting Started

1. **Fork** the repository on GitHub.
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/<your-username>/GarudaEye.git
   cd GarudaEye
   ```
3. Add the upstream remote:
   ```bash
   git remote add upstream https://github.com/pranaypaine/GarudaEye.git
   ```

---

## Project Structure

GarudaEye is a Cargo workspace with six crates:

| Crate | Purpose |
|---|---|
| `crates/garudaeye` | Binary entry point — CLI, server, orchestrator, relationship builder, background workers |
| `crates/garudaeye_core` | Shared domain types — `Asset`, `AssetType`, `CloudProvider`, `Config`, `Error` |
| `crates/infra` | Storage/queue trait definitions and adapters (SQLite local, Postgres/Redis cloud) |
| `crates/collectors` | Per-resource-type cloud collectors (currently 17 AWS collectors) |
| `crates/analyzers` | Enrichment analyzers — Shodan (active); VirusTotal/Observatory (planned) |
| `crates/api` | Axum HTTP router and handlers for the REST API |

The `frontend/` directory contains a Vue.js 3 SPA built with Vite. The compiled output is embedded into the binary via `rust-embed`.

---

## Development Setup

### Prerequisites

- **Rust** (see `rust-toolchain.toml` for the pinned toolchain version)
- **Node.js** ≥ 18 and **npm** (for the frontend)
- **AWS credentials** configured in environment or `~/.aws/credentials` (for running collectors)
- Optional: a **Shodan API key** for enrichment (`SHODAN_API_KEY` env var)

### Build

```bash
# 1. Build the frontend first (required — binary embeds the compiled SPA)
cd frontend && npm install && npm run build && cd ..

# 2. Build the full workspace
cargo build

# 3. Run locally (opens browser at http://127.0.0.1:8080)
cargo run -- --open

# 4. Run on a custom port
cargo run -- --port 8000
```

### Release Build (static musl binary)

```bash
./scripts/release.sh
```

### Running Tests

```bash
cargo test --workspace
```

### Development Server (hot reload)

```bash
./scripts/dev.sh
```

---

## Making Changes

1. **Sync with upstream** before starting:
   ```bash
   git fetch upstream
   git rebase upstream/master
   ```
2. **Create a feature branch** from `master`:
   ```bash
   git checkout -b feat/my-feature
   ```
3. Make your changes, keeping commits focused and atomic.
4. **Run the full test suite** and ensure it passes:
   ```bash
   cargo test --workspace
   cargo clippy --workspace -- -D warnings
   cargo fmt --check
   ```

### Adding a New Cloud Collector

New collectors live in `crates/collectors/src/<provider>/`. Follow the pattern of an existing AWS collector (e.g., `crates/collectors/src/aws/ec2.rs`):

1. Implement the collector function returning `Vec<Asset>`.
2. Register the new `AssetType` variant in `crates/garudaeye_core/src/asset.rs` if needed.
3. Wire the collector into the orchestrator in `crates/garudaeye/src/orchestrator.rs`.
4. Add relationship-building logic in `crates/garudaeye/src/relationship_builder.rs` if applicable.
5. Add a migration in `migrations/` if new columns are required.

### Adding a New Analyzer

Analyzers live in `crates/analyzers/src/`. Implement the enrichment logic and register it in `crates/analyzers/src/lib.rs`.

---

## Submitting a Pull Request

1. Push your branch to your fork:
   ```bash
   git push origin feat/my-feature
   ```
2. Open a Pull Request against the `master` branch of the upstream repository.
3. Fill in the PR template completely, including:
   - A clear description of **what** changed and **why**
   - Reference to any related issues (`Closes #123`)
   - Notes on testing performed
4. Ensure all CI checks pass before requesting review.
5. Address review feedback promptly. Maintainers may request changes before merging.

PRs that introduce new features without tests will not be merged.

---

## Reporting Bugs

Please [open a GitHub issue](https://github.com/pranaypaine/GarudaEye/issues/new) and include:

- GarudaEye version or commit SHA
- Operating system and architecture
- Steps to reproduce
- Expected vs. actual behaviour
- Relevant log output (redact any credentials or API keys)

For **security vulnerabilities**, do **not** open a public issue. See [SECURITY.md](SECURITY.md).

---

## Requesting Features

Open a GitHub issue with the `enhancement` label. Describe the use case first — we evaluate features based on alignment with the project's goal of cloud-native attack surface management.

---

## Coding Standards

- **Format:** `cargo fmt` before every commit. CI enforces this.
- **Lints:** code must pass `cargo clippy -- -D warnings` with no suppressions without justification.
- **Error handling:** use the `garudaeye_core::Error` type for cross-crate errors; avoid `.unwrap()` in library code.
- **Secrets:** never log or expose credentials, API keys, or tokens — not even in debug builds.
- **SQL:** always use parameterised queries via `sqlx`; never construct SQL strings with user-supplied or runtime values.
- **Tests:** add unit tests alongside new logic; integration tests go in `tests/` within the relevant crate.
- **Dependencies:** discuss new dependencies in the issue before adding them; minimise the build surface.

---
