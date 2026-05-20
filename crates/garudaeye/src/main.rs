use clap::Parser;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use std::sync::Arc;

mod server;
mod worker;
mod orchestrator;
mod relationship_builder;

pub use orchestrator::Orchestrator;
pub use relationship_builder::RelationshipBuilder;

#[derive(Parser, Debug)]
#[command(name = "garudaeye")]
#[command(author = "GarudaEye Team")]
#[command(version = "0.1.0")]
#[command(about = "Single-binary cloud asset discovery and security analysis tool", long_about = None)]
struct Cli {
    /// Runtime mode: local or cloud
    #[arg(short, long, env = "MODE", default_value = "local")]
    mode: String,
    
    /// Server host to bind to
    #[arg(long, env = "SERVER_HOST", default_value = "127.0.0.1")]
    host: String,
    
    /// Server port to bind to
    #[arg(short, long, env = "SERVER_PORT", default_value = "8080")]
    port: u16,
    
    /// Database URL
    #[arg(long, env = "DATABASE_URL", default_value = "sqlite://./data/garudaeye.db")]
    database_url: String,
    
    /// Redis URL (cloud mode only)
    #[arg(long, env = "REDIS_URL")]
    redis_url: Option<String>,
    
    /// Log level (trace, debug, info, warn, error)
    #[arg(long, env = "LOG_LEVEL", default_value = "info")]
    log_level: String,
    
    /// Log format (pretty or json)
    #[arg(long, env = "LOG_FORMAT", default_value = "pretty")]
    log_format: String,
    
    /// Number of worker threads
    #[arg(short, long, env = "WORKER_COUNT", default_value = "4")]
    workers: usize,
    
    /// Open browser after starting (local mode only)
    #[arg(long)]
    open: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install rustls crypto provider (must happen before any TLS usage)
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Load .env file if present
    let _ = dotenvy::dotenv();
    
    let cli = Cli::parse();
    
    // Initialize logging
    init_logging(&cli.log_format, &cli.log_level)?;
    
    tracing::info!(
        "Starting GarudaEye v{} in {} mode",
        env!("CARGO_PKG_VERSION"),
        cli.mode
    );
    
    // Initialize infrastructure based on mode
    let (asset_store, event_bus): (
        Arc<dyn infra::AssetStore + Send + Sync>,
        Arc<dyn infra::EventBus + Send + Sync>
    ) = if cli.mode == "cloud" {
        // Cloud mode: Postgres + Redis
        if cli.redis_url.is_none() {
            anyhow::bail!("REDIS_URL must be set in cloud mode");
        }
        
        tracing::info!("Initializing cloud infrastructure (Postgres + Redis)");
        let asset_store = infra::cloud::PostgresAssetStore::new(&cli.database_url).await?;
        let event_bus = infra::cloud::RedisEventBus::new(cli.redis_url.as_ref().unwrap()).await?;
        
        (
            Arc::new(asset_store),
            Arc::new(event_bus),
        )
    } else {
        // Local mode: SQLite + Memory channels
        tracing::info!("Initializing local infrastructure (SQLite + memory channels)");
        let asset_store = infra::local::SqliteAssetStore::new(&cli.database_url).await?;
        let event_bus = infra::local::MemoryEventBus::new();
        
        (
            Arc::new(asset_store),
            Arc::new(event_bus),
        )
    };
    
    // Start background workers
    tracing::info!("Starting {} background workers", cli.workers);
    let worker_handle = tokio::spawn(worker::run_workers(
        cli.workers,
        asset_store.clone(),
        event_bus.clone(),
    ));
    
    // Start HTTP server
    let server_addr = format!("{}:{}", cli.host, cli.port);
    tracing::info!("Starting HTTP server on {}", server_addr);
    
    if cli.open && cli.mode == "local" {
        let url = format!("http://{}:{}", cli.host, cli.port);
        tracing::info!("Opening browser to {}", url);
        let _ = open::that(&url);
    }
    
    let server_handle = tokio::spawn(server::serve(
        server_addr,
        asset_store,
        event_bus,
    ));
    
    // Wait for both to complete (or Ctrl+C)
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received Ctrl+C, shutting down...");
        }
        result = server_handle => {
            if let Err(e) = result {
                tracing::error!("Server error: {}", e);
            }
        }
        result = worker_handle => {
            if let Err(e) = result {
                tracing::error!("Worker error: {}", e);
            }
        }
    }
    
    tracing::info!("GarudaEye shutdown complete");
    Ok(())
}

fn init_logging(format: &str, level: &str) -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(level))
        .unwrap();
    
    if format == "json" {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().pretty())
            .init();
    }
    
    Ok(())
}
