use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub mode: RuntimeMode,
    pub server_host: String,
    pub server_port: u16,
    pub log_level: String,
    pub log_format: LogFormat,
    pub database_url: String,
    pub redis_url: Option<String>,
    pub worker_count: usize,
    pub collector_timeout_secs: u64,
    pub analyzer_timeout_secs: u64,
    
    // Cloud provider credentials (optional, can use env defaults)
    pub aws_region: Option<String>,
    pub azure_subscription_id: Option<String>,
    pub digitalocean_token: Option<String>,
    
    // Analyzer API keys
    pub shodan_api_key: Option<String>,
    pub virustotal_api_key: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: RuntimeMode::Local,
            server_host: "127.0.0.1".to_string(),
            server_port: 8080,
            log_level: "info".to_string(),
            log_format: LogFormat::Pretty,
            database_url: "sqlite://./data/garudaeye.db".to_string(),
            redis_url: None,
            worker_count: 4,
            collector_timeout_secs: 300,
            analyzer_timeout_secs: 60,
            aws_region: None,
            azure_subscription_id: None,
            digitalocean_token: None,
            shodan_api_key: None,
            virustotal_api_key: None,
        }
    }
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        use figment::{Figment, providers::{Env, Format, Toml}};
        
        let config: Config = Figment::new()
            .merge(Toml::file("garudaeye.toml").nested())
            .merge(Env::prefixed("").split("__"))
            .extract()?;
        
        Ok(config)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeMode {
    Local,
    Cloud,
}

impl std::fmt::Display for RuntimeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuntimeMode::Local => write!(f, "local"),
            RuntimeMode::Cloud => write!(f, "cloud"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Pretty,
    Json,
}
