use aws_sdk_lambda::Client;
use garudaeye_core::{Asset, AssetType, CloudProvider};
use infra::traits::{AssetStore, EventBus};
use tracing::{info, error, debug};

pub struct LambdaCollector {
    client: Client,
    region: String,
}

impl LambdaCollector {
    pub async fn new(config: &aws_config::SdkConfig, region: String) -> Self {
        let client = Client::new(config);
        Self { client, region }
    }

    pub async fn collect(
        &self,
        asset_store: &dyn AssetStore,
        _event_bus: &dyn EventBus,
    ) -> anyhow::Result<()> {
        info!("Starting Lambda collection...");

        let mut count = 0;

        let result = self.client.list_functions().send().await;

        match result {
            Ok(output) => {
                for function in output.functions.unwrap_or_default() {
                    let function_name = match function.function_name() {
                        Some(n) => n.to_string(),
                        None => continue,
                    };

                    let mut asset = Asset::new(
                        AssetType::Lambda,
                        function_name.clone(),
                        CloudProvider::Aws,
                    );

                    asset.service = Some("Lambda".to_string());
                    asset.resource_id = Some(function_name.clone());
                    asset.arn = function.function_arn().map(|s| s.to_string());
                    asset.region = Some(self.region.clone());

                    // Extract region from ARN
                    if let Some(arn) = function.function_arn() {
                        let parts: Vec<&str> = arn.split(':').collect();
                        if parts.len() > 3 {
                            asset.region = Some(parts[3].to_string());
                        }
                    }

                    // VPC config
                    if let Some(vpc_config) = function.vpc_config() {
                        asset.vpc_id = vpc_config.vpc_id()
                            .filter(|s| !s.is_empty())
                            .map(|s| s.to_string());

                        let subnet_ids: Vec<String> = vpc_config.subnet_ids()
                            .iter()
                            .map(|s| s.to_string())
                            .collect();
                        asset.subnet_id = subnet_ids.first().cloned();

                        let sg_ids: Vec<String> = vpc_config.security_group_ids()
                            .iter()
                            .map(|s| s.to_string())
                            .collect();
                        if !sg_ids.is_empty() {
                            asset.security_groups = Some(sg_ids);
                        }
                    }

                    asset.iam_role = function.role().map(|s| s.to_string());

                    // Env var keys (not values for security)
                    let env_var_keys: Vec<String> = function.environment()
                        .and_then(|e| e.variables())
                        .map(|vars| vars.keys().map(|k| k.to_string()).collect())
                        .unwrap_or_default();

                    // Layers
                    let layers: Vec<serde_json::Value> = function.layers()
                        .iter()
                        .map(|l| serde_json::json!({
                            "arn": l.arn(),
                            "code_size": l.code_size(),
                        }))
                        .collect();

                    // File system configs (EFS)
                    let fs_configs: Vec<serde_json::Value> = function.file_system_configs()
                        .iter()
                        .map(|fs| serde_json::json!({
                            "arn": fs.arn(),
                            "local_mount_path": fs.local_mount_path(),
                        }))
                        .collect();

                    // Function URL — check if it has a public HTTP endpoint
                    let function_url_config = match self.client
                        .get_function_url_config()
                        .function_name(&function_name)
                        .send()
                        .await
                    {
                        Ok(url_config) => {
                            let url = url_config.function_url().to_string();
                            let auth_type = url_config.auth_type().as_str().to_string();
                            let is_public = auth_type == "NONE";
                            if is_public {
                                asset.public_access = Some(true);
                            }
                            Some(serde_json::json!({
                                "function_url": url,
                                "auth_type": auth_type,
                                "creation_time": url_config.creation_time(),
                                "last_modified_time": url_config.last_modified_time(),
                                "cors": url_config.cors().map(|c| serde_json::json!({
                                    "allow_origins": c.allow_origins(),
                                    "allow_methods": c.allow_methods(),
                                    "allow_headers": c.allow_headers(),
                                    "expose_headers": c.expose_headers(),
                                    "allow_credentials": c.allow_credentials(),
                                    "max_age": c.max_age(),
                                })),
                            }))
                        }
                        Err(_) => None,
                    };

                    // Reserved concurrency
                    let reserved_concurrency = match self.client
                        .get_function_concurrency()
                        .function_name(&function_name)
                        .send()
                        .await
                    {
                        Ok(c) => c.reserved_concurrent_executions(),
                        Err(_) => None,
                    };

                    let config_json = serde_json::json!({
                        "function_name": function_name,
                        "function_arn": function.function_arn(),
                        "runtime": function.runtime().map(|r| r.as_str()),
                        "handler": function.handler(),
                        "code_size": function.code_size(),
                        "code_sha256": function.code_sha256(),
                        "memory_size": function.memory_size(),
                        "timeout": function.timeout(),
                        "last_modified": function.last_modified(),
                        "description": function.description(),
                        "role": function.role(),
                        "package_type": function.package_type().map(|p| p.as_str()),
                        "architectures": function.architectures()
                            .iter()
                            .map(|a| a.as_str())
                            .collect::<Vec<_>>(),
                        "ephemeral_storage_size": function.ephemeral_storage()
                            .map(|e| e.size()),
                        "dead_letter_queue": function.dead_letter_config()
                            .and_then(|d| d.target_arn())
                            .map(|s| s.to_string()),
                        "tracing_mode": function.tracing_config()
                            .and_then(|t| t.mode())
                            .map(|m| m.as_str()),
                        "snap_start_apply_on": function.snap_start()
                            .and_then(|s| s.apply_on())
                            .map(|a| a.as_str()),
                        "snap_start_optimization_status": function.snap_start()
                            .and_then(|s| s.optimization_status())
                            .map(|s| s.as_str()),
                        "has_environment_variables": !env_var_keys.is_empty(),
                        "environment_variable_keys": env_var_keys,
                        "layers": layers,
                        "file_system_configs": fs_configs,
                        "vpc_config": function.vpc_config().map(|v| serde_json::json!({
                            "vpc_id": v.vpc_id(),
                            "subnet_ids": v.subnet_ids(),
                            "security_group_ids": v.security_group_ids(),
                        })),
                        "function_url": function_url_config,
                        "reserved_concurrency": reserved_concurrency,
                    });

                    asset.configuration = Some(config_json);
                    asset_store.insert(asset.clone()).await?;

                    count += 1;
                    debug!("Collected Lambda function: {}", function_name);
                }
            }
            Err(e) => {
                error!("Failed to list Lambda functions: {}", e);
            }
        }

        info!("Lambda collection complete. Collected {} functions", count);
        Ok(())
    }
}

