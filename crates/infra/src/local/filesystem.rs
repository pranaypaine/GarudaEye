use async_trait::async_trait;
use std::path::PathBuf;
use tokio::fs;
use tracing::debug;

/// Local filesystem-based object storage
pub struct FilesystemObjectStore {
    base_path: PathBuf,
}

impl FilesystemObjectStore {
    pub async fn new(base_path: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let base_path = base_path.into();
        fs::create_dir_all(&base_path).await?;
        
        Ok(Self { base_path })
    }
    
    fn resolve_path(&self, key: &str) -> PathBuf {
        self.base_path.join(key)
    }
}

#[async_trait]
impl crate::traits::ObjectStore for FilesystemObjectStore {
    async fn put(&self, key: &str, data: &[u8]) -> anyhow::Result<()> {
        let path = self.resolve_path(key);
        
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }
        
        fs::write(&path, data).await?;
        debug!("Wrote {} bytes to {}", data.len(), path.display());
        
        Ok(())
    }
    
    async fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let path = self.resolve_path(key);
        
        if !path.exists() {
            return Ok(None);
        }
        
        let data = fs::read(&path).await?;
        debug!("Read {} bytes from {}", data.len(), path.display());
        
        Ok(Some(data))
    }
    
    async fn delete(&self, key: &str) -> anyhow::Result<()> {
        let path = self.resolve_path(key);
        
        if path.exists() {
            fs::remove_file(&path).await?;
            debug!("Deleted {}", path.display());
        }
        
        Ok(())
    }
    
    async fn list(&self, prefix: &str) -> anyhow::Result<Vec<String>> {
        let prefix_path = self.resolve_path(prefix);
        let mut results = Vec::new();
        
        if !prefix_path.exists() {
            return Ok(results);
        }
        
        let mut entries = fs::read_dir(&prefix_path).await?;
        
        while let Some(entry) = entries.next_entry().await? {
            if let Ok(name) = entry.file_name().into_string() {
                results.push(format!("{}/{}", prefix, name));
            }
        }
        
        debug!("Listed {} files with prefix '{}'", results.len(), prefix);
        
        Ok(results)
    }
}
