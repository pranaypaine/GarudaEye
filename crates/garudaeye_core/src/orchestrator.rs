use crate::Result;

/// Orchestrator interface for triggering collections and analysis
/// The actual implementation is in the main binary to avoid circular dependencies
pub trait Orchestrator: Send + Sync {
    fn start_collection(&self) -> impl std::future::Future<Output = Result<()>> + Send;
    fn start_analysis(&self) -> impl std::future::Future<Output = Result<()>> + Send;
}
