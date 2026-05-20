use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::debug;

/// In-memory event bus using tokio mpsc channels
pub struct MemoryEventBus {
    subscribers: Arc<Mutex<HashMap<String, Vec<mpsc::UnboundedSender<String>>>>>,
}

impl MemoryEventBus {
    pub fn new() -> Self {
        Self {
            subscribers: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Default for MemoryEventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl crate::traits::EventBus for MemoryEventBus {
    async fn publish(&self, topic: &str, message: &str) -> anyhow::Result<()> {
        let subscribers = self.subscribers.lock().await;
        
        if let Some(senders) = subscribers.get(topic) {
            for sender in senders {
                let _ = sender.send(message.to_string());
            }
            debug!("Published message to topic '{}': {} subscribers", topic, senders.len());
        } else {
            debug!("No subscribers for topic '{}'", topic);
        }
        
        Ok(())
    }
    
    async fn subscribe(&self, topic: &str) -> anyhow::Result<Box<dyn crate::traits::EventSubscriber>> {
        let (tx, rx) = mpsc::unbounded_channel();
        
        let mut subscribers = self.subscribers.lock().await;
        subscribers
            .entry(topic.to_string())
            .or_insert_with(Vec::new)
            .push(tx);
        
        debug!("New subscriber for topic '{}'", topic);
        
        Ok(Box::new(MemoryEventSubscriber { receiver: rx }))
    }
}

pub struct MemoryEventSubscriber {
    receiver: mpsc::UnboundedReceiver<String>,
}

#[async_trait]
impl crate::traits::EventSubscriber for MemoryEventSubscriber {
    async fn next(&mut self) -> anyhow::Result<Option<String>> {
        Ok(self.receiver.recv().await)
    }
}
