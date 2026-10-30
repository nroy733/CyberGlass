//! # Event Bus Abstraction over NATS
//!
//! Provides a high-throughput event bus with automatic fallback to an
//! in-memory broadcast channel when NATS is unreachable. Supports both
//! publishing and local subscribing.

use crate::error::{BusError, Result};
use async_trait::async_trait;
use bytes::Bytes;
use cg_core::config::BusConfig;
use cg_core::traits::{HealthStatus, Service};
use cg_proto::common::Event;
use prost::Message;
use tokio::sync::broadcast;
use tracing::{info, warn};

#[derive(Clone)]
pub struct EventBus {
    client: Option<async_nats::Client>,
    internal_tx: broadcast::Sender<(String, Bytes)>,
}

impl EventBus {
    pub async fn connect(config: &BusConfig) -> Result<Self> {
        let (internal_tx, _) = broadcast::channel(100_000);

        let client = match async_nats::connect(&config.listen_addr).await {
            Ok(c) => {
                info!("Connected to NATS bus at {}", config.listen_addr);
                Some(c)
            }
            Err(e) => {
                warn!(
                    "NATS not reachable at {} ({}), operating with high-speed in-memory bus",
                    config.listen_addr, e
                );
                None
            }
        };

        Ok(Self {
            client,
            internal_tx,
        })
    }

    pub fn in_memory() -> Self {
        let (internal_tx, _) = broadcast::channel(100_000);
        Self {
            client: None,
            internal_tx,
        }
    }

    /// Publish raw bytes to a subject.
    pub async fn publish(&self, subject: &str, payload: Bytes) -> Result<()> {
        if let Some(ref client) = self.client {
            client
                .publish(subject.to_string(), payload.clone())
                .await
                .map_err(|e| BusError::Publish(e.to_string()))?;
        }
        // Also fan out to local subscribers
        let _ = self.internal_tx.send((subject.to_string(), payload));
        Ok(())
    }

    /// Publish a protobuf Event to its normalized subject.
    pub async fn publish_event(&self, event: &Event) -> Result<()> {
        let mut buf = Vec::with_capacity(event.encoded_len());
        event
            .encode(&mut buf)
            .map_err(|e| BusError::Serialization(e.to_string()))?;

        let subject = format!(
            "events.normalized.{}",
            if event.index.is_empty() {
                "main"
            } else {
                &event.index
            }
        );
        self.publish(&subject, Bytes::from(buf)).await
    }

    /// Subscribe to local broadcast messages. Returns a receiver that gets
    /// all (subject, payload) pairs published on this bus instance.
    pub fn subscribe_local(&self) -> broadcast::Receiver<(String, Bytes)> {
        self.internal_tx.subscribe()
    }

    /// Subscribe to a NATS subject and forward messages to an mpsc channel.
    /// Works only when NATS is connected; otherwise returns an error.
    pub async fn subscribe_nats(
        &self,
        subject: &str,
    ) -> Result<tokio::sync::mpsc::Receiver<(String, Bytes)>> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| BusError::Subscribe("NATS not connected".to_string()))?;

        let (tx, rx) = tokio::sync::mpsc::channel(10_000);
        let mut sub = client
            .subscribe(subject.to_string())
            .await
            .map_err(|e| BusError::Subscribe(e.to_string()))?;

        let tx_inner = tx;
        let internal_tx = self.internal_tx.clone();
        let subject_filter = subject.to_string();

        tokio::spawn(async move {
            use tokio_stream::StreamExt;
            while let Some(msg) = sub.next().await {
                let payload = Bytes::copy_from_slice(&msg.payload);
                let subj1 = subject_filter.clone();
                let subj2 = subject_filter.clone();
                let _ = tx_inner.send((subj1, payload.clone())).await;
                let _ = internal_tx.send((subj2, payload));
            }
        });

        Ok(rx)
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::in_memory()
    }
}

#[async_trait]
impl Service for EventBus {
    async fn start(&self) -> cg_core::error::Result<()> {
        info!("EventBus started");
        Ok(())
    }

    async fn stop(&self) -> cg_core::error::Result<()> {
        info!("EventBus stopped");
        Ok(())
    }

    fn health(&self) -> HealthStatus {
        HealthStatus {
            component: "event_bus".into(),
            status: "healthy".into(),
            message: if self.client.is_some() {
                "NATS cluster connected".into()
            } else {
                "In-memory broadcast mode".into()
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subject_matching() {
        // Simple validation that the module loads
        let _bus = EventBus::in_memory();
        assert!(!_bus.client.is_some());
    }
}
