use crate::error::Result;
use crate::types::ParsedEvent;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub component: String,
    pub status: String,
    pub message: String,
}

#[async_trait]
pub trait Service: Send + Sync {
    async fn start(&self) -> Result<()>;
    async fn stop(&self) -> Result<()>;
    fn health(&self) -> HealthStatus;
}

/// Destination for fully parsed and enriched events.
///
/// Implementations fan an event out to storage, detection, and the knowledge
/// graph. Ingestion awaits this hook so that a successful ingest response means
/// the event is durable in the search index, not merely published to the bus.
#[async_trait]
pub trait EventSink: Send + Sync {
    async fn on_event(&self, event: &ParsedEvent) -> Result<()>;

    /// Flush buffered state (for example, commit pending index segments).
    async fn flush(&self) -> Result<()> {
        Ok(())
    }
}

pub trait Parser: Send + Sync {
    fn name(&self) -> &str;
    fn can_parse(&self, raw: &[u8]) -> bool;
    fn parse(&self, raw: &[u8]) -> Result<ParsedEvent>;
}

pub trait Enricher: Send + Sync {
    fn name(&self) -> &str;
    fn enrich(&self, event: &mut ParsedEvent) -> Result<()>;
}
