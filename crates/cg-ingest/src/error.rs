//! Error types for the ingestion pipeline.

use thiserror::Error;

/// Errors that can occur during event ingestion.
#[derive(Debug, Error)]
pub enum IngestError {
    /// Failed to parse raw event data.
    #[error("parse error for source type '{source_type}': {message}")]
    Parse {
        /// The source type that failed to parse.
        source_type: String,
        /// Human-readable description of the parse failure.
        message: String,
    },

    /// Failed to normalize parsed event fields.
    #[error("normalization error: {0}")]
    Normalize(String),

    /// An enricher failed to process the event.
    #[error("enrichment error in '{enricher}': {message}")]
    Enrich {
        /// Name of the enricher that failed.
        enricher: String,
        /// Human-readable description of the enrichment failure.
        message: String,
    },

    /// Failed to route the event to the event bus.
    #[error("routing error: {0}")]
    Route(String),

    /// Generic pipeline error wrapping an inner cause.
    #[error("pipeline error: {0}")]
    Pipeline(String),

    /// Back-pressure signal — upstream is producing faster than we can consume.
    #[error("back-pressure: pipeline buffer full ({queue_depth} pending)")]
    BackPressure {
        /// Current depth of the internal queue.
        queue_depth: usize,
    },

    /// Write-ahead log error (WAL persistence failure).
    #[error("WAL error: {0}")]
    Wal(String),

    /// Error originating from the event bus.
    #[error("bus error: {0}")]
    Bus(#[from] cg_bus::BusError),

    /// Serialization / deserialization error.
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),

    /// I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Convenience result type for ingestion operations.
pub type Result<T> = std::result::Result<T, IngestError>;
