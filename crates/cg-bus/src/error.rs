//! Error types for the CyberGlass event bus.

use thiserror::Error;

/// Errors that can occur during event bus operations.
#[derive(Debug, Error)]
pub enum BusError {
    /// Failed to connect to the NATS server.
    #[error("connection error: {0}")]
    Connection(String),

    /// Failed to publish a message.
    #[error("publish error: {0}")]
    Publish(String),

    /// Failed to subscribe to a subject.
    #[error("subscribe error: {0}")]
    Subscribe(String),

    /// Failed to create a JetStream stream.
    #[error("stream creation error: {0}")]
    StreamCreate(String),

    /// A timeout occurred waiting for a response.
    #[error("timeout: {0}")]
    Timeout(String),

    /// Failed to serialize or deserialize a message.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// An internal bus error occurred.
    #[error("internal error: {0}")]
    Internal(String),
}

/// Result type alias for bus operations.
pub type Result<T> = std::result::Result<T, BusError>;
