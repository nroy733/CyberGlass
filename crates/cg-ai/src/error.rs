//! # AI Error Types

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AiError {
    #[error("Model not found: {0}")]
    ModelNotFound(String),

    #[error("Model load failed: {0}")]
    ModelLoadFailed(String),

    #[error("Inference failed: {0}")]
    InferenceFailed(String),

    #[error("Tool execution error: {0}")]
    ToolExecution(String),

    #[error("Remote API error: {0}")]
    RemoteApiError(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Context too long: {0}")]
    ContextTooLong(String),

    #[error("Authentication error: {0}")]
    AuthenticationError(String),

    #[error("Provider error: {0}")]
    ProviderError(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, AiError>;
