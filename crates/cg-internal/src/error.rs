//! # Internal Logging Error Types

use thiserror::Error;

#[derive(Debug, Error)]
pub enum InternalError {
    #[error("Index error: {0}")]
    Index(String),

    #[error("Write error: {0}")]
    Write(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Tantivy error: {0}")]
    Tantivy(#[from] tantivy::TantivyError),
}

pub type Result<T> = std::result::Result<T, InternalError>;
