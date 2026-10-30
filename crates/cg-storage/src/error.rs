//! Error types for the CyberGlass tiered storage system.

use thiserror::Error;

/// Errors that can occur during storage operations.
#[derive(Debug, Error)]
pub enum StorageError {
    /// An I/O error occurred during a storage operation.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Failed to compress data.
    #[error("compression error: {0}")]
    Compression(String),

    /// Failed to decompress data.
    #[error("decompression error: {0}")]
    Decompression(String),

    /// Failed to serialize or deserialize data.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// The target storage tier is full and cannot accept more data.
    #[error("storage tier is full: {0}")]
    TierFull(String),

    /// The requested segment was not found.
    #[error("segment not found: {0}")]
    SegmentNotFound(String),

    /// The data segment is corrupted.
    #[error("corrupted data: {0}")]
    CorruptedData(String),

    /// Arrow/Parquet error.
    #[error("arrow error: {0}")]
    Arrow(#[from] arrow::error::ArrowError),

    /// Parquet error.
    #[error("parquet error: {0}")]
    Parquet(#[from] parquet::errors::ParquetError),
}

/// Result type alias for storage operations.
pub type Result<T> = std::result::Result<T, StorageError>;
