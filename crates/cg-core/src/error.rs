use thiserror::Error;

#[derive(Error, Debug)]
pub enum CyberGlassError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("gRPC error: {0}")]
    Grpc(String),

    #[error("Index error: {0}")]
    Index(String),

    #[error("Query error: {0}")]
    Query(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Detection error: {0}")]
    Detection(String),

    #[error("Ontology error: {0}")]
    Ontology(String),

    #[error("AI error: {0}")]
    Ai(String),

    #[error("Plugin error: {0}")]
    Plugin(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, CyberGlassError>;
