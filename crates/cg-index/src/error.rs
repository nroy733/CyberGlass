use thiserror::Error;

#[derive(Error, Debug)]
pub enum IndexError {
    #[error("Tantivy error: {0}")]
    Tantivy(#[from] tantivy::TantivyError),

    #[error("Directory error: {0}")]
    Directory(#[from] tantivy::directory::error::OpenDirectoryError),

    #[error("Schema error: {0}")]
    Schema(String),

    #[error("Document not found: {0}")]
    DocumentNotFound(String),

    #[error("Query parse error: {0}")]
    QueryParse(String),

    #[error("Index is full: {0}")]
    IndexFull(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Corruption error: {0}")]
    Corruption(String),
}

pub type Result<T> = std::result::Result<T, IndexError>;
