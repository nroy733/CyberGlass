use thiserror::Error;

#[derive(Error, Debug)]
pub enum OntologyError {
    #[error("Entity not found: {0}")]
    EntityNotFound(String),

    #[error("Relationship not found: {0}")]
    RelationshipNotFound(String),

    #[error("Invalid entity type: {0}")]
    InvalidEntityType(String),

    #[error("Duplicate entity: {0}")]
    DuplicateEntity(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Extraction error: {0}")]
    ExtractionError(String),
}

pub type Result<T> = std::result::Result<T, OntologyError>;
