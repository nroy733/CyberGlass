use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Key generation error: {0}")]
    KeyGeneration(String),

    #[error("Signing error: {0}")]
    Signing(String),

    #[error("Verification error: {0}")]
    Verification(String),

    #[error("Hashing error: {0}")]
    Hashing(String),

    #[error("Encoding error: {0}")]
    Encoding(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;
