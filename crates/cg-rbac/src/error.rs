//! # RBAC Error Types

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RbacError {
    #[error("User not found: {0}")]
    UserNotFound(String),

    #[error("Role not found: {0}")]
    RoleNotFound(String),

    #[error("Session not found: {0}")]
    SessionNotFound(String),

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Account is disabled")]
    AccountDisabled,

    #[error("Account is locked")]
    AccountLocked,

    #[error("Insufficient permissions: required {required}, got {got}")]
    InsufficientPermissions { required: String, got: String },

    #[error("Authentication token invalid: {0}")]
    InvalidToken(String),

    #[error("Authentication token expired")]
    TokenExpired,

    #[error("API key not found or invalid")]
    InvalidApiKey,

    #[error("MFA required but not configured")]
    MfaRequired,

    #[error("User already exists: {0}")]
    UserAlreadyExists(String),

    #[error("Password does not meet minimum strength requirements")]
    WeakPassword,

    #[error("Role already exists: {0}")]
    RoleAlreadyExists(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Cannot delete or modify protected system role")]
    SystemRoleProtected,

    #[error("Serialization error: {0}")]
    Serialization(String),
}

pub type Result<T> = std::result::Result<T, RbacError>;
