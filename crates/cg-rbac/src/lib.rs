//! # CyberGlass Role-Based Access Control (RBAC)
//!
//! Role-based access control with:
//! - **User management** - Create, authenticate, and manage users
//! - **Role-based permissions** - Granular permission system
//! - **JWT authentication** - Stateless token-based auth
//! - **Session management** - Track active sessions
//! - **API key authentication** - For service-to-service access
//! - **Resource-level access control** - Fine-grained resource permissions

pub mod auth;
pub mod error;
pub mod manager;
pub mod models;

pub use auth::{
    constant_time_eq, hash_password, jwt_secret_path, password_needs_rehash, token_hash,
    verify_password, AuthConfig, AuthManager, Claims,
};
pub use error::{RbacError, Result};
pub use manager::{RbacConfig, RbacManager, RbacStats};
pub use models::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_api_re_exports_work() {
        let hash = hash_password("correct horse battery staple");
        assert!(verify_password("correct horse battery staple", &hash));

        let permission = Permission::from("search:read");
        assert!(permission.grants(&Permission::new("search", "read")));
        assert!(!permission.grants(&Permission::new("search", "write")));
    }
}
