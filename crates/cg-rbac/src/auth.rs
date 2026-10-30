//! # Authentication Module
//!
//! JWT issuance/validation plus password and token hashing primitives.
//!
//! Security notes:
//! - The JWT signing secret is never a compiled-in default. It is loaded from
//!   `CYBERGLASS_JWT_SECRET` or generated once and persisted with owner-only
//!   permissions under the CyberGlass data directory.
//! - Passwords use Argon2id. Legacy SHA-256 hashes are accepted only so that an
//!   existing deployment can migrate; callers should rehash after a successful
//!   legacy verification.
//! - Bearer tokens are never persisted. Only SHA-256 digests are stored.

use crate::error::{RbacError, Result};
use crate::models::UserId;
use argon2::{
    password_hash::{
        rand_core::OsRng as ArgonOsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
    },
    Algorithm, Argon2, Params, Version,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{
    decode, encode, Algorithm as JwtAlgorithm, DecodingKey, EncodingKey, Header, Validation,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq;
use tracing::warn;

const MIN_JWT_SECRET_BYTES: usize = 32;

/// Claims embedded in a JWT token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub username: String,
    pub roles: Vec<String>,
    pub exp: usize,
    pub iat: usize,
    pub iss: String,
    pub aud: String,
    pub typ: String,
    pub jti: String,
}

/// Configuration for JWT authentication.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub jwt_algorithm: JwtAlgorithm,
    pub access_token_ttl_hours: u64,
    pub refresh_token_ttl_days: u64,
    pub issuer: String,
    pub audience: String,
}

impl Default for AuthConfig {
    fn default() -> Self {
        // A random per-process secret is secure for ephemeral/test use. Server
        // deployments must call `resolve` so tokens survive restarts.
        Self {
            jwt_secret: random_secret(),
            jwt_algorithm: JwtAlgorithm::HS256,
            access_token_ttl_hours: 8,
            refresh_token_ttl_days: 30,
            issuer: "cyberglass".to_string(),
            audience: "cyberglass-api".to_string(),
        }
    }
}

impl AuthConfig {
    /// Resolve a persistent signing secret.
    ///
    /// Order of precedence:
    /// 1. `CYBERGLASS_JWT_SECRET` environment variable (must be >= 32 bytes).
    /// 2. `<data_dir>/jwt.secret` (created with 0600 permissions if absent).
    pub fn resolve(data_dir: &Path) -> Result<Self> {
        let secret = if let Ok(env_secret) = std::env::var("CYBERGLASS_JWT_SECRET") {
            if env_secret.as_bytes().len() < MIN_JWT_SECRET_BYTES {
                return Err(RbacError::Internal(format!(
                    "CYBERGLASS_JWT_SECRET must be at least {} bytes",
                    MIN_JWT_SECRET_BYTES
                )));
            }
            env_secret
        } else {
            load_or_create_secret(&data_dir.join("jwt.secret"))?
        };

        Ok(Self {
            jwt_secret: secret,
            ..Self::default()
        })
    }

    /// Build a deterministic config for unit tests only.
    pub fn for_tests() -> Self {
        Self {
            jwt_secret: "test-secret-that-is-long-enough-for-hs256-0123456789".to_string(),
            ..Self::default()
        }
    }
}

fn random_secret() -> String {
    let mut bytes = [0u8; 48];
    OsRng.fill_bytes(&mut bytes);
    base64_url(&bytes)
}

fn load_or_create_secret(path: &Path) -> Result<String> {
    if path.exists() {
        let secret = std::fs::read_to_string(path)
            .map_err(|e| RbacError::Internal(format!("read {}: {}", path.display(), e)))?;
        let secret = secret.trim().to_string();
        if secret.as_bytes().len() < MIN_JWT_SECRET_BYTES {
            return Err(RbacError::Internal(format!(
                "JWT secret at {} is too short; delete it to regenerate",
                path.display()
            )));
        }
        return Ok(secret);
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| RbacError::Internal(format!("create {}: {}", parent.display(), e)))?;
    }

    let secret = random_secret();
    write_private_file(path, secret.as_bytes())?;
    warn!(
        path = %path.display(),
        "Generated a new JWT signing secret. Back it up; rotating it invalidates all sessions."
    );
    Ok(secret)
}

#[cfg(unix)]
fn write_private_file(path: &Path, content: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| RbacError::Internal(format!("create {}: {}", path.display(), e)))?;
    file.write_all(content)
        .and_then(|_| file.sync_all())
        .map_err(|e| RbacError::Internal(format!("write {}: {}", path.display(), e)))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| RbacError::Internal(format!("chmod {}: {}", path.display(), e)))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, content: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|e| RbacError::Internal(format!("create {}: {}", path.display(), e)))?;
    file.write_all(content)
        .and_then(|_| file.sync_all())
        .map_err(|e| RbacError::Internal(format!("write {}: {}", path.display(), e)))?;
    Ok(())
}

/// JWT authentication manager.
#[derive(Debug)]
pub struct AuthManager {
    config: AuthConfig,
}

impl AuthManager {
    pub fn new(config: AuthConfig) -> Self {
        Self { config }
    }

    /// Create access and refresh tokens for a user.
    pub fn create_tokens(
        &self,
        user_id: &UserId,
        username: &str,
        roles: &[String],
    ) -> Result<(String, String)> {
        let now = Utc::now();
        let access_exp =
            (now + Duration::hours(self.config.access_token_ttl_hours as i64)).timestamp() as usize;
        let refresh_exp =
            (now + Duration::days(self.config.refresh_token_ttl_days as i64)).timestamp() as usize;

        let access_token = self.encode(Claims {
            sub: user_id.as_str().to_string(),
            username: username.to_string(),
            roles: roles.to_vec(),
            exp: access_exp,
            iat: now.timestamp() as usize,
            iss: self.config.issuer.clone(),
            aud: self.config.audience.clone(),
            typ: "access".to_string(),
            jti: new_jti(),
        })?;

        let refresh_token = self.encode(Claims {
            sub: user_id.as_str().to_string(),
            username: username.to_string(),
            roles: roles.to_vec(),
            exp: refresh_exp,
            iat: now.timestamp() as usize,
            iss: self.config.issuer.clone(),
            aud: self.config.audience.clone(),
            typ: "refresh".to_string(),
            jti: new_jti(),
        })?;

        Ok((access_token, refresh_token))
    }

    fn encode(&self, claims: Claims) -> Result<String> {
        encode(
            &Header::new(self.config.jwt_algorithm),
            &claims,
            &EncodingKey::from_secret(self.config.jwt_secret.as_bytes()),
        )
        .map_err(|e| RbacError::Internal(format!("encode token: {}", e)))
    }

    /// Validate signature, issuer, audience, and expiry. Does not enforce token type.
    pub fn validate_token(&self, token: &str) -> Result<Claims> {
        let mut validation = Validation::new(self.config.jwt_algorithm);
        validation.set_issuer(&[self.config.issuer.as_str()]);
        validation.set_audience(&[self.config.audience.as_str()]);

        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.config.jwt_secret.as_bytes()),
            &validation,
        )
        .map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => RbacError::TokenExpired,
            _ => RbacError::InvalidToken(e.to_string()),
        })?;

        Ok(token_data.claims)
    }

    /// Validate an access token (rejects refresh tokens used as bearer credentials).
    pub fn validate_access_token(&self, token: &str) -> Result<Claims> {
        let claims = self.validate_token(token)?;
        if claims.typ != "access" {
            return Err(RbacError::InvalidToken("Not an access token".to_string()));
        }
        Ok(claims)
    }

    /// Refresh an access token using a refresh token.
    pub fn refresh_access_token(&self, refresh_token: &str) -> Result<String> {
        let claims = self.validate_token(refresh_token)?;
        if claims.typ != "refresh" {
            return Err(RbacError::InvalidToken("Not a refresh token".to_string()));
        }

        let now = Utc::now();
        let access_exp =
            (now + Duration::hours(self.config.access_token_ttl_hours as i64)).timestamp() as usize;

        self.encode(Claims {
            sub: claims.sub,
            username: claims.username,
            roles: claims.roles,
            exp: access_exp,
            iat: now.timestamp() as usize,
            iss: self.config.issuer.clone(),
            aud: self.config.audience.clone(),
            typ: "access".to_string(),
            jti: new_jti(),
        })
    }

    /// Extract bearer token from an Authorization header.
    pub fn extract_bearer_token(auth_header: &str) -> Option<String> {
        auth_header
            .strip_prefix("Bearer ")
            .or_else(|| auth_header.strip_prefix("bearer "))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    pub fn config(&self) -> &AuthConfig {
        &self.config
    }
}

fn new_jti() -> String {
    uuid::Uuid::now_v7().to_string()
}

fn base64_url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Hash a password with Argon2id and a random salt.
pub fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut ArgonOsRng);
    let params = Params::new(19_456, 2, 1, None).expect("valid Argon2 parameters");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password(password.as_bytes(), &salt)
        .expect("password hashing cannot fail with valid parameters")
        .to_string()
}

/// Verify a password. Supports Argon2id PHC strings and legacy SHA-256 hex.
pub fn verify_password(password: &str, stored: &str) -> bool {
    if stored.starts_with("$argon2") {
        let Ok(parsed) = PasswordHash::new(stored) else {
            return false;
        };
        return Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok();
    }

    // Legacy migration path: 64 lowercase/uppercase hex characters == SHA-256.
    if stored.len() == 64 && stored.bytes().all(|b| b.is_ascii_hexdigit()) {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let computed = hex::encode(hasher.finalize());
        return computed.as_bytes().ct_eq(stored.as_bytes()).into();
    }

    false
}

/// Returns true when a stored hash should be upgraded to Argon2id.
pub fn password_needs_rehash(stored: &str) -> bool {
    !stored.starts_with("$argon2")
}

/// Stable hash for bearer/refresh tokens. These are high-entropy secrets, so a
/// single SHA-256 is sufficient (unlike user-chosen passwords).
pub fn token_hash(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Constant-time comparison for API key hashes.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Resolve `<data_dir>/jwt.secret` without creating it. Used by diagnostics.
pub fn jwt_secret_path(data_dir: &Path) -> PathBuf {
    data_dir.join("jwt.secret")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2_roundtrip_and_legacy_verification() {
        let hash = hash_password("correct horse battery staple");
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password("correct horse battery staple", &hash));
        assert!(!verify_password("wrong", &hash));
        assert!(password_needs_rehash(&hash) == false);

        let legacy = {
            let mut hasher = Sha256::new();
            hasher.update(b"legacy-password");
            hex::encode(hasher.finalize())
        };
        assert!(verify_password("legacy-password", &legacy));
        assert!(password_needs_rehash(&legacy));
        assert!(!verify_password("wrong", &legacy));
    }

    #[test]
    fn tokens_are_typed_and_audience_bound() {
        let auth = AuthManager::new(AuthConfig::for_tests());
        let user_id = UserId::new();
        let (access, refresh) = auth
            .create_tokens(&user_id, "testuser", &["analyst".to_string()])
            .unwrap();

        assert!(auth.validate_access_token(&access).is_ok());
        assert!(auth.validate_access_token(&refresh).is_err());
        assert!(auth.refresh_access_token(&refresh).is_ok());

        let claims = auth.validate_token(&access).unwrap();
        assert_eq!(claims.aud, "cyberglass-api");
        assert_eq!(claims.username, "testuser");
    }

    #[test]
    fn token_hashes_are_stable_and_different() {
        assert_eq!(token_hash("abc"), token_hash("abc"));
        assert_ne!(token_hash("abc"), token_hash("abd"));
        assert!(constant_time_eq(&token_hash("x"), &token_hash("x")));
        assert!(!constant_time_eq(&token_hash("x"), &token_hash("y")));
    }
}
