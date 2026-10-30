//! # Authentication & Authorization Middleware
//!
//! Every protected REST route passes through this middleware. It accepts:
//! - `Authorization: Bearer <access token>` for interactive sessions
//! - `Authorization: ApiKey <key>` or `X-API-Key: <key>` for service accounts
//! - `?token=<access token>` only for the WebSocket route, because browsers
//!   cannot attach headers to a WebSocket handshake
//!
//! Authentication proves *who* the caller is; the permission policy below
//! proves *what* they may do. Unknown paths are deny-by-default.

use axum::extract::{Request, State};
use axum::http::{header, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use cg_rbac::{Claims, Permission, RbacManager, User};
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, warn};

/// How the caller authenticated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthMethod {
    Bearer,
    ApiKey,
}

/// Authenticated principal attached to the request extensions.
#[derive(Clone, Debug)]
pub struct AuthContext {
    pub user: User,
    pub claims: Option<Claims>,
    /// API-key permissions. Empty for interactive sessions, whose permissions
    /// are derived from roles at check time.
    pub api_key_permissions: Vec<Permission>,
    pub method: AuthMethod,
    /// Raw bearer token, retained so the logout handler can revoke the session.
    pub bearer_token: Option<String>,
    pub rbac: Arc<RbacManager>,
}

impl AuthContext {
    /// Check a permission against the principal's effective grants.
    pub fn allows(&self, permission: &Permission) -> bool {
        match self.method {
            AuthMethod::Bearer => self
                .rbac
                .check_permission(&self.user, permission)
                .is_allowed(),
            AuthMethod::ApiKey => {
                RbacManager::api_key_allows(&self.api_key_permissions, permission)
            }
        }
    }
}

/// Public paths that do not require authentication. The collector endpoints
/// authenticate with HEC tokens inside their handlers.
pub fn is_public_path(method: &Method, path: &str) -> bool {
    if method == Method::OPTIONS {
        return true;
    }

    matches!(
        path,
        "/" | "/ui"
            | "/docs/commands"
            | "/api/v1/info"
            | "/api/v1/health"
            | "/api/v1/auth/login"
            | "/api/v1/auth/refresh"
            | "/services/collector"
            | "/services/collector/event"
            | "/services/collector/health"
    )
}

/// Map an HTTP method and path to the permission required to execute it.
///
/// Returns `None` for endpoints that only require a valid identity (for
/// example `/auth/me` and `/auth/logout`). Unknown protected paths map to an
/// administrative permission so that new routes fail closed.
pub fn required_permission(method: &Method, path: &str) -> Option<Permission> {
    if path == "/api/v1/auth/me" || path == "/api/v1/auth/logout" {
        return None;
    }

    let read_only = method == Method::GET || method == Method::HEAD;

    // Mapping is ordered longest-prefix-first.
    let (resource, write_action) = if path.starts_with("/api/v1/auth/users") {
        ("rbac", "manage")
    } else if path.starts_with("/api/v1/auth/roles") {
        ("rbac", "manage")
    } else if path.starts_with("/api/v1/auth/api-keys") {
        ("rbac", "manage")
    } else if path.starts_with("/api/v1/indices") {
        if read_only {
            return Some(Permission::new("index", "read"));
        }
        return Some(Permission::new("index", "manage"));
    } else if path.starts_with("/api/v1/hec/tokens") {
        ("ingest", "manage")
    } else if path.starts_with("/api/v1/monitors") || path.starts_with("/api/v1/listeners") {
        ("ingest", "manage")
    } else if path.starts_with("/api/v1/ingest") {
        if read_only {
            return Some(Permission::new("ingest", "read"));
        }
        return Some(Permission::new("ingest", "write"));
    } else if path.starts_with("/api/v1/events") || path.starts_with("/api/v1/query") {
        if read_only {
            return Some(Permission::new("search", "read"));
        }
        return Some(Permission::new("search", "write"));
    } else if path.starts_with("/api/v1/stream/tail") || path == "/api/v1/ws" {
        return Some(Permission::new("search", "realtime"));
    } else if path.starts_with("/api/v1/alerts") {
        ("alert", "write")
    } else if path.starts_with("/api/v1/rules") {
        ("rule", "write")
    } else if path.starts_with("/api/v1/entities") || path.starts_with("/api/v1/graph") {
        if read_only {
            return Some(Permission::new("ontology", "read"));
        }
        return Some(Permission::new("ontology", "write"));
    } else if path.starts_with("/api/v1/ai") {
        ("ai", "chat")
    } else if path.starts_with("/api/v1/xdr") {
        ("xdr", "manage")
    } else if path.starts_with("/api/v1/soar") {
        if read_only {
            return Some(Permission::new("soar", "read"));
        }
        return Some(Permission::new("soar", "execute"));
    } else if path.starts_with("/api/v1/mcp") {
        if read_only {
            return Some(Permission::new("mcp", "read"));
        }
        return Some(Permission::new("mcp", "execute"));
    } else if path.starts_with("/api/v1/mitre") {
        return Some(Permission::new("rule", "read"));
    } else if path.starts_with("/api/v1/internal") {
        return Some(Permission::new("internal", "read"));
    } else if path.starts_with("/api/v1/settings") || path.starts_with("/api/v1/sidebar") {
        ("settings", "write")
    } else if path.starts_with("/api/v1/dashboards") {
        if read_only {
            return Some(Permission::new("dashboard", "read"));
        }
        return Some(Permission::new("dashboard", "write"));
    } else if path.starts_with("/api/v1/metrics") {
        return Some(Permission::new("system", "read"));
    } else if path.starts_with("/api/v1/agent") {
        return Some(Permission::new("xdr", "read"));
    } else {
        return Some(Permission::new("system", "admin"));
    };

    if read_only {
        Some(Permission::new(resource, "read"))
    } else {
        Some(Permission::new(resource, write_action))
    }
}

fn unauthorized(message: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        Json(json!({
            "status": "ERROR",
            "error": message,
        })),
    )
        .into_response()
}

fn forbidden(message: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "status": "ERROR",
            "error": message,
        })),
    )
        .into_response()
}

fn bearer_from_headers(request: &Request) -> Option<String> {
    let value = request
        .headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .trim();
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty())?;
    Some(token.to_string())
}

fn api_key_from_headers(request: &Request) -> Option<String> {
    if let Some(value) = request
        .headers()
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some(value.to_string());
    }

    let value = request
        .headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .trim();

    if let Some(key) = value
        .strip_prefix("ApiKey ")
        .or_else(|| value.strip_prefix("apikey "))
    {
        let key = key.trim();
        return (!key.is_empty()).then(|| key.to_string());
    }

    // Convenience: `Authorization: Bearer cg_...` is an API key, not a JWT.
    if let Some(key) = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
    {
        let key = key.trim();
        if key.starts_with("cg_") {
            return Some(key.to_string());
        }
    }

    None
}

fn query_token(request: &Request) -> Option<String> {
    let query = request.uri().query()?;
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        if key == "token" && !value.is_empty() {
            Some(urlencoding_decode(value).unwrap_or_else(|| value.to_string()))
        } else {
            None
        }
    })
}

/// Minimal percent-decoding for the WebSocket query token.
fn urlencoding_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = value.get(i + 1..i + 3)?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn authenticate(rbac: &Arc<RbacManager>, request: &Request) -> Result<AuthContext, Response> {
    if let Some(key) = api_key_from_headers(request) {
        return match rbac.validate_api_key(&key) {
            Ok((user, permissions)) => {
                debug!(username = %user.username, "Authenticated request via API key");
                Ok(AuthContext {
                    user,
                    claims: None,
                    api_key_permissions: permissions,
                    method: AuthMethod::ApiKey,
                    bearer_token: None,
                    rbac: rbac.clone(),
                })
            }
            Err(error) => {
                warn!(error = %error, "API key authentication failed");
                Err(unauthorized("Invalid or expired API key"))
            }
        };
    }

    let token = bearer_from_headers(request).or_else(|| {
        if request.uri().path() == "/api/v1/ws" {
            query_token(request)
        } else {
            None
        }
    });

    let Some(token) = token else {
        return Err(unauthorized("Authentication required"));
    };

    match rbac.validate_session(&token) {
        Ok((user, claims)) => {
            debug!(username = %user.username, "Authenticated request via bearer token");
            Ok(AuthContext {
                user,
                claims: Some(claims),
                api_key_permissions: Vec::new(),
                method: AuthMethod::Bearer,
                bearer_token: Some(token),
                rbac: rbac.clone(),
            })
        }
        Err(error) => {
            warn!(error = %error, "Bearer authentication failed");
            Err(unauthorized("Invalid or expired access token"))
        }
    }
}

/// Combined authentication and route-permission middleware.
pub async fn auth_middleware(
    State(rbac): State<Arc<RbacManager>>,
    mut request: Request,
    next: Next,
) -> Response {
    if is_public_path(request.method(), request.uri().path()) {
        return next.run(request).await;
    }

    let context = match authenticate(&rbac, &request) {
        Ok(context) => context,
        Err(response) => return response,
    };

    if let Some(required) = required_permission(request.method(), request.uri().path()) {
        if !context.allows(&required) {
            warn!(
                username = %context.user.username,
                method = %request.method(),
                path = %request.uri().path(),
                permission = %required,
                "Authorization denied"
            );
            return forbidden(&format!("Missing permission: {}", required));
        }
    }

    request.extensions_mut().insert(context);
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_paths_are_exact() {
        assert!(is_public_path(&Method::GET, "/api/v1/health"));
        assert!(!is_public_path(&Method::GET, "/api/v1/health/details"));
        assert!(!is_public_path(&Method::GET, "/api/v1/query"));
        assert!(is_public_path(&Method::OPTIONS, "/api/v1/query"));
    }

    #[test]
    fn permission_mapping_is_deny_by_default() {
        assert_eq!(
            required_permission(&Method::GET, "/api/v1/query"),
            Some(Permission::new("search", "read"))
        );
        assert_eq!(
            required_permission(&Method::POST, "/api/v1/ingest"),
            Some(Permission::new("ingest", "write"))
        );
        assert_eq!(
            required_permission(&Method::GET, "/api/v1/unknown"),
            Some(Permission::new("system", "admin"))
        );
        assert_eq!(required_permission(&Method::GET, "/api/v1/auth/me"), None);
    }

    #[test]
    fn requests_without_credentials_are_unauthenticated_even_when_admin_exists() {
        let rbac = Arc::new(RbacManager::new(cg_rbac::RbacConfig {
            auth: cg_rbac::AuthConfig::for_tests(),
            ..Default::default()
        }));
        rbac.bootstrap_admin("admin", "test-password-long-enough")
            .unwrap();
        let request = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/internal/logs")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = authenticate(&rbac, &request).unwrap_err();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn query_tokens_are_decoded() {
        assert_eq!(urlencoding_decode("abc%2Fdef"), Some("abc/def".to_string()));
        assert_eq!(urlencoding_decode("plain"), Some("plain".to_string()));
    }
}
