//! # RBAC Data Models
//!
//! Users, roles, permissions, sessions, audit records, and API keys.
//!
//! Security invariants:
//! - Passwords are stored as Argon2id PHC strings (never plaintext, never bare SHA-256).
//! - Session tokens are stored as SHA-256 hashes, never as bearer secrets.
//! - API keys are high-entropy, shown once, and stored hashed.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

/// Unique identifier for a user.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(pub String);

impl UserId {
    pub fn new() -> Self {
        Self(Uuid::now_v7().to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for UserId {
    fn default() -> Self {
        Self::new()
    }
}

/// Unique identifier for a role.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RoleId(pub String);

impl RoleId {
    pub fn new() -> Self {
        Self(Uuid::now_v7().to_string())
    }
}

impl Default for RoleId {
    fn default() -> Self {
        Self::new()
    }
}

/// Unique identifier for a session.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub String);

impl SessionId {
    pub fn new() -> Self {
        Self(Uuid::now_v7().to_string())
    }
}

/// Permission string - format: "resource:action" (e.g., "search:read", "ingest:all").
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Permission(pub String);

impl Permission {
    pub fn new(resource: &str, action: &str) -> Self {
        Self(format!("{}:{}", resource, action))
    }

    pub fn resource(&self) -> &str {
        self.0.split(':').next().unwrap_or("")
    }

    pub fn action(&self) -> &str {
        self.0.split(':').nth(1).unwrap_or("")
    }

    /// Returns true when `self` (a granted permission) covers `required`.
    ///
    /// Wildcards are supported for `*`, `resource:*`, and `*:action`.
    pub fn grants(&self, required: &Permission) -> bool {
        if self.0 == "*:*" || self == required {
            return true;
        }
        let (self_resource, self_action) = split_permission(&self.0);
        let (req_resource, req_action) = split_permission(&required.0);

        (self_resource == "*" || self_resource == req_resource)
            && (self_action == "*" || self_action == req_action)
    }
}

impl From<&str> for Permission {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl From<String> for Permission {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn split_permission(value: &str) -> (&str, &str) {
    match value.split_once(':') {
        Some((resource, action)) => (resource, action),
        None => (value, ""),
    }
}

/// A security role with assigned permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: RoleId,
    pub name: String,
    pub description: String,
    pub permissions: HashSet<Permission>,
    /// Roles that this role inherits permissions from.
    pub inherits: Vec<RoleId>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_system: bool,
}

impl Role {
    pub fn new(name: String) -> Self {
        let now = Utc::now();
        Self {
            id: RoleId::new(),
            name,
            description: String::new(),
            permissions: HashSet::new(),
            inherits: Vec::new(),
            created_at: now,
            updated_at: now,
            is_system: false,
        }
    }

    pub fn grant_permission(&mut self, permission: Permission) {
        self.permissions.insert(permission);
        self.updated_at = Utc::now();
    }

    pub fn revoke_permission(&mut self, permission: &Permission) {
        self.permissions.remove(permission);
        self.updated_at = Utc::now();
    }

    pub fn inherits_from(&mut self, role_id: RoleId) {
        if !self.inherits.contains(&role_id) {
            self.inherits.push(role_id);
        }
    }

    /// Checks direct permissions only. Use `RbacManager::check_permission` for
    /// inheritance-aware authorization decisions.
    pub fn has_permission(&self, perm: &str) -> bool {
        self.permissions.iter().any(|p| p.0 == perm)
    }

    pub fn has_permission_obj(&self, permission: &Permission) -> bool {
        self.permissions
            .iter()
            .any(|granted| granted.grants(permission))
    }
}

/// A user account in the CyberGlass system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub username: String,
    pub email: String,
    /// Argon2id PHC hash. `None` for SSO/API-only users.
    #[serde(skip_serializing)]
    pub password_hash: Option<String>,
    pub full_name: String,
    pub role_ids: Vec<RoleId>,
    pub is_active: bool,
    pub is_sso: bool,
    pub mfa_enabled: bool,
    /// Set when an administrator creates a user with a temporary password.
    pub must_change_password: bool,
    pub last_login: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
}

impl User {
    pub fn new(username: String, email: String) -> Self {
        let now = Utc::now();
        Self {
            id: UserId::new(),
            username,
            email,
            password_hash: None,
            full_name: String::new(),
            role_ids: Vec::new(),
            is_active: true,
            is_sso: false,
            mfa_enabled: false,
            must_change_password: false,
            last_login: None,
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        }
    }

    pub fn assign_role(&mut self, role_id: RoleId) {
        if !self.role_ids.contains(&role_id) {
            self.role_ids.push(role_id);
        }
    }

    pub fn remove_role(&mut self, role_id: &RoleId) {
        self.role_ids.retain(|id| id != role_id);
    }

    /// Checks assignment by *role name* against the role IDs previously
    /// resolved by `RbacManager`.
    pub fn has_role(&self, role_name: &str) -> bool {
        self.role_ids.iter().any(|id| id.0 == role_name)
    }

    pub fn set_password_hash(&mut self, hash: String) {
        self.password_hash = Some(hash);
    }
}

/// An active user session. Only token hashes are retained.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: SessionId,
    pub user_id: UserId,
    pub access_token_hash: String,
    pub refresh_token_hash: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub refresh_expires_at: DateTime<Utc>,
    pub last_accessed: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub is_active: bool,
}

impl Session {
    pub fn new(
        user_id: UserId,
        access_token_hash: String,
        refresh_token_hash: String,
        access_ttl_hours: u64,
        refresh_ttl_days: u64,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: SessionId::new(),
            user_id,
            access_token_hash,
            refresh_token_hash,
            created_at: now,
            expires_at: now + Duration::hours(access_ttl_hours as i64),
            refresh_expires_at: now + Duration::days(refresh_ttl_days as i64),
            last_accessed: now,
            ip_address: None,
            user_agent: None,
            is_active: true,
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn is_refresh_expired(&self) -> bool {
        Utc::now() > self.refresh_expires_at
    }

    pub fn touch(&mut self) {
        self.last_accessed = Utc::now();
    }
}

/// An API key for service-to-service authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: Uuid,
    pub name: String,
    /// First 8 characters, for operator identification only.
    pub key_prefix: String,
    /// SHA-256 of the full key.
    pub key_hash: String,
    pub user_id: UserId,
    pub permissions: HashSet<Permission>,
    pub is_active: bool,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl ApiKey {
    pub fn new(name: String, user_id: UserId, permissions: HashSet<Permission>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::now_v7(),
            name,
            key_prefix: String::new(),
            key_hash: String::new(),
            user_id,
            permissions,
            is_active: true,
            expires_at: None,
            last_used: None,
            created_at: now,
        }
    }
}

/// A tamper-evident authorization/audit record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: u64,
    pub timestamp: DateTime<Utc>,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub outcome: String,
    pub detail: String,
    pub source_ip: Option<String>,
}

/// Access control result for a resource request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessResult {
    Allowed,
    Denied { reason: String },
}

impl AccessResult {
    pub fn is_allowed(&self) -> bool {
        matches!(self, AccessResult::Allowed)
    }
}

/// Resource types in the system.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResourceType {
    Search,
    Ingest,
    Dashboard,
    Alert,
    Rule,
    Ontology,
    User,
    Role,
    Setting,
    Index,
    Internal,
    System,
    Xdr,
    Soar,
    Mcp,
    Custom(String),
}

impl std::fmt::Display for ResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourceType::Search => write!(f, "search"),
            ResourceType::Ingest => write!(f, "ingest"),
            ResourceType::Dashboard => write!(f, "dashboard"),
            ResourceType::Alert => write!(f, "alert"),
            ResourceType::Rule => write!(f, "rule"),
            ResourceType::Ontology => write!(f, "ontology"),
            ResourceType::User => write!(f, "user"),
            ResourceType::Role => write!(f, "role"),
            ResourceType::Setting => write!(f, "setting"),
            ResourceType::Index => write!(f, "index"),
            ResourceType::Internal => write!(f, "internal"),
            ResourceType::System => write!(f, "system"),
            ResourceType::Xdr => write!(f, "xdr"),
            ResourceType::Soar => write!(f, "soar"),
            ResourceType::Mcp => write!(f, "mcp"),
            ResourceType::Custom(s) => write!(f, "{}", s),
        }
    }
}

/// Action types that can be performed on resources.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActionType {
    Read,
    Write,
    Create,
    Delete,
    Execute,
    Manage,
    Export,
    Admin,
    Custom(String),
}

impl std::fmt::Display for ActionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActionType::Read => write!(f, "read"),
            ActionType::Write => write!(f, "write"),
            ActionType::Create => write!(f, "create"),
            ActionType::Delete => write!(f, "delete"),
            ActionType::Execute => write!(f, "execute"),
            ActionType::Manage => write!(f, "manage"),
            ActionType::Export => write!(f, "export"),
            ActionType::Admin => write!(f, "admin"),
            ActionType::Custom(s) => write!(f, "{}", s),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_wildcards_are_bounded() {
        assert!(Permission::new("*", "*").grants(&Permission::new("search", "read")));
        assert!(Permission::new("search", "*").grants(&Permission::new("search", "export")));
        assert!(!Permission::new("search", "*").grants(&Permission::new("ingest", "write")));
        assert!(!Permission::new("*", "read").grants(&Permission::new("search", "write")));
        assert!(Permission::new("*", "read").grants(&Permission::new("search", "read")));
    }

    #[test]
    fn role_and_user_assignment_uses_stable_ids() {
        let role = Role::new("analyst".into());
        let mut user = User::new("analyst1".into(), "analyst@example.com".into());
        user.assign_role(role.id.clone());
        assert_eq!(user.role_ids.len(), 1);
        assert!(!user.has_role("analyst"), "role names are not IDs");
        user.assign_role(role.id.clone());
        assert_eq!(user.role_ids.len(), 1, "duplicate assignment is a no-op");
    }
}
