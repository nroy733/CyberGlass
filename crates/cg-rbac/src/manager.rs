//! # RBAC Manager
//!
//! Central manager for users, roles, sessions, audit records, and access
//! control decisions.
//!
//! Authorization is deny-by-default: a caller must possess an explicit
//! permission (directly, by wildcard, or through role inheritance).

use crate::auth::{
    constant_time_eq, hash_password, password_needs_rehash, token_hash, verify_password,
    AuthConfig, AuthManager, Claims,
};
use crate::error::{RbacError, Result};
use crate::models::*;
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};

/// Configuration for the RBAC system.
#[derive(Debug, Clone)]
pub struct RbacConfig {
    pub auth: AuthConfig,
    pub max_failed_login_attempts: u32,
    pub lockout_duration_minutes: u64,
    pub session_ttl_hours: u64,
    /// Optional JSONL audit log. `None` keeps audit records in memory only.
    pub audit_log_path: Option<PathBuf>,
}

impl Default for RbacConfig {
    fn default() -> Self {
        Self {
            auth: AuthConfig::default(),
            max_failed_login_attempts: 5,
            lockout_duration_minutes: 15,
            session_ttl_hours: 8,
            audit_log_path: None,
        }
    }
}

/// Main RBAC manager - thread-safe, cheap to clone.
#[derive(Clone)]
pub struct RbacManager {
    config: RbacConfig,
    auth_manager: Arc<AuthManager>,
    users: Arc<DashMap<String, User>>,
    roles: Arc<DashMap<String, Role>>,
    /// Role UUID -> role name. Keeps role-ID lookups O(1).
    role_ids: Arc<DashMap<String, String>>,
    /// SHA-256(access token) -> session.
    sessions: Arc<DashMap<String, Session>>,
    api_keys: Arc<DashMap<uuid::Uuid, ApiKey>>,
    failed_logins: Arc<DashMap<String, u32>>,
    locked_accounts: Arc<DashMap<String, DateTime<Utc>>>,
    audit_entries: Arc<DashMap<u64, AuditEntry>>,
    audit_seq: Arc<AtomicU64>,
    audit_file: Arc<Mutex<Option<std::fs::File>>>,
}

impl std::fmt::Debug for RbacManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RbacManager")
            .field("users", &self.users.len())
            .field("roles", &self.roles.len())
            .field("sessions", &self.sessions.len())
            .finish()
    }
}

impl RbacManager {
    pub fn new(config: RbacConfig) -> Self {
        let roles: Arc<DashMap<String, Role>> = Arc::new(DashMap::new());
        let role_ids: Arc<DashMap<String, String>> = Arc::new(DashMap::new());
        let users: Arc<DashMap<String, User>> = Arc::new(DashMap::new());
        let audit_file = config.audit_log_path.as_ref().and_then(|path| {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                Ok(file) => Some(file),
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "Could not open RBAC audit log");
                    None
                }
            }
        });

        Self::create_default_roles(&roles, &role_ids);

        Self {
            config: config.clone(),
            auth_manager: Arc::new(AuthManager::new(config.auth)),
            users,
            roles,
            role_ids,
            sessions: Arc::new(DashMap::new()),
            api_keys: Arc::new(DashMap::new()),
            failed_logins: Arc::new(DashMap::new()),
            locked_accounts: Arc::new(DashMap::new()),
            audit_entries: Arc::new(DashMap::new()),
            audit_seq: Arc::new(AtomicU64::new(0)),
            audit_file: Arc::new(Mutex::new(audit_file)),
        }
    }

    fn insert_role(
        roles: &Arc<DashMap<String, Role>>,
        role_ids: &Arc<DashMap<String, String>>,
        role: Role,
    ) {
        role_ids.insert(role.id.0.clone(), role.name.clone());
        roles.insert(role.name.clone(), role);
    }

    fn create_default_roles(
        roles: &Arc<DashMap<String, Role>>,
        role_ids: &Arc<DashMap<String, String>>,
    ) {
        let mut admin = Role::new("admin".into());
        admin.description = "Super administrator with full system access".into();
        admin.is_system = true;
        admin.grant_permission(Permission::new("*", "*"));
        Self::insert_role(roles, role_ids, admin);

        let mut sec_admin = Role::new("security_admin".into());
        sec_admin.description =
            "Security administrator - detection, ingestion, settings, and access control".into();
        sec_admin.is_system = true;
        for permission in [
            "*:read",
            "ingest:*",
            "alert:*",
            "rule:*",
            "ontology:*",
            "rbac:*",
            "settings:*",
            "index:*",
            "xdr:*",
            "soar:*",
            "mcp:*",
        ] {
            sec_admin.grant_permission(permission.into());
        }
        Self::insert_role(roles, role_ids, sec_admin);

        let mut hunter = Role::new("threat_hunter".into());
        hunter.description =
            "Senior threat hunter - proactive hunting, CyberQL, AI, and rules".into();
        hunter.is_system = true;
        for permission in [
            "search:*",
            "ai:*",
            "alert:*",
            "rule:*",
            "ontology:*",
            "dashboard:*",
            "internal:read",
            "xdr:read",
        ] {
            hunter.grant_permission(permission.into());
        }
        Self::insert_role(roles, role_ids, hunter);

        let mut analyst = Role::new("analyst".into());
        analyst.description = "Security analyst - search, triage, and analyze telemetry".into();
        analyst.is_system = true;
        for permission in [
            "search:read",
            "search:export",
            "search:realtime",
            "alert:read",
            "alert:write",
            "ontology:read",
            "dashboard:read",
            "ai:chat",
            "xdr:read",
        ] {
            analyst.grant_permission(permission.into());
        }
        Self::insert_role(roles, role_ids, analyst);

        let mut soc_op = Role::new("soc_operator".into());
        soc_op.description = "SOC Tier 1 operator - triage alerts and monitor dashboards".into();
        soc_op.is_system = true;
        for permission in ["search:read", "alert:read", "alert:write", "dashboard:read"] {
            soc_op.grant_permission(permission.into());
        }
        Self::insert_role(roles, role_ids, soc_op);

        let mut auditor = Role::new("auditor".into());
        auditor.description = "Compliance auditor - read-only audit and policy access".into();
        auditor.is_system = true;
        for permission in ["internal:*", "rbac:read", "dashboard:read", "search:read"] {
            auditor.grant_permission(permission.into());
        }
        Self::insert_role(roles, role_ids, auditor);

        let mut ingest_op = Role::new("ingest_operator".into());
        ingest_op.description = "Ingest operator - submit data and manage collectors".into();
        ingest_op.is_system = true;
        for permission in ["ingest:*", "collector:*"] {
            ingest_op.grant_permission(permission.into());
        }
        Self::insert_role(roles, role_ids, ingest_op);

        let mut viewer = Role::new("viewer".into());
        viewer.description = "Read-only access to dashboards and basic search".into();
        viewer.is_system = true;
        for permission in [
            "search:read",
            "dashboard:read",
            "alert:read",
            "ontology:read",
        ] {
            viewer.grant_permission(permission.into());
        }
        Self::insert_role(roles, role_ids, viewer);

        info!("Default RBAC roles initialized");
    }

    /// Create the first administrator on a fresh installation.
    ///
    /// Returns `Ok(None)` when at least one active user already exists.
    pub fn bootstrap_admin(&self, username: &str, password: &str) -> Result<Option<User>> {
        if self.users.iter().any(|u| u.value().is_active) {
            return Ok(None);
        }
        if password.chars().count() < 12 {
            return Err(RbacError::WeakPassword);
        }

        let role_id = self
            .roles
            .get("admin")
            .map(|r| r.id.clone())
            .ok_or_else(|| RbacError::RoleNotFound("admin".into()))?;

        let mut user = User::new(username.to_string(), String::new());
        user.full_name = "Initial Administrator".into();
        user.set_password_hash(hash_password(password));
        user.assign_role(role_id);
        self.users.insert(user.username.clone(), user.clone());

        self.record_audit(
            &user.username,
            "bootstrap_admin",
            username,
            "SUCCESS",
            "initial admin created",
        );
        Ok(Some(user))
    }

    // ========================================================================
    // User Management
    // ========================================================================

    pub fn create_user(&self, mut user: User) -> Result<User> {
        if user.username.trim().is_empty() {
            return Err(RbacError::Internal("username cannot be empty".into()));
        }
        if self.users.contains_key(&user.username) {
            return Err(RbacError::UserAlreadyExists(user.username.clone()));
        }

        user.created_at = Utc::now();
        user.updated_at = Utc::now();
        self.users.insert(user.username.clone(), user.clone());
        self.record_audit(
            "system",
            "user_create",
            &user.username,
            "SUCCESS",
            "user created",
        );
        Ok(user)
    }

    pub fn get_user(&self, username: &str) -> Option<User> {
        self.users.get(username).map(|v| v.clone())
    }

    pub fn get_user_by_id(&self, user_id: &UserId) -> Option<User> {
        self.users
            .iter()
            .find(|v| v.value().id == *user_id)
            .map(|v| v.value().clone())
    }

    pub fn list_users(&self) -> Vec<User> {
        self.users.iter().map(|v| v.value().clone()).collect()
    }

    pub fn update_user(&self, username: &str, updates: impl FnOnce(&mut User)) -> Result<()> {
        let mut user = self
            .users
            .get_mut(username)
            .ok_or_else(|| RbacError::UserNotFound(username.to_string()))?;
        updates(&mut user);
        user.updated_at = Utc::now();
        Ok(())
    }

    pub fn delete_user(&self, username: &str) -> Result<()> {
        // Capture first: removing a map entry drops the value.
        let user = self
            .users
            .remove(username)
            .map(|(_, user)| user)
            .ok_or_else(|| RbacError::UserNotFound(username.to_string()))?;
        self.revoke_all_sessions_for_user(&user.id);
        self.record_audit("system", "user_delete", username, "SUCCESS", "user deleted");
        Ok(())
    }

    pub fn assign_user_role(&self, username: &str, role_name: &str) -> Result<()> {
        let role_id = self
            .roles
            .get(role_name)
            .map(|r| r.id.clone())
            .ok_or_else(|| RbacError::RoleNotFound(role_name.to_string()))?;

        let mut user = self
            .users
            .get_mut(username)
            .ok_or_else(|| RbacError::UserNotFound(username.to_string()))?;
        user.assign_role(role_id);
        user.updated_at = Utc::now();
        Ok(())
    }

    // ========================================================================
    // Role Management
    // ========================================================================

    pub fn create_role(&self, mut role: Role) -> Result<Role> {
        if role.name.trim().is_empty() {
            return Err(RbacError::Internal("role name cannot be empty".into()));
        }
        if self.roles.contains_key(&role.name) {
            return Err(RbacError::RoleAlreadyExists(role.name.clone()));
        }
        role.created_at = Utc::now();
        role.updated_at = Utc::now();
        self.role_ids.insert(role.id.0.clone(), role.name.clone());
        self.roles.insert(role.name.clone(), role.clone());
        Ok(role)
    }

    pub fn get_role(&self, name: &str) -> Option<Role> {
        self.roles.get(name).map(|v| v.clone())
    }

    pub fn list_roles(&self) -> Vec<Role> {
        self.roles.iter().map(|v| v.value().clone()).collect()
    }

    pub fn grant_role_permission(&self, role_name: &str, permission: Permission) -> Result<()> {
        let mut role = self
            .roles
            .get_mut(role_name)
            .ok_or_else(|| RbacError::RoleNotFound(role_name.to_string()))?;
        role.grant_permission(permission);
        Ok(())
    }

    pub fn get_role_by_id(&self, id: &RoleId) -> Option<Role> {
        self.role_ids
            .get(&id.0)
            .and_then(|name| self.roles.get(name.value()).map(|r| r.value().clone()))
    }

    pub fn update_role(&self, name: &str, updates: impl FnOnce(&mut Role)) -> Result<()> {
        let mut role = self
            .roles
            .get_mut(name)
            .ok_or_else(|| RbacError::RoleNotFound(name.to_string()))?;
        updates(&mut role);
        role.updated_at = Utc::now();
        Ok(())
    }

    pub fn delete_role(&self, name: &str) -> Result<()> {
        if let Some(r) = self.roles.get(name) {
            if r.is_system {
                return Err(RbacError::SystemRoleProtected);
            }
        } else {
            return Err(RbacError::RoleNotFound(name.to_string()));
        }

        if let Some((_, role)) = self.roles.remove(name) {
            self.role_ids.remove(&role.id.0);
            for mut user in self.users.iter_mut() {
                user.remove_role(&role.id);
            }
        }
        Ok(())
    }

    pub fn clear_user_roles(&self, username: &str) -> Result<()> {
        let mut user = self
            .users
            .get_mut(username)
            .ok_or_else(|| RbacError::UserNotFound(username.to_string()))?;
        user.role_ids.clear();
        user.updated_at = Utc::now();
        Ok(())
    }

    // ========================================================================
    // Authentication
    // ========================================================================

    pub fn authenticate(
        &self,
        username: &str,
        password: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<(User, String, String)> {
        if let Some(lockout_until) = self.locked_accounts.get(username) {
            if Utc::now() < *lockout_until.value() {
                self.record_audit(username, "login", "", "LOCKED", "account locked");
                return Err(RbacError::AccountLocked);
            }
            drop(lockout_until);
            self.locked_accounts.remove(username);
            self.failed_logins.remove(username);
        }

        let mut user = self
            .users
            .get(username)
            .ok_or_else(|| RbacError::InvalidCredentials)?
            .clone();

        if !user.is_active {
            return Err(RbacError::AccountDisabled);
        }

        let Some(ref hash) = user.password_hash else {
            self.record_audit(username, "login", "", "FAILED", "no password set");
            return Err(RbacError::InvalidCredentials);
        };

        if !verify_password(password, hash) {
            self.record_failed_login(username);
            self.record_audit(username, "login", "", "FAILED", "bad credentials");
            return Err(RbacError::InvalidCredentials);
        }

        // Transparently upgrade legacy hashes while the plaintext is available.
        if password_needs_rehash(hash) {
            let new_hash = hash_password(password);
            if let Some(mut stored) = self.users.get_mut(username) {
                stored.password_hash = Some(new_hash);
            }
            user.password_hash = self
                .users
                .get(username)
                .and_then(|u| u.password_hash.clone());
        }

        self.failed_logins.remove(username);

        let role_names = self.role_names_for(&user);
        let (access_token, refresh_token) =
            self.auth_manager
                .create_tokens(&user.id, username, &role_names)?;

        let mut session = Session::new(
            user.id.clone(),
            token_hash(&access_token),
            token_hash(&refresh_token),
            self.config.session_ttl_hours,
            self.config.auth.refresh_token_ttl_days,
        );
        session.ip_address = ip_address.map(str::to_string);
        session.user_agent = user_agent.map(str::to_string);
        self.sessions
            .insert(session.access_token_hash.clone(), session);

        self.update_user(username, |u| {
            u.last_login = Some(Utc::now());
        })?;
        self.record_audit(username, "login", "", "SUCCESS", "authenticated");

        debug!(username, "User authenticated");
        Ok((user, access_token, refresh_token))
    }

    /// Validate a bearer token and its server-side session.
    pub fn validate_session(&self, token: &str) -> Result<(User, Claims)> {
        let claims = self.auth_manager.validate_access_token(token)?;
        let hash = token_hash(token);

        let mut session = self
            .sessions
            .get_mut(&hash)
            .ok_or_else(|| RbacError::InvalidToken("Session not found or revoked".into()))?;

        if !session.is_active || session.is_expired() {
            drop(session);
            self.sessions.remove(&hash);
            return Err(RbacError::TokenExpired);
        }

        let user = self
            .get_user_by_id(&UserId(claims.sub.clone()))
            .ok_or_else(|| RbacError::InvalidToken("User not found".into()))?;
        if !user.is_active {
            return Err(RbacError::AccountDisabled);
        }
        session.touch();

        Ok((user, claims))
    }

    /// Refresh an access token using a refresh token. The session is updated so
    /// the new access token can be validated server-side.
    pub fn refresh_token(&self, refresh_token: &str) -> Result<String> {
        let claims = self.auth_manager.validate_token(refresh_token)?;
        if claims.typ != "refresh" {
            return Err(RbacError::InvalidToken("Not a refresh token".to_string()));
        }

        let refresh_hash = token_hash(refresh_token);
        // The map is keyed by access-token hash. Locate the session, remove it by
        // its current key, then re-insert under the new access-token hash.
        let old_key = self
            .sessions
            .iter()
            .find(|s| s.value().refresh_token_hash == refresh_hash)
            .map(|s| s.key().clone())
            .ok_or_else(|| RbacError::InvalidToken("Refresh session not found".into()))?;

        let mut session = self
            .sessions
            .remove(&old_key)
            .map(|(_, session)| session)
            .ok_or_else(|| RbacError::InvalidToken("Refresh session not found".into()))?;

        if !session.is_active || session.is_refresh_expired() {
            return Err(RbacError::TokenExpired);
        }

        let new_access = self.auth_manager.refresh_access_token(refresh_token)?;
        session.access_token_hash = token_hash(&new_access);
        session.expires_at = Utc::now() + Duration::hours(self.config.session_ttl_hours as i64);
        session.touch();
        let new_key = session.access_token_hash.clone();
        self.sessions.insert(new_key, session);

        Ok(new_access)
    }

    pub fn revoke_session(&self, token: &str) {
        let hash = token_hash(token);
        if self.sessions.remove(&hash).is_some() {
            self.record_audit("system", "logout", "", "SUCCESS", "session revoked");
        }
    }

    pub fn revoke_all_sessions_for_user(&self, user_id: &UserId) {
        self.sessions.retain(|_, s| s.user_id != *user_id);
    }

    fn role_names_for(&self, user: &User) -> Vec<String> {
        user.role_ids
            .iter()
            .filter_map(|id| self.role_ids.get(&id.0).map(|name| name.value().clone()))
            .collect()
    }

    fn record_failed_login(&self, username: &str) {
        let count = {
            let mut entry = self.failed_logins.entry(username.to_string()).or_insert(0);
            *entry += 1;
            *entry
        };

        if count >= self.config.max_failed_login_attempts {
            let lockout_until =
                Utc::now() + Duration::minutes(self.config.lockout_duration_minutes as i64);
            self.locked_accounts
                .insert(username.to_string(), lockout_until);
            warn!(username, "Account locked until {}", lockout_until);
        }
    }

    // ========================================================================
    // Access Control
    // ========================================================================

    /// Check a permission, resolving wildcards and role inheritance.
    pub fn check_permission(&self, user: &User, permission: &Permission) -> AccessResult {
        let mut stack: Vec<RoleId> = user.role_ids.clone();
        let mut visited: HashSet<String> = HashSet::new();

        while let Some(role_id) = stack.pop() {
            if !visited.insert(role_id.0.clone()) {
                continue;
            }
            let Some(role_name) = self.role_ids.get(&role_id.0).map(|n| n.value().clone()) else {
                continue;
            };
            let Some(role) = self.roles.get(&role_name) else {
                continue;
            };
            if role.has_permission_obj(permission) {
                return AccessResult::Allowed;
            }
            stack.extend(role.inherits.iter().cloned());
        }

        AccessResult::Denied {
            reason: format!("User {} lacks permission {}", user.username, permission),
        }
    }

    pub fn check_access(
        &self,
        user: &User,
        resource: &ResourceType,
        action: &ActionType,
    ) -> AccessResult {
        self.check_permission(
            user,
            &Permission::new(&resource.to_string(), &action.to_string()),
        )
    }

    pub fn require_permission(&self, user: &User, permission: &Permission) -> Result<()> {
        match self.check_permission(user, permission) {
            AccessResult::Allowed => Ok(()),
            AccessResult::Denied { reason } => Err(RbacError::InsufficientPermissions {
                required: permission.0.clone(),
                got: reason,
            }),
        }
    }

    /// All permissions granted to a user, including role inheritance.
    /// Wildcards are preserved as granted; callers should use
    /// `Permission::grants` for checks.
    pub fn effective_permissions(&self, user: &User) -> HashSet<Permission> {
        let mut permissions = HashSet::new();
        let mut stack: Vec<RoleId> = user.role_ids.clone();
        let mut visited: HashSet<String> = HashSet::new();

        while let Some(role_id) = stack.pop() {
            if !visited.insert(role_id.0.clone()) {
                continue;
            }
            let Some(role_name) = self.role_ids.get(&role_id.0).map(|n| n.value().clone()) else {
                continue;
            };
            let Some(role) = self.roles.get(&role_name) else {
                continue;
            };
            permissions.extend(role.permissions.iter().cloned());
            stack.extend(role.inherits.iter().cloned());
        }

        permissions
    }

    /// Role names assigned to a user, resolved through stable role IDs.
    pub fn role_names_for_user(&self, user: &User) -> Vec<String> {
        let mut names: Vec<String> = user
            .role_ids
            .iter()
            .filter_map(|id| self.role_ids.get(&id.0).map(|name| name.value().clone()))
            .collect();
        names.sort();
        names.dedup();
        names
    }

    /// Permission check for API-key principals.
    pub fn api_key_allows(permissions: &[Permission], required: &Permission) -> bool {
        permissions.iter().any(|p| p.grants(required))
    }

    // ========================================================================
    // API Keys
    // ========================================================================

    pub fn create_api_key(
        &self,
        user_id: &UserId,
        name: String,
        permissions: HashSet<Permission>,
    ) -> Result<(ApiKey, String)> {
        let _user = self
            .get_user_by_id(user_id)
            .ok_or_else(|| RbacError::UserNotFound(user_id.0.clone()))?;

        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let full_key = format!("cg_{}", hex::encode(bytes));

        let mut api_key = ApiKey::new(name, user_id.clone(), permissions);
        let mut hasher = Sha256::new();
        hasher.update(full_key.as_bytes());
        api_key.key_hash = hex::encode(hasher.finalize());
        api_key.key_prefix = full_key[..11.min(full_key.len())].to_string();

        self.api_keys.insert(api_key.id, api_key.clone());
        self.record_audit(
            "system",
            "api_key_create",
            &api_key.name,
            "SUCCESS",
            "api key issued",
        );
        Ok((api_key, full_key))
    }

    pub fn validate_api_key(&self, key: &str) -> Result<(User, Vec<Permission>)> {
        if key.len() < 16 {
            return Err(RbacError::InvalidApiKey);
        }

        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let candidate = hex::encode(hasher.finalize());

        let api_key = self
            .api_keys
            .iter()
            .find(|ak| ak.value().is_active && constant_time_eq(&ak.value().key_hash, &candidate))
            .map(|ak| ak.value().clone())
            .ok_or(RbacError::InvalidApiKey)?;

        if let Some(expires) = api_key.expires_at {
            if Utc::now() > expires {
                return Err(RbacError::InvalidApiKey);
            }
        }

        let user = self
            .get_user_by_id(&api_key.user_id)
            .ok_or(RbacError::InvalidApiKey)?;
        if !user.is_active {
            return Err(RbacError::AccountDisabled);
        }

        if let Some(mut entry) = self.api_keys.get_mut(&api_key.id) {
            entry.last_used = Some(Utc::now());
        }

        Ok((user, api_key.permissions.into_iter().collect()))
    }

    pub fn list_api_keys(&self, user_id: &UserId) -> Vec<ApiKey> {
        self.api_keys
            .iter()
            .filter(|ak| ak.value().user_id == *user_id)
            .map(|ak| ak.value().clone())
            .collect()
    }

    pub fn list_all_api_keys(&self) -> Vec<ApiKey> {
        self.api_keys.iter().map(|ak| ak.value().clone()).collect()
    }

    pub fn revoke_api_key(&self, key_id: uuid::Uuid) -> Result<()> {
        if self.api_keys.remove(&key_id).is_some() {
            Ok(())
        } else {
            Err(RbacError::Internal("API key not found".to_string()))
        }
    }

    // ========================================================================
    // Audit
    // ========================================================================

    pub fn record_audit(
        &self,
        actor: &str,
        action: &str,
        target: &str,
        outcome: &str,
        detail: &str,
    ) {
        let id = self.audit_seq.fetch_add(1, Ordering::SeqCst) + 1;
        let entry = AuditEntry {
            id,
            timestamp: Utc::now(),
            actor: actor.to_string(),
            action: action.to_string(),
            target: target.to_string(),
            outcome: outcome.to_string(),
            detail: detail.to_string(),
            source_ip: None,
        };

        if let Ok(mut file) = self.audit_file.lock() {
            if let Some(file) = file.as_mut() {
                if let Ok(line) = serde_json::to_string(&entry) {
                    let _ = writeln!(file, "{}", line);
                    let _ = file.flush();
                }
            }
        }

        self.audit_entries.insert(id, entry);
        if self.audit_entries.len() > 20_000 {
            let cutoff = id.saturating_sub(10_000);
            self.audit_entries.retain(|k, _| *k > cutoff);
        }
    }

    pub fn list_audit(&self, limit: usize) -> Vec<AuditEntry> {
        let mut entries: Vec<AuditEntry> = self
            .audit_entries
            .iter()
            .map(|e| e.value().clone())
            .collect();
        entries.sort_by(|a, b| b.id.cmp(&a.id));
        entries.truncate(limit);
        entries
    }

    // ========================================================================
    // Configuration / Stats
    // ========================================================================

    pub fn config(&self) -> &RbacConfig {
        &self.config
    }

    pub fn stats(&self) -> RbacStats {
        let now = Utc::now();
        RbacStats {
            total_users: self.users.len(),
            active_users: self.users.iter().filter(|u| u.value().is_active).count(),
            total_roles: self.roles.len(),
            total_sessions: self.sessions.len(),
            active_sessions: self
                .sessions
                .iter()
                .filter(|s| s.value().is_active && !s.value().is_expired())
                .count(),
            total_api_keys: self.api_keys.len(),
            locked_accounts: self
                .locked_accounts
                .iter()
                .filter(|l| *l.value() > now)
                .count(),
        }
    }
}

/// RBAC statistics for dashboards.
#[derive(Debug, Clone, Serialize)]
pub struct RbacStats {
    pub total_users: usize,
    pub active_users: usize,
    pub total_roles: usize,
    pub total_sessions: usize,
    pub active_sessions: usize,
    pub total_api_keys: usize,
    pub locked_accounts: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager() -> RbacManager {
        RbacManager::new(RbacConfig {
            auth: AuthConfig::for_tests(),
            ..Default::default()
        })
    }

    #[test]
    fn bootstrap_and_authenticate() {
        let rbac = manager();
        let admin = rbac
            .bootstrap_admin("root", "a-very-long-password")
            .unwrap()
            .expect("first admin");
        assert_eq!(admin.username, "root");
        assert!(rbac
            .bootstrap_admin("second", "another-long-password")
            .unwrap()
            .is_none());

        let (user, access, refresh) = rbac
            .authenticate("root", "a-very-long-password", Some("127.0.0.1"), None)
            .unwrap();
        assert_eq!(user.username, "root");
        assert!(rbac.validate_session(&access).is_ok());
        assert!(
            rbac.validate_session(&refresh).is_err(),
            "refresh is not a bearer token"
        );

        let refreshed = rbac.refresh_token(&refresh).unwrap();
        assert!(rbac.validate_session(&refreshed).is_ok());
        assert!(
            rbac.validate_session(&access).is_err(),
            "old access token is replaced"
        );
    }

    #[test]
    fn authorization_resolves_ids_and_wildcards() {
        let rbac = manager();
        let admin = rbac
            .bootstrap_admin("root", "a-very-long-password")
            .unwrap()
            .unwrap();
        let mut analyst = User::new("analyst".into(), String::new());
        let analyst_role = rbac.get_role("analyst").unwrap();
        analyst.assign_role(analyst_role.id);
        assert_eq!(
            rbac.check_permission(&analyst, &Permission::new("search", "read")),
            AccessResult::Allowed
        );
        assert!(matches!(
            rbac.check_permission(&analyst, &Permission::new("rbac", "manage")),
            AccessResult::Denied { .. }
        ));
    }

    #[test]
    fn role_inheritance_is_transitive_and_cycle_safe() {
        let rbac = manager();
        let mut base = Role::new("base".into());
        base.grant_permission(Permission::new("search", "read"));
        let base = rbac.create_role(base).unwrap();

        let mut mid = Role::new("mid".into());
        mid.inherits_from(base.id.clone());
        let mid = rbac.create_role(mid).unwrap();

        let mut top = Role::new("top".into());
        top.inherits_from(mid.id.clone());
        top.inherits_from(mid.id.clone());
        let top = rbac.create_role(top).unwrap();

        // Introduce a cycle to prove the resolver terminates.
        rbac.update_role("base", |r| r.inherits_from(top.id.clone()))
            .unwrap();

        let mut user = User::new("hunter".into(), String::new());
        user.assign_role(top.id);
        assert_eq!(
            rbac.check_permission(&user, &Permission::new("search", "read")),
            AccessResult::Allowed
        );
    }

    #[test]
    fn api_keys_are_hashed_and_scoped() {
        let rbac = manager();
        let admin = rbac
            .bootstrap_admin("root", "a-very-long-password")
            .unwrap()
            .unwrap();

        let mut permissions = HashSet::new();
        permissions.insert(Permission::new("search", "read"));
        let (api_key, full_key) = rbac
            .create_api_key(&admin.id, "readonly".into(), permissions)
            .unwrap();
        assert!(full_key.starts_with("cg_"));
        assert!(!api_key.key_hash.contains(&full_key));

        let (_, perms) = rbac.validate_api_key(&full_key).unwrap();
        assert!(RbacManager::api_key_allows(
            &perms,
            &Permission::new("search", "read")
        ));
        assert!(!RbacManager::api_key_allows(
            &perms,
            &Permission::new("ingest", "write")
        ));
    }

    #[test]
    fn deleting_user_revokes_sessions() {
        let rbac = manager();
        let _ = rbac
            .bootstrap_admin("root", "a-very-long-password")
            .unwrap();
        let (_, access, _) = rbac
            .authenticate("root", "a-very-long-password", None, None)
            .unwrap();
        assert!(rbac.validate_session(&access).is_ok());
        rbac.delete_user("root").unwrap();
        assert!(rbac.validate_session(&access).is_err());
    }
}
