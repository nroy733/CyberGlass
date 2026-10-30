//! # Audit Logger
//!
//! Logs security-relevant events (RBAC changes, configuration changes,
//! authentication events) to the `cg_audit` internal index and can be cleared
//! by authorized index maintenance.

use crate::error::Result;
use crate::internal_index::{InternalIndexManager, AUDIT_INDEX};
use serde_json::json;
use std::sync::Arc;
use tracing::info;

/// Security audit event types.
#[derive(Debug, Clone, PartialEq)]
pub enum AuditEventType {
    Login,
    Logout,
    LoginFailed,
    UserCreated,
    UserUpdated,
    UserDeleted,
    RoleCreated,
    RoleUpdated,
    RoleDeleted,
    RoleAssigned,
    RoleRevoked,
    ApiKeyCreated,
    ApiKeyRevoked,
    ConfigChanged,
    DataIngested,
    SearchExecuted,
    DashboardAccessed,
    Custom(String),
}

impl std::fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditEventType::Login => write!(f, "login"),
            AuditEventType::Logout => write!(f, "logout"),
            AuditEventType::LoginFailed => write!(f, "login_failed"),
            AuditEventType::UserCreated => write!(f, "user_created"),
            AuditEventType::UserUpdated => write!(f, "user_updated"),
            AuditEventType::UserDeleted => write!(f, "user_deleted"),
            AuditEventType::RoleCreated => write!(f, "role_created"),
            AuditEventType::RoleUpdated => write!(f, "role_updated"),
            AuditEventType::RoleDeleted => write!(f, "role_deleted"),
            AuditEventType::RoleAssigned => write!(f, "role_assigned"),
            AuditEventType::RoleRevoked => write!(f, "role_revoked"),
            AuditEventType::ApiKeyCreated => write!(f, "api_key_created"),
            AuditEventType::ApiKeyRevoked => write!(f, "api_key_revoked"),
            AuditEventType::ConfigChanged => write!(f, "config_changed"),
            AuditEventType::DataIngested => write!(f, "data_ingested"),
            AuditEventType::SearchExecuted => write!(f, "search_executed"),
            AuditEventType::DashboardAccessed => write!(f, "dashboard_accessed"),
            AuditEventType::Custom(s) => write!(f, "custom:{}", s),
        }
    }
}

/// Audit logger that writes to the `cg_audit` internal index.
pub struct AuditLogger {
    index_manager: Arc<InternalIndexManager>,
}

impl AuditLogger {
    pub fn new(index_manager: Arc<InternalIndexManager>) -> Self {
        Self { index_manager }
    }

    /// Log an audit event.
    pub fn log(
        &self,
        event_type: AuditEventType,
        user: Option<&str>,
        resource: Option<&str>,
        action: Option<&str>,
        details: Option<serde_json::Value>,
        ip_address: Option<&str>,
    ) -> Result<()> {
        let mut entry = crate::internal_index::InternalLogEntry::new(
            "cyberglass.audit",
            "audit",
            "info",
            &format!("{}", event_type),
        )
        .with_field("event_type", &event_type.to_string())
        .with_field("user", user.unwrap_or("system"))
        .with_field("resource", resource.unwrap_or("-"))
        .with_field("action", action.unwrap_or("-"))
        .with_field("ip_address", ip_address.unwrap_or("-"))
        .with_field(
            "details",
            &details.map(|d| d.to_string()).unwrap_or_default(),
        );

        entry.index = AUDIT_INDEX.to_string();
        self.index_manager.log_entry(entry)?;

        info!(
            "AUDIT: {} user={:?} resource={:?} action={:?}",
            event_type, user, resource, action
        );
        Ok(())
    }

    /// Log a user authentication event.
    pub fn log_auth(
        &self,
        event_type: AuditEventType,
        username: &str,
        success: bool,
        ip_address: &str,
    ) -> Result<()> {
        self.log(
            event_type,
            Some(username),
            Some("auth"),
            if success {
                Some("login")
            } else {
                Some("login_failed")
            },
            Some(json!({ "success": success })),
            Some(ip_address),
        )
    }

    /// Log a configuration change.
    pub fn log_config_change(
        &self,
        user: &str,
        config_key: &str,
        old_value: Option<&str>,
        new_value: Option<&str>,
    ) -> Result<()> {
        self.log(
            AuditEventType::ConfigChanged,
            Some(user),
            Some("config"),
            Some("update"),
            Some(json!({
                "key": config_key,
                "old_value": old_value,
                "new_value": new_value
            })),
            None,
        )
    }
}

// Placeholder field constant - should be defined in internal_index
pub const INTERNAL_LOG_ENTRY_FIELDS: &[&str] = &[
    "id",
    "_time",
    "source",
    "source_type",
    "level",
    "message",
    "fields",
];
