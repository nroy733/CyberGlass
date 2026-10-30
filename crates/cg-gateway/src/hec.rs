//! Persistent HTTP Event Collector (HEC) token store.
//!
//! Tokens are high-entropy secrets. Only their SHA-256 hashes are stored on
//! disk; the plaintext is returned exactly once when the token is created.
//! Ingestion is denied when no token matches.

use cg_rbac::{constant_time_eq, token_hash};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use uuid::Uuid;

/// Persisted token record (hash only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HecTokenRecord {
    pub id: String,
    pub name: String,
    pub token_hash: String,
    /// First characters of the token, for operator identification only.
    pub token_prefix: String,
    pub index: String,
    pub sourcetype: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
    pub events_count: u64,
}

/// Public (non-secret) view returned by the list endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct HecTokenView {
    pub id: String,
    pub name: String,
    pub token_prefix: String,
    pub index: String,
    pub sourcetype: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
    pub events_count: u64,
}

impl From<&HecTokenRecord> for HecTokenView {
    fn from(record: &HecTokenRecord) -> Self {
        Self {
            id: record.id.clone(),
            name: record.name.clone(),
            token_prefix: record.token_prefix.clone(),
            index: record.index.clone(),
            sourcetype: record.sourcetype.clone(),
            enabled: record.enabled,
            created_at: record.created_at,
            last_used: record.last_used,
            events_count: record.events_count,
        }
    }
}

/// Result of a successful token validation.
#[derive(Debug, Clone)]
pub struct HecPrincipal {
    pub token_id: String,
    pub index: String,
    pub sourcetype: String,
}

pub struct HecTokenStore {
    records: RwLock<HashMap<String, HecTokenRecord>>,
    path: Option<PathBuf>,
    usage_since_save: AtomicU64,
}

impl HecTokenStore {
    /// Load the token store from `path`, or start empty when the file does not
    /// exist yet. Malformed files are an error rather than a silent reset.
    pub fn new(path: Option<PathBuf>) -> std::io::Result<Self> {
        let mut records = HashMap::new();
        if let Some(ref path) = path {
            if path.exists() {
                let raw = std::fs::read_to_string(path)?;
                let stored: Vec<HecTokenRecord> = serde_json::from_str(&raw)
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
                for record in stored {
                    records.insert(record.id.clone(), record);
                }
            }
        }

        let store = Self {
            records: RwLock::new(records),
            path,
            usage_since_save: AtomicU64::new(0),
        };

        // Bootstrap default ingestion token on first installation.
        if store.is_empty() {
            let bootstrap_token = std::env::var("CYBERGLASS_HEC_TOKEN")
                .unwrap_or_else(|_| "hec-token-sec-ops-001".to_string());
            let record = HecTokenRecord {
                id: Uuid::new_v4().to_string(),
                name: "Default Collector Token".to_string(),
                token_hash: token_hash(&bootstrap_token),
                token_prefix: bootstrap_token.chars().take(12).collect(),
                index: "main".to_string(),
                sourcetype: "json".to_string(),
                enabled: true,
                created_at: Utc::now(),
                last_used: None,
                events_count: 0,
            };
            store.write().insert(record.id.clone(), record);
            let _ = store.save();
        }

        Ok(store)
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<String, HecTokenRecord>> {
        self.records
            .read()
            .unwrap_or_else(|error| error.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<String, HecTokenRecord>> {
        self.records
            .write()
            .unwrap_or_else(|error| error.into_inner())
    }

    pub fn is_empty(&self) -> bool {
        self.read().is_empty()
    }

    pub fn create(
        &self,
        name: String,
        index: String,
        sourcetype: String,
    ) -> std::io::Result<(HecTokenView, String)> {
        let plaintext = format!(
            "cg-hec-{}{}",
            Uuid::new_v4().simple(),
            Uuid::new_v4().simple()
        );
        let record = HecTokenRecord {
            id: Uuid::new_v4().to_string(),
            name,
            token_hash: token_hash(&plaintext),
            token_prefix: plaintext.chars().take(12).collect(),
            index,
            sourcetype,
            enabled: true,
            created_at: Utc::now(),
            last_used: None,
            events_count: 0,
        };
        let view = HecTokenView::from(&record);
        self.write().insert(record.id.clone(), record);
        self.save()?;
        Ok((view, plaintext))
    }

    /// Validate a plaintext token in constant time across all stored hashes.
    pub fn validate(&self, token: &str) -> Option<HecPrincipal> {
        if token.is_empty() {
            return None;
        }
        let candidate = token_hash(token);
        let records = self.read();
        records
            .values()
            .find(|record| record.enabled && constant_time_eq(&record.token_hash, &candidate))
            .map(|record| HecPrincipal {
                token_id: record.id.clone(),
                index: record.index.clone(),
                sourcetype: record.sourcetype.clone(),
            })
    }

    /// Record usage. Persistence is batched to avoid a disk write per request.
    pub fn record_usage(&self, token_id: &str, accepted: u64) {
        {
            let mut records = self.write();
            if let Some(record) = records.get_mut(token_id) {
                record.last_used = Some(Utc::now());
                record.events_count = record.events_count.saturating_add(accepted);
            }
        }
        let count = self.usage_since_save.fetch_add(1, Ordering::Relaxed) + 1;
        if count >= 100 {
            self.usage_since_save.store(0, Ordering::Relaxed);
            let _ = self.save();
        }
    }

    pub fn list(&self) -> Vec<HecTokenView> {
        let mut views: Vec<HecTokenView> = self.read().values().map(HecTokenView::from).collect();
        views.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        views
    }

    /// Delete by record ID. Returns false when no such token exists.
    pub fn delete(&self, id: &str) -> std::io::Result<bool> {
        let removed = self.write().remove(id).is_some();
        if removed {
            self.save()?;
        }
        Ok(removed)
    }

    pub fn flush(&self) -> std::io::Result<()> {
        self.save()
    }

    fn save(&self) -> std::io::Result<()> {
        let Some(ref path) = self.path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let records: Vec<HecTokenRecord> = self.read().values().cloned().collect();
        let json = serde_json::to_vec_pretty(&records)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;

        // Write atomically: temp file in the same directory, then rename.
        let temp = path.with_extension("json.tmp");
        std::fs::write(&temp, &json)?;
        restrict_permissions(&temp)?;
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        std::fs::rename(&temp, path)?;
        Ok(())
    }
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_hashed_and_revocable() {
        let store = HecTokenStore::new(None).unwrap();
        let (view, plaintext) = store
            .create("test".into(), "main".into(), "json".into())
            .unwrap();
        assert!(plaintext.starts_with("cg-hec-"));
        assert!(!view.token_prefix.is_empty());
        assert!(store.validate(&plaintext).is_some());
        assert!(store.validate("wrong").is_none());

        assert!(store.delete(&view.id).unwrap());
        assert!(store.validate(&plaintext).is_none());
    }
}
