//! Persistent internal indexes for system logs, audit records, and telemetry.

use crate::error::{InternalError, Result};
use cg_core::types::{ParsedEvent, Severity};
use dashmap::DashMap;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tantivy::collector::TopDocs;
use tantivy::query::AllQuery;
use tantivy::schema::{Field, Schema, Value, FAST, INDEXED, STORED, STRING, TEXT};
use tantivy::store::{Compressor, ZstdCompressor};
use tantivy::{Index, IndexWriter, TantivyDocument};
use tracing::{debug, info};
use uuid::Uuid;

pub const INTERNAL_INDEX: &str = "cg_internal";
pub const AUDIT_INDEX: &str = "cg_audit";
pub const INTROSPECTION_INDEX: &str = "cg_introspection";

pub const ALL_INTERNAL_INDEXES: &[&str] = &[INTERNAL_INDEX, AUDIT_INDEX, INTROSPECTION_INDEX];

const MAX_LOG_MESSAGE_BYTES: usize = 256 * 1024;
const MAX_LOG_FIELDS: usize = 256;
const MAX_QUERY_LIMIT: usize = 1_000;

#[derive(Debug, Clone)]
pub struct InternalIndexConfig {
    pub base_dir: PathBuf,
    pub memory_budget: usize,
}

impl Default for InternalIndexConfig {
    fn default() -> Self {
        Self {
            base_dir: PathBuf::from("./data/internal_index"),
            memory_budget: 256 * 1024 * 1024,
        }
    }
}

#[derive(Clone)]
struct InternalEventSchema {
    schema: Schema,
    id: Field,
    timestamp: Field,
    source: Field,
    source_type: Field,
    index_name: Field,
    level: Field,
    message: Field,
    fields: Field,
}

impl InternalEventSchema {
    fn build() -> Self {
        let mut builder = Schema::builder();
        let id = builder.add_text_field("id", STRING | STORED);
        let timestamp = builder.add_date_field("_time", INDEXED | STORED | FAST);
        let source = builder.add_text_field("source", STRING | STORED);
        let source_type = builder.add_text_field("source_type", STRING | STORED);
        let index_name = builder.add_text_field("index_name", STRING | STORED);
        let level = builder.add_text_field("level", STRING | STORED);
        let message = builder.add_text_field("message", TEXT | STORED);
        let fields = builder.add_text_field("fields", STORED);
        Self {
            schema: builder.build(),
            id,
            timestamp,
            source,
            source_type,
            index_name,
            level,
            message,
            fields,
        }
    }
}

pub struct InternalIndexManager {
    config: InternalIndexConfig,
    schema: InternalEventSchema,
    indexes: DashMap<String, Arc<Index>>,
    writers: DashMap<String, Arc<Mutex<IndexWriter>>>,
}

impl InternalIndexManager {
    pub fn new(config: InternalIndexConfig) -> Result<Self> {
        std::fs::create_dir_all(&config.base_dir)?;
        migrate_legacy_index_directories(&config.base_dir)?;
        let manager = Self {
            config,
            schema: InternalEventSchema::build(),
            indexes: DashMap::new(),
            writers: DashMap::new(),
        };
        for index_name in ALL_INTERNAL_INDEXES {
            manager.create_index(index_name)?;
        }
        info!(
            count = ALL_INTERNAL_INDEXES.len(),
            "Internal index manager initialized"
        );
        Ok(manager)
    }

    fn create_index(&self, name: &str) -> Result<()> {
        let index_dir = self.config.base_dir.join(name);
        std::fs::create_dir_all(&index_dir)?;
        let mut index = Index::open_or_create(
            tantivy::directory::MmapDirectory::open(&index_dir)
                .map_err(|error| InternalError::Index(error.to_string()))?,
            self.schema.schema.clone(),
        )?;
        index.settings_mut().docstore_compression = Compressor::Zstd(ZstdCompressor {
            compression_level: Some(3),
        });
        let index = Arc::new(index);
        let writer = index
            .writer((self.config.memory_budget / ALL_INTERNAL_INDEXES.len()).max(1024 * 1024))
            .map_err(|error| InternalError::Index(error.to_string()))?;
        self.writers
            .insert(name.to_string(), Arc::new(Mutex::new(writer)));
        self.indexes.insert(name.to_string(), index);
        debug!(index = name, "Opened internal index");
        Ok(())
    }

    pub fn get_index(&self, name: &str) -> Option<Arc<Index>> {
        let canonical = canonical_index_name(name)?;
        self.indexes
            .get(canonical)
            .map(|index| index.value().clone())
    }

    pub fn is_internal_index(name: &str) -> bool {
        canonical_index_name(name).is_some()
    }

    pub fn list_internal_indexes(&self) -> Vec<String> {
        ALL_INTERNAL_INDEXES
            .iter()
            .map(|name| name.to_string())
            .collect()
    }

    pub fn log_entry(&self, mut entry: InternalLogEntry) -> Result<()> {
        let canonical = canonical_index_name(&entry.index).ok_or_else(|| {
            InternalError::Index(format!("unknown internal index: {}", entry.index))
        })?;
        if entry.message.len() > MAX_LOG_MESSAGE_BYTES {
            return Err(InternalError::Write(format!(
                "internal log message exceeds {MAX_LOG_MESSAGE_BYTES} bytes"
            )));
        }
        if entry.fields.len() > MAX_LOG_FIELDS {
            return Err(InternalError::Write(format!(
                "internal log entry exceeds {MAX_LOG_FIELDS} fields"
            )));
        }
        entry.index = canonical.to_string();
        let writer = self.writers.get(canonical).ok_or_else(|| {
            InternalError::Index(format!("internal index is unavailable: {canonical}"))
        })?;
        let mut document = TantivyDocument::default();
        document.add_text(self.schema.id, &entry.id);
        document.add_date(
            self.schema.timestamp,
            tantivy::DateTime::from_timestamp_millis(entry.timestamp.timestamp_millis()),
        );
        document.add_text(self.schema.source, &entry.source);
        document.add_text(self.schema.source_type, &entry.source_type);
        document.add_text(self.schema.index_name, canonical);
        document.add_text(self.schema.level, &entry.level);
        document.add_text(self.schema.message, &entry.message);
        document.add_text(
            self.schema.fields,
            &serde_json::to_string(&entry.fields)
                .map_err(|error| InternalError::Serialization(error.to_string()))?,
        );

        let mut writer = writer.value().lock();
        writer.delete_term(tantivy::Term::from_field_text(self.schema.id, &entry.id));
        writer
            .add_document(document)
            .map_err(|error| InternalError::Write(error.to_string()))?;
        writer
            .commit()
            .map_err(|error| InternalError::Write(error.to_string()))?;
        Ok(())
    }

    pub fn list_logs(&self, name: &str, limit: usize) -> Result<Vec<InternalLogEntry>> {
        let canonical = canonical_index_name(name)
            .ok_or_else(|| InternalError::Index(format!("unknown internal index: {name}")))?;
        let index = self.indexes.get(canonical).ok_or_else(|| {
            InternalError::Index(format!("internal index is unavailable: {canonical}"))
        })?;
        let reader = index
            .reader()
            .map_err(|error| InternalError::Index(error.to_string()))?;
        reader
            .reload()
            .map_err(|error| InternalError::Index(error.to_string()))?;
        let searcher = reader.searcher();
        let top_docs = searcher
            .search(
                &AllQuery,
                &TopDocs::with_limit(limit.clamp(1, MAX_QUERY_LIMIT))
                    .order_by_fast_field::<tantivy::DateTime>("_time", tantivy::Order::Desc),
            )
            .map_err(|error| InternalError::Index(error.to_string()))?;
        top_docs
            .into_iter()
            .map(|(_, address)| {
                let document: TantivyDocument = searcher
                    .doc(address)
                    .map_err(|error| InternalError::Index(error.to_string()))?;
                let id = stored_text(&document, self.schema.id);
                let timestamp = document
                    .get_first(self.schema.timestamp)
                    .and_then(|value| value.as_datetime())
                    .and_then(|time| {
                        chrono::DateTime::from_timestamp_millis(time.into_timestamp_millis())
                    })
                    .ok_or_else(|| {
                        InternalError::Index("internal log has invalid timestamp".into())
                    })?;
                let fields = document
                    .get_first(self.schema.fields)
                    .and_then(|value| value.as_str())
                    .map(serde_json::from_str)
                    .transpose()
                    .map_err(|error| InternalError::Serialization(error.to_string()))?
                    .unwrap_or_default();
                Ok(InternalLogEntry {
                    id,
                    timestamp,
                    source: stored_text(&document, self.schema.source),
                    source_type: stored_text(&document, self.schema.source_type),
                    index: canonical.to_string(),
                    level: stored_text(&document, self.schema.level),
                    message: stored_text(&document, self.schema.message),
                    fields,
                })
            })
            .collect()
    }

    pub fn clear_all(&self) -> Result<usize> {
        for writer in self.writers.iter() {
            let mut writer = writer.value().lock();
            writer
                .delete_all_documents()
                .and_then(|_| writer.commit())
                .map_err(|error| InternalError::Write(error.to_string()))?;
        }
        Ok(ALL_INTERNAL_INDEXES.len())
    }

    pub fn get_stats(&self) -> Result<Vec<InternalIndexStats>> {
        ALL_INTERNAL_INDEXES
            .iter()
            .map(|name| {
                let index = self.indexes.get(*name).ok_or_else(|| {
                    InternalError::Index(format!("internal index is unavailable: {name}"))
                })?;
                let reader = index
                    .reader()
                    .map_err(|error| InternalError::Index(error.to_string()))?;
                reader
                    .reload()
                    .map_err(|error| InternalError::Index(error.to_string()))?;
                let size_bytes = directory_size(&self.config.base_dir.join(name))?;
                Ok(InternalIndexStats {
                    name: name.to_string(),
                    doc_count: reader.searcher().num_docs(),
                    size_bytes,
                })
            })
            .collect()
    }
}

fn canonical_index_name(name: &str) -> Option<&'static str> {
    match name {
        "cg_internal" => Some(INTERNAL_INDEX),
        "cg_audit" => Some(AUDIT_INDEX),
        "cg_introspection" => Some(INTROSPECTION_INDEX),
        _ => None,
    }
}

fn migrate_legacy_index_directories(base_dir: &Path) -> Result<()> {
    for (legacy_name, current_name) in [
        ("_internal", INTERNAL_INDEX),
        ("_audit", AUDIT_INDEX),
        ("_introspection", INTROSPECTION_INDEX),
    ] {
        let legacy_path = base_dir.join(legacy_name);
        let current_path = base_dir.join(current_name);
        if !legacy_path.exists() {
            continue;
        }
        if current_path.exists() {
            return Err(InternalError::Index(format!(
                "both legacy and current internal index directories exist for {current_name}; \
                 reconcile {legacy_path:?} and {current_path:?} before starting"
            )));
        }
        std::fs::rename(&legacy_path, &current_path)?;
        info!(
            legacy_index = legacy_name,
            index = current_name,
            "Migrated internal index directory"
        );
    }
    Ok(())
}

fn stored_text(document: &TantivyDocument, field: Field) -> String {
    document
        .get_first(field)
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_string()
}

fn directory_size(path: &Path) -> std::io::Result<u64> {
    let mut total = 0u64;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            total = total.saturating_add(directory_size(&entry.path())?);
        } else {
            total = total.saturating_add(metadata.len());
        }
    }
    Ok(total)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InternalLogEntry {
    pub id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub source: String,
    pub source_type: String,
    pub level: String,
    pub message: String,
    pub fields: HashMap<String, String>,
    pub index: String,
}

impl InternalLogEntry {
    pub fn new(source: &str, source_type: &str, level: &str, message: &str) -> Self {
        Self {
            id: Uuid::now_v7().to_string(),
            timestamp: chrono::Utc::now(),
            source: source.to_string(),
            source_type: source_type.to_string(),
            level: level.to_string(),
            message: message.to_string(),
            fields: HashMap::new(),
            index: INTERNAL_INDEX.to_string(),
        }
    }

    pub fn with_field(mut self, key: &str, value: &str) -> Self {
        self.fields.insert(key.to_string(), value.to_string());
        self
    }

    pub fn to_parsed_event(&self) -> ParsedEvent {
        let mut event = ParsedEvent::new(
            &self.source,
            &self.source_type,
            self.message.as_bytes().to_vec(),
        );
        event.id = self.id.clone();
        event.timestamp = self.timestamp;
        event.index = self.index.clone();
        event.fields = self.fields.clone();
        event.severity = match self.level.to_ascii_lowercase().as_str() {
            "debug" => Severity::Debug,
            "info" => Severity::Info,
            "notice" => Severity::Notice,
            "warning" | "warn" => Severity::Warning,
            "error" => Severity::Error,
            "critical" => Severity::Critical,
            "alert" => Severity::Alert,
            "emergency" => Severity::Emergency,
            _ => Severity::Info,
        };
        event
    }
}

#[derive(Debug, Clone)]
pub struct InternalIndexStats {
    pub name: String,
    pub doc_count: u64,
    pub size_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditEventType, AuditLogger};

    fn manager() -> (InternalIndexManager, PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("cyberglass_internal_indexes_{}", Uuid::now_v7()));
        let manager = InternalIndexManager::new(InternalIndexConfig {
            base_dir: dir.clone(),
            memory_budget: 64 * 1024 * 1024,
        })
        .unwrap();
        (manager, dir)
    }

    #[test]
    fn internal_logs_persist_and_are_queryable_after_restart() {
        let (manager, dir) = manager();
        assert!(matches!(
            &manager
                .get_index("cg_internal")
                .unwrap()
                .settings()
                .docstore_compression,
            Compressor::Zstd(_)
        ));
        manager
            .log_entry(
                InternalLogEntry::new("server", "runtime", "INFO", "server started")
                    .with_field("component", "gateway"),
            )
            .unwrap();
        assert_eq!(manager.list_logs("cg_internal", 10).unwrap().len(), 1);
        drop(manager);

        let reopened = InternalIndexManager::new(InternalIndexConfig {
            base_dir: dir.clone(),
            memory_budget: 64 * 1024 * 1024,
        })
        .unwrap();
        assert!(matches!(
            &reopened
                .get_index("cg_internal")
                .unwrap()
                .settings()
                .docstore_compression,
            Compressor::Zstd(_)
        ));
        let logs = reopened.list_logs("cg_internal", 10).unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].message, "server started");
        assert_eq!(logs[0].fields.get("component").unwrap(), "gateway");
        assert_eq!(reopened.get_stats().unwrap()[0].doc_count, 1);
        drop(reopened);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn clear_internal_indexes_removes_documents_but_preserves_indexes() {
        let (manager, dir) = manager();
        manager
            .log_entry(InternalLogEntry::new(
                "server", "runtime", "INFO", "clear me",
            ))
            .unwrap();
        assert_eq!(manager.clear_all().unwrap(), ALL_INTERNAL_INDEXES.len());
        assert!(manager.list_logs("cg_internal", 10).unwrap().is_empty());
        assert_eq!(
            manager.list_internal_indexes().len(),
            ALL_INTERNAL_INDEXES.len()
        );
        drop(manager);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn legacy_index_directories_are_renamed_to_canonical_names() {
        let dir =
            std::env::temp_dir().join(format!("cyberglass_internal_migration_{}", Uuid::now_v7()));
        std::fs::create_dir_all(dir.join("_internal")).unwrap();
        std::fs::write(dir.join("_internal").join("migration-marker"), b"preserve").unwrap();

        let manager = InternalIndexManager::new(InternalIndexConfig {
            base_dir: dir.clone(),
            memory_budget: 64 * 1024 * 1024,
        })
        .unwrap();

        assert!(!dir.join("_internal").exists());
        assert_eq!(
            std::fs::read(dir.join("cg_internal").join("migration-marker")).unwrap(),
            b"preserve"
        );
        assert!(manager.get_index("cg_internal").is_some());
        drop(manager);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn legacy_index_names_are_not_accepted_as_query_aliases() {
        let (manager, dir) = manager();
        assert!(manager.list_logs("_internal", 10).is_err());
        drop(manager);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn audit_logger_persists_authentication_events_in_audit_index() {
        let (manager, dir) = manager();
        let manager = Arc::new(manager);
        let logger = AuditLogger::new(manager.clone());

        logger
            .log_auth(AuditEventType::Login, "analyst", true, "127.0.0.1")
            .unwrap();

        let logs = manager.list_logs("cg_audit", 10).unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].message, "login");
        assert_eq!(logs[0].fields.get("user").unwrap(), "analyst");
        assert_eq!(logs[0].fields.get("ip_address").unwrap(), "127.0.0.1");

        drop(logger);
        drop(manager);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
