use crate::error::Result;
use crate::reader::IndexReader;
use crate::schema::EventSchema;
use crate::writer::IndexWriter;
use cg_core::config::IndexConfig;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tantivy::store::{Compressor, ZstdCompressor};
use tantivy::Index;
use tracing::warn;

const MAX_OPEN_INDEXES: usize = 1_024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexInfo {
    pub name: String,
    pub event_count: u64,
    pub size_bytes: u64,
    pub created_at: DateTime<Utc>,
}

pub struct IndexHandle {
    pub name: String,
    pub index: Index,
    pub writer: Arc<IndexWriter>,
    pub reader: Arc<IndexReader>,
}

pub struct IndexManager {
    base_dir: PathBuf,
    memory_budget: usize,
    schema: EventSchema,
    indices: DashMap<String, Arc<IndexHandle>>,
}

impl IndexManager {
    pub fn new(config: &IndexConfig) -> Result<Self> {
        let base_dir = PathBuf::from(&config.index_dir);
        std::fs::create_dir_all(&base_dir)?;

        let schema = EventSchema::build();

        let manager = Self {
            base_dir,
            memory_budget: config.memory_budget,
            schema,
            indices: DashMap::new(),
        };

        // Open the default index and any existing named indexes on restart.
        manager.get_or_create_index("main")?;
        for entry in std::fs::read_dir(&manager.base_dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if name != "main"
                && Self::validate_index_name(&name).is_ok()
                && entry.path().join("meta.json").is_file()
            {
                manager.get_or_create_index(&name)?;
            }
        }

        Ok(manager)
    }

    pub fn in_memory() -> Result<Self> {
        let schema = EventSchema::build();
        let manager = Self {
            base_dir: PathBuf::from("./target/test_index"),
            memory_budget: 50 * 1024 * 1024,
            schema,
            indices: DashMap::new(),
        };
        manager.get_or_create_index("main")?;
        Ok(manager)
    }

    pub fn get_or_create_index(&self, name: &str) -> Result<Arc<IndexHandle>> {
        Self::validate_index_name(name)?;
        if let Some(handle) = self.indices.get(name) {
            return Ok(handle.value().clone());
        }

        if self.indices.len() >= MAX_OPEN_INDEXES {
            return Err(crate::error::IndexError::IndexFull(format!(
                "open-index limit of {MAX_OPEN_INDEXES} reached"
            )));
        }

        let index_dir = self.base_dir.join(name);
        std::fs::create_dir_all(&index_dir)?;

        let mut index = Index::open_or_create(
            tantivy::directory::MmapDirectory::open(&index_dir)?,
            self.schema.schema.clone(),
        )?;
        index.settings_mut().docstore_compression = Compressor::Zstd(ZstdCompressor {
            compression_level: Some(3),
        });

        let writer = Arc::new(IndexWriter::new(
            &index,
            self.schema.clone(),
            self.memory_budget,
        )?);

        let reader = Arc::new(IndexReader::new(&index, self.schema.clone())?);

        let handle = Arc::new(IndexHandle {
            name: name.to_string(),
            index,
            writer,
            reader,
        });

        self.indices.insert(name.to_string(), handle.clone());
        Ok(handle)
    }

    fn validate_index_name(name: &str) -> Result<()> {
        if name.is_empty()
            || name.len() > 128
            || name == "."
            || name == ".."
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            return Err(crate::error::IndexError::Schema(format!(
                "invalid index name: {name:?}"
            )));
        }

        Ok(())
    }

    pub fn delete_index(&self, name: &str) -> bool {
        if name == "main" {
            return false;
        }
        self.indices.remove(name).is_some()
    }

    /// Delete all documents while preserving each configured index.
    pub fn clear_all(&self) -> Result<usize> {
        let handles: Vec<Arc<IndexHandle>> = self
            .indices
            .iter()
            .map(|entry| entry.value().clone())
            .collect();
        for handle in &handles {
            handle.writer.clear()?;
        }
        Ok(handles.len())
    }

    /// Commit every open index. Called periodically and on shutdown so events
    /// become searchable and are safely persisted.
    pub fn commit_all(&self) -> Result<()> {
        for handle in self.indices.iter() {
            handle.value().writer.commit()?;
        }
        Ok(())
    }

    pub fn list_indices(&self) -> Vec<IndexInfo> {
        self.indices
            .iter()
            .map(|entry| {
                let handle = entry.value();
                let size_bytes = match directory_size(&self.base_dir.join(&handle.name)) {
                    Ok(size_bytes) => size_bytes,
                    Err(error) => {
                        warn!(
                            index = %handle.name,
                            error = %error,
                            "Failed to measure index directory size"
                        );
                        0
                    }
                };
                IndexInfo {
                    name: handle.name.clone(),
                    event_count: handle.writer.total_indexed(),
                    size_bytes,
                    created_at: Utc::now(),
                }
            })
            .collect()
    }
}

fn directory_size(path: &std::path::Path) -> std::io::Result<u64> {
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
