//! # File/Directory Monitor for Data Onboarding
//!
//! Watches directories for new or modified files and ingests their contents
//! through the CyberGlass ingestion pipeline. Supports:
//! - **Directory watching** via polling (cross-platform, no native dependencies)
//! - **File tailing** for append-only log files
//! - **Per-file source type** assignment
//! - **Already-processed file tracking** to avoid re-ingestion

use crate::error::{IngestError, Result};
use crate::pipeline::IngestPipeline;
use bytes::Bytes;
use dashmap::DashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, warn};

/// Configuration for a monitored directory.
#[derive(Debug, Clone)]
pub struct MonitorConfig {
    /// Directory path to watch.
    pub path: PathBuf,
    /// Source name to tag events with.
    pub source: String,
    /// Source type for parsing (json, syslog, cef, kv, etc.).
    pub source_type: String,
    /// File extension filter (e.g., "log", "json").
    pub file_extension: String,
    /// Whether to tail files (read new lines as they are appended).
    pub tail: bool,
    /// Poll interval in milliseconds.
    pub poll_interval_ms: u64,
    /// Index to write events to.
    pub index: String,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("/var/log/cyberglass"),
            source: "file_monitor".into(),
            source_type: "json".into(),
            file_extension: "log".into(),
            tail: false,
            poll_interval_ms: 5000,
            index: "main".into(),
        }
    }
}

/// Tracks the read offset for tailed files.
#[derive(Debug, Clone, Default)]
struct FileOffset {
    /// Byte offset already read.
    offset: u64,
}

/// File monitor that watches directories and ingests files.
pub struct FileMonitor {
    pipeline: Arc<IngestPipeline>,
    config: MonitorConfig,
    /// Tracked file offsets for tailing.
    offsets: Arc<DashMap<PathBuf, FileOffset>>,
    /// Set of already-ingested file paths (for non-tail mode).
    ingested: Arc<DashMap<PathBuf, ()>>,
    /// Total events ingested by this monitor.
    events_ingested: AtomicU64,
    /// Total files processed.
    files_processed: AtomicU64,
}

impl FileMonitor {
    /// Creates a new file monitor.
    pub fn new(pipeline: Arc<IngestPipeline>, config: MonitorConfig) -> Self {
        Self {
            pipeline,
            config,
            offsets: Arc::new(DashMap::new()),
            ingested: Arc::new(DashMap::new()),
            events_ingested: AtomicU64::new(0),
            files_processed: AtomicU64::new(0),
        }
    }

    /// Starts the monitor loop. This runs indefinitely until the shutdown
    /// future completes.
    pub async fn run(
        self: Arc<Self>,
        mut shutdown: tokio::sync::broadcast::Receiver<()>,
    ) -> Result<()> {
        info!(
            "File monitor watching {} (ext={}, source={}, source_type={})",
            self.config.path.display(),
            self.config.file_extension,
            self.config.source,
            self.config.source_type
        );

        // Ensure the directory exists
        if !self.config.path.exists() {
            let _ = fs::create_dir_all(&self.config.path);
            warn!("Created monitor directory: {}", self.config.path.display());
        }

        let poll_interval = Duration::from_millis(self.config.poll_interval_ms);

        loop {
            tokio::select! {
                _ = shutdown.recv() => {
                    info!("File monitor shutting down");
                    break;
                }
                _ = sleep(poll_interval) => {
                    if let Err(e) = self.scan_once().await {
                        error!("File monitor scan error: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Performs a single scan of the monitored directory.
    async fn scan_once(&self) -> Result<()> {
        let entries = match fs::read_dir(&self.config.path) {
            Ok(e) => e,
            Err(e) => return Err(IngestError::Io(e)),
        };

        let ext = &self.config.file_extension;

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            // Match file extension
            if !Self::matches_extension(&path, ext) {
                continue;
            }

            if self.config.tail {
                self.tail_file(&path).await?;
            } else {
                self.ingest_file_once(&path).await?;
            }
        }

        Ok(())
    }

    /// Checks if a file's extension matches the filter.
    fn matches_extension(path: &Path, ext: &str) -> bool {
        path.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case(ext))
            .unwrap_or(false)
    }

    /// Ingests a file completely (non-tail mode), skipping already-processed files.
    async fn ingest_file_once(&self, path: &Path) -> Result<()> {
        if self.ingested.contains_key(path) {
            return Ok(());
        }

        let content = match fs::read(path) {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to read {}: {}", path.display(), e);
                return Err(IngestError::Io(e));
            }
        };

        if content.is_empty() {
            self.ingested.insert(path.to_path_buf(), ());
            return Ok(());
        }

        // Split content by lines for line-by-line ingestion
        let text = String::from_utf8_lossy(&content);
        let mut accepted = 0u64;

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            match self
                .pipeline
                .process_raw(
                    Bytes::copy_from_slice(line.as_bytes()),
                    &self.config.source,
                    &self.config.source_type,
                )
                .await
            {
                Ok(_) => accepted += 1,
                Err(e) => {
                    warn!("Failed to ingest line from {}: {}", path.display(), e);
                }
            }
        }

        self.events_ingested.fetch_add(accepted, Ordering::Relaxed);
        self.files_processed.fetch_add(1, Ordering::Relaxed);
        self.ingested.insert(path.to_path_buf(), ());

        debug!("Ingested {} events from {}", path.display(), accepted);

        Ok(())
    }

    /// Tails a file, reading only new content since last offset.
    async fn tail_file(&self, path: &Path) -> Result<()> {
        let metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(e) => return Err(IngestError::Io(e)),
        };

        let file_len = metadata.len();

        let mut offset_entry = self.offsets.entry(path.to_path_buf()).or_default();

        // If file was truncated, reset offset
        if file_len < offset_entry.offset {
            offset_entry.offset = 0;
        }

        if file_len <= offset_entry.offset {
            return Ok(()); // no new data
        }

        let content = match fs::read(path) {
            Ok(c) => c,
            Err(e) => return Err(IngestError::Io(e)),
        };

        let new_bytes = &content[offset_entry.offset as usize..];
        let text = String::from_utf8_lossy(new_bytes);
        let mut accepted = 0u64;
        let mut new_offset = offset_entry.offset;

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                new_offset += line.len() as u64 + 1;
                continue;
            }

            match self
                .pipeline
                .process_raw(
                    Bytes::copy_from_slice(line.as_bytes()),
                    &self.config.source,
                    &self.config.source_type,
                )
                .await
            {
                Ok(_) => accepted += 1,
                Err(e) => {
                    warn!(
                        "Failed to ingest tailed line from {}: {}",
                        path.display(),
                        e
                    );
                }
            }
            new_offset += line.len() as u64 + 1;
        }

        offset_entry.offset = new_offset;
        self.events_ingested.fetch_add(accepted, Ordering::Relaxed);

        if accepted > 0 {
            debug!(
                "Tailed {}: accepted={} new_offset={}",
                path.display(),
                accepted,
                new_offset
            );
        }

        Ok(())
    }

    /// Returns total events ingested by this monitor.
    pub fn events_ingested(&self) -> u64 {
        self.events_ingested.load(Ordering::Relaxed)
    }

    /// Returns total files processed.
    pub fn files_processed(&self) -> u64 {
        self.files_processed.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir() -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        PathBuf::from(env::temp_dir()).join(format!("cg_monitor_test_{}", ts))
    }

    #[test]
    fn test_matches_extension() {
        assert!(FileMonitor::matches_extension(Path::new("test.log"), "log"));
        assert!(FileMonitor::matches_extension(Path::new("test.LOG"), "log"));
        assert!(!FileMonitor::matches_extension(
            Path::new("test.txt"),
            "log"
        ));
        assert!(!FileMonitor::matches_extension(Path::new("test"), "log"));
    }

    #[test]
    fn test_monitor_creation() {
        let dir = temp_dir();
        let _ = fs::create_dir_all(&dir);
        let config = MonitorConfig {
            path: dir.clone(),
            source: "test".into(),
            source_type: "json".into(),
            file_extension: "json".into(),
            tail: false,
            poll_interval_ms: 100,
            index: "main".into(),
        };
        assert_eq!(config.source, "test");
        assert_eq!(config.source_type, "json");
        let _ = fs::remove_dir_all(&dir);
    }
}
