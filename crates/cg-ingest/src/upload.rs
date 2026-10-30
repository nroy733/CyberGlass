//! # Universal File Upload & Ingestion
//!
//! Supports uploading and ingesting any file type:
//! - Text logs (.log, .txt, .csv, .json, .xml, .yaml)
//! - Security exports (.pcap, .evtx, .json)
//! - Binary files (.exe, .dll, images, videos)
//! - Metrics & traces (.prom, .json, .protobuf)
//! - Any extension with MIME type detection

use crate::error::{IngestError, Result};
use crate::pipeline::IngestPipeline;
use bytes::Bytes;
use cg_core::types::ParsedEvent;
use mime::Mime;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tracing::{debug, error, info, warn};

/// Configuration for file upload ingestion.
#[derive(Debug, Clone)]
pub struct UploadConfig {
    pub max_file_size: usize,        // bytes (default 100MB)
    pub upload_dir: PathBuf,         // staging directory
    pub auto_parse_text: bool,       // auto-parse text files line-by-line
    pub store_binary_as_event: bool, // store binary files as base64 events
    pub extract_metadata: bool,      // extract file metadata
}

impl Default for UploadConfig {
    fn default() -> Self {
        Self {
            max_file_size: 100 * 1024 * 1024,
            upload_dir: PathBuf::from("./data/uploads"),
            auto_parse_text: true,
            store_binary_as_event: true,
            extract_metadata: true,
        }
    }
}

/// Result of uploading and ingesting a file.
#[derive(Debug, Clone, serde::Serialize)]
pub struct UploadResult {
    pub filename: String,
    pub size_bytes: u64,
    pub mime_type: String,
    pub events_ingested: u64,
    pub event_ids: Vec<String>,
    pub status: UploadStatus,
    pub error: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq)]
pub enum UploadStatus {
    Accepted,
    Partial,
    Rejected,
    Parsed,
    BinaryStored,
}

/// Universal file ingestion handler.
pub struct FileUploader {
    pipeline: Arc<IngestPipeline>,
    config: UploadConfig,
}

impl FileUploader {
    pub fn new(pipeline: Arc<IngestPipeline>, config: UploadConfig) -> Self {
        Self { pipeline, config }
    }

    /// Upload and ingest a file. Returns the upload result.
    pub async fn upload_file(
        &self,
        filename: String,
        content: Bytes,
        source: Option<String>,
        source_type: Option<String>,
        index: Option<String>,
    ) -> Result<UploadResult> {
        let size = content.len() as u64;

        // Check file size limit
        if size > self.config.max_file_size as u64 {
            return Ok(UploadResult {
                filename,
                size_bytes: size,
                mime_type: "application/octet-stream".to_string(),
                events_ingested: 0,
                event_ids: Vec::new(),
                status: UploadStatus::Rejected,
                error: Some(format!(
                    "File too large: {} bytes (max {})",
                    size, self.config.max_file_size
                )),
            });
        }

        // Detect MIME type
        let mime_type = detect_mime_type(&content);
        let mime_str = mime_type.to_string();

        let src = source.unwrap_or_else(|| "file_upload".to_string());
        let st = source_type.unwrap_or_else(|| mime_str.clone());
        let idx = index.unwrap_or_else(|| "main".to_string());

        // Stage file to disk
        let staged_path = self.stage_file(&filename, &content).await?;

        // Determine ingestion strategy based on MIME type
        let result = if mime_type.type_() == mime::TEXT
            || mime_str.contains("json")
            || mime_str.contains("xml")
            || mime_str.contains("csv")
            || mime_str.contains("yaml")
            || mime_str.contains("log")
        {
            self.ingest_text_file(&content, &src, &st, &idx).await?
        } else if self.config.store_binary_as_event {
            self.ingest_binary_file(&content, &filename, &mime_str, &src, &st, &idx)
                .await?
        } else {
            UploadResult {
                filename,
                size_bytes: size,
                mime_type: mime_str,
                events_ingested: 0,
                event_ids: Vec::new(),
                status: UploadStatus::Rejected,
                error: Some("Binary file ingestion not enabled".to_string()),
            }
        };

        // Clean up staged file
        let _ = fs::remove_file(&staged_path).await;

        Ok(result)
    }

    /// Stage uploaded file to disk for processing.
    async fn stage_file(&self, filename: &str, content: &Bytes) -> Result<PathBuf> {
        fs::create_dir_all(&self.config.upload_dir)
            .await
            .map_err(|e| {
                IngestError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ))
            })?;

        let safe_name = filename.replace('/', "_").replace('\\', "_");
        let path = self
            .config
            .upload_dir
            .join(format!("{}_{}", uuid::Uuid::new_v4(), safe_name));

        fs::write(&path, content.as_ref()).await.map_err(|e| {
            IngestError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })?;

        Ok(path)
    }

    /// Ingest a text file line by line.
    async fn ingest_text_file(
        &self,
        content: &Bytes,
        source: &str,
        source_type: &str,
        index: &str,
    ) -> Result<UploadResult> {
        let text = std::str::from_utf8(content.as_ref()).unwrap_or("");
        let lines: Vec<&str> = text.lines().collect();
        let mut event_ids = Vec::new();
        let mut accepted = 0u64;
        let total_lines = lines.len() as u64;

        for line in &lines {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            match self
                .pipeline
                .process_raw(Bytes::from(line.as_bytes().to_vec()), source, source_type)
                .await
            {
                Ok(event) => {
                    event_ids.push(event.id.clone());
                    accepted += 1;
                }
                Err(e) => {
                    debug!("Failed to ingest line: {}", e);
                }
            }
        }

        let status = if accepted == total_lines {
            UploadStatus::Parsed
        } else if accepted > 0 {
            UploadStatus::Partial
        } else {
            UploadStatus::Rejected
        };

        Ok(UploadResult {
            filename: source.to_string(),
            size_bytes: content.len() as u64,
            mime_type: source_type.to_string(),
            events_ingested: accepted,
            event_ids,
            status,
            error: None,
        })
    }

    /// Ingest a binary file as a single event with base64-encoded content.
    async fn ingest_binary_file(
        &self,
        content: &Bytes,
        filename: &str,
        mime_type: &str,
        source: &str,
        source_type: &str,
        index: &str,
    ) -> Result<UploadResult> {
        let mut fields = HashMap::new();
        fields.insert("filename".to_string(), filename.to_string());
        fields.insert("mime_type".to_string(), mime_type.to_string());
        fields.insert("size_bytes".to_string(), content.len().to_string());
        fields.insert(
            "file_hash".to_string(),
            format!("{:x}", md5::compute(content.as_ref())),
        );

        // Store base64 encoded content in a field (may be truncated for very large files)
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::STANDARD.encode(content.as_ref());
        fields.insert("content_base64".to_string(), encoded);

        let mut event = ParsedEvent::new(source, source_type, content.as_ref().to_vec());
        event.index = index.to_string();
        event.fields = fields;

        // Route through pipeline using process_raw
        self.pipeline
            .process_raw(Bytes::from(content.as_ref().to_vec()), source, source_type)
            .await
            .map_err(|e| IngestError::Route(format!("Failed to route binary event: {}", e)))?;

        Ok(UploadResult {
            filename: filename.to_string(),
            size_bytes: content.len() as u64,
            mime_type: mime_type.to_string(),
            events_ingested: 1,
            event_ids: vec![event.id.clone()],
            status: UploadStatus::BinaryStored,
            error: None,
        })
    }

    /// Monitor a file for changes and ingest new content (tail mode).
    pub async fn start_file_monitor(
        &self,
        path: PathBuf,
        source: String,
        source_type: String,
        index: String,
    ) -> Result<tokio::task::JoinHandle<()>> {
        let pipeline = self.pipeline.clone();
        let poll_interval = std::time::Duration::from_millis(2000);

        let handle = tokio::spawn(async move {
            let mut last_size: u64 = 0;

            loop {
                match tokio::fs::metadata(&path).await {
                    Ok(metadata) => {
                        let size = metadata.len();

                        if size > last_size {
                            // Read new content
                            match tokio::fs::read(&path).await {
                                Ok(content) => {
                                    let start = std::cmp::min(last_size as usize, content.len());
                                    let new_bytes = &content[start..];
                                    let text = std::str::from_utf8(new_bytes).unwrap_or("");

                                    for line in text.lines() {
                                        let line = line.trim();
                                        if line.is_empty() {
                                            continue;
                                        }
                                        let _ = pipeline
                                            .process_raw(
                                                Bytes::from(line.as_bytes().to_vec()),
                                                &source,
                                                &source_type,
                                            )
                                            .await;
                                    }
                                }
                                Err(e) => {
                                    warn!("Failed to read monitored file {:?}: {}", path, e);
                                }
                            }
                            last_size = size;
                        }
                    }
                    Err(e) => {
                        warn!("Failed to monitor file {:?}: {}", path, e);
                    }
                }

                tokio::time::sleep(poll_interval).await;
            }
        });

        Ok(handle)
    }

    /// Get upload configuration.
    pub fn config(&self) -> &UploadConfig {
        &self.config
    }
}

/// Detect MIME type from file content using magic bytes.
fn detect_mime_type(content: &[u8]) -> Mime {
    // Check for common magic bytes
    if content.starts_with(b"{") || content.starts_with(b"[") {
        return "application/json"
            .parse()
            .unwrap_or(mime::APPLICATION_OCTET_STREAM);
    }
    if content.starts_with(b"<?xml") {
        return "application/xml"
            .parse()
            .unwrap_or(mime::APPLICATION_OCTET_STREAM);
    }
    if content.starts_with(b"%PDF") {
        return "application/pdf"
            .parse()
            .unwrap_or(mime::APPLICATION_OCTET_STREAM);
    }
    if content.starts_with(b"PK\x03\x04") {
        return "application/zip"
            .parse()
            .unwrap_or(mime::APPLICATION_OCTET_STREAM);
    }
    if content.starts_with(b"\x7fELF") {
        return "application/x-executable"
            .parse()
            .unwrap_or(mime::APPLICATION_OCTET_STREAM);
    }
    if content.starts_with(b"MZ") {
        return "application/x-dosexec"
            .parse()
            .unwrap_or(mime::APPLICATION_OCTET_STREAM);
    }
    if content.starts_with(b"\x89PNG") {
        return "image/png"
            .parse()
            .unwrap_or(mime::APPLICATION_OCTET_STREAM);
    }
    if content.starts_with(b"\xff\xd8\xff") {
        return "image/jpeg"
            .parse()
            .unwrap_or(mime::APPLICATION_OCTET_STREAM);
    }
    if content.starts_with(b"RIFF") && content.len() > 12 && &content[8..12] == b"WAVE" {
        return "audio/wav"
            .parse()
            .unwrap_or(mime::APPLICATION_OCTET_STREAM);
    }
    if content.starts_with(b"\x00\x00\x00\x18ftyp") || content.starts_with(b"\x00\x00\x00\x20ftyp")
    {
        return "video/mp4"
            .parse()
            .unwrap_or(mime::APPLICATION_OCTET_STREAM);
    }

    // Valid UTF-8 can still be binary when it contains control bytes.
    if let Ok(text) = std::str::from_utf8(content) {
        if text.chars().all(|character| {
            !character.is_control() || matches!(character, '\n' | '\r' | '\t' | '\u{000C}')
        }) {
            return "text/plain"
                .parse()
                .unwrap_or(mime::APPLICATION_OCTET_STREAM);
        }
    }

    mime::APPLICATION_OCTET_STREAM
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_mime_json() {
        let mime = detect_mime_type(b"{\"key\": \"value\"}");
        assert_eq!(mime.type_(), mime::APPLICATION);
        assert_eq!(mime.subtype(), mime::JSON);
    }

    #[test]
    fn test_detect_mime_xml() {
        let mime = detect_mime_type(b"<?xml version=\"1.0\"?>");
        assert_eq!(mime.type_(), mime::APPLICATION);
        assert_eq!(mime.subtype(), mime::XML);
    }

    #[test]
    fn test_detect_mime_pdf() {
        let mime = detect_mime_type(b"%PDF-1.4");
        assert_eq!(mime.subtype(), mime::PDF);
    }

    #[test]
    fn test_detect_mime_text() {
        let mime = detect_mime_type(b"hello world");
        assert_eq!(mime.subtype(), mime::PLAIN);
    }

    #[test]
    fn test_detect_mime_binary() {
        let mime = detect_mime_type(&[0x00, 0x01, 0x02, 0x03]);
        assert_eq!(mime.subtype(), mime::OCTET_STREAM);
    }
}
