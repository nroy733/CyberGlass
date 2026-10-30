//! # CyberGlass Ingestion Engine (`cg-ingest`)
//!
//! High-performance ingestion and parsing engine for CyberGlass SIEM.
//!
//! This crate provides:
//! - **Multi-format parsing** — JSON, key-value, Syslog (RFC 3164/5424), CEF
//! - **Field normalization** — maps vendor field names to OCSF-compatible names
//! - **Enrichment chain** — pluggable enrichers (GeoIP, Threat Intel, etc.)
//! - **Event routing** — publishes parsed events to the event bus by source type
//!
//! ## Architecture
//!
//! ```text
//! Raw Bytes ──► Parser ──► Normalizer ──► Enricher Chain ──► Router ──► Event Bus
//! ```

pub mod enricher;
pub mod error;
pub mod monitor;
pub mod normalizer;
pub mod parser;
pub mod pipeline;
pub mod receiver;
pub mod router;
pub mod upload;
pub mod wal;

pub use enricher::{EnricherChain, GeoIpEnricher, ThreatIntelEnricher};
pub use error::IngestError;
pub use monitor::FileMonitor;
pub use normalizer::Normalizer;
pub use parser::ParserRegistry;
pub use pipeline::{IngestPipeline, IngestStats};
pub use receiver::SyslogReceiver;
pub use router::EventRouter;
pub use upload::{FileUploader, UploadConfig, UploadResult, UploadStatus};
pub use wal::{WalConfig, WriteAheadLog};
