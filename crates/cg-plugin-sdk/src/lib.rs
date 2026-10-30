//! # CyberGlass Plugin SDK
//!
//! SDK for building WASM-based extensions for the CyberGlass SIEM platform.
//!
//! **Status**: Coming in Phase 6. This crate provides the manifest and
//! capability types that plugins use to declare their functionality.
//! Plugins are compiled to WebAssembly and loaded at runtime by the
//! plugin host engine.
//!
//! ## Planned Capabilities
//!
//! - **Parser**: Custom log format parsers
//! - **Enricher**: Event enrichment with external data
//! - **Detector**: Custom detection logic
//! - **Action**: Response actions (e.g., block IP, isolate host)
//! - **Visualization**: Custom dashboard widgets

use serde::{Deserialize, Serialize};

/// Plugin manifest describing a CyberGlass WASM extension.
///
/// Every plugin must include a manifest that declares its identity,
/// authorship, and the capabilities it provides to the platform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Unique plugin name (e.g., `"acme-firewall-parser"`).
    pub name: String,
    /// Semantic version string (e.g., `"1.2.3"`).
    pub version: String,
    /// Human-readable description of the plugin.
    pub description: String,
    /// Plugin author or organization.
    pub author: String,
    /// List of capabilities this plugin provides.
    pub capabilities: Vec<PluginCapability>,
}

/// A capability that a plugin can provide to the CyberGlass platform.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PluginCapability {
    /// Custom log format parser — transforms raw bytes into structured events.
    Parser,
    /// Event enrichment — adds contextual data (geo-IP, threat intel, etc.).
    Enricher,
    /// Custom detection rule / anomaly detector.
    Detector,
    /// Response action (block, isolate, quarantine, etc.).
    Action,
    /// Custom visualization widget for dashboards.
    Visualization,
}

impl std::fmt::Display for PluginCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parser => write!(f, "Parser"),
            Self::Enricher => write!(f, "Enricher"),
            Self::Detector => write!(f, "Detector"),
            Self::Action => write!(f, "Action"),
            Self::Visualization => write!(f, "Visualization"),
        }
    }
}
