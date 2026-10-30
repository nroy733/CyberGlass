use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventId(pub String);

impl EventId {
    pub fn new_v7() -> Self {
        Self(Uuid::now_v7().to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for EventId {
    fn default() -> Self {
        Self::new_v7()
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub String);

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IndexName(pub String);

impl fmt::Display for IndexName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Unspecified = 0,
    Debug = 1,
    Info = 2,
    Notice = 3,
    Warning = 4,
    Error = 5,
    Critical = 6,
    Alert = 7,
    Emergency = 8,
}

impl From<i32> for Severity {
    fn from(val: i32) -> Self {
        match val {
            1 => Severity::Debug,
            2 => Severity::Info,
            3 => Severity::Notice,
            4 => Severity::Warning,
            5 => Severity::Error,
            6 => Severity::Critical,
            7 => Severity::Alert,
            8 => Severity::Emergency,
            _ => Severity::Unspecified,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageTier {
    Hot,
    Warm,
    Cold,
    Frozen,
}

impl fmt::Display for StorageTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageTier::Hot => write!(f, "hot"),
            StorageTier::Warm => write!(f, "warm"),
            StorageTier::Cold => write!(f, "cold"),
            StorageTier::Frozen => write!(f, "frozen"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub ingest_time: DateTime<Utc>,
    pub source: String,
    pub source_type: String,
    pub index: String,
    pub raw: Vec<u8>,
    pub fields: std::collections::HashMap<String, String>,
    pub metadata: std::collections::HashMap<String, String>,
    pub severity: Severity,
}

impl ParsedEvent {
    pub fn new(source: impl Into<String>, source_type: impl Into<String>, raw: Vec<u8>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::now_v7().to_string(),
            timestamp: now,
            ingest_time: now,
            source: source.into(),
            source_type: source_type.into(),
            index: "main".to_string(),
            raw,
            fields: std::collections::HashMap::new(),
            metadata: std::collections::HashMap::new(),
            severity: Severity::Info,
        }
    }
}
