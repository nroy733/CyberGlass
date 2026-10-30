use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntityType {
    Unknown,
    Host,
    User,
    IpAddress,
    Domain,
    Url,
    FileHash,
    Process,
    Email,
    Certificate,
    Vulnerability,
    ThreatActor,
    Campaign,
    Malware,
    NetworkConnection,
    RegistryKey,
    Service,
    Container,
    CloudResource,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entity {
    pub id: Uuid,
    pub entity_type: EntityType,
    pub display_name: String,
    pub properties: HashMap<String, serde_json::Value>,
    pub confidence: f64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub event_count: u64,
    pub tags: Vec<String>,
    pub risk_score: f64,
}

impl Entity {
    pub fn new(entity_type: EntityType, display_name: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::now_v7(),
            entity_type,
            display_name: display_name.into(),
            properties: HashMap::new(),
            confidence: 1.0,
            first_seen: now,
            last_seen: now,
            event_count: 1,
            tags: Vec::new(),
            risk_score: 0.0,
        }
    }

    pub fn update_seen(&mut self, timestamp: DateTime<Utc>) {
        if timestamp > self.last_seen {
            self.last_seen = timestamp;
        }
        if timestamp < self.first_seen {
            self.first_seen = timestamp;
        }
        self.event_count += 1;
    }

    pub fn add_tag(&mut self, tag: impl Into<String>) {
        let t = tag.into();
        if !self.tags.contains(&t) {
            self.tags.push(t);
        }
    }

    pub fn merge_with(&mut self, other: &Entity) {
        if other.last_seen > self.last_seen {
            self.last_seen = other.last_seen;
        }
        if other.first_seen < self.first_seen {
            self.first_seen = other.first_seen;
        }
        self.event_count += other.event_count;
        for (k, v) in &other.properties {
            self.properties.insert(k.clone(), v.clone());
        }
        for tag in &other.tags {
            self.add_tag(tag.clone());
        }
        self.risk_score = self.risk_score.max(other.risk_score);
    }
}
