use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RelationType {
    Unknown,
    ConnectedTo,
    AuthenticatedTo,
    Accessed,
    Executed,
    Spawned,
    Modified,
    Created,
    Deleted,
    CommunicatedWith,
    ResolvedTo,
    Contains,
    MemberOf,
    Loaded,
    Downloaded,
    Uploaded,
    LateralMovement,
    EscalatedTo,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relationship {
    pub id: Uuid,
    pub source_entity_id: Uuid,
    pub target_entity_id: Uuid,
    pub relation_type: RelationType,
    pub weight: f64,
    pub confidence: f64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub occurrence_count: u64,
    pub properties: HashMap<String, String>,
    pub evidence_event_ids: Vec<String>,
}

impl Relationship {
    pub fn new(source_id: Uuid, target_id: Uuid, relation_type: RelationType) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::now_v7(),
            source_entity_id: source_id,
            target_entity_id: target_id,
            relation_type,
            weight: 1.0,
            confidence: 1.0,
            first_seen: now,
            last_seen: now,
            occurrence_count: 1,
            properties: HashMap::new(),
            evidence_event_ids: Vec::new(),
        }
    }
}
