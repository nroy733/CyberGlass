use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleSeverity {
    Informational = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleType {
    Simple,
    Threshold,
    Correlation,
    Anomaly,
    Chain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSchedule {
    pub interval_seconds: u32,
    pub lookback_seconds: u32,
    pub suppression_seconds: u32,
}

impl Default for RuleSchedule {
    fn default() -> Self {
        Self {
            interval_seconds: 60,
            lookback_seconds: 300,
            suppression_seconds: 3600,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleThreshold {
    pub count: u64,
    pub time_window_seconds: u64,
    pub group_by_field: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub query: String,
    pub severity: RuleSeverity,
    pub enabled: bool,
    pub rule_type: RuleType,
    pub threshold: Option<RuleThreshold>,
    pub mitre_techniques: Vec<String>,
    pub tags: Vec<String>,
    pub schedule: RuleSchedule,
    pub risk_score: f64,
    pub author: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl DetectionRule {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        query: impl Into<String>,
        severity: RuleSeverity,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            query: query.into(),
            severity,
            enabled: true,
            rule_type: RuleType::Simple,
            threshold: None,
            mitre_techniques: Vec::new(),
            tags: Vec::new(),
            schedule: RuleSchedule::default(),
            risk_score: 25.0,
            author: "CyberGlass".into(),
            created_at: now,
            updated_at: now,
        }
    }
}
