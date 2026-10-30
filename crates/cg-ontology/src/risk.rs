use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskContributor {
    pub source: String,
    pub score: f64,
    pub description: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    pub total: f64,
    pub level: RiskLevel,
    pub contributors: Vec<RiskContributor>,
}

pub struct RiskScorer {
    decay_rate: f64,
    scores: RwLock<HashMap<Uuid, Vec<RiskContributor>>>,
}

impl Default for RiskScorer {
    fn default() -> Self {
        Self::new(0.95)
    }
}

impl RiskScorer {
    pub fn new(decay_rate: f64) -> Self {
        Self {
            decay_rate,
            scores: RwLock::new(HashMap::new()),
        }
    }

    pub fn add_risk(&self, entity_id: &Uuid, source: &str, score: f64, description: &str) {
        let mut map = self.scores.write().unwrap();
        let list = map.entry(*entity_id).or_default();
        list.push(RiskContributor {
            source: source.to_string(),
            score,
            description: description.to_string(),
            timestamp: Utc::now(),
        });
    }

    pub fn calculate_risk(&self, entity_id: &Uuid) -> RiskScore {
        let map = self.scores.read().unwrap();
        let contributors = map.get(entity_id).cloned().unwrap_or_default();

        let mut total = 0.0;
        let now = Utc::now();

        for c in &contributors {
            let days_old = (now - c.timestamp).num_hours() as f64 / 24.0;
            let decay = self.decay_rate.powf(days_old);
            total += c.score * decay;
        }

        total = total.clamp(0.0, 100.0);

        let level = if total >= 80.0 {
            RiskLevel::Critical
        } else if total >= 60.0 {
            RiskLevel::High
        } else if total >= 30.0 {
            RiskLevel::Medium
        } else if total > 0.0 {
            RiskLevel::Low
        } else {
            RiskLevel::None
        };

        RiskScore {
            total,
            level,
            contributors,
        }
    }
}
