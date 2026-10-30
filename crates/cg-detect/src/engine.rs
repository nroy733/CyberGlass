//! # Detection and Correlation Engine
//!
//! Real-time rule evaluation, sliding-window threshold correlation,
//! MITRE ATT&CK tagging, and alert generation.

use crate::alert::{Alert, AlertStatus, AlertStore};
use crate::error::Result;
use crate::rule::{DetectionRule, RuleSeverity, RuleThreshold, RuleType};
use cg_core::config::DetectionConfig;
use cg_core::types::ParsedEvent;
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use std::sync::Arc;
use uuid::Uuid;

type TrackerKey = (String, String);
type EventOccurrence = (DateTime<Utc>, String);
type ThresholdTracker = DashMap<TrackerKey, Vec<EventOccurrence>>;

pub struct DetectionEngine {
    rules: DashMap<String, DetectionRule>,
    alert_store: Arc<AlertStore>,
    // Sliding window tracking: (rule_id, group_key) -> list of (timestamp, event_id)
    threshold_tracker: ThresholdTracker,
    // Suppression tracking: (rule_id, group_key) -> last_triggered_at
    last_triggered: DashMap<TrackerKey, DateTime<Utc>>,
}

impl DetectionEngine {
    pub fn new(config: &DetectionConfig) -> Result<Self> {
        Self::with_alert_store(config, Arc::new(AlertStore::new()))
    }

    pub fn with_alert_store(
        _config: &DetectionConfig,
        alert_store: Arc<AlertStore>,
    ) -> Result<Self> {
        let engine = Self {
            rules: DashMap::new(),
            alert_store,
            threshold_tracker: DashMap::new(),
            last_triggered: DashMap::new(),
        };

        // Add built-in core detection rules with MITRE ATT&CK mappings
        let mut brute_force = DetectionRule::new(
            "rule-brute-force",
            "Brute Force Authentication Attempt",
            "action=failure",
            RuleSeverity::High,
        );
        brute_force.mitre_techniques = vec!["T1110".to_string()];
        brute_force.rule_type = RuleType::Threshold;
        brute_force.threshold = Some(RuleThreshold {
            count: 5,
            time_window_seconds: 60,
            group_by_field: Some("src_ip".to_string()),
        });
        brute_force.description =
            "Detects multiple failed authentication attempts within a sliding time window.".into();
        engine.add_rule(brute_force)?;

        let mut priv_esc = DetectionRule::new(
            "rule-priv-escalation",
            "Privilege Escalation Detected",
            "action=sudo",
            RuleSeverity::Critical,
        );
        priv_esc.mitre_techniques = vec!["T1068".to_string(), "T1078".to_string()];
        priv_esc.description =
            "Detects administrative privilege elevation command execution.".into();
        engine.add_rule(priv_esc)?;

        Ok(engine)
    }

    pub fn add_rule(&self, rule: DetectionRule) -> Result<()> {
        self.rules.insert(rule.id.clone(), rule);
        Ok(())
    }

    pub fn remove_rule(&self, id: &str) -> Result<()> {
        self.rules.remove(id);
        Ok(())
    }

    pub fn list_rules(&self) -> Vec<DetectionRule> {
        self.rules.iter().map(|r| r.value().clone()).collect()
    }

    pub fn get_rule(&self, id: &str) -> Option<DetectionRule> {
        self.rules.get(id).map(|r| r.value().clone())
    }

    pub fn alert_store(&self) -> Arc<AlertStore> {
        self.alert_store.clone()
    }

    pub fn evaluate(&self, event: &ParsedEvent) -> Result<Vec<Alert>> {
        let mut alerts = Vec::new();
        let now = Utc::now();

        for rule in self.rules.iter() {
            if !rule.enabled {
                continue;
            }

            if !matches_rule_query(&rule.query, event) {
                continue;
            }

            // If this is a threshold rule, track occurrences in a sliding window
            if let Some(ref th) = rule.threshold {
                let group_key = th
                    .group_by_field
                    .as_ref()
                    .and_then(|f| event.fields.get(f))
                    .cloned()
                    .unwrap_or_else(|| "global".to_string());

                let tracker_key = (rule.id.clone(), group_key.clone());

                // Check alert suppression
                if let Some(last) = self.last_triggered.get(&tracker_key) {
                    let suppression_dur =
                        Duration::seconds(rule.schedule.suppression_seconds as i64);
                    if now - *last < suppression_dur {
                        continue;
                    }
                }

                let cutoff = now - Duration::seconds(th.time_window_seconds as i64);

                let mut entries = self
                    .threshold_tracker
                    .entry(tracker_key.clone())
                    .or_default();
                // Retain only events within the sliding window
                entries.retain(|(ts, _)| *ts >= cutoff);
                entries.push((now, event.id.clone()));

                if entries.len() as u64 >= th.count {
                    let event_ids: Vec<String> = entries.iter().map(|(_, id)| id.clone()).collect();
                    let alert = Alert {
                        id: Uuid::now_v7(),
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        severity: rule.severity,
                        description: format!(
                            "Threshold exceeded: {} events within {}s (group: {})",
                            entries.len(),
                            th.time_window_seconds,
                            group_key
                        ),
                        event_ids,
                        fields: event.fields.clone(),
                        triggered_at: now,
                        status: AlertStatus::New,
                        assignee: None,
                        mitre_techniques: rule.mitre_techniques.clone(),
                        risk_score: rule.risk_score,
                        entity_ids: Vec::new(),
                        incident_id: None,
                    };

                    self.alert_store.add(alert.clone())?;
                    self.last_triggered.insert(tracker_key, now);
                    entries.clear();
                    alerts.push(alert);
                }
            } else {
                // Simple rule: trigger immediately
                let alert = Alert {
                    id: Uuid::now_v7(),
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    severity: rule.severity,
                    description: if rule.description.is_empty() {
                        format!("Rule triggered: {}", rule.name)
                    } else {
                        rule.description.clone()
                    },
                    event_ids: vec![event.id.clone()],
                    fields: event.fields.clone(),
                    triggered_at: now,
                    status: AlertStatus::New,
                    assignee: None,
                    mitre_techniques: rule.mitre_techniques.clone(),
                    risk_score: rule.risk_score,
                    entity_ids: Vec::new(),
                    incident_id: None,
                };

                self.alert_store.add(alert.clone())?;
                alerts.push(alert);
            }
        }

        Ok(alerts)
    }
}

/// Matches an event against a query pattern.
/// Supports `*`, prefix/suffix wildcards, `k=v`, whitespace-separated ANDs, and `OR` logic.
fn matches_rule_query(query: &str, event: &ParsedEvent) -> bool {
    let q = query.trim();
    if q == "*" || q.is_empty() {
        return true;
    }

    // Support OR clauses: e.g. "action=blocked OR action=drop"
    if q.contains(" OR ") || q.contains(" or ") {
        let parts: Vec<&str> = if q.contains(" OR ") {
            q.split(" OR ").collect()
        } else {
            q.split(" or ").collect()
        };
        return parts.iter().any(|sub| matches_rule_query(sub, event));
    }

    // Split query by whitespace tokens (all must match)
    for token in q.split_whitespace() {
        let clean_token = token.trim().trim_matches('(').trim_matches(')');
        if clean_token.is_empty() || clean_token.eq_ignore_ascii_case("and") {
            continue;
        }

        if let Some((k, v)) = clean_token.split_once('=') {
            let key = k.trim().trim_matches('(').trim_matches(')');
            let val = v
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .trim_matches(')');

            let event_val = event
                .fields
                .get(key)
                .or_else(|| event.metadata.get(key))
                .or_else(|| {
                    if key.eq_ignore_ascii_case("source") {
                        Some(&event.source)
                    } else {
                        None
                    }
                })
                .or_else(|| {
                    if key.eq_ignore_ascii_case("source_type")
                        || key.eq_ignore_ascii_case("sourcetype")
                    {
                        Some(&event.source_type)
                    } else {
                        None
                    }
                });

            match event_val {
                Some(actual) => {
                    if val.starts_with('*') && val.ends_with('*') && val.len() > 1 {
                        let clean = &val[1..val.len() - 1];
                        if !actual.to_lowercase().contains(&clean.to_lowercase()) {
                            return false;
                        }
                    } else if val.starts_with('*') && val.len() > 1 {
                        let suffix = &val[1..];
                        if !actual.to_lowercase().ends_with(&suffix.to_lowercase()) {
                            return false;
                        }
                    } else if val.ends_with('*') && val.len() > 1 {
                        let prefix = &val[..val.len() - 1];
                        if !actual.to_lowercase().starts_with(&prefix.to_lowercase()) {
                            return false;
                        }
                    } else if val == "*" {
                        if actual.is_empty() {
                            return false;
                        }
                    } else if !actual.eq_ignore_ascii_case(val) {
                        return false;
                    }
                }
                None => return false,
            }
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_test_event(id: &str, action: &str, src_ip: &str) -> ParsedEvent {
        let mut fields = HashMap::new();
        fields.insert("action".to_string(), action.to_string());
        fields.insert("src_ip".to_string(), src_ip.to_string());

        let mut ev = ParsedEvent::new(
            "test",
            "syslog",
            format!("action={} src_ip={}", action, src_ip).into_bytes(),
        );
        ev.id = id.to_string();
        ev.fields = fields;
        ev
    }

    #[test]
    fn test_simple_rule_evaluation() {
        let config = DetectionConfig::default();
        let engine = DetectionEngine::new(&config).unwrap();

        let event = make_test_event("ev-1", "sudo", "10.0.0.1");
        let alerts = engine.evaluate(&event).unwrap();

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, "rule-priv-escalation");
        assert_eq!(alerts[0].severity, RuleSeverity::Critical);
        assert!(alerts[0].mitre_techniques.contains(&"T1068".to_string()));
    }

    #[test]
    fn test_threshold_correlation_sliding_window() {
        let config = DetectionConfig::default();
        let engine = DetectionEngine::new(&config).unwrap();

        // rule-brute-force has threshold count 5
        let ip = "192.168.1.100";
        for i in 1..=4 {
            let ev = make_test_event(&format!("fail-{}", i), "failure", ip);
            let alerts = engine.evaluate(&ev).unwrap();
            assert_eq!(alerts.len(), 0, "Should not trigger on attempt {}", i);
        }

        // 5th attempt should trigger correlation alert!
        let ev5 = make_test_event("fail-5", "failure", ip);
        let alerts = engine.evaluate(&ev5).unwrap();
        assert_eq!(alerts.len(), 1, "5th attempt must trigger threshold alert");
        assert_eq!(alerts[0].rule_id, "rule-brute-force");
        assert_eq!(alerts[0].event_ids.len(), 5);
    }

    #[test]
    fn test_rule_or_and_wildcard_matching() {
        let mut ev = make_test_event("ev-10", "dropped", "10.0.0.99");
        ev.fields.insert(
            "process".to_string(),
            "C:\\Windows\\System32\\powershell.exe".to_string(),
        );

        assert!(matches_rule_query("action=blocked OR action=dropped", &ev));
        assert!(matches_rule_query("process=*.exe", &ev));
        assert!(matches_rule_query("process=*powershell*", &ev));
        assert!(!matches_rule_query("process=*.dll", &ev));
    }

    #[test]
    fn test_alert_store_status_and_ordering() {
        let store = AlertStore::new();
        let alert = Alert {
            id: Uuid::now_v7(),
            rule_id: "test-rule".to_string(),
            rule_name: "Test Rule".to_string(),
            severity: RuleSeverity::High,
            description: "Test description".to_string(),
            event_ids: vec!["ev-1".to_string()],
            fields: HashMap::new(),
            triggered_at: Utc::now(),
            status: AlertStatus::New,
            assignee: None,
            mitre_techniques: vec![],
            risk_score: 50.0,
            entity_ids: vec![],
            incident_id: None,
        };
        let alert_id = store.add(alert).unwrap();
        assert_eq!(store.list(10).len(), 1);

        assert!(store
            .update_status(&alert_id, AlertStatus::Acknowledged)
            .is_ok());
        assert_eq!(
            store.get(&alert_id).unwrap().status,
            AlertStatus::Acknowledged
        );

        let random_id = Uuid::new_v4();
        assert!(store
            .update_status(&random_id, AlertStatus::Resolved)
            .is_err());
    }
}
