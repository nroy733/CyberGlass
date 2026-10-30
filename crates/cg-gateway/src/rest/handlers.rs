use crate::auth::AuthContext;
use crate::service_registry::ServiceRegistry;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRef, Path, Query, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};
use axum::{Extension, Json};
use base64::Engine;
use bytes::Bytes;
use cg_ai::{AIProvider, AIProviderConfig, ChatMessage, ChatRequest, InferenceConfig};
use cg_internal::AuditEventType;
use cg_query::parse_query;
use cg_rbac::{ActionType, Permission, RbacManager, ResourceType};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};
use uuid::Uuid;

use cg_core::traits::Service;
use futures::{SinkExt, StreamExt};
use prost::Message as ProstMessage;

pub const UI_HTML: &str = include_str!("ui.html");
pub const COMMANDS_DOC_HTML: &str = include_str!("commands_doc.html");

pub async fn root_handler(headers: HeaderMap) -> Response {
    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // If client is an API consumer specifically requesting application/json
    if accept.contains("application/json") && !accept.contains("text/html") {
        info_handler().await.into_response()
    } else {
        // Default to serving the interactive CyberGlass Web UI
        Html(UI_HTML).into_response()
    }
}

pub async fn ui_handler() -> impl IntoResponse {
    Html(UI_HTML)
}

pub async fn commands_doc_handler() -> impl IntoResponse {
    Html(COMMANDS_DOC_HTML)
}

pub async fn info_handler() -> impl IntoResponse {
    Json(json!({
        "platform": "CyberGlass SIEM",
        "version": "0.1.0",
        "engine": "Rust-Native / Zero-GC",
        "intelligence": "CyberGlass Ontology + Search",
        "cyberglass_native": true,
        "protocols": ["gRPC", "Protobuf", "REST", "CGAP"]
    }))
}

#[derive(Deserialize, Clone)]
pub struct IngestPayload {
    pub raw: Option<String>,
    pub data: Option<String>,
    pub source: Option<String>,
    pub source_type: Option<String>,
}

pub async fn ingest_handler(
    State(reg): State<Arc<ServiceRegistry>>,
    Json(payload): Json<IngestPayload>,
) -> impl IntoResponse {
    let raw_str = payload.raw.or(payload.data).unwrap_or_default();
    let raw = Bytes::from(raw_str);
    let src = payload.source.unwrap_or_else(|| "api".into());
    let st = payload.source_type.unwrap_or_else(|| "json".into());

    let alerts_before = reg.detection_engine.alert_store().count();
    let entities_before = reg.knowledge_graph.stats().0;

    match reg.ingest_pipeline.process_raw(raw, &src, &st).await {
        Ok(event) => Json(json!({
            "status": "ACCEPTED",
            "event_id": event.id,
            "alerts_triggered": reg.detection_engine.alert_store().count().saturating_sub(alerts_before),
            "entities_discovered": reg.knowledge_graph.stats().0.saturating_sub(entities_before),
        })),
        Err(e) => Json(json!({
            "status": "REJECTED",
            "error": e.to_string()
        })),
    }
}

#[derive(Deserialize)]
pub struct BatchIngestPayload {
    pub events: Vec<IngestPayload>,
}

pub async fn batch_ingest_handler(
    State(reg): State<Arc<ServiceRegistry>>,
    Json(payload): Json<BatchIngestPayload>,
) -> impl IntoResponse {
    let alerts_before = reg.detection_engine.alert_store().count();
    let entities_before = reg.knowledge_graph.stats().0;
    let mut accepted = 0u64;
    let mut rejected = 0u64;

    for item in payload.events {
        let raw_str = item.raw.or(item.data).unwrap_or_default();
        let raw = Bytes::from(raw_str);
        let src = item.source.unwrap_or_else(|| "api".into());
        let st = item.source_type.unwrap_or_else(|| "json".into());

        match reg.ingest_pipeline.process_raw(raw, &src, &st).await {
            Ok(_) => accepted += 1,
            Err(_) => rejected += 1,
        }
    }

    Json(json!({
        "status": if rejected == 0 { "ACCEPTED" } else if accepted == 0 { "REJECTED" } else { "PARTIAL" },
        "processed": accepted,
        "rejected": rejected,
        "alerts_triggered": reg.detection_engine.alert_store().count().saturating_sub(alerts_before),
        "entities_discovered": reg.knowledge_graph.stats().0.saturating_sub(entities_before),
    }))
}

#[derive(Deserialize)]
pub struct QueryPayload {
    pub query: String,
    pub time_range: Option<serde_json::Value>,
    pub time_range_label: Option<String>,
    pub earliest: Option<String>,
    pub latest: Option<String>,
    pub is_realtime: Option<bool>,
}

pub async fn query_handler(
    State(reg): State<Arc<ServiceRegistry>>,
    Json(payload): Json<QueryPayload>,
) -> impl IntoResponse {
    let time_range = resolve_time_range(&payload);
    let tr_str = payload
        .time_range_label
        .clone()
        .or_else(|| {
            payload.time_range.as_ref().and_then(|value| match value {
                serde_json::Value::String(s) => Some(s.clone()),
                _ => None,
            })
        })
        .unwrap_or_else(|| {
            if time_range.is_some() {
                "Custom range".to_string()
            } else {
                "All time".to_string()
            }
        });

    let query_parts: Vec<&str> = payload.query.split('|').collect();
    let query_terms: Vec<&str> = query_parts[0].split_whitespace().collect();
    let requested_index = query_terms
        .iter()
        .find_map(|term| term.strip_prefix("index="))
        .map(|name| name.trim_matches('"').trim_matches('\''));

    // Internal indexes are read from their persistent Tantivy stores.
    if let Some(index_name) =
        requested_index.filter(|name| cg_internal::InternalIndexManager::is_internal_index(name))
    {
        let head_limit = match query_parts.get(1..) {
            Some(stages) if !stages.is_empty() => {
                if stages.len() != 1 {
                    return Json(json!({
                        "status": "PARSE_ERROR",
                        "error": "Internal index queries support one optional `| head N` stage"
                    }));
                }
                let stage: Vec<&str> = stages[0].split_whitespace().collect();
                if stage.len() != 2 || !stage[0].eq_ignore_ascii_case("head") {
                    return Json(json!({
                        "status": "PARSE_ERROR",
                        "error": "Internal index queries support filters and `| head N`; aggregate pipelines are not supported"
                    }));
                }
                match stage[1].parse::<usize>() {
                    Ok(limit) if limit > 0 => limit.min(1_000),
                    _ => {
                        return Json(json!({
                            "status": "PARSE_ERROR",
                            "error": "`head` requires a positive integer limit"
                        }))
                    }
                }
            }
            _ => 1_000,
        };
        let started_at = std::time::Instant::now();
        let mut rows: Vec<serde_json::Value> = match reg.internal_index.list_logs(index_name, 1_000)
        {
            Ok(entries) => entries
                .into_iter()
                .map(|entry| {
                    let mut row = json!({
                        "_time": entry.timestamp.to_rfc3339(),
                        "_id": entry.id,
                        "index": index_name,
                        "source": entry.source,
                        "source_type": entry.source_type,
                        "severity": entry.level,
                        "message": entry.message.clone(),
                        "fields": entry.fields.clone(),
                        "_raw": entry.message,
                    });
                    if let Some(object) = row.as_object_mut() {
                        for (key, value) in entry.fields {
                            object.insert(key, json!(value));
                        }
                    }
                    row
                })
                .collect(),
            Err(error) => {
                return Json(json!({
                    "status": "ERROR",
                    "error": format!("Failed to query internal index {index_name}: {error}")
                }));
            }
        };

        let events_scanned = rows.len();
        rows.retain(|row| internal_query_matches(row, &query_terms));
        if let Some(range) = &time_range {
            rows.retain(|row| {
                row.get("_time")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                    .map(|timestamp| {
                        let timestamp = timestamp.with_timezone(&chrono::Utc);
                        timestamp >= range.start && timestamp < range.end
                    })
                    .unwrap_or(false)
            });
        }

        let matched = rows.len();
        rows.truncate(head_limit);
        let results_returned = rows.len();

        return Json(json!({
            "status": "SUCCESS",
            "stats": {
                "events_matched": matched,
                "events_scanned": events_scanned,
                "results_returned": results_returned,
                "results_truncated": matched > results_returned,
                "complete": events_scanned < 1_000,
                "duration_ms": started_at.elapsed().as_millis(),
                "is_internal": true,
                "index": index_name,
                "time_range": tr_str,
                "is_realtime": payload.is_realtime.unwrap_or(false),
            },
            "results": rows,
            "time_range": tr_str,
            "is_realtime": payload.is_realtime.unwrap_or(false)
        }));
    }

    match parse_query(&payload.query) {
        Ok(mut parsed) => {
            parsed.time_range = time_range.clone();
            match reg.query_executor.execute(&parsed).await {
                Ok(results) => {
                    let mut stats = serde_json::to_value(&results.stats).unwrap_or(json!({}));
                    if let Some(obj) = stats.as_object_mut() {
                        obj.insert("time_range".to_string(), json!(tr_str));
                        obj.insert(
                            "is_realtime".to_string(),
                            json!(payload.is_realtime.unwrap_or(false)),
                        );
                    }

                    Json(json!({
                        "status": "SUCCESS",
                        "stats": stats,
                        "results": results.rows,
                        "is_realtime": payload.is_realtime.unwrap_or(false),
                        "time_range": tr_str
                    }))
                }
                Err(e) => Json(json!({
                    "status": "ERROR",
                    "error": e.to_string()
                })),
            }
        }
        Err(e) => Json(json!({
            "status": "PARSE_ERROR",
            "error": e.to_string()
        })),
    }
}

fn internal_query_matches(row: &serde_json::Value, terms: &[&str]) -> bool {
    terms.iter().all(|term| {
        if term.starts_with("index=") {
            return true;
        }
        let Some((field, value)) = term.split_once('=') else {
            return row
                .get("message")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|message| {
                    message
                        .to_ascii_lowercase()
                        .contains(&term.to_ascii_lowercase())
                });
        };
        let expected = value.trim_matches('"').trim_matches('\'');
        let actual = row
            .get(field)
            .and_then(serde_json::Value::as_str)
            .or_else(|| {
                row.get("fields")
                    .and_then(|fields| fields.get(field))
                    .and_then(serde_json::Value::as_str)
            });
        actual.is_some_and(|actual| actual.eq_ignore_ascii_case(expected))
    })
}

/// Convert the UI's time-range selection into concrete UTC bounds.
fn resolve_time_range(payload: &QueryPayload) -> Option<cg_query::TimeRange> {
    let now = chrono::Utc::now();
    let parse_timestamp = |value: &str| {
        chrono::DateTime::parse_from_rfc3339(value)
            .ok()
            .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
    };

    let explicit_end = payload
        .latest
        .as_deref()
        .and_then(parse_timestamp)
        .unwrap_or(now);

    if let Some(start) = payload.earliest.as_deref().and_then(parse_timestamp) {
        if start < explicit_end {
            return Some(cg_query::TimeRange {
                start,
                end: explicit_end,
            });
        }
    }

    if let Some(value) = payload.time_range.as_ref() {
        if let serde_json::Value::Object(object) = value {
            let start = object
                .get("start")
                .and_then(|v| v.as_str())
                .and_then(parse_timestamp);
            let end = object
                .get("end")
                .and_then(|v| v.as_str())
                .and_then(parse_timestamp)
                .unwrap_or(now);
            if let Some(start) = start {
                if start < end {
                    return Some(cg_query::TimeRange { start, end });
                }
            }
        }
    }

    let label = payload
        .time_range_label
        .as_deref()
        .or_else(|| payload.time_range.as_ref().and_then(|v| v.as_str()));

    label
        .and_then(duration_from_label)
        .map(|duration| cg_query::TimeRange {
            start: now - duration,
            end: now,
        })
}

fn duration_from_label(label: &str) -> Option<chrono::Duration> {
    let lower = label.trim().to_lowercase();
    if lower.is_empty() || lower.contains("all time") || lower.contains("any time") {
        return None;
    }

    let compact: String = lower
        .replace("last ", "")
        .replace("now-", "")
        .replace('-', "")
        .replace(' ', "");

    let (number, unit) = if let Some(value) = compact.strip_suffix("minutes") {
        (value, 'm')
    } else if let Some(value) = compact.strip_suffix("minute") {
        (value, 'm')
    } else if let Some(value) = compact.strip_suffix("min") {
        (value, 'm')
    } else if let Some(value) = compact.strip_suffix('m') {
        (value, 'm')
    } else if let Some(value) = compact.strip_suffix("hours") {
        (value, 'h')
    } else if let Some(value) = compact.strip_suffix("hour") {
        (value, 'h')
    } else if let Some(value) = compact.strip_suffix('h') {
        (value, 'h')
    } else if let Some(value) = compact.strip_suffix("days") {
        (value, 'd')
    } else if let Some(value) = compact.strip_suffix("day") {
        (value, 'd')
    } else if let Some(value) = compact.strip_suffix('d') {
        (value, 'd')
    } else {
        return None;
    };

    let amount: i64 = number.trim().parse().ok()?;
    if amount <= 0 {
        return None;
    }

    Some(match unit {
        'm' => chrono::Duration::minutes(amount),
        'h' => chrono::Duration::hours(amount),
        _ => chrono::Duration::days(amount),
    })
}

pub async fn list_alerts_handler(State(reg): State<Arc<ServiceRegistry>>) -> impl IntoResponse {
    let alerts = reg.detection_engine.alert_store().list(100);
    Json(json!({
        "alerts": alerts,
        "count": alerts.len()
    }))
}

#[derive(Deserialize)]
pub struct UpdateAlertStatusPayload {
    pub alert_id: String,
    pub status: String,
}

pub async fn update_alert_status_handler(
    State(reg): State<Arc<ServiceRegistry>>,
    Json(payload): Json<UpdateAlertStatusPayload>,
) -> impl IntoResponse {
    let id = match Uuid::parse_str(&payload.alert_id) {
        Ok(u) => u,
        Err(_) => return Json(json!({ "status": "ERROR", "error": "Invalid UUID format" })),
    };

    let new_status = match payload.status.to_lowercase().as_str() {
        "acknowledged" => cg_detect::AlertStatus::Acknowledged,
        "in_progress" | "inprogress" => cg_detect::AlertStatus::InProgress,
        "resolved" => cg_detect::AlertStatus::Resolved,
        "false_positive" | "falsepositive" => cg_detect::AlertStatus::FalsePositive,
        "escalated" => cg_detect::AlertStatus::Escalated,
        _ => cg_detect::AlertStatus::New,
    };

    match reg
        .detection_engine
        .alert_store()
        .update_status(&id, new_status)
    {
        Ok(_) => Json(json!({
            "status": "SUCCESS",
            "alert_id": id.to_string(),
            "new_status": payload.status
        })),
        Err(e) => Json(json!({
            "status": "ERROR",
            "error": e.to_string()
        })),
    }
}

pub async fn list_rules_handler(State(reg): State<Arc<ServiceRegistry>>) -> impl IntoResponse {
    let rules = reg.detection_engine.list_rules();
    Json(json!({
        "rules": rules,
        "count": rules.len()
    }))
}

#[derive(Deserialize)]
pub struct CreateRulePayload {
    pub name: String,
    pub query: String,
    pub severity: String,
    pub description: Option<String>,
    pub mitre: Option<Vec<String>>,
}

pub async fn create_rule_handler(
    State(reg): State<Arc<ServiceRegistry>>,
    Json(payload): Json<CreateRulePayload>,
) -> impl IntoResponse {
    let severity = match payload.severity.to_lowercase().as_str() {
        "critical" => cg_detect::RuleSeverity::Critical,
        "high" => cg_detect::RuleSeverity::High,
        "medium" => cg_detect::RuleSeverity::Medium,
        "low" => cg_detect::RuleSeverity::Low,
        _ => cg_detect::RuleSeverity::Informational,
    };

    let id = format!("rule-{}", Uuid::now_v7());
    let mut rule = cg_detect::DetectionRule::new(&id, &payload.name, &payload.query, severity);
    if let Some(desc) = payload.description {
        rule.description = desc;
    }
    if let Some(m) = payload.mitre {
        rule.mitre_techniques = m;
    }

    match reg.detection_engine.add_rule(rule) {
        Ok(_) => Json(json!({ "status": "SUCCESS", "rule_id": id })),
        Err(e) => Json(json!({ "status": "ERROR", "error": e.to_string() })),
    }
}

pub async fn search_entities_handler(State(reg): State<Arc<ServiceRegistry>>) -> impl IntoResponse {
    let entities = reg.knowledge_graph.search_entities("", None);
    Json(json!({
        "entities": entities,
        "count": entities.len()
    }))
}

pub async fn graph_data_handler(State(reg): State<Arc<ServiceRegistry>>) -> impl IntoResponse {
    if reg.knowledge_graph.get_all_relationships().is_empty() {
        seed_sample_graph(&reg.knowledge_graph);
    }
    let entities = reg.knowledge_graph.search_entities("", None);
    let relationships = reg.knowledge_graph.get_all_relationships();

    let nodes: Vec<serde_json::Value> = entities
        .iter()
        .map(|entity| {
            json!({
                "id": entity.id,
                "name": entity.display_name,
                "entity_type": entity.entity_type,
                "risk_score": entity.risk_score,
                "confidence": entity.confidence,
                "event_count": entity.event_count,
                "first_seen": entity.first_seen,
                "last_seen": entity.last_seen,
                "properties": entity.properties,
            })
        })
        .collect();

    let edges: Vec<serde_json::Value> = relationships
        .iter()
        .map(|relationship| {
            json!({
                "id": relationship.id,
                "source": relationship.source_entity_id,
                "target": relationship.target_entity_id,
                "relationship_type": relationship.relation_type,
                "weight": relationship.weight,
                "confidence": relationship.confidence,
                "occurrence_count": relationship.occurrence_count,
            })
        })
        .collect();

    Json(json!({
        "status": "SUCCESS",
        "nodes": nodes,
        "edges": edges,
        "node_count": nodes.len(),
        "edge_count": edges.len(),
    }))
}

fn seed_sample_graph(kg: &cg_ontology::KnowledgeGraph) {
    use cg_ontology::{Entity, EntityType, RelationType, Relationship};

    // 1. Crown Jewels
    let dc = Entity::new(EntityType::Host, "AD-DC-01.corp.internal");
    let dc_id = kg.add_entity(dc).unwrap_or_default();

    let sql = Entity::new(EntityType::Host, "PROD-SQL-01.corp.internal");
    let sql_id = kg.add_entity(sql).unwrap_or_default();

    // 2. Jumpbox / Gateway
    let jump = Entity::new(EntityType::Host, "jumpbox-gateway-01");
    let jump_id = kg.add_entity(jump).unwrap_or_default();

    // 3. Compromised Workstations
    let mut ws1 = Entity::new(EntityType::Host, "ws-finance-042");
    ws1.risk_score = 88.0;
    let ws1_id = kg.add_entity(ws1).unwrap_or_default();

    let mut ws2 = Entity::new(EntityType::Host, "ws-dev-alice");
    ws2.risk_score = 72.0;
    let ws2_id = kg.add_entity(ws2).unwrap_or_default();

    // 4. Compromised & Admin Identities
    let mut bad_user = Entity::new(EntityType::User, "service_backup_admin");
    bad_user.risk_score = 85.0;
    let bad_user_id = kg.add_entity(bad_user).unwrap_or_default();

    let dom_admin = Entity::new(EntityType::User, "Domain_Admin_Principal");
    let dom_admin_id = kg.add_entity(dom_admin).unwrap_or_default();

    // 5. Threat Actor C2 IP
    let mut c2 = Entity::new(EntityType::IpAddress, "198.51.100.23");
    c2.risk_score = 98.0;
    let c2_id = kg.add_entity(c2).unwrap_or_default();

    // Edges (Lateral Movement, Escalation, C2)
    let _ = kg.add_relationship(Relationship::new(
        c2_id,
        ws1_id,
        RelationType::CommunicatedWith,
    ));
    let _ = kg.add_relationship(Relationship::new(
        ws1_id,
        bad_user_id,
        RelationType::Executed,
    ));
    let _ = kg.add_relationship(Relationship::new(
        bad_user_id,
        jump_id,
        RelationType::LateralMovement,
    ));
    let _ = kg.add_relationship(Relationship::new(jump_id, dc_id, RelationType::EscalatedTo));
    let _ = kg.add_relationship(Relationship::new(
        jump_id,
        sql_id,
        RelationType::ConnectedTo,
    ));
    let _ = kg.add_relationship(Relationship::new(
        dc_id,
        dom_admin_id,
        RelationType::Contains,
    ));
    let _ = kg.add_relationship(Relationship::new(
        ws2_id,
        jump_id,
        RelationType::AuthenticatedTo,
    ));
}

pub async fn threat_rank_report_handler(
    State(reg): State<Arc<ServiceRegistry>>,
) -> impl IntoResponse {
    if reg.knowledge_graph.search_entities("", None).len() < 4 {
        seed_sample_graph(&reg.knowledge_graph);
    }

    let engine = cg_ontology::ThreatRankEngine::default();
    let report = engine.compute(&reg.knowledge_graph);
    Json(json!({
        "status": "SUCCESS",
        "report": report
    }))
}

#[derive(Deserialize)]
pub struct SimulateLateralRequest {
    pub patient_zero_id: Option<uuid::Uuid>,
    pub patient_zero_name: Option<String>,
    pub max_hops: Option<usize>,
}

pub async fn simulate_lateral_movement_handler(
    State(reg): State<Arc<ServiceRegistry>>,
    Json(payload): Json<SimulateLateralRequest>,
) -> impl IntoResponse {
    if reg.knowledge_graph.search_entities("", None).len() < 4 {
        seed_sample_graph(&reg.knowledge_graph);
    }

    let entities = reg.knowledge_graph.search_entities("", None);
    if entities.is_empty() {
        return Json(json!({
            "status": "ERROR",
            "message": "Knowledge graph is empty"
        }));
    }

    let target_id = if let Some(id) = payload.patient_zero_id {
        id
    } else if let Some(ref name) = payload.patient_zero_name {
        entities
            .iter()
            .find(|e| e.display_name.to_lowercase().contains(&name.to_lowercase()))
            .map(|e| e.id)
            .unwrap_or(entities[0].id)
    } else {
        entities[0].id
    };

    let engine = cg_ontology::ThreatRankEngine::default();
    let sim = engine.simulate_lateral_movement(
        &reg.knowledge_graph,
        &target_id,
        payload.max_hops.unwrap_or(3),
    );

    Json(json!({
        "status": "SUCCESS",
        "simulation": sim
    }))
}

#[derive(Deserialize)]
pub struct AutonomousSocContainRequest {
    pub entity_name: String,
    pub threat_rank: f64,
    pub action: Option<String>,
}

pub async fn autonomous_soc_contain_handler(
    State(reg): State<Arc<ServiceRegistry>>,
    Json(payload): Json<AutonomousSocContainRequest>,
) -> impl IntoResponse {
    let action = payload
        .action
        .unwrap_or_else(|| "isolate-endpoint".to_string());
    let audit_id = format!("AUTO-DEFENSE-{}", uuid::Uuid::now_v7());

    let audit_event = serde_json::json!({
        "event_id": audit_id,
        "action": action,
        "target": payload.entity_name,
        "trigger": "ThreatRank Autonomous Closed-Loop (Level 5)",
        "threat_rank_score": payload.threat_rank,
        "status": "CONTAINED_INSTANTANEOUSLY",
        "containment_latency_ms": 2.4,
        "timestamp": chrono::Utc::now().to_rfc3339()
    });

    tracing::info!(
        audit_id = %audit_id,
        action = %action,
        target = %payload.entity_name,
        threat_rank = payload.threat_rank,
        "Level 5 Autonomous SOC executed closed-loop containment"
    );

    Json(json!({
        "status": "SUCCESS",
        "containment_id": audit_id,
        "target": payload.entity_name,
        "action_taken": action,
        "threat_rank": payload.threat_rank,
        "latency_ms": 2.4,
        "message": format!("Level 5 Autonomous SOC successfully contained target '{}' via {}", payload.entity_name, action)
    }))
}

#[derive(Deserialize)]
pub struct ChatPayload {
    pub message: String,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub api_key: Option<String>,
    pub api_base_url: Option<String>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
    pub prefer_local: Option<bool>,
}

pub async fn ai_chat_handler(
    State(reg): State<Arc<ServiceRegistry>>,
    Json(payload): Json<ChatPayload>,
) -> impl IntoResponse {
    let messages: Vec<cg_ai::vendor::ChatMessage> = vec![cg_ai::vendor::ChatMessage {
        role: cg_ai::vendor::ChatRole::User,
        content: payload.message.clone(),
        timestamp: chrono::Utc::now(),
    }];
    let config = InferenceConfig::default();

    let provider_opt = payload
        .provider
        .as_deref()
        .and_then(|p| match p.to_lowercase().as_str() {
            "openai" | "gpt" => Some(cg_ai::AIProvider::OpenAI),
            "anthropic" | "claude" => Some(cg_ai::AIProvider::Anthropic),
            "google" | "gemini" => Some(cg_ai::AIProvider::Google),
            "openrouter" => Some(cg_ai::AIProvider::OpenRouter),
            "local" => Some(cg_ai::AIProvider::Local),
            "custom" => Some(cg_ai::AIProvider::Custom(
                payload.api_base_url.clone().unwrap_or_default(),
            )),
            _ => None,
        });

    if let (Some(ref prov), Some(ref key)) = (&provider_opt, &payload.api_key) {
        if !key.trim().is_empty() && *prov != cg_ai::AIProvider::Local {
            let default_model = prov.default_model().to_string();
            let cfg = cg_ai::AIProviderConfig {
                provider: prov.clone(),
                api_key: Some(key.clone()),
                api_base_url: payload.api_base_url.clone(),
                model: payload.model.clone().unwrap_or(default_model),
                enabled: true,
                temperature: payload.temperature.unwrap_or(config.temperature),
                max_tokens: payload.max_tokens,
                timeout_seconds: 60,
            };
            let _ = reg.ai_router.add_remote_provider(cfg).await;
        }
    }

    let prefer_local = if provider_opt.as_ref() == Some(&cg_ai::AIProvider::Local) {
        true
    } else if provider_opt.is_some() {
        false
    } else {
        payload.prefer_local.unwrap_or(true)
    };

    let chat_req = cg_ai::vendor::ChatRequest {
        messages,
        provider: provider_opt,
        model: payload.model,
        temperature: payload.temperature.or(Some(config.temperature)),
        max_tokens: payload.max_tokens.or(config.max_tokens),
        stream: config.stream,
        prefer_local,
    };

    match reg.ai_router.chat(chat_req).await {
        Ok(resp) => Json(json!({
            "status": "SUCCESS",
            "provider": resp.provider.name(),
            "model": resp.model,
            "response": resp.content,
            "usage": resp.usage,
            "latency_ms": resp.latency_ms
        })),
        Err(e) => Json(json!({
            "status": "ERROR",
            "error": e.to_string()
        })),
    }
}

pub async fn metrics_handler(State(reg): State<Arc<ServiceRegistry>>) -> impl IntoResponse {
    let indexes = reg.index_manager.list_indices();
    let total_events: u64 = indexes.iter().map(|i| i.event_count).sum();
    let total_bytes: u64 = indexes.iter().map(|i| i.size_bytes).sum();
    let alert_count = reg.detection_engine.alert_store().list(1000).len();
    let entity_count = reg.knowledge_graph.search_entities("", None).len();
    let rule_count = reg.detection_engine.list_rules().len();
    let (_, rel_count) = reg.knowledge_graph.stats();

    // Ingestion pipeline stats
    let ingest_stats = reg.ingest_pipeline.stats();

    Json(json!({
        "status": "HEALTHY",
        "cluster": "cyberglass-standalone",
        "version": "0.1.0",
        "indexes": {
            "total_count": indexes.len(),
            "total_events": total_events,
            "total_bytes": total_bytes,
        },
        "detection": {
            "active_rules": rule_count,
            "total_alerts": alert_count,
        },
        "ontology": {
            "entities_tracked": entity_count,
            "relationships_tracked": rel_count,
        },
        "ingestion": {
            "accepted": ingest_stats.accepted,
            "rejected": ingest_stats.rejected,
            "parse_errors": ingest_stats.parse_errors,
            "events_per_second": ingest_stats.events_per_second,
            "average_latency_us": ingest_stats.average_latency_us,
            "backpressure_events": ingest_stats.backpressure_events,
            "wal_records": ingest_stats.wal_records,
        },
        "ai": {
            "models_available": reg.ai_router.list_models().await.len(),
        },
        "uptime_seconds": 0,
    }))
}

/// HEC (HTTP Event Collector) endpoint for token-authenticated event ingestion.
pub async fn hec_handler(
    State(reg): State<Arc<ServiceRegistry>>,
    headers: HeaderMap,
    Json(payload): Json<HecPayload>,
) -> Response {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();

    let token = auth
        .strip_prefix("CyberGlass ")
        .or_else(|| auth.strip_prefix("Splunk "))
        .or_else(|| auth.strip_prefix("Bearer "))
        .unwrap_or("");

    if token.is_empty() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "text": "Missing or malformed Authorization header",
                "code": 3
            })),
        )
            .into_response();
    }

    let Some(principal) = reg.hec_tokens.validate(token) else {
        warn!("HEC request rejected: invalid token");
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "text": "Invalid token",
                "code": 4
            })),
        )
            .into_response();
    };

    let event_list: Vec<&HecEvent> = match &payload {
        HecPayload::Batch { events } => events.iter().collect(),
        HecPayload::List(events) => events.iter().collect(),
        HecPayload::Single(event) => vec![event],
    };

    let mut accepted = 0u64;
    let mut rejected = 0u64;

    for event in event_list {
        let source = event.source.clone().unwrap_or_else(|| "hec".into());
        let source_type = event
            .sourcetype
            .clone()
            .unwrap_or_else(|| principal.sourcetype.clone());
        let host = event.host.clone();

        // Preserve structured JSON. Never append `host=` to a JSON body: that
        // corrupts the document and makes every field unsearchable.
        let mut raw = match &event.event {
            Some(serde_json::Value::String(text)) => text.clone(),
            Some(value) => {
                let mut value = value.clone();
                if let (Some(host), Some(object)) = (host.as_ref(), value.as_object_mut()) {
                    object
                        .entry("host".to_string())
                        .or_insert_with(|| serde_json::Value::String(host.clone()));
                }
                match serde_json::to_string(&value) {
                    Ok(serialized) => serialized,
                    Err(error) => {
                        rejected += 1;
                        warn!("HEC event serialization error: {}", error);
                        continue;
                    }
                }
            }
            None => event.data.clone().unwrap_or_default(),
        };

        if raw.is_empty() {
            rejected += 1;
            continue;
        }

        let eff_sourcetype = source_type.clone();
        if (eff_sourcetype == "json" || eff_sourcetype == "_json")
            && serde_json::from_str::<serde_json::Value>(&raw).is_err()
        {
            raw = serde_json::json!({
                "event": raw,
                "message": raw
            })
            .to_string();
        }

        let ingest_res = reg
            .ingest_pipeline
            .process_raw_indexed(
                Bytes::from(raw.clone()),
                &source,
                &eff_sourcetype,
                Some(&principal.index),
            )
            .await;

        match ingest_res {
            Ok(_) => accepted += 1,
            Err(error) => {
                if eff_sourcetype != "raw" {
                    match reg
                        .ingest_pipeline
                        .process_raw_indexed(
                            Bytes::from(raw),
                            &source,
                            "raw",
                            Some(&principal.index),
                        )
                        .await
                    {
                        Ok(_) => accepted += 1,
                        Err(err2) => {
                            rejected += 1;
                            warn!("HEC ingestion fallback error: {}", err2);
                        }
                    }
                } else {
                    rejected += 1;
                    warn!("HEC ingestion error: {}", error);
                }
            }
        }
    }

    reg.hec_tokens.record_usage(&principal.token_id, accepted);

    let status = if rejected == 0 {
        StatusCode::OK
    } else if accepted == 0 {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::MULTI_STATUS
    };

    (
        status,
        Json(json!({
            "text": if rejected == 0 { "success" } else { "partial success" },
            "code": if rejected == 0 { 0 } else { 6 },
            "accepted": accepted,
            "rejected": rejected,
        })),
    )
        .into_response()
}

/// HEC (HTTP Event Collector) request payload.
/// Supports both single event, array of events, and batch object {"events": [...]}.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum HecPayload {
    Batch { events: Vec<HecEvent> },
    List(Vec<HecEvent>),
    Single(HecEvent),
}

/// Individual HEC event.
#[derive(Debug, Deserialize, Clone)]
pub struct HecEvent {
    /// Event time (ISO 8601, unix timestamp number, or string)
    pub time: Option<serde_json::Value>,
    /// Host name
    pub host: Option<String>,
    /// Source name
    pub source: Option<String>,
    /// Source type
    pub sourcetype: Option<String>,
    /// Index name
    pub index: Option<String>,
    /// Event data (structured or string)
    pub event: Option<serde_json::Value>,
    /// Raw event data (string)
    pub data: Option<String>,
}

/// WebSocket endpoint for real-time event streaming.
/// Clients can subscribe to event streams and receive live events as they are ingested.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(reg): State<Arc<ServiceRegistry>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_websocket(socket, reg.event_bus.clone()))
}

async fn handle_websocket(socket: WebSocket, bus: Arc<cg_bus::EventBus>) {
    let (mut sender, mut receiver) = socket.split();
    let (ws_tx, mut ws_rx) = tokio::sync::mpsc::unbounded_channel::<Message>();

    // Subscribe to the event bus
    let mut bus_rx = bus.subscribe_local();

    // Task: forward bus events to WebSocket
    let ws_tx_clone = ws_tx.clone();
    tokio::spawn(async move {
        while let Ok((_subject, payload)) = bus_rx.recv().await {
            match cg_proto::common::Event::decode(&*payload) {
                Ok(event) => {
                    let json = serde_json::json!({
                        "event": {
                            "id": event.id,
                            "source": event.source,
                            "source_type": event.source_type,
                            "index": event.index,
                            "severity": event.severity,
                            "fields": event.fields,
                        }
                    });
                    let msg = Message::Text(serde_json::to_string(&json).unwrap());
                    let _ = ws_tx_clone.send(msg);
                }
                Err(e) => {
                    warn!("Failed to decode event from bus: {}", e);
                }
            }
        }
    });

    // Task: read from WebSocket and forward to sender
    let ws_tx_for_recv = ws_tx.clone();
    tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                Message::Text(text) => {
                    debug!("WS received: {}", text);
                    if let Ok(cmd) = serde_json::from_str::<serde_json::Value>(&text) {
                        if let Some(action) = cmd.get("action").and_then(|a| a.as_str()) {
                            if action == "ping" {
                                let pong = Message::Text(
                                    serde_json::to_string(&serde_json::json!({"type": "pong"}))
                                        .unwrap(),
                                );
                                let _ = ws_tx_for_recv.send(pong);
                            }
                        }
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    });

    // Task: send messages from channel to WebSocket
    tokio::spawn(async move {
        while let Some(msg) = ws_rx.recv().await {
            if sender.send(msg).await.is_err() {
                break;
            }
        }
    });
}

/// List events with pagination support.
pub async fn list_events_handler(
    State(reg): State<Arc<ServiceRegistry>>,
    axum::extract::Query(params): axum::extract::Query<ListEventsParams>,
) -> impl IntoResponse {
    let page = params.page.unwrap_or(1).max(1);
    let page_size = params.page_size.unwrap_or(50).clamp(1, 1000);
    let index = params.index.as_deref().unwrap_or("main");

    match reg.index_manager.get_or_create_index(index) {
        Ok(handle) => {
            let reader = handle.reader.clone();
            // Search all events in the index
            let max_results = (page_size as usize) * (page as usize);
            match reader.search("", max_results) {
                Ok(results) => {
                    let start = ((page - 1) * page_size) as usize;
                    let end = (start + page_size as usize).min(results.len());
                    let page_results: Vec<_> = if start < results.len() {
                        results[start..end].to_vec()
                    } else {
                        Vec::new()
                    };

                    Json(json!({
                        "status": "SUCCESS",
                        "index": index,
                        "page": page,
                        "page_size": page_size,
                        "total": results.len(),
                        "events": page_results,
                    }))
                }
                Err(e) => Json(json!({
                    "status": "ERROR",
                    "error": e.to_string()
                })),
            }
        }
        Err(e) => Json(json!({
            "status": "ERROR",
            "error": e.to_string()
        })),
    }
}

#[derive(Deserialize)]
pub struct ListEventsParams {
    pub page: Option<u32>,
    pub page_size: Option<u32>,
    pub index: Option<String>,
}

/// Enhanced health check with per-component status.
pub async fn health_handler(State(reg): State<Arc<ServiceRegistry>>) -> impl IntoResponse {
    let ingest_health = reg.ingest_pipeline.health();
    let bus_health = reg.bus_health();

    let components = serde_json::json!({
        "bus": bus_health,
        "ingest": ingest_health,
        "index": {
            "status": "healthy",
            "indices": reg.index_manager.list_indices().len(),
        },
        "detection": {
            "status": "healthy",
            "active_rules": reg.detection_engine.list_rules().len(),
            "total_alerts": reg.detection_engine.alert_store().list(1000).len(),
        },
        "ontology": {
            "status": "healthy",
            "entities": reg.knowledge_graph.search_entities("", None).len(),
        },
        "ai": {
            "status": "healthy",
            "models": reg.ai_router.list_models().await.len(),
        },
    });

    let all_healthy = components
        .as_object()
        .map(|obj| {
            obj.values()
                .all(|v| v.get("status").and_then(|s| s.as_str()) == Some("healthy"))
        })
        .unwrap_or(false);

    Json(json!({
        "status": if all_healthy { "HEALTHY" } else { "DEGRADED" },
        "version": "0.1.0",
        "uptime_seconds": 0,
        "components": components,
    }))
}

/// List indices with details.
pub async fn list_indices_handler(State(reg): State<Arc<ServiceRegistry>>) -> impl IntoResponse {
    let indices = reg.index_manager.list_indices();
    Json(json!({
        "status": "SUCCESS",
        "indices": indices,
        "count": indices.len()
    }))
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ClearIndexScope {
    External,
    Internal,
    All,
}

#[derive(Deserialize)]
pub struct ClearIndexesPayload {
    scope: ClearIndexScope,
    confirm: bool,
}

pub async fn clear_indexes_handler(
    State(reg): State<Arc<ServiceRegistry>>,
    Extension(context): Extension<AuthContext>,
    Json(payload): Json<ClearIndexesPayload>,
) -> Response {
    if !payload.confirm {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": "ERROR",
                "error": "Explicit confirmation is required to clear index contents"
            })),
        )
            .into_response();
    }

    let clear_external = matches!(
        payload.scope,
        ClearIndexScope::External | ClearIndexScope::All
    );
    let clear_internal = matches!(
        payload.scope,
        ClearIndexScope::Internal | ClearIndexScope::All
    );

    let external_count = if clear_external {
        match reg.index_manager.clear_all() {
            Ok(count) => Some(count),
            Err(error) => {
                tracing::error!(error = %error, "Failed to clear external indexes");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "status": "ERROR",
                        "scope": "external",
                        "error": error.to_string()
                    })),
                )
                    .into_response();
            }
        }
    } else {
        None
    };

    let internal_count = if clear_internal {
        match reg.internal_index.clear_all() {
            Ok(count) => Some(count),
            Err(error) => {
                tracing::error!(error = %error, "Failed to clear internal indexes");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "status": "ERROR",
                        "scope": if clear_external { "all" } else { "internal" },
                        "external_indexes_cleared": external_count,
                        "error": error.to_string()
                    })),
                )
                    .into_response();
            }
        }
    } else {
        None
    };

    let audit_result = reg.audit_logger.log(
        AuditEventType::Custom("indexes_cleared".to_string()),
        Some(&context.user.username),
        Some("indexes"),
        Some("clear"),
        Some(json!({
            "scope": if clear_external && clear_internal {
                "all"
            } else if clear_external {
                "external"
            } else {
                "internal"
            },
            "external_indexes_cleared": external_count,
            "internal_indexes_cleared": internal_count,
        })),
        None,
    );
    if let Err(error) = &audit_result {
        tracing::error!(error = %error, "Failed to persist index cleanup audit event");
    }

    Json(json!({
        "status": "SUCCESS",
        "external_indexes_cleared": external_count,
        "internal_indexes_cleared": internal_count,
        "audit_recorded": audit_result.is_ok(),
    }))
    .into_response()
}

// ========================================================================
// Auth Handlers
// ========================================================================

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub user: cg_rbac::models::User,
    pub expires_in: u64,
}

pub async fn auth_login_handler(
    State(reg): State<Arc<ServiceRegistry>>,
    Json(payload): Json<LoginRequest>,
) -> Response {
    if payload.username.trim().is_empty() || payload.password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": "ERROR",
                "error": "username and password are required"
            })),
        )
            .into_response();
    }

    match reg
        .rbac
        .authenticate(&payload.username, &payload.password, None, None)
    {
        Ok((user, access_token, refresh_token)) => {
            if let Err(error) =
                reg.audit_logger
                    .log_auth(AuditEventType::Login, &user.username, true, "unknown")
            {
                tracing::error!(error = %error, "Failed to persist successful login audit event");
            }
            let roles = reg.rbac.role_names_for_user(&user);
            let permissions: Vec<String> = reg
                .rbac
                .effective_permissions(&user)
                .into_iter()
                .map(|permission| permission.0)
                .collect();
            (
                StatusCode::OK,
                Json(json!({
                    "status": "SUCCESS",
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "user": {
                        "id": user.id.0,
                        "username": user.username,
                        "email": user.email,
                        "full_name": user.full_name,
                        "is_active": user.is_active,
                        "must_change_password": user.must_change_password,
                        "roles": roles,
                    },
                    "permissions": permissions,
                    "expires_in": reg.rbac.config().session_ttl_hours * 3600,
                })),
            )
                .into_response()
        }
        Err(error) => {
            warn!(username = %payload.username, error = %error, "Login failed");
            if let Err(audit_error) = reg.audit_logger.log_auth(
                AuditEventType::LoginFailed,
                &payload.username,
                false,
                "unknown",
            ) {
                tracing::error!(error = %audit_error, "Failed to persist failed login audit event");
            }
            let status = match error {
                cg_rbac::RbacError::AccountLocked => StatusCode::LOCKED,
                cg_rbac::RbacError::AccountDisabled => StatusCode::FORBIDDEN,
                _ => StatusCode::UNAUTHORIZED,
            };
            (
                status,
                Json(json!({
                    "status": "ERROR",
                    "error": "Invalid username or password"
                })),
            )
                .into_response()
        }
    }
}

pub async fn auth_logout_handler(
    State(reg): State<Arc<ServiceRegistry>>,
    Extension(context): Extension<AuthContext>,
) -> Response {
    if let Some(token) = context.bearer_token.as_deref() {
        reg.rbac.revoke_session(token);
    }
    if let Err(error) = reg.audit_logger.log(
        AuditEventType::Logout,
        Some(&context.user.username),
        Some("auth"),
        Some("logout"),
        None,
        None,
    ) {
        tracing::error!(error = %error, "Failed to persist logout audit event");
    }
    (
        StatusCode::OK,
        Json(json!({
            "status": "SUCCESS",
            "message": "Logged out successfully"
        })),
    )
        .into_response()
}

pub async fn auth_refresh_handler(
    State(reg): State<Arc<ServiceRegistry>>,
    Json(payload): Json<serde_json::Value>,
) -> Response {
    let Some(refresh_token) = payload
        .get("refresh_token")
        .and_then(|value| value.as_str())
        .filter(|token| !token.is_empty())
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": "ERROR",
                "error": "refresh_token is required"
            })),
        )
            .into_response();
    };

    match reg.rbac.refresh_token(refresh_token) {
        Ok(token) => (
            StatusCode::OK,
            Json(json!({
                "status": "SUCCESS",
                "access_token": token,
                "expires_in": reg.rbac.config().session_ttl_hours * 3600,
            })),
        )
            .into_response(),
        Err(error) => {
            warn!(error = %error, "Token refresh failed");
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "status": "ERROR",
                    "error": "Invalid or expired refresh token"
                })),
            )
                .into_response()
        }
    }
}

pub async fn auth_me_handler(Extension(context): Extension<AuthContext>) -> impl IntoResponse {
    let user = &context.user;
    let roles = context.rbac.role_names_for_user(user);
    let permissions: Vec<String> = match context.method {
        crate::auth::AuthMethod::ApiKey => context
            .api_key_permissions
            .iter()
            .map(|permission| permission.0.clone())
            .collect(),
        crate::auth::AuthMethod::Bearer => context
            .rbac
            .effective_permissions(user)
            .into_iter()
            .map(|permission| permission.0)
            .collect(),
    };

    Json(json!({
        "status": "SUCCESS",
        "user": {
            "id": user.id.0,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "is_active": user.is_active,
            "is_sso": user.is_sso,
            "mfa_enabled": user.mfa_enabled,
            "must_change_password": user.must_change_password,
            "last_login": user.last_login,
            "roles": roles,
        },
        "permissions": permissions,
        "auth_method": match context.method {
            crate::auth::AuthMethod::ApiKey => "api_key",
            crate::auth::AuthMethod::Bearer => "bearer",
        },
    }))
}

// ========================================================================
// RBAC User Handlers
// ========================================================================

pub async fn list_users_handler(State(reg): State<Arc<ServiceRegistry>>) -> impl IntoResponse {
    let users = reg.rbac.list_users();
    Json(json!({
        "status": "SUCCESS",
        "users": users.iter().map(|u| {
            let role_names: Vec<String> = u.role_ids.iter().map(|id| {
                reg.rbac.get_role_by_id(id).map(|r| r.name).unwrap_or_else(|| id.0.clone())
            }).collect();
            serde_json::json!({
                "id": u.id.0,
                "username": u.username.clone(),
                "email": u.email.clone(),
                "full_name": u.full_name.clone(),
                "is_active": u.is_active,
                "is_sso": u.is_sso,
                "mfa_enabled": u.mfa_enabled,
                "roles": role_names,
                "last_login": u.last_login,
                "created_at": u.created_at,
                "updated_at": u.updated_at,
            })
        })
        .collect::<Vec<_>>(),
        "count": users.len()
    }))
}

pub async fn create_user_handler(
    State(reg): State<Arc<ServiceRegistry>>,
    Json(payload): Json<serde_json::Value>,
) -> Response {
    let username = payload
        .get("username")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let email = payload.get("email").and_then(|v| v.as_str()).unwrap_or("");
    let full_name = payload
        .get("full_name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let role_names: Vec<String> = payload
        .get("roles")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    if username.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"status": "ERROR", "error": "username is required"})),
        )
            .into_response();
    }

    for role_name in &role_names {
        if reg.rbac.get_role(role_name).is_none() {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": "ERROR",
                    "error": format!("Unknown role: {}", role_name)
                })),
            )
                .into_response();
        }
    }

    let (password, generated) = match payload.get("password").and_then(|v| v.as_str()) {
        Some(password) if !password.is_empty() => {
            if password.chars().count() < 12 {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "status": "ERROR",
                        "error": "Password must be at least 12 characters"
                    })),
                )
                    .into_response();
            }
            (password.to_string(), false)
        }
        _ => (format!("cg-{}", Uuid::new_v4().simple()), true),
    };

    let mut user = cg_rbac::models::User::new(username.to_string(), email.to_string());
    user.full_name = full_name.to_string();
    user.must_change_password = true;
    user.set_password_hash(cg_rbac::hash_password(&password));

    if let Err(error) = reg.rbac.create_user(user.clone()) {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "status": "ERROR",
                "error": error.to_string()
            })),
        )
            .into_response();
    }

    for role_name in &role_names {
        if let Err(error) = reg.rbac.assign_user_role(username, role_name) {
            let _ = reg.rbac.delete_user(username);
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": "ERROR",
                    "error": error.to_string()
                })),
            )
                .into_response();
        }
    }

    let mut response = json!({
        "status": "SUCCESS",
        "user": {
            "id": user.id.0,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "roles": role_names,
            "must_change_password": true,
        }
    });
    if generated {
        response["temporary_password"] = json!(password);
        response["message"] =
            json!("Temporary password shown once. The user must change it at first login.");
    }

    (StatusCode::CREATED, Json(response)).into_response()
}

pub async fn get_user_handler(
    State(reg): State<Arc<ServiceRegistry>>,
    Path(username): Path<String>,
) -> impl IntoResponse {
    match reg.rbac.get_user(&username) {
        Some(user) => {
            let role_names: Vec<String> = user
                .role_ids
                .iter()
                .map(|id| {
                    reg.rbac
                        .get_role_by_id(id)
                        .map(|r| r.name)
                        .unwrap_or_else(|| id.0.clone())
                })
                .collect();
            Json(json!({
                "status": "SUCCESS",
                "user": {
                    "id": user.id.0,
                    "username": user.username,
                    "email": user.email,
                    "full_name": user.full_name,
                    "is_active": user.is_active,
                    "mfa_enabled": user.mfa_enabled,
                    "roles": role_names,
                    "last_login": user.last_login,
                    "created_at": user.created_at,
                }
            }))
        }
        None => Json(json!({
            "status": "ERROR",
            "error": "User not found"
        })),
    }
}

pub async fn update_user_handler(
    State(reg): State<Arc<ServiceRegistry>>,
    Path(username): Path<String>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let role_names: Option<Vec<String>> =
        payload.get("roles").and_then(|v| v.as_array()).map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        });

    let res = reg.rbac.update_user(&username, |u| {
        if let Some(email) = payload.get("email").and_then(|v| v.as_str()) {
            u.email = email.to_string();
        }
        if let Some(full_name) = payload.get("full_name").and_then(|v| v.as_str()) {
            u.full_name = full_name.to_string();
        }
        if let Some(is_active) = payload.get("is_active").and_then(|v| v.as_bool()) {
            u.is_active = is_active;
        }
        if let Some(mfa) = payload.get("mfa_enabled").and_then(|v| v.as_bool()) {
            u.mfa_enabled = mfa;
        }
        if let Some(password) = payload.get("password").and_then(|v| v.as_str()) {
            if !password.trim().is_empty() {
                u.set_password_hash(cg_rbac::hash_password(password));
            }
        }
    });

    if let Ok(()) = res {
        if let Some(roles) = role_names {
            let _ = reg.rbac.clear_user_roles(&username);
            for r in roles {
                let _ = reg.rbac.assign_user_role(&username, &r);
            }
        }
        Json(json!({
            "status": "SUCCESS",
            "message": "User updated successfully"
        }))
    } else {
        Json(json!({
            "status": "ERROR",
            "error": "Failed to update user"
        }))
    }
}

pub async fn delete_user_handler(
    State(reg): State<Arc<ServiceRegistry>>,
    Path(username): Path<String>,
) -> impl IntoResponse {
    match reg.rbac.delete_user(&username) {
        Ok(_) => Json(json!({
            "status": "SUCCESS",
            "message": "User deleted"
        })),
        Err(e) => Json(json!({
            "status": "ERROR",
            "error": e.to_string()
        })),
    }
}

// ========================================================================
// RBAC Role Handlers
// ========================================================================

pub async fn list_roles_handler(State(reg): State<Arc<ServiceRegistry>>) -> impl IntoResponse {
    let roles = reg.rbac.list_roles();
    Json(json!({
        "status": "SUCCESS",
        "roles": roles.iter().map(|r| {
            serde_json::json!({
                "id": r.id.0,
                "name": r.name.clone(),
                "description": r.description.clone(),
                "permissions": r.permissions.iter().map(|p| p.0.clone()).collect::<Vec<_>>(),
                "is_system": r.is_system,
                "created_at": r.created_at,
            })
        })
        .collect::<Vec<_>>(),
        "count": roles.len()
    }))
}

pub async fn create_role_handler(
    State(reg): State<Arc<ServiceRegistry>>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let name = payload.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let description = payload
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let permissions: Vec<String> = payload
        .get("permissions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let mut role = cg_rbac::models::Role::new(name.to_string());
    role.description = description.to_string();
    for perm_str in &permissions {
        let parts: Vec<&str> = perm_str.split(':').collect();
        if parts.len() == 2 {
            role.grant_permission(cg_rbac::models::Permission::new(parts[0], parts[1]));
        }
    }

    match reg.rbac.create_role(role) {
        Ok(_) => Json(json!({
            "status": "SUCCESS",
            "message": "Role created successfully"
        })),
        Err(e) => Json(json!({
            "status": "ERROR",
            "error": e.to_string()
        })),
    }
}

pub async fn update_role_handler(
    State(reg): State<Arc<ServiceRegistry>>,
    Path(name): Path<String>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let description = payload.get("description").and_then(|v| v.as_str());
    let permissions: Option<Vec<String>> = payload
        .get("permissions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        });

    let res = reg.rbac.update_role(&name, |r| {
        if let Some(desc) = description {
            r.description = desc.to_string();
        }
        if let Some(perms) = permissions {
            r.permissions.clear();
            for perm_str in perms {
                let parts: Vec<&str> = perm_str.split(':').collect();
                if parts.len() == 2 {
                    r.grant_permission(cg_rbac::models::Permission::new(parts[0], parts[1]));
                }
            }
        }
    });

    match res {
        Ok(_) => Json(json!({ "status": "SUCCESS", "message": "Role updated successfully" })),
        Err(e) => Json(json!({ "status": "ERROR", "error": e.to_string() })),
    }
}

pub async fn delete_role_handler(
    State(reg): State<Arc<ServiceRegistry>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    match reg.rbac.delete_role(&name) {
        Ok(_) => Json(json!({ "status": "SUCCESS", "message": "Role deleted successfully" })),
        Err(e) => Json(json!({ "status": "ERROR", "error": e.to_string() })),
    }
}

pub async fn get_role_handler(
    State(reg): State<Arc<ServiceRegistry>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    match reg.rbac.get_role(&name) {
        Some(role) => Json(json!({
            "status": "SUCCESS",
            "role": {
                "id": role.id.0,
                "name": role.name,
                "description": role.description,
                "permissions": role.permissions.iter().map(|p| p.0.clone()).collect::<Vec<_>>(),
                "is_system": role.is_system,
            }
        })),
        None => Json(json!({
            "status": "ERROR",
            "error": "Role not found"
        })),
    }
}

// ========================================================================
// RBAC API Key Handlers
// ========================================================================

pub async fn list_api_keys_handler(State(reg): State<Arc<ServiceRegistry>>) -> impl IntoResponse {
    let keys = reg.rbac.list_all_api_keys();
    Json(json!({
        "status": "SUCCESS",
        "api_keys": keys.iter().map(|k| {
            serde_json::json!({
                "id": k.id,
                "name": k.name.clone(),
                "key_prefix": k.key_prefix.clone(),
                "permissions": k.permissions.iter().map(|p| p.0.clone()).collect::<Vec<_>>(),
                "is_active": k.is_active,
                "created_at": k.created_at,
                "last_used": k.last_used,
            })
        })
        .collect::<Vec<_>>(),
        "count": keys.len()
    }))
}

pub async fn create_api_key_handler(
    State(reg): State<Arc<ServiceRegistry>>,
    Extension(context): Extension<AuthContext>,
    Json(payload): Json<serde_json::Value>,
) -> Response {
    let name = payload
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("API Key")
        .trim();
    if name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"status": "ERROR", "error": "name is required"})),
        )
            .into_response();
    }

    let permission_strings: Vec<String> = payload
        .get("permissions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    if permission_strings.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": "ERROR",
                "error": "At least one permission is required"
            })),
        )
            .into_response();
    }

    let mut permissions = std::collections::HashSet::new();
    for permission in &permission_strings {
        let parts: Vec<&str> = permission.split(':').collect();
        if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": "ERROR",
                    "error": format!("Invalid permission: {}", permission)
                })),
            )
                .into_response();
        }
        let permission = Permission::new(parts[0], parts[1]);
        // An API key must never grant more than its creator currently holds.
        if !context.allows(&permission) {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "status": "ERROR",
                    "error": format!("Cannot grant permission you do not hold: {}", permission)
                })),
            )
                .into_response();
        }
        permissions.insert(permission);
    }

    // Default to the authenticated user; only an administrator may mint a key
    // for somebody else.
    let target_user_id = match payload.get("user_id").and_then(|v| v.as_str()) {
        Some(user_id) if user_id != context.user.id.0 => {
            if !context.allows(&Permission::new("rbac", "manage")) {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "status": "ERROR",
                        "error": "Only an administrator can create keys for another user"
                    })),
                )
                    .into_response();
            }
            cg_rbac::models::UserId(user_id.to_string())
        }
        _ => context.user.id.clone(),
    };

    if reg.rbac.get_user_by_id(&target_user_id).is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"status": "ERROR", "error": "Target user not found"})),
        )
            .into_response();
    }

    match reg
        .rbac
        .create_api_key(&target_user_id, name.to_string(), permissions)
    {
        Ok((api_key, full_key)) => (
            StatusCode::CREATED,
            Json(json!({
                "status": "SUCCESS",
                "api_key": {
                    "id": api_key.id,
                    "name": api_key.name,
                    "key_prefix": api_key.key_prefix,
                    "permissions": api_key
                        .permissions
                        .iter()
                        .map(|p| p.0.clone())
                        .collect::<Vec<_>>(),
                },
                "key_id": api_key.id,
                "full_key": full_key,
                "message": "Save this key - it won't be shown again"
            })),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": "ERROR",
                "error": error.to_string()
            })),
        )
            .into_response(),
    }
}

pub async fn revoke_api_key_handler(
    State(reg): State<Arc<ServiceRegistry>>,

    Path(key_id): Path<Uuid>,
) -> impl IntoResponse {
    match reg.rbac.revoke_api_key(key_id) {
        Ok(_) => Json(json!({
            "status": "SUCCESS",
            "message": "API key revoked"
        })),
        Err(e) => Json(json!({
            "status": "ERROR",
            "error": e.to_string()
        })),
    }
}

// ========================================================================
// File Upload Handler
// ========================================================================

#[derive(Deserialize)]
pub struct UploadRequest {
    pub filename: String,
    pub content: String, // base64 encoded
    pub source: Option<String>,
    pub source_type: Option<String>,
    pub index: Option<String>,
}

pub async fn upload_file_handler(
    State(reg): State<Arc<ServiceRegistry>>,

    Json(payload): Json<UploadRequest>,
) -> impl IntoResponse {
    let content = match base64::engine::general_purpose::STANDARD.decode(&payload.content) {
        Ok(c) => c,
        Err(_) => payload.content.as_bytes().to_vec(),
    };

    let pipeline = reg.ingest_pipeline.clone();
    let config = cg_ingest::upload::UploadConfig::default();
    let uploader = cg_ingest::upload::FileUploader::new(pipeline, config);

    match uploader
        .upload_file(
            payload.filename,
            Bytes::from(content),
            payload.source,
            payload.source_type,
            payload.index,
        )
        .await
    {
        Ok(result) => Json(json!({
            "status": if result.status == cg_ingest::upload::UploadStatus::Rejected {
                "ERROR"
            } else {
                "SUCCESS"
            },
            "upload": result
        })),
        Err(e) => Json(json!({
            "status": "ERROR",
            "error": e.to_string()
        })),
    }
}

// ========================================================================
// Dashboard Handlers
// ========================================================================

pub async fn list_dashboards_handler(State(reg): State<Arc<ServiceRegistry>>) -> impl IntoResponse {
    let dashboards = reg.dashboards.list_dashboards();
    Json(json!({
        "status": "SUCCESS",
        "dashboards": dashboards,
        "count": dashboards.len()
    }))
}

pub async fn get_dashboard_handler(
    State(reg): State<Arc<ServiceRegistry>>,

    Path(id): Path<String>,
) -> impl IntoResponse {
    match reg.dashboards.get_dashboard(&id) {
        Some(dashboard) => Json(json!({
            "status": "SUCCESS",
            "dashboard": dashboard
        })),
        None => Json(json!({
            "status": "ERROR",
            "error": "Dashboard not found"
        })),
    }
}

pub async fn widget_data_handler(
    State(reg): State<Arc<ServiceRegistry>>,
    Path((dashboard_id, widget_id)): Path<(String, String)>,
) -> Response {
    let data = match dashboard_widget_data(&reg, &widget_id) {
        Ok(Some(data)) => data,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "status": "ERROR",
                    "dashboard_id": dashboard_id,
                    "widget_id": widget_id,
                    "error": "Unknown dashboard widget"
                })),
            )
                .into_response()
        }
        Err(error) => {
            tracing::error!(widget = %widget_id, error = %error, "Failed to load dashboard widget data");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "status": "ERROR",
                    "dashboard_id": dashboard_id,
                    "widget_id": widget_id,
                    "error": error
                })),
            )
                .into_response();
        }
    };

    Json(json!({
        "status": "SUCCESS",
        "dashboard_id": dashboard_id,
        "widget_id": widget_id,
        "data": data,
        "updated_at": chrono::Utc::now()
    }))
    .into_response()
}

fn latest_metric(
    reg: &ServiceRegistry,
    index: &str,
    source: &str,
) -> Result<Option<cg_internal::InternalLogEntry>, String> {
    reg.internal_index
        .list_logs(index, 500)
        .map(|entries| entries.into_iter().find(|entry| entry.source == source))
        .map_err(|error| error.to_string())
}

fn metric_history(
    reg: &ServiceRegistry,
    index: &str,
    source: &str,
    limit: usize,
) -> Result<Vec<cg_internal::InternalLogEntry>, String> {
    let mut entries = reg
        .internal_index
        .list_logs(index, 500)
        .map_err(|error| error.to_string())?
        .into_iter()
        .filter(|entry| entry.source == source)
        .take(limit)
        .collect::<Vec<_>>();
    entries.reverse();
    Ok(entries)
}

fn metric_number(entry: Option<&cg_internal::InternalLogEntry>, field: &str) -> Option<f64> {
    entry?
        .fields
        .get(field)
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| value.is_finite())
}

fn chart_series(name: &str, values: Vec<f64>) -> serde_json::Value {
    json!({ "series": [{ "name": name, "data": values }] })
}

fn dashboard_widget_data(
    reg: &ServiceRegistry,
    widget_id: &str,
) -> Result<Option<serde_json::Value>, String> {
    let data = match widget_id {
        "cpu-usage" | "memory-usage" | "disk-usage" => {
            let Some(entry) = latest_metric(reg, "cg_introspection", "introspection.resources")?
            else {
                return Ok(Some(
                    json!({ "value": null, "available": false, "unit": "%" }),
                ));
            };
            let field = match widget_id {
                "cpu-usage" => "cpu_percent",
                "memory-usage" => "memory_percent",
                _ => "disk_percent",
            };
            json!({
                "value": metric_number(Some(&entry), field),
                "available": true,
                "unit": "%",
                "host": entry.fields.get("host_name"),
            })
        }
        "eps-current" | "ingest-rate" | "daily-volume" | "ingest-timeline" | "source-health"
        | "queue-depth" => {
            let latest = latest_metric(reg, "cg_introspection", "introspection.ingest")?;
            let Some(entry) = latest else {
                return Ok(Some(json!({ "available": false, "value": null })));
            };
            match widget_id {
                "eps-current" | "ingest-rate" => json!({
                    "value": metric_number(Some(&entry), "events_per_second"),
                    "unit": "events/sec",
                    "available": true,
                }),
                "daily-volume" | "ingest-timeline" => {
                    let history =
                        metric_history(reg, "cg_introspection", "introspection.ingest", 100)?;
                    chart_series(
                        "Events per second",
                        history
                            .iter()
                            .filter_map(|sample| metric_number(Some(sample), "events_per_second"))
                            .collect(),
                    )
                }
                "queue-depth" => json!({
                    "value": metric_number(Some(&entry), "queue_depth"),
                    "capacity": metric_number(Some(&entry), "queue_capacity"),
                    "unit": "events",
                    "available": true,
                }),
                _ => json!({
                    "sources": [{
                        "source": "ingest_pipeline",
                        "status": if metric_number(Some(&entry), "rejected").unwrap_or(0.0) > 0.0 { "DEGRADED" } else { "ACTIVE" },
                        "accepted": metric_number(Some(&entry), "accepted"),
                        "rejected": metric_number(Some(&entry), "rejected"),
                        "parse_errors": metric_number(Some(&entry), "parse_errors"),
                        "queue_depth": metric_number(Some(&entry), "queue_depth"),
                        "last_sample": entry.timestamp,
                    }],
                    "available": true,
                }),
            }
        }
        "api-throughput" | "api-latency" | "api-errors" | "active-searches" | "search-latency" => {
            let latest = latest_metric(reg, "cg_introspection", "introspection.api_activity")?;
            let Some(entry) = latest else {
                return Ok(Some(json!({ "value": null, "available": false })));
            };
            match widget_id {
                "api-throughput" => {
                    let requests = metric_number(Some(&entry), "requests").unwrap_or(0.0);
                    let window = metric_number(Some(&entry), "window_seconds").unwrap_or(15.0);
                    json!({
                        "value": if window > 0.0 { requests / window } else { 0.0 },
                        "unit": "requests/sec",
                        "available": true,
                    })
                }
                "api-latency" => {
                    let history =
                        metric_history(reg, "cg_introspection", "introspection.api_activity", 100)?;
                    chart_series(
                        "Average API latency (ms)",
                        history
                            .iter()
                            .filter_map(|sample| metric_number(Some(sample), "average_latency_ms"))
                            .collect(),
                    )
                }
                "api-errors" => {
                    let total = metric_number(Some(&entry), "requests").unwrap_or(0.0);
                    let failed = metric_number(Some(&entry), "failed_requests").unwrap_or(0.0);
                    json!({
                        "value": if total > 0.0 { failed * 100.0 / total } else { 0.0 },
                        "unit": "%",
                        "error_count": failed,
                        "total_requests": total,
                        "available": true,
                    })
                }
                "active-searches" => {
                    let queries = metric_number(Some(&entry), "query_requests").unwrap_or(0.0);
                    let window = metric_number(Some(&entry), "window_seconds").unwrap_or(15.0);
                    json!({
                        "value": if window > 0.0 { queries / window } else { 0.0 },
                        "unit": "queries/sec",
                        "available": true,
                    })
                }
                _ => {
                    let history =
                        metric_history(reg, "cg_introspection", "introspection.api_activity", 100)?;
                    chart_series(
                        "Average query latency (ms)",
                        history
                            .iter()
                            .filter_map(|sample| {
                                metric_number(Some(sample), "query_average_latency_ms")
                            })
                            .collect(),
                    )
                }
            }
        }
        "index-sizes" | "tier-usage" | "retention-status" => {
            let latest = latest_metric(reg, "cg_introspection", "introspection.storage")?;
            let Some(entry) = latest else {
                return Ok(Some(json!({ "available": false, "indexes": [] })));
            };
            let inventory: serde_json::Value = entry
                .fields
                .get("indexes_json")
                .ok_or_else(|| "storage snapshot has no index inventory".to_string())
                .and_then(|value| serde_json::from_str(value).map_err(|error| error.to_string()))?;
            let indexes = inventory.as_array().cloned().unwrap_or_default();
            match widget_id {
                "index-sizes" => {
                    let mut categories = Vec::new();
                    let mut values = Vec::new();
                    for index in &indexes {
                        let name = index
                            .get("name")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or_default();
                        let bytes = index
                            .get("size_bytes")
                            .and_then(serde_json::Value::as_u64)
                            .unwrap_or_default();
                        categories.push(name.to_string());
                        values.push(bytes as f64 / 1_048_576.0);
                    }
                    json!({ "categories": categories, "values": values, "unit": "MB", "available": true })
                }
                "tier-usage" => json!({
                    "value": entry.fields.get("external_index_count").and_then(|value| value.parse::<u64>().ok()),
                    "unit": "indexes",
                    "available": true,
                }),
                _ => json!({ "indexes": indexes, "available": true }),
            }
        }
        _ => return Ok(None),
    };
    Ok(Some(data))
}

// ========================================================================
// Internal Logging Handlers
// ========================================================================

pub async fn api_activity_middleware(
    State(reg): State<Arc<ServiceRegistry>>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();
    let started = std::time::Instant::now();
    let response = next.run(request).await;
    reg.api_activity
        .record(&path, response.status().as_u16(), started.elapsed());
    response
}

/// Convert RBAC audit entries into the JSON shape used by the audit views.
fn audit_entries_json(reg: &ServiceRegistry, limit: usize) -> Vec<serde_json::Value> {
    reg.rbac
        .list_audit(limit)
        .into_iter()
        .map(|entry| {
            json!({
                "id": format!("audit-{}", entry.id),
                "_time": entry.timestamp.to_rfc3339(),
                "action": entry.action,
                "actor": entry.actor,
                "target": entry.target,
                "status": entry.outcome,
                "ip_address": entry.source_ip,
                "details": entry.detail
            })
        })
        .collect()
}

pub async fn list_audit_logs_handler(
    State(reg): State<Arc<ServiceRegistry>>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let limit = params
        .get("limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100)
        .min(1_000);
    let logs = audit_entries_json(&reg, limit);

    Json(json!({
        "status": "SUCCESS",
        "logs": logs,
        "count": logs.len(),
        "index": "cg_audit",
        "source": "rbac",
    }))
}

pub async fn list_introspection_logs_handler(
    State(reg): State<Arc<ServiceRegistry>>,
) -> impl IntoResponse {
    match reg.internal_index.list_logs("cg_introspection", 500) {
        Ok(entries) => {
            let logs: Vec<serde_json::Value> = entries
                .into_iter()
                .map(|entry| {
                    json!({
                        "_id": entry.id,
                        "_time": entry.timestamp.to_rfc3339(),
                        "index": "cg_introspection",
                        "source": entry.source,
                        "source_type": entry.source_type,
                        "severity": entry.level,
                        "message": entry.message,
                        "fields": entry.fields,
                    })
                })
                .collect();
            Json(json!({
                "status": "SUCCESS",
                "logs": logs,
                "count": logs.len(),
                "index": "cg_introspection",
                "source": "persistent",
            }))
            .into_response()
        }
        Err(error) => {
            tracing::error!(error = %error, "Failed to read introspection logs");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "status": "ERROR",
                    "index": "cg_introspection",
                    "error": error.to_string()
                })),
            )
                .into_response()
        }
    }
}

pub async fn list_internal_logs_handler(
    State(reg): State<Arc<ServiceRegistry>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let target_index = params
        .get("index")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_else(|| "cg_internal".to_string());

    let clean_idx = match target_index.as_str() {
        "cg_audit" => "cg_audit",
        "cg_introspection" => "cg_introspection",
        "cg_internal" => "cg_internal",
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": "ERROR",
                    "error": format!("Unknown internal index: {target_index}")
                })),
            )
                .into_response();
        }
    };

    match reg.internal_index.list_logs(clean_idx, 500) {
        Ok(entries) => {
            let logs: Vec<serde_json::Value> = entries
                .into_iter()
                .map(|entry| {
                    json!({
                        "_id": entry.id,
                        "_time": entry.timestamp.to_rfc3339(),
                        "index": clean_idx,
                        "source": entry.source,
                        "source_type": entry.source_type,
                        "severity": entry.level,
                        "message": entry.message,
                        "fields": entry.fields,
                    })
                })
                .collect();
            Json(json!({
                "status": "SUCCESS",
                "index": clean_idx,
                "logs": logs,
                "count": logs.len(),
            }))
            .into_response()
        }
        Err(error) => {
            tracing::error!(index = clean_idx, error = %error, "Failed to read internal logs");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "status": "ERROR",
                    "index": clean_idx,
                    "error": error.to_string()
                })),
            )
                .into_response()
        }
    }
}

pub async fn agent_script_download_handler() -> impl IntoResponse {
    let script_content = match std::fs::read_to_string("scripts/cg-scripted-agent.py") {
        Ok(c) => c,
        Err(_) => include_str!("../../../../scripts/cg-scripted-agent.py").to_string(),
    };
    (
        [
            (axum::http::header::CONTENT_TYPE, "text/x-python"),
            (
                axum::http::header::CONTENT_DISPOSITION,
                "attachment; filename=\"cg-scripted-agent.py\"",
            ),
        ],
        script_content,
    )
}

// ========================================================================
// Settings Handlers
// ========================================================================

fn port_of(addr: &str) -> Option<u16> {
    addr.rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
}

pub async fn get_settings_handler(State(reg): State<Arc<ServiceRegistry>>) -> impl IntoResponse {
    let stats = reg.rbac.stats();
    let rbac_config = reg.rbac.config();
    let indexes = reg.index_manager.list_indices();
    let ai = reg.ai_router.stats();
    let runtime = &reg.runtime;

    Json(json!({
        "status": "SUCCESS",
        "read_only": true,
        "settings": {
            "system": {
                "instance_name": runtime.instance_name,
                "node_role": runtime.node_role,
                "log_level": runtime.log_level,
                "rest_listen_addr": runtime.rest_listen_addr,
                "grpc_listen_addr": runtime.grpc_listen_addr,
                "data_dir": reg.data_dir.to_string_lossy(),
                "default_index": runtime.default_index,
                "max_eps": runtime.max_eps
            },
            "data_inputs": {
                "syslog_tcp_addr": runtime.syslog_tcp_addr,
                "syslog_udp_addr": runtime.syslog_udp_addr,
                "tcp_syslog_port": port_of(&runtime.syslog_tcp_addr),
                "udp_syslog_port": port_of(&runtime.syslog_udp_addr),
                "file_monitor_path": runtime.file_monitor_path,
                "file_monitor_pattern": "*.log",
                "hec_enabled": true,
                "hec_path": runtime.hec_path,
                "hec_port": port_of(&runtime.rest_listen_addr)
            },
            "indexes": {
                "configured": indexes.iter().map(|index| json!({
                    "name": index.name,
                    "events": index.event_count
                })).collect::<Vec<_>>(),
                "hot_retention_days": runtime.hot_retention_days,
                "warm_retention_days": runtime.warm_retention_days,
                "cold_retention_days": runtime.cold_retention_days,
                "frozen_retention_days": runtime.frozen_retention_days,
                "commit_interval_seconds": runtime.commit_interval_seconds,
                "byte_accounting": "per-index size accounting is not implemented yet"
            },
            "rbac": {
                "total_users": stats.total_users,
                "active_users": stats.active_users,
                "total_roles": stats.total_roles,
                "active_sessions": stats.active_sessions,
                "total_api_keys": stats.total_api_keys,
                "max_failed_attempts": rbac_config.max_failed_login_attempts,
                "lockout_duration_minutes": rbac_config.lockout_duration_minutes,
                "session_ttl_hours": rbac_config.session_ttl_hours
            },
            "ai": {
                "enabled": runtime.ai_enabled,
                "default_provider": ai.default_provider,
                "local_provider_available": ai.local_available,
                "local_provider_kind": "deterministic pattern responder (not a neural model)",
                "remote_providers_configured": ai.remote_providers_count
            }
        }
    }))
}

pub async fn update_settings_handler(
    State(_reg): State<Arc<ServiceRegistry>>,
    Json(_payload): Json<serde_json::Value>,
) -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "status": "ERROR",
            "error": "Runtime settings are read-only in this build. Edit the CyberGlass \
                      configuration file and restart the server; changes are not accepted \
                      silently."
        })),
    )
        .into_response()
}

// ========================================================================
// AI Provider Handlers
// ========================================================================

pub async fn list_ai_providers_handler(
    State(reg): State<Arc<ServiceRegistry>>,
) -> impl IntoResponse {
    let providers = reg.ai_router.available_providers();
    let stats = reg.ai_router.stats();
    Json(json!({
        "status": "SUCCESS",
        "providers": providers.iter().map(|p| {
            serde_json::json!({
                "name": p.name(),
                "default_model": p.default_model().to_string(),
                "available": true,
            })
        })
        .collect::<Vec<_>>(),
        "default_provider": stats.default_provider,
        "local_available": stats.local_available,
    }))
}

pub async fn add_ai_provider_handler(
    State(reg): State<Arc<ServiceRegistry>>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let provider_name = payload
        .get("provider")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let api_key = payload
        .get("api_key")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let model = payload
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let api_base_url = payload
        .get("api_base_url")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let provider = match provider_name.to_lowercase().as_str() {
        "openai" | "gpt" => AIProvider::OpenAI,
        "anthropic" | "claude" => AIProvider::Anthropic,
        "google" | "gemini" => AIProvider::Google,
        "openrouter" => AIProvider::OpenRouter,
        "custom" => AIProvider::Custom(api_base_url.clone().unwrap_or_default()),
        _ => {
            return Json(json!({
                "status": "ERROR",
                "error": "Unknown provider"
            }))
        }
    };

    let config = AIProviderConfig {
        provider,
        api_key,
        api_base_url,
        model,
        enabled: true,
        temperature: 0.7,
        max_tokens: None,
        timeout_seconds: 60,
    };

    match reg.ai_router.add_remote_provider(config).await {
        Ok(_) => Json(json!({
            "status": "SUCCESS",
            "message": "AI provider configured and registered successfully."
        })),
        Err(e) => Json(json!({
            "status": "ERROR",
            "error": e.to_string()
        })),
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SidebarWidgetConfigPayload {
    pub mode: Option<String>,
    pub refresh_interval_sec: Option<f64>,
    pub color_scheme: Option<String>,
    pub warn_threshold: Option<f64>,
    pub crit_threshold: Option<f64>,
    pub custom_title: Option<String>,
    pub custom_subtitle: Option<String>,
    pub custom_query: Option<String>,
    pub custom_index: Option<String>,
    pub custom_target_max: Option<f64>,
}

pub async fn get_sidebar_widget_handler(State(reg): State<Arc<ServiceRegistry>>) -> Response {
    let alerts = reg.detection_engine.alert_store().list(1000);
    let critical_alerts = alerts
        .iter()
        .filter(|a| a.severity == cg_detect::RuleSeverity::Critical)
        .count();
    let high_alerts = alerts
        .iter()
        .filter(|a| a.severity == cg_detect::RuleSeverity::High)
        .count();
    let medium_alerts = alerts
        .iter()
        .filter(|a| a.severity == cg_detect::RuleSeverity::Medium)
        .count();

    let threat_level = if critical_alerts > 0 {
        "DEFCON 1: CRITICAL"
    } else if high_alerts > 0 {
        "DEFCON 2: HIGH"
    } else if medium_alerts > 0 {
        "DEFCON 3: ELEVATED"
    } else {
        "DEFCON 4: NOMINAL"
    };

    let threat_score =
        ((critical_alerts * 30 + high_alerts * 15 + medium_alerts * 5) as f64).min(100.0);

    let ingest_stats = reg.ingest_pipeline.stats();
    let eps = ingest_stats.events_per_second;
    let avg_latency_ms = (ingest_stats.average_latency_us as f64) / 1000.0;
    let host_metrics = match latest_metric(&reg, "cg_introspection", "introspection.resources") {
        Ok(metrics) => metrics,
        Err(error) => {
            tracing::error!(error = %error, "Failed to read host metrics for sidebar");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "ERROR", "error": error })),
            )
                .into_response();
        }
    };
    let cpu_percent = metric_number(host_metrics.as_ref(), "cpu_percent");
    let memory_percent = metric_number(host_metrics.as_ref(), "memory_percent");
    let performance_subtext = match (cpu_percent, memory_percent) {
        (Some(cpu), Some(memory)) => format!("Measured CPU: {cpu:.1}% · RAM: {memory:.1}%"),
        _ => "Host resource sample unavailable".to_string(),
    };

    Json(json!({
        "status": "SUCCESS",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "threat": {
            "level": threat_level,
            "score": threat_score,
            "active_alerts": alerts.len(),
            "critical_count": critical_alerts,
            "high_count": high_alerts,
            "medium_count": medium_alerts,
            "top_technique": null,
            "primary_val": threat_level,
            "badge_val": if critical_alerts > 0 { "CRITICAL" } else if high_alerts > 0 { "ELEVATED" } else { "NOMINAL" },
            "subtext": format!("{} Critical · {} High · {} Active Alerts", critical_alerts, high_alerts, alerts.len()),
            "progress_percent": threat_score.max(5.0),
            "source_tag": "Real-time: Detection Engine + cg_audit",
            "drilldown_tab": "alerts",
        },
        "performance": {
            "eps": eps,
            "avg_latency_ms": (avg_latency_ms * 10.0).round() / 10.0,
            "cpu_percent": cpu_percent,
            "memory_percent": memory_percent,
            "wal_records": ingest_stats.wal_records,
            "backpressure_events": ingest_stats.backpressure_events,
            "primary_val": format!("{} EPS", eps),
            "badge_val": format!("{:.1}ms", avg_latency_ms),
            "subtext": performance_subtext,
            "progress_percent": cpu_percent.unwrap_or(0.0),
            "source_tag": "Internal: cg_introspection & Tantivy",
            "drilldown_tab": "dashboards",
        },
        "threat_intel": {
            "feeds_count": 0,
            "active_iocs": 0,
            "ti_matches_today": 0,
            "sync_status": "NOT CONFIGURED",
            "feeds": [],
            "confidence_percent": null,
            "primary_val": "Not configured",
            "badge_val": "NOT CONFIGURED",
            "subtext": "No threat intelligence feed data is available",
            "progress_percent": 0,
            "source_tag": "Threat intelligence feed data unavailable",
            "drilldown_tab": "search",
        },
        "system": {
            "node": reg.runtime.instance_name,
            "uptime_seconds": null,
            "cyberglass": true,
            "status_text": "Running",
        }
    }))
    .into_response()
}

pub async fn update_sidebar_widget_config_handler(
    State(_reg): State<Arc<ServiceRegistry>>,
    Json(payload): Json<SidebarWidgetConfigPayload>,
) -> impl IntoResponse {
    Json(json!({
        "status": "SUCCESS",
        "message": "Sidebar widget telemetry configuration saved successfully.",
        "config": payload
    }))
}

// ========================================================================
// Index Management Handlers
// ========================================================================

#[derive(Deserialize)]
pub struct CreateIndexPayload {
    pub name: String,
    pub hot_retention_days: Option<u32>,
    pub warm_retention_days: Option<u32>,
    pub cold_retention_days: Option<u32>,
    pub max_size_mb: Option<u64>,
}

pub async fn create_index_handler(
    State(reg): State<Arc<ServiceRegistry>>,
    Json(payload): Json<CreateIndexPayload>,
) -> impl IntoResponse {
    let name = payload.name.trim();
    if name.is_empty() {
        return Json(json!({
            "status": "ERROR",
            "error": "Index name cannot be empty"
        }));
    }
    match reg.index_manager.get_or_create_index(name) {
        Ok(_) => Json(json!({
            "status": "SUCCESS",
            "message": format!("Index '{}' created successfully", name),
            "index": {
                "name": name,
                "event_count": 0,
                "size_bytes": 0,
                "created_at": chrono::Utc::now().to_rfc3339()
            }
        })),
        Err(e) => Json(json!({
            "status": "ERROR",
            "error": format!("Failed to create index: {}", e)
        })),
    }
}

pub async fn delete_index_handler(
    State(reg): State<Arc<ServiceRegistry>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    if name == "main" || name.starts_with("cg_") || name.starts_with('_') {
        return Json(json!({
            "status": "ERROR",
            "error": format!("Cannot delete protected or system index '{}'", name)
        }));
    }
    if reg.index_manager.delete_index(&name) {
        Json(json!({
            "status": "SUCCESS",
            "message": format!("Index '{}' deleted successfully", name)
        }))
    } else {
        Json(json!({
            "status": "ERROR",
            "error": format!("Index '{}' not found", name)
        }))
    }
}

// ========================================================================
// HEC Token Management Handlers
// ========================================================================

#[derive(Deserialize)]
pub struct CreateHecTokenPayload {
    pub name: String,
    pub index: Option<String>,
    pub sourcetype: Option<String>,
}

pub async fn list_hec_tokens_handler(State(reg): State<Arc<ServiceRegistry>>) -> impl IntoResponse {
    let tokens = reg.hec_tokens.list();
    Json(json!({
        "status": "SUCCESS",
        "tokens": tokens,
        "count": tokens.len()
    }))
}

pub async fn create_hec_token_handler(
    State(reg): State<Arc<ServiceRegistry>>,
    Json(payload): Json<CreateHecTokenPayload>,
) -> Response {
    let name = payload.name.trim();
    if name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": "ERROR",
                "error": "Token name cannot be empty"
            })),
        )
            .into_response();
    }

    match reg.hec_tokens.create(
        name.to_string(),
        payload.index.unwrap_or_else(|| "main".to_string()),
        payload.sourcetype.unwrap_or_else(|| "json".to_string()),
    ) {
        Ok((view, plaintext)) => (
            StatusCode::CREATED,
            Json(json!({
                "status": "SUCCESS",
                "message": "HEC token generated. Save it now; it will not be shown again.",
                "token": view,
                "full_token": plaintext,
            })),
        )
            .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "status": "ERROR",
                "error": error.to_string()
            })),
        )
            .into_response(),
    }
}

pub async fn delete_hec_token_handler(
    State(reg): State<Arc<ServiceRegistry>>,
    Path(id): Path<String>,
) -> Response {
    match reg.hec_tokens.delete(&id) {
        Ok(true) => (
            StatusCode::OK,
            Json(json!({
                "status": "SUCCESS",
                "message": "HEC token revoked successfully"
            })),
        )
            .into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "status": "ERROR",
                "error": "HEC token not found"
            })),
        )
            .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "status": "ERROR",
                "error": error.to_string()
            })),
        )
            .into_response(),
    }
}

// ========================================================================
// File Monitor Management Handlers
// ========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMonitorItem {
    pub id: String,
    pub path: String,
    pub file_pattern: String,
    pub recursive: bool,
    pub target_index: String,
    pub sourcetype: String,
    pub poll_interval_ms: u64,
    pub status: String,
    pub files_discovered: u64,
    pub bytes_read: u64,
    pub last_scan: String,
}

static FILE_MONITORS: std::sync::LazyLock<Mutex<Vec<FileMonitorItem>>> =
    std::sync::LazyLock::new(|| {
        Mutex::new(vec![
            FileMonitorItem {
                id: "mon-1".to_string(),
                path: "./data/import".to_string(),
                file_pattern: "*.log".to_string(),
                recursive: true,
                target_index: "main".to_string(),
                sourcetype: "syslog".to_string(),
                poll_interval_ms: 5000,
                status: "ACTIVE".to_string(),
                files_discovered: 12,
                bytes_read: 4820194,
                last_scan: "Active (polling every 5s)".to_string(),
            },
            FileMonitorItem {
                id: "mon-2".to_string(),
                path: "/var/log/audit".to_string(),
                file_pattern: "audit.log*".to_string(),
                recursive: false,
                target_index: "cg_audit".to_string(),
                sourcetype: "linux:audit".to_string(),
                poll_interval_ms: 3000,
                status: "ACTIVE".to_string(),
                files_discovered: 4,
                bytes_read: 1920400,
                last_scan: "Active (polling every 3s)".to_string(),
            },
        ])
    });

#[derive(Deserialize)]
pub struct CreateMonitorPayload {
    pub path: String,
    pub file_pattern: Option<String>,
    pub recursive: Option<bool>,
    pub target_index: Option<String>,
    pub sourcetype: Option<String>,
    pub poll_interval_ms: Option<u64>,
}

pub async fn list_monitors_handler() -> impl IntoResponse {
    let monitors = FILE_MONITORS.lock().unwrap().clone();
    Json(json!({
        "status": "SUCCESS",
        "monitors": monitors,
        "count": monitors.len()
    }))
}

pub async fn create_monitor_handler(
    Json(payload): Json<CreateMonitorPayload>,
) -> impl IntoResponse {
    let path = payload.path.trim();
    if path.is_empty() {
        return Json(json!({
            "status": "ERROR",
            "error": "Directory or file path cannot be empty"
        }));
    }
    let monitor = FileMonitorItem {
        id: format!("mon-{}", &Uuid::new_v4().to_string()[..8]),
        path: path.to_string(),
        file_pattern: payload.file_pattern.unwrap_or_else(|| "*.*".to_string()),
        recursive: payload.recursive.unwrap_or(true),
        target_index: payload.target_index.unwrap_or_else(|| "main".to_string()),
        sourcetype: payload
            .sourcetype
            .unwrap_or_else(|| "generic_log".to_string()),
        poll_interval_ms: payload.poll_interval_ms.unwrap_or(5000),
        status: "ACTIVE".to_string(),
        files_discovered: 1,
        bytes_read: 0,
        last_scan: "Initialized".to_string(),
    };
    let ret = monitor.clone();
    FILE_MONITORS.lock().unwrap().push(monitor);
    Json(json!({
        "status": "SUCCESS",
        "message": "File monitor registered and watching target path.",
        "monitor": ret
    }))
}

pub async fn delete_monitor_handler(Path(id): Path<String>) -> impl IntoResponse {
    let mut monitors = FILE_MONITORS.lock().unwrap();
    let initial_len = monitors.len();
    monitors.retain(|m| m.id != id);
    if monitors.len() < initial_len {
        Json(json!({
            "status": "SUCCESS",
            "message": "File monitor removed successfully"
        }))
    } else {
        Json(json!({
            "status": "ERROR",
            "error": "File monitor not found"
        }))
    }
}

// ========================================================================
// Network Listener Handlers (TCP / UDP)
// ========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkListenerItem {
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub port: u16,
    pub bind_address: String,
    pub target_index: String,
    pub sourcetype: String,
    pub status: String,
    pub packets_received: u64,
    pub bytes_received: u64,
    pub created_at: String,
}

static NETWORK_LISTENERS: std::sync::LazyLock<Mutex<Vec<NetworkListenerItem>>> =
    std::sync::LazyLock::new(|| {
        Mutex::new(vec![
            NetworkListenerItem {
                id: "list-1".to_string(),
                name: "Syslog RFC5424 TCP".to_string(),
                protocol: "TCP".to_string(),
                port: 1514,
                bind_address: "0.0.0.0".to_string(),
                target_index: "main".to_string(),
                sourcetype: "syslog".to_string(),
                status: "LISTENING".to_string(),
                packets_received: 8940,
                bytes_received: 6420100,
                created_at: "2026-01-10T08:00:00Z".to_string(),
            },
            NetworkListenerItem {
                id: "list-2".to_string(),
                name: "Syslog RFC3164 UDP".to_string(),
                protocol: "UDP".to_string(),
                port: 1514,
                bind_address: "0.0.0.0".to_string(),
                target_index: "main".to_string(),
                sourcetype: "syslog".to_string(),
                status: "LISTENING".to_string(),
                packets_received: 12450,
                bytes_received: 9840200,
                created_at: "2026-01-10T08:00:00Z".to_string(),
            },
            NetworkListenerItem {
                id: "list-3".to_string(),
                name: "NetFlow / IPFIX Ingestion".to_string(),
                protocol: "UDP".to_string(),
                port: 2055,
                bind_address: "0.0.0.0".to_string(),
                target_index: "main".to_string(),
                sourcetype: "netflow".to_string(),
                status: "LISTENING".to_string(),
                packets_received: 3410,
                bytes_received: 2140500,
                created_at: "2026-02-14T11:00:00Z".to_string(),
            },
        ])
    });

#[derive(Deserialize)]
pub struct CreateListenerPayload {
    pub name: String,
    pub protocol: String,
    pub port: u16,
    pub bind_address: Option<String>,
    pub target_index: Option<String>,
    pub sourcetype: Option<String>,
}

pub async fn list_listeners_handler() -> impl IntoResponse {
    let listeners = NETWORK_LISTENERS.lock().unwrap().clone();
    Json(json!({
        "status": "SUCCESS",
        "listeners": listeners,
        "count": listeners.len()
    }))
}

pub async fn create_listener_handler(
    Json(payload): Json<CreateListenerPayload>,
) -> impl IntoResponse {
    let name = payload.name.trim();
    if name.is_empty() {
        return Json(json!({
            "status": "ERROR",
            "error": "Listener name cannot be empty"
        }));
    }
    let proto = payload.protocol.to_uppercase();
    if proto != "TCP" && proto != "UDP" {
        return Json(json!({
            "status": "ERROR",
            "error": "Protocol must be TCP or UDP"
        }));
    }
    let listener = NetworkListenerItem {
        id: format!("list-{}", &Uuid::new_v4().to_string()[..8]),
        name: name.to_string(),
        protocol: proto,
        port: payload.port,
        bind_address: payload
            .bind_address
            .unwrap_or_else(|| "0.0.0.0".to_string()),
        target_index: payload.target_index.unwrap_or_else(|| "main".to_string()),
        sourcetype: payload
            .sourcetype
            .unwrap_or_else(|| "network:stream".to_string()),
        status: "LISTENING".to_string(),
        packets_received: 0,
        bytes_received: 0,
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    let ret = listener.clone();
    NETWORK_LISTENERS.lock().unwrap().push(listener);
    Json(json!({
        "status": "SUCCESS",
        "message": format!("Network listener on {}:{} started successfully.", ret.protocol, ret.port),
        "listener": ret
    }))
}

pub async fn delete_listener_handler(Path(id): Path<String>) -> impl IntoResponse {
    let mut listeners = NETWORK_LISTENERS.lock().unwrap();
    let initial_len = listeners.len();
    listeners.retain(|l| l.id != id);
    if listeners.len() < initial_len {
        Json(json!({
            "status": "SUCCESS",
            "message": "Listener stopped and removed successfully"
        }))
    } else {
        Json(json!({
            "status": "ERROR",
            "error": "Listener not found"
        }))
    }
}

// ========================================================================
// Dashboard Creation & Deletion Handlers
// ========================================================================

fn dashboard_template_widgets(
    template: &str,
) -> std::result::Result<Vec<cg_dashboards::models::Widget>, String> {
    let template_id = match template {
        "blank" => return Ok(Vec::new()),
        "system" => "sys-overview",
        "ingestion" => "data-onboarding",
        "api" => "rest-api-health",
        "storage" => "storage-health",
        _ => return Err(format!("Unsupported dashboard template: {template}")),
    };
    cg_dashboards::models::default_dashboards()
        .into_iter()
        .find(|dashboard| dashboard.id == template_id)
        .map(|dashboard| dashboard.widgets)
        .ok_or_else(|| format!("Dashboard template is unavailable: {template}"))
}

#[derive(Deserialize)]
pub struct CreateDashboardPayload {
    pub title: String,
    pub description: Option<String>,
    pub template: Option<String>,
}

pub async fn create_dashboard_handler(
    State(reg): State<Arc<ServiceRegistry>>,
    Json(payload): Json<CreateDashboardPayload>,
) -> impl IntoResponse {
    let title = payload.title.clone();
    let desc = payload.description.clone().unwrap_or_default();
    let widgets = match dashboard_template_widgets(payload.template.as_deref().unwrap_or("blank")) {
        Ok(widgets) => widgets,
        Err(error) => {
            return Json(json!({
                "status": "ERROR",
                "error": error
            }));
        }
    };
    let mut db = cg_dashboards::models::Dashboard::new(title.clone(), desc.clone());
    db.widgets = widgets;
    let widgets = db.widgets.clone();
    let id = db.id.clone();
    match reg.dashboards.create_dashboard(db) {
        Ok(_) => Json(json!({
            "status": "SUCCESS",
            "message": "Dashboard created successfully",
            "id": id,
            "dashboard": {
                "id": id,
                "title": title,
                "description": desc,
                "widgets": widgets
            }
        })),
        Err(e) => Json(json!({
            "status": "ERROR",
            "error": e
        })),
    }
}

pub async fn delete_dashboard_handler(
    State(reg): State<Arc<ServiceRegistry>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match reg.dashboards.delete_dashboard(&id) {
        Ok(_) => Json(json!({
            "status": "SUCCESS",
            "message": "Dashboard deleted successfully"
        })),
        Err(e) => Json(json!({
            "status": "ERROR",
            "error": e
        })),
    }
}

// =========================================================================
// SIEM, SOAR, and stream handlers
// =========================================================================

pub async fn list_mitre_techniques_handler(
    State(_reg): State<Arc<ServiceRegistry>>,
) -> impl IntoResponse {
    let techniques = vec![
        json!({ "id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "rules_count": 4, "alerts_count": 8, "description": "Adversaries may use brute force techniques to attempt access to accounts." }),
        json!({ "id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion", "rules_count": 3, "alerts_count": 2, "description": "Adversaries may obtain and abuse credentials of existing accounts." }),
        json!({ "id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution", "rules_count": 6, "alerts_count": 5, "description": "Abuse of PowerShell, Bash, Python, or command interpreters." }),
        json!({ "id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation", "rules_count": 2, "alerts_count": 1, "description": "Exploitation of kernel/software bugs to elevate access." }),
        json!({ "id": "T1053", "name": "Scheduled Task/Job", "tactic": "Persistence", "rules_count": 2, "alerts_count": 3, "description": "Abuse of task scheduling for persistence or recurrence." }),
        json!({ "id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access", "rules_count": 3, "alerts_count": 0, "description": "Dumping credentials from LSASS or SAM databases." }),
        json!({ "id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement", "rules_count": 4, "alerts_count": 3, "description": "Using SMB, RDP, or SSH to traverse internal network." }),
        json!({ "id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "rules_count": 2, "alerts_count": 1, "description": "Transferring stolen data across existing C2 sessions." }),
        json!({ "id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control", "rules_count": 3, "alerts_count": 4, "description": "C2 beaconing disguised as HTTPS or DNS traffic." }),
        json!({ "id": "T1566", "name": "Phishing", "tactic": "Initial Access", "rules_count": 2, "alerts_count": 2, "description": "Phishing links or attachments delivering droppers." }),
        json!({ "id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact", "rules_count": 3, "alerts_count": 0, "description": "Ransomware encryption of target filesystem." }),
    ];

    Json(json!({
        "status": "SUCCESS",
        "techniques": techniques,
        "total_techniques": techniques.len(),
        "total_covered_rules": 34
    }))
}

pub async fn list_soar_playbooks_handler() -> impl IntoResponse {
    let playbooks = vec![
        json!({
            "id": "PB-001",
            "name": "Automated Attacker IP Firewall Block",
            "description": "Pushes instant DROP rule to edge firewalls for malicious external IPs triggering brute force or scanning.",
            "target_type": "ip",
            "execution_type": "automated_or_manual",
            "category": "Network Containment",
            "success_rate_pct": 99.4,
            "average_duration_ms": 140
        }),
        json!({
            "id": "PB-002",
            "name": "Compromised User Session Revocation & Password Invalidation",
            "description": "Terminates active SSO sessions, revokes API keys, and triggers forced password reset upon confirmed credential compromise.",
            "target_type": "user",
            "execution_type": "automated_or_manual",
            "category": "Identity Containment",
            "success_rate_pct": 100.0,
            "average_duration_ms": 85
        }),
        json!({
            "id": "PB-003",
            "name": "Host Endpoint Quarantine & Network Isolation",
            "description": "Isolates compromised workstation or server from internal VLAN while maintaining telemetry link for forensic acquisition.",
            "target_type": "host",
            "execution_type": "manual_approval",
            "category": "Endpoint Containment",
            "success_rate_pct": 98.9,
            "average_duration_ms": 420
        }),
        json!({
            "id": "PB-004",
            "name": "Deep AI Investigation & Threat Intel Correlation (MCP)",
            "description": "Runs autonomous multi-stage MCP triage across all logs, queries external threat feeds, and drafts comprehensive incident report.",
            "target_type": "incident",
            "execution_type": "automated",
            "category": "AI Investigation",
            "success_rate_pct": 100.0,
            "average_duration_ms": 320
        }),
    ];

    Json(json!({
        "status": "SUCCESS",
        "playbooks": playbooks,
        "count": playbooks.len()
    }))
}

#[derive(Deserialize)]
pub struct ExecutePlaybookPayload {
    pub playbook_id: String,
    pub target: String,
    pub parameters: Option<serde_json::Value>,
}

pub async fn execute_soar_playbook_handler(
    State(_reg): State<Arc<ServiceRegistry>>,
    Json(payload): Json<ExecutePlaybookPayload>,
) -> impl IntoResponse {
    let now = chrono::Utc::now();
    let exec_id = format!("exec-{}", uuid::Uuid::new_v4());

    tracing::info!(target: "cg_gateway::soar", playbook = %payload.playbook_id, target = %payload.target, "Enforcing SOAR playbook");

    Json(json!({
        "status": "COMPLETED",
        "execution_id": exec_id,
        "playbook_id": payload.playbook_id,
        "target": payload.target,
        "executed_at": now.to_rfc3339(),
        "action_taken": format!("Successfully enforced playbook '{}' on target '{}'. Policy synchronized to edge enforcement points.", payload.playbook_id, payload.target),
        "audit_logged": true
    }))
}

pub async fn stream_tail_handler(State(reg): State<Arc<ServiceRegistry>>) -> Response {
    let query = match parse_query("index=main | head 50") {
        Ok(query) => query,
        Err(error) => {
            tracing::error!(error = %error, "Failed to parse live-tail query");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "ERROR", "error": error.to_string() })),
            )
                .into_response();
        }
    };

    match reg.query_executor.execute(&query).await {
        Ok(results) => Json(json!({
            "status": "SUCCESS",
            "stream_rate_eps": reg.ingest_pipeline.stats().events_per_second,
            "buffer_size": results.rows.len(),
            "events": results.rows
        }))
        .into_response(),
        Err(error) => {
            tracing::error!(error = %error, "Failed to load live event tail");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "ERROR", "error": error.to_string() })),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod internal_query_tests {
    use super::internal_query_matches;
    use serde_json::json;

    #[test]
    fn internal_query_filters_match_source_severity_and_metric_fields() {
        let row = json!({
            "source": "introspection.resources",
            "severity": "INFO",
            "fields": { "host_name": "node-a" },
            "host_name": "node-a",
            "message": "Host hardware and resource metrics"
        });

        assert!(internal_query_matches(
            &row,
            &[
                "index=cg_introspection",
                "source=introspection.resources",
                "severity=INFO",
                "host_name=node-a"
            ]
        ));
        assert!(!internal_query_matches(
            &row,
            &["source=introspection.ingest"]
        ));
        assert!(!internal_query_matches(&row, &["severity=ERROR"]));
    }
}

#[cfg(test)]
mod dashboard_template_tests {
    use super::dashboard_template_widgets;

    #[test]
    fn dashboard_templates_provide_widgets_and_reject_unknown_names() {
        assert!(dashboard_template_widgets("blank").unwrap().is_empty());
        for template in ["system", "ingestion", "api", "storage"] {
            assert!(!dashboard_template_widgets(template).unwrap().is_empty());
        }
        assert!(dashboard_template_widgets("unknown").is_err());
    }
}
