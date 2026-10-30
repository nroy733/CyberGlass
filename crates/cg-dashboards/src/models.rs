//! # Dashboard Data Models

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// A dashboard with widgets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dashboard {
    pub id: String,
    pub title: String,
    pub description: String,
    pub widgets: Vec<Widget>,
    pub is_builtin: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: Option<String>,
}

impl Dashboard {
    pub fn new(title: String, description: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            title,
            description,
            widgets: Vec::new(),
            is_builtin: false,
            created_at: now,
            updated_at: now,
            created_by: None,
        }
    }

    pub fn add_widget(&mut self, widget: Widget) {
        self.widgets.push(widget);
        self.updated_at = Utc::now();
    }
}

/// A widget within a dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Widget {
    pub id: String,
    pub title: String,
    pub widget_type: WidgetType,
    pub query: Option<String>,
    pub position: WidgetPosition,
    pub size: WidgetSize,
    pub refresh_interval_secs: u64,
    pub config: HashMap<String, serde_json::Value>,
}

/// Types of widgets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WidgetType {
    Stat,
    LineChart,
    BarChart,
    PieChart,
    Table,
    Gauge,
    Heatmap,
    LogStream,
    Map,
}

/// Widget position on the dashboard grid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WidgetPosition {
    pub x: u32,
    pub y: u32,
}

/// Widget size on the dashboard grid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WidgetSize {
    pub width: u32,
    pub height: u32,
}

/// Widget data result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WidgetData {
    pub widget_id: String,
    pub data: serde_json::Value,
    pub updated_at: DateTime<Utc>,
}

/// Pre-built default dashboards.
pub fn default_dashboards() -> Vec<Dashboard> {
    vec![
        Dashboard {
            id: "sys-overview".to_string(),
            title: "System Overview".to_string(),
            description: "System health and performance metrics".to_string(),
            widgets: vec![
                Widget {
                    id: "cpu-usage".to_string(),
                    title: "CPU Usage".to_string(),
                    widget_type: WidgetType::Gauge,
                    query: Some(
                        "index=cg_introspection source=introspection.resources".to_string(),
                    ),
                    position: WidgetPosition { x: 0, y: 0 },
                    size: WidgetSize {
                        width: 4,
                        height: 3,
                    },
                    refresh_interval_secs: 30,
                    config: HashMap::new(),
                },
                Widget {
                    id: "memory-usage".to_string(),
                    title: "Memory Usage".to_string(),
                    widget_type: WidgetType::Gauge,
                    query: Some(
                        "index=cg_introspection source=introspection.resources".to_string(),
                    ),
                    position: WidgetPosition { x: 4, y: 0 },
                    size: WidgetSize {
                        width: 4,
                        height: 3,
                    },
                    refresh_interval_secs: 30,
                    config: HashMap::new(),
                },
                Widget {
                    id: "disk-usage".to_string(),
                    title: "Disk Usage".to_string(),
                    widget_type: WidgetType::Gauge,
                    query: Some(
                        "index=cg_introspection source=introspection.resources".to_string(),
                    ),
                    position: WidgetPosition { x: 8, y: 0 },
                    size: WidgetSize {
                        width: 4,
                        height: 3,
                    },
                    refresh_interval_secs: 30,
                    config: HashMap::new(),
                },
            ],
            is_builtin: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: Some("system".to_string()),
        },
        Dashboard {
            id: "data-onboarding".to_string(),
            title: "Data Onboarding".to_string(),
            description: "Data ingestion rates by source".to_string(),
            widgets: vec![
                Widget {
                    id: "ingest-rate".to_string(),
                    title: "Current Ingestion Rate".to_string(),
                    widget_type: WidgetType::Stat,
                    query: Some("index=cg_introspection source=introspection.ingest".to_string()),
                    position: WidgetPosition { x: 0, y: 0 },
                    size: WidgetSize {
                        width: 6,
                        height: 4,
                    },
                    refresh_interval_secs: 30,
                    config: HashMap::new(),
                },
                Widget {
                    id: "ingest-timeline".to_string(),
                    title: "Ingestion Timeline".to_string(),
                    widget_type: WidgetType::LineChart,
                    query: Some("index=cg_introspection source=introspection.ingest".to_string()),
                    position: WidgetPosition { x: 6, y: 0 },
                    size: WidgetSize {
                        width: 6,
                        height: 4,
                    },
                    refresh_interval_secs: 30,
                    config: HashMap::new(),
                },
                Widget {
                    id: "source-health".to_string(),
                    title: "Pipeline Health".to_string(),
                    widget_type: WidgetType::Table,
                    query: Some("index=cg_introspection source=introspection.ingest".to_string()),
                    position: WidgetPosition { x: 0, y: 4 },
                    size: WidgetSize {
                        width: 12,
                        height: 3,
                    },
                    refresh_interval_secs: 60,
                    config: HashMap::new(),
                },
            ],
            is_builtin: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: Some("system".to_string()),
        },
        Dashboard {
            id: "rest-api-health".to_string(),
            title: "REST API Health".to_string(),
            description: "API throughput, latency, and error rates".to_string(),
            widgets: vec![
                Widget {
                    id: "api-throughput".to_string(),
                    title: "API Requests/sec".to_string(),
                    widget_type: WidgetType::Stat,
                    query: Some(
                        "index=cg_introspection source=introspection.api_activity".to_string(),
                    ),
                    position: WidgetPosition { x: 0, y: 0 },
                    size: WidgetSize {
                        width: 4,
                        height: 3,
                    },
                    refresh_interval_secs: 10,
                    config: HashMap::new(),
                },
                Widget {
                    id: "api-latency".to_string(),
                    title: "API Latency (average / max)".to_string(),
                    widget_type: WidgetType::LineChart,
                    query: Some(
                        "index=cg_introspection source=introspection.api_activity".to_string(),
                    ),
                    position: WidgetPosition { x: 4, y: 0 },
                    size: WidgetSize {
                        width: 4,
                        height: 3,
                    },
                    refresh_interval_secs: 10,
                    config: HashMap::new(),
                },
                Widget {
                    id: "api-errors".to_string(),
                    title: "API Error Rate".to_string(),
                    widget_type: WidgetType::Stat,
                    query: Some(
                        "index=cg_introspection source=introspection.api_activity".to_string(),
                    ),
                    position: WidgetPosition { x: 8, y: 0 },
                    size: WidgetSize {
                        width: 4,
                        height: 3,
                    },
                    refresh_interval_secs: 10,
                    config: HashMap::new(),
                },
            ],
            is_builtin: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: Some("system".to_string()),
        },
        Dashboard {
            id: "search-concurrency".to_string(),
            title: "Query Performance".to_string(),
            description: "Query request volume and latency from measured API activity".to_string(),
            widgets: vec![
                Widget {
                    id: "active-searches".to_string(),
                    title: "Query Requests / sec".to_string(),
                    widget_type: WidgetType::Stat,
                    query: Some(
                        "index=cg_introspection source=introspection.api_activity".to_string(),
                    ),
                    position: WidgetPosition { x: 0, y: 0 },
                    size: WidgetSize {
                        width: 3,
                        height: 2,
                    },
                    refresh_interval_secs: 5,
                    config: HashMap::new(),
                },
                Widget {
                    id: "queue-depth".to_string(),
                    title: "Ingest Queue Depth".to_string(),
                    widget_type: WidgetType::Stat,
                    query: Some("index=cg_introspection source=introspection.ingest".to_string()),
                    position: WidgetPosition { x: 3, y: 0 },
                    size: WidgetSize {
                        width: 3,
                        height: 2,
                    },
                    refresh_interval_secs: 5,
                    config: HashMap::new(),
                },
                Widget {
                    id: "search-latency".to_string(),
                    title: "Query Latency".to_string(),
                    widget_type: WidgetType::LineChart,
                    query: Some(
                        "index=cg_introspection source=introspection.api_activity".to_string(),
                    ),
                    position: WidgetPosition { x: 6, y: 0 },
                    size: WidgetSize {
                        width: 6,
                        height: 4,
                    },
                    refresh_interval_secs: 10,
                    config: HashMap::new(),
                },
            ],
            is_builtin: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: Some("system".to_string()),
        },
        Dashboard {
            id: "storage-health".to_string(),
            title: "Storage Health".to_string(),
            description: "Measured index sizes and inventory".to_string(),
            widgets: vec![
                Widget {
                    id: "index-sizes".to_string(),
                    title: "Index Sizes".to_string(),
                    widget_type: WidgetType::BarChart,
                    query: Some("index=cg_introspection source=introspection.storage".to_string()),
                    position: WidgetPosition { x: 0, y: 0 },
                    size: WidgetSize {
                        width: 6,
                        height: 4,
                    },
                    refresh_interval_secs: 60,
                    config: HashMap::new(),
                },
                Widget {
                    id: "tier-usage".to_string(),
                    title: "External Index Count".to_string(),
                    widget_type: WidgetType::Stat,
                    query: Some("index=cg_introspection source=introspection.storage".to_string()),
                    position: WidgetPosition { x: 6, y: 0 },
                    size: WidgetSize {
                        width: 6,
                        height: 4,
                    },
                    refresh_interval_secs: 60,
                    config: HashMap::new(),
                },
                Widget {
                    id: "retention-status".to_string(),
                    title: "Index Inventory".to_string(),
                    widget_type: WidgetType::Table,
                    query: Some("index=cg_introspection source=introspection.storage".to_string()),
                    position: WidgetPosition { x: 0, y: 4 },
                    size: WidgetSize {
                        width: 12,
                        height: 3,
                    },
                    refresh_interval_secs: 300,
                    config: HashMap::new(),
                },
            ],
            is_builtin: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: Some("system".to_string()),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::default_dashboards;

    #[test]
    fn built_in_dashboard_queries_select_supported_internal_sources() {
        for dashboard in default_dashboards() {
            for widget in dashboard.widgets {
                let query = widget.query.expect("built-in widget query");
                assert!(query.starts_with("index=cg_"), "{query}");
                assert!(query.contains(" source="), "{query}");
                assert!(
                    !query.contains("| stats")
                        && !query.contains("| table")
                        && !query.contains("| sort"),
                    "{query}"
                );
            }
        }
    }
}
