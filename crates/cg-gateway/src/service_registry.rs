use cg_ai::AiRouter;
use cg_bus::EventBus;
use cg_core::traits::Service;
use cg_dashboards::DashboardManager;
use cg_detect::DetectionEngine;
use cg_index::IndexManager;
use cg_ingest::IngestPipeline;
use cg_internal::{AuditLogger, InternalIndexManager};
use cg_ontology::KnowledgeGraph;
use cg_query::QueryExecutor;
use cg_rbac::RbacManager;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::hec::HecTokenStore;

/// Immutable runtime facts reported by the settings and introspection APIs.
#[derive(Debug, Clone, Serialize)]
pub struct RuntimeInfo {
    pub instance_name: String,
    pub node_role: String,
    pub log_level: String,
    pub rest_listen_addr: String,
    pub grpc_listen_addr: String,
    pub syslog_tcp_addr: String,
    pub syslog_udp_addr: String,
    pub file_monitor_path: String,
    pub hec_path: String,
    pub default_index: String,
    pub commit_interval_seconds: u64,
    pub hot_retention_days: u64,
    pub warm_retention_days: u64,
    pub cold_retention_days: u64,
    pub frozen_retention_days: u64,
    pub max_eps: u64,
    pub ai_enabled: bool,
}

pub struct ServiceRegistry {
    pub ingest_pipeline: Arc<IngestPipeline>,
    pub index_manager: Arc<IndexManager>,
    pub query_executor: Arc<QueryExecutor>,
    pub detection_engine: Arc<DetectionEngine>,
    pub ai_router: Arc<AiRouter>,
    pub knowledge_graph: Arc<KnowledgeGraph>,
    pub event_bus: Arc<EventBus>,
    pub rbac: Arc<RbacManager>,
    pub internal_index: Arc<InternalIndexManager>,
    pub audit_logger: Arc<AuditLogger>,
    pub dashboards: Arc<DashboardManager>,
    pub hec_tokens: Arc<HecTokenStore>,
    /// Root data directory (JWT secret, HEC tokens, audit log).
    pub data_dir: PathBuf,
    /// Static configuration actually used by this process.
    pub runtime: RuntimeInfo,
    /// Bounded counters used to persist periodic API activity summaries.
    pub api_activity: ApiActivityMetrics,
}

#[derive(Default)]
pub struct ApiActivityMetrics {
    requests: AtomicU64,
    failed_requests: AtomicU64,
    ingest_requests: AtomicU64,
    query_requests: AtomicU64,
    total_latency_us: AtomicU64,
    max_latency_us: AtomicU64,
    query_total_latency_us: AtomicU64,
    query_max_latency_us: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ApiActivitySnapshot {
    pub requests: u64,
    pub failed_requests: u64,
    pub ingest_requests: u64,
    pub query_requests: u64,
    pub average_latency_ms: f64,
    pub max_latency_ms: f64,
    pub query_average_latency_ms: f64,
    pub query_max_latency_ms: f64,
}

impl ApiActivityMetrics {
    pub fn record(&self, path: &str, status: u16, elapsed: Duration) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        if status >= 400 {
            self.failed_requests.fetch_add(1, Ordering::Relaxed);
        }
        if path == "/api/v1/ingest" || path.starts_with("/api/v1/ingest/") {
            self.ingest_requests.fetch_add(1, Ordering::Relaxed);
        } else if path == "/api/v1/query" {
            self.query_requests.fetch_add(1, Ordering::Relaxed);
        }

        let latency_us = elapsed.as_micros().min(u128::from(u64::MAX)) as u64;
        self.total_latency_us
            .fetch_add(latency_us, Ordering::Relaxed);
        self.max_latency_us.fetch_max(latency_us, Ordering::Relaxed);
        if path == "/api/v1/query" {
            self.query_total_latency_us
                .fetch_add(latency_us, Ordering::Relaxed);
            self.query_max_latency_us
                .fetch_max(latency_us, Ordering::Relaxed);
        }
    }

    pub fn take_snapshot(&self) -> ApiActivitySnapshot {
        let requests = self.requests.swap(0, Ordering::Relaxed);
        let failed_requests = self.failed_requests.swap(0, Ordering::Relaxed);
        let ingest_requests = self.ingest_requests.swap(0, Ordering::Relaxed);
        let query_requests = self.query_requests.swap(0, Ordering::Relaxed);
        let total_latency_us = self.total_latency_us.swap(0, Ordering::Relaxed);
        let max_latency_us = self.max_latency_us.swap(0, Ordering::Relaxed);
        let query_total_latency_us = self.query_total_latency_us.swap(0, Ordering::Relaxed);
        let query_max_latency_us = self.query_max_latency_us.swap(0, Ordering::Relaxed);

        ApiActivitySnapshot {
            requests,
            failed_requests,
            ingest_requests,
            query_requests,
            average_latency_ms: if requests == 0 {
                0.0
            } else {
                total_latency_us as f64 / requests as f64 / 1000.0
            },
            max_latency_ms: max_latency_us as f64 / 1000.0,
            query_average_latency_ms: if query_requests == 0 {
                0.0
            } else {
                query_total_latency_us as f64 / query_requests as f64 / 1000.0
            },
            query_max_latency_ms: query_max_latency_us as f64 / 1000.0,
        }
    }
}

impl ServiceRegistry {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ingest_pipeline: Arc<IngestPipeline>,
        index_manager: Arc<IndexManager>,
        query_executor: Arc<QueryExecutor>,
        detection_engine: Arc<DetectionEngine>,
        ai_router: Arc<AiRouter>,
        knowledge_graph: Arc<KnowledgeGraph>,
        event_bus: Arc<EventBus>,
        rbac: Arc<RbacManager>,
        internal_index: Arc<InternalIndexManager>,
        audit_logger: Arc<AuditLogger>,
        dashboards: Arc<DashboardManager>,
        hec_tokens: Arc<HecTokenStore>,
        data_dir: PathBuf,
        runtime: RuntimeInfo,
    ) -> Self {
        Self {
            ingest_pipeline,
            index_manager,
            query_executor,
            detection_engine,
            ai_router,
            knowledge_graph,
            event_bus,
            rbac,
            internal_index,
            audit_logger,
            dashboards,
            hec_tokens,
            data_dir,
            runtime,
            api_activity: ApiActivityMetrics::default(),
        }
    }

    /// Subscribe to the event bus for real-time event streaming.
    pub fn bus_subscribe(&self) -> tokio::sync::broadcast::Receiver<(String, bytes::Bytes)> {
        self.event_bus.subscribe_local()
    }

    /// Get health status of the event bus.
    pub fn bus_health(&self) -> cg_core::traits::HealthStatus {
        self.event_bus.health()
    }
}

#[cfg(test)]
mod tests {
    use super::ApiActivityMetrics;
    use std::time::Duration;

    #[test]
    fn api_activity_snapshots_are_bounded_and_reset_after_read() {
        let metrics = ApiActivityMetrics::default();
        metrics.record("/api/v1/ingest", 202, Duration::from_millis(10));
        metrics.record("/api/v1/query", 500, Duration::from_millis(30));

        let snapshot = metrics.take_snapshot();
        assert_eq!(snapshot.requests, 2);
        assert_eq!(snapshot.failed_requests, 1);
        assert_eq!(snapshot.ingest_requests, 1);
        assert_eq!(snapshot.query_requests, 1);
        assert!((snapshot.average_latency_ms - 20.0).abs() < f64::EPSILON);
        assert!((snapshot.max_latency_ms - 30.0).abs() < f64::EPSILON);
        assert!((snapshot.query_average_latency_ms - 30.0).abs() < f64::EPSILON);
        assert!((snapshot.query_max_latency_ms - 30.0).abs() < f64::EPSILON);
        assert_eq!(metrics.take_snapshot().requests, 0);
    }
}
