//! # Introspection Logger
//!
//! Logs internal performance metrics, search concurrency, resource usage
//! to the `cg_introspection` internal index.

use crate::error::Result;
use crate::internal_index::{InternalIndexManager, InternalLogEntry, INTROSPECTION_INDEX};
use std::sync::Arc;
use sysinfo::{Disks, Networks, System};

/// Search concurrency metrics.
#[derive(Debug, Clone)]
pub struct SearchConcurrencyMetrics {
    pub active_searches: u64,
    pub max_concurrent_searches: u64,
    pub queued_searches: u64,
    pub completed_searches: u64,
    pub failed_searches: u64,
    pub avg_search_latency_ms: f64,
}

/// Resource consumption metrics.
#[derive(Debug, Clone)]
pub struct ResourceMetrics {
    pub host_name: String,
    pub os_name: String,
    pub os_version: String,
    pub kernel_version: String,
    pub cpu_model: String,
    pub cpu_cores: usize,
    pub cpu_percent: f64,
    pub memory_percent: f64,
    pub memory_used_bytes: u64,
    pub memory_total_bytes: u64,
    pub swap_used_bytes: u64,
    pub swap_total_bytes: u64,
    pub disk_percent: f64,
    pub disk_used_bytes: u64,
    pub disk_total_bytes: u64,
    pub disk_count: usize,
    pub network_in_bytes: u64,
    pub network_out_bytes: u64,
    pub network_interface_count: usize,
}

/// Collects host-level resource metrics supported by sysinfo on this platform.
pub struct HostMetricsCollector {
    system: System,
    disks: Disks,
    networks: Networks,
}

impl HostMetricsCollector {
    pub fn new() -> Self {
        let mut system = System::new();
        system.refresh_cpu_all();
        system.refresh_memory();
        Self {
            system,
            disks: Disks::new_with_refreshed_list(),
            networks: Networks::new_with_refreshed_list(),
        }
    }

    pub fn collect(&mut self) -> ResourceMetrics {
        self.system.refresh_cpu_usage();
        self.system.refresh_memory();
        self.disks.refresh_list();
        self.disks.refresh();
        self.networks.refresh_list();
        self.networks.refresh();

        let disk_total_bytes = self
            .disks
            .list()
            .iter()
            .map(|disk| disk.total_space())
            .fold(0u64, u64::saturating_add);
        let disk_available_bytes = self
            .disks
            .list()
            .iter()
            .map(|disk| disk.available_space())
            .fold(0u64, u64::saturating_add);
        let memory_total_bytes = self.system.total_memory();
        let memory_used_bytes = self.system.used_memory();
        let swap_total_bytes = self.system.total_swap();
        let swap_used_bytes = self.system.used_swap();

        ResourceMetrics {
            host_name: System::host_name().unwrap_or_default(),
            os_name: System::name().unwrap_or_default(),
            os_version: System::long_os_version().unwrap_or_default(),
            kernel_version: System::kernel_version().unwrap_or_default(),
            cpu_model: self
                .system
                .cpus()
                .first()
                .map(|cpu| cpu.brand().to_string())
                .unwrap_or_default(),
            cpu_cores: self.system.cpus().len(),
            cpu_percent: f64::from(self.system.global_cpu_usage()),
            memory_percent: percentage(memory_used_bytes, memory_total_bytes),
            memory_used_bytes,
            memory_total_bytes,
            swap_used_bytes,
            swap_total_bytes,
            disk_percent: percentage(
                disk_total_bytes.saturating_sub(disk_available_bytes),
                disk_total_bytes,
            ),
            disk_used_bytes: disk_total_bytes.saturating_sub(disk_available_bytes),
            disk_total_bytes,
            disk_count: self.disks.list().len(),
            network_in_bytes: self
                .networks
                .list()
                .values()
                .map(|network| network.received())
                .fold(0u64, u64::saturating_add),
            network_out_bytes: self
                .networks
                .list()
                .values()
                .map(|network| network.transmitted())
                .fold(0u64, u64::saturating_add),
            network_interface_count: self.networks.list().len(),
        }
    }
}

impl Default for HostMetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

fn percentage(used: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        (used as f64 / total as f64 * 100.0).clamp(0.0, 100.0)
    }
}

/// Introspection logger for system metrics.
pub struct IntrospectionLogger {
    index_manager: Arc<InternalIndexManager>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StorageIndexMetrics {
    pub name: String,
    pub kind: String,
    pub event_count: u64,
    pub size_bytes: u64,
}

impl IntrospectionLogger {
    pub fn new(index_manager: Arc<InternalIndexManager>) -> Self {
        Self { index_manager }
    }

    /// Log search concurrency metrics.
    pub fn log_search_metrics(&self, metrics: &SearchConcurrencyMetrics) -> Result<()> {
        let entry = InternalLogEntry::new(
            "introspection.search",
            "metrics",
            "INFO",
            "Search concurrency metrics",
        )
        .with_field("active_searches", &metrics.active_searches.to_string())
        .with_field(
            "max_concurrent_searches",
            &metrics.max_concurrent_searches.to_string(),
        )
        .with_field("queued_searches", &metrics.queued_searches.to_string())
        .with_field(
            "completed_searches",
            &metrics.completed_searches.to_string(),
        )
        .with_field("failed_searches", &metrics.failed_searches.to_string())
        .with_field(
            "avg_search_latency_ms",
            &metrics.avg_search_latency_ms.to_string(),
        );
        self.write(entry)
    }

    /// Log resource consumption metrics.
    pub fn log_resource_metrics(&self, metrics: &ResourceMetrics) -> Result<()> {
        let entry = InternalLogEntry::new(
            "introspection.resources",
            "metrics",
            "INFO",
            "Host hardware and resource metrics",
        )
        .with_field("host_name", &metrics.host_name)
        .with_field("os_name", &metrics.os_name)
        .with_field("os_version", &metrics.os_version)
        .with_field("kernel_version", &metrics.kernel_version)
        .with_field("cpu_model", &metrics.cpu_model)
        .with_field("cpu_cores", &metrics.cpu_cores.to_string())
        .with_field("cpu_percent", &metrics.cpu_percent.to_string())
        .with_field("memory_percent", &metrics.memory_percent.to_string())
        .with_field("memory_used_bytes", &metrics.memory_used_bytes.to_string())
        .with_field(
            "memory_total_bytes",
            &metrics.memory_total_bytes.to_string(),
        )
        .with_field("swap_used_bytes", &metrics.swap_used_bytes.to_string())
        .with_field("swap_total_bytes", &metrics.swap_total_bytes.to_string())
        .with_field("disk_percent", &metrics.disk_percent.to_string())
        .with_field("disk_used_bytes", &metrics.disk_used_bytes.to_string())
        .with_field("disk_total_bytes", &metrics.disk_total_bytes.to_string())
        .with_field("disk_count", &metrics.disk_count.to_string())
        .with_field("network_in_bytes", &metrics.network_in_bytes.to_string())
        .with_field("network_out_bytes", &metrics.network_out_bytes.to_string())
        .with_field(
            "network_interface_count",
            &metrics.network_interface_count.to_string(),
        );
        self.write(entry)
    }

    /// Persist a bounded activity summary for API requests since the previous snapshot.
    pub fn log_api_activity(
        &self,
        requests: u64,
        failed_requests: u64,
        ingest_requests: u64,
        query_requests: u64,
        average_latency_ms: f64,
        max_latency_ms: f64,
        query_average_latency_ms: f64,
        query_max_latency_ms: f64,
        window_seconds: u64,
    ) -> Result<()> {
        let entry = InternalLogEntry::new(
            "introspection.api_activity",
            "activity",
            "INFO",
            "API request activity summary",
        )
        .with_field("requests", &requests.to_string())
        .with_field("failed_requests", &failed_requests.to_string())
        .with_field("ingest_requests", &ingest_requests.to_string())
        .with_field("query_requests", &query_requests.to_string())
        .with_field("average_latency_ms", &average_latency_ms.to_string())
        .with_field("max_latency_ms", &max_latency_ms.to_string())
        .with_field(
            "query_average_latency_ms",
            &query_average_latency_ms.to_string(),
        )
        .with_field("query_max_latency_ms", &query_max_latency_ms.to_string())
        .with_field("window_seconds", &window_seconds.to_string());
        self.write(entry)
    }

    pub fn log_storage_metrics(
        &self,
        indexes: &[StorageIndexMetrics],
        external_index_count: usize,
        internal_index_count: usize,
        total_event_count: u64,
        total_size_bytes: u64,
    ) -> Result<()> {
        let index_summary = serde_json::to_string(indexes)
            .map_err(|error| crate::error::InternalError::Serialization(error.to_string()))?;
        let entry = InternalLogEntry::new(
            "introspection.storage",
            "metrics",
            "INFO",
            "Index storage inventory snapshot",
        )
        .with_field("external_index_count", &external_index_count.to_string())
        .with_field("internal_index_count", &internal_index_count.to_string())
        .with_field("total_event_count", &total_event_count.to_string())
        .with_field("total_size_bytes", &total_size_bytes.to_string())
        .with_field("indexes_json", &index_summary);
        self.write(entry)
    }

    pub fn log_ingest_metrics(
        &self,
        accepted: u64,
        rejected: u64,
        parse_errors: u64,
        events_per_second: f64,
        average_latency_us: u64,
        queue_depth: usize,
        queue_capacity: usize,
        backpressure_events: u64,
        wal_records: u64,
    ) -> Result<()> {
        let level = if rejected > 0 || backpressure_events > 0 {
            "WARN"
        } else {
            "INFO"
        };
        let entry = InternalLogEntry::new(
            "introspection.ingest",
            "metrics",
            level,
            "Ingestion pipeline performance snapshot",
        )
        .with_field("accepted", &accepted.to_string())
        .with_field("rejected", &rejected.to_string())
        .with_field("parse_errors", &parse_errors.to_string())
        .with_field("events_per_second", &events_per_second.to_string())
        .with_field("average_latency_us", &average_latency_us.to_string())
        .with_field("queue_depth", &queue_depth.to_string())
        .with_field("queue_capacity", &queue_capacity.to_string())
        .with_field("backpressure_events", &backpressure_events.to_string())
        .with_field("wal_records", &wal_records.to_string());
        self.write(entry)
    }

    /// Log data onboarding metrics.
    pub fn log_onboarding_metrics(
        &self,
        source: &str,
        events_ingested: u64,
        bytes_ingested: u64,
    ) -> Result<()> {
        let entry = InternalLogEntry::new(
            "introspection.ingest",
            "metrics",
            "INFO",
            "Ingestion onboarding metrics",
        )
        .with_field("source", source)
        .with_field("events_ingested", &events_ingested.to_string())
        .with_field("bytes_ingested", &bytes_ingested.to_string());
        self.write(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::{HostMetricsCollector, IntrospectionLogger, StorageIndexMetrics};
    use crate::internal_index::{InternalIndexConfig, InternalIndexManager};
    use std::sync::Arc;
    use uuid::Uuid;

    #[test]
    fn host_resource_metrics_are_persisted_with_hardware_fields() {
        let dir = std::env::temp_dir().join(format!("cyberglass_host_metrics_{}", Uuid::now_v7()));
        let manager = Arc::new(
            InternalIndexManager::new(InternalIndexConfig {
                base_dir: dir.clone(),
                memory_budget: 64 * 1024 * 1024,
            })
            .unwrap(),
        );
        let logger = IntrospectionLogger::new(manager.clone());
        let metrics = HostMetricsCollector::new().collect();

        logger.log_resource_metrics(&metrics).unwrap();
        let entries = manager.list_logs("cg_introspection", 10).unwrap();
        let entry = entries
            .iter()
            .find(|entry| entry.source == "introspection.resources")
            .unwrap();
        assert_eq!(
            entry.fields["memory_total_bytes"],
            metrics.memory_total_bytes.to_string()
        );
        assert!(entry.fields.contains_key("cpu_cores"));
        assert!(entry.fields.contains_key("disk_total_bytes"));
        assert!(entry.fields.contains_key("network_interface_count"));

        logger
            .log_api_activity(3, 1, 1, 1, 12.5, 25.0, 4.0, 8.0, 15)
            .unwrap();
        logger
            .log_ingest_metrics(10, 1, 1, 2.5, 400, 2, 128, 1, 10)
            .unwrap();
        logger
            .log_storage_metrics(
                &[StorageIndexMetrics {
                    name: "main".into(),
                    kind: "external".into(),
                    event_count: 7,
                    size_bytes: 4096,
                }],
                1,
                4,
                7,
                8192,
            )
            .unwrap();
        let entries = manager.list_logs("cg_introspection", 10).unwrap();
        assert!(entries
            .iter()
            .any(|entry| entry.source == "introspection.api_activity"));
        assert!(entries
            .iter()
            .any(|entry| entry.source == "introspection.ingest"));
        let storage = entries
            .iter()
            .find(|entry| entry.source == "introspection.storage")
            .unwrap();
        let indexes: Vec<serde_json::Value> =
            serde_json::from_str(&storage.fields["indexes_json"]).unwrap();
        assert_eq!(indexes[0]["name"], "main");

        drop(logger);
        drop(manager);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

/// Data health metrics.
#[derive(Debug, Clone)]
pub struct DataHealthMetrics {
    pub index_name: String,
    pub event_count: u64,
    pub last_event_time: Option<chrono::DateTime<chrono::Utc>>,
    pub error_count: u64,
    pub latency_ms: f64,
}

impl IntrospectionLogger {
    pub fn log_data_health(&self, metrics: &DataHealthMetrics) -> Result<()> {
        let mut entry = InternalLogEntry::new(
            "introspection.data_health",
            "metrics",
            "INFO",
            "Data health metrics",
        )
        .with_field("index", &metrics.index_name)
        .with_field("event_count", &metrics.event_count.to_string())
        .with_field("error_count", &metrics.error_count.to_string())
        .with_field("latency_ms", &metrics.latency_ms.to_string());
        if let Some(last_event_time) = metrics.last_event_time.as_ref() {
            entry = entry.with_field("last_event_time", &last_event_time.to_rfc3339());
        }
        self.write(entry)
    }

    fn write(&self, mut entry: InternalLogEntry) -> Result<()> {
        entry.index = INTROSPECTION_INDEX.to_string();
        self.index_manager.log_entry(entry)
    }
}
