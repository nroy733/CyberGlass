//! Fan-out for fully parsed events: index storage, detection, and graph.
//!
//! Indexing is intentionally part of the ingest acknowledgement: when
//! `on_event` returns `Ok`, the document has been handed to Tantivy. The
//! background commit task makes it searchable within the refresh interval.

use async_trait::async_trait;
use cg_core::error::{CyberGlassError, Result};
use cg_core::traits::EventSink;
use cg_core::types::ParsedEvent;
use cg_detect::{AlertStore, DetectionEngine};
use cg_index::IndexManager;
use cg_ontology::{EntityExtractor, KnowledgeGraph};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

pub struct PipelineSink {
    index_manager: Arc<IndexManager>,
    detection_engine: Arc<DetectionEngine>,
    knowledge_graph: Arc<KnowledgeGraph>,
    extractor: EntityExtractor,
    seen_entities: Mutex<HashSet<String>>,
    events_indexed: AtomicU64,
    alerts_generated: AtomicU64,
    entities_discovered: AtomicU64,
}

impl PipelineSink {
    pub fn new(
        index_manager: Arc<IndexManager>,
        detection_engine: Arc<DetectionEngine>,
        knowledge_graph: Arc<KnowledgeGraph>,
    ) -> Self {
        Self {
            index_manager,
            detection_engine,
            knowledge_graph,
            extractor: EntityExtractor::new(),
            seen_entities: Mutex::new(HashSet::new()),
            events_indexed: AtomicU64::new(0),
            alerts_generated: AtomicU64::new(0),
            entities_discovered: AtomicU64::new(0),
        }
    }

    pub fn events_indexed(&self) -> u64 {
        self.events_indexed.load(Ordering::Relaxed)
    }

    pub fn alerts_generated(&self) -> u64 {
        self.alerts_generated.load(Ordering::Relaxed)
    }

    pub fn entities_discovered(&self) -> u64 {
        self.entities_discovered.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl EventSink for PipelineSink {
    async fn on_event(&self, event: &ParsedEvent) -> Result<()> {
        let handle = self
            .index_manager
            .get_or_create_index(&event.index)
            .map_err(|error| CyberGlassError::Index(error.to_string()))?;
        handle
            .writer
            .add_event(event)
            .map_err(|error| CyberGlassError::Index(error.to_string()))?;
        self.events_indexed.fetch_add(1, Ordering::Relaxed);

        let alerts = self
            .detection_engine
            .evaluate(event)
            .map_err(|error| CyberGlassError::Detection(error.to_string()))?;
        self.alerts_generated
            .fetch_add(alerts.len() as u64, Ordering::Relaxed);

        let extracted = self.extractor.extract(event);
        if !extracted.is_empty() {
            let mut seen = self
                .seen_entities
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            for item in extracted {
                let key = format!("{:?}:{}", item.entity_type, item.value);
                if !seen.insert(key) {
                    continue;
                }
                let mut entity = self.extractor.to_entity(&item);
                entity.properties.insert(
                    "first_event_id".to_string(),
                    serde_json::Value::String(event.id.clone()),
                );
                entity.properties.insert(
                    "source_field".to_string(),
                    serde_json::Value::String(item.source_field.clone()),
                );
                if let Err(error) = self.knowledge_graph.add_entity(entity) {
                    tracing::debug!(error = %error, "Failed to add extracted entity");
                } else {
                    self.entities_discovered.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        self.index_manager
            .commit_all()
            .map_err(|error| CyberGlassError::Index(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cg_bus::EventBus;
    use cg_core::config::{IndexConfig, IngestConfig};
    use cg_ingest::{
        wal::{WalConfig, WriteAheadLog},
        IngestPipeline,
    };
    use cg_query::{Query, QueryExecutor, Source};

    #[tokio::test]
    async fn test_ingest_index_detection_alert_and_index_restart() {
        let index_dir = std::env::temp_dir().join(format!(
            "cyberglass_vertical_slice_{}",
            uuid::Uuid::new_v4()
        ));
        let wal_dir = index_dir.join("wal");
        let alerts_path = index_dir.join("alerts").join("alerts.journal");
        let index_config = IndexConfig {
            index_dir: index_dir.to_string_lossy().into_owned(),
            memory_budget: 50 * 1024 * 1024,
            num_threads: 0,
            commit_interval_seconds: 5,
            columnar_enabled: false,
        };
        let index_manager = Arc::new(IndexManager::new(&index_config).unwrap());
        let alert_store = Arc::new(AlertStore::open(&alerts_path, 100, 1024 * 1024).unwrap());
        let detection_engine = Arc::new(
            DetectionEngine::with_alert_store(
                &cg_core::config::DetectionConfig::default(),
                alert_store,
            )
            .unwrap(),
        );
        let graph = Arc::new(KnowledgeGraph::new());
        let sink = Arc::new(PipelineSink::new(
            index_manager.clone(),
            detection_engine.clone(),
            graph,
        ));
        let ingest_config = IngestConfig {
            wal_dir: wal_dir.to_string_lossy().into_owned(),
            wal_max_size: 16 * 1024 * 1024,
            batch_size: 1,
            batch_timeout_ms: 10,
            ..Default::default()
        };
        let pipeline = IngestPipeline::new(&ingest_config, EventBus::in_memory(), Some(sink))
            .await
            .unwrap();

        let mut ingest_latencies = Vec::new();
        let mut ingested_events = Vec::new();
        for _ in 0..5 {
            let started = std::time::Instant::now();
            let event = pipeline
                .process_raw(
                    bytes::Bytes::from(r#"{"src_ip":"10.0.0.7","action":"failure"}"#),
                    "auth",
                    "json",
                )
                .await
                .unwrap();
            ingested_events.push(event);
            ingest_latencies.push(started.elapsed().as_millis());
        }
        ingest_latencies.sort_unstable();
        let p95 = ingest_latencies[(ingest_latencies.len() * 95).div_ceil(100) - 1];
        assert!(
            p95 < 250,
            "local durable ingest p95 was {p95}ms, target is <250ms"
        );

        let alerts = detection_engine.alert_store().list(10);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].event_ids.len(), 5);

        let query = Query {
            source: Some(Source {
                index_name: "main".into(),
                source_type: None,
            }),
            filters: Vec::new(),
            transforms: Vec::new(),
            limit: Some(10),
            time_range: None,
        };
        let results = QueryExecutor::new(index_manager.clone())
            .execute(&query)
            .await
            .unwrap();
        assert_eq!(results.rows.len(), 5);
        assert_eq!(results.stats.candidate_count, 5);
        assert!(!results.stats.results_truncated);

        drop(pipeline);
        drop(index_manager);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let wal = WriteAheadLog::open(WalConfig {
            dir: wal_dir.clone(),
            max_total_size: ingest_config.wal_max_size as u64,
            ..Default::default()
        })
        .unwrap();
        let replay_event = ingested_events.last().unwrap();
        wal.append(
            &replay_event.source,
            &replay_event.source_type,
            &replay_event.index,
            &serde_json::to_vec(replay_event).unwrap(),
        )
        .unwrap();
        drop(wal);

        let recovered = Arc::new(IndexManager::new(&index_config).unwrap());
        let recovered_alerts = Arc::new(AlertStore::open(&alerts_path, 100, 1024 * 1024).unwrap());
        let recovered_detection = Arc::new(
            DetectionEngine::with_alert_store(
                &cg_core::config::DetectionConfig::default(),
                recovered_alerts.clone(),
            )
            .unwrap(),
        );
        let recovered_sink = Arc::new(PipelineSink::new(
            recovered.clone(),
            recovered_detection.clone(),
            Arc::new(KnowledgeGraph::new()),
        ));
        let recovered_pipeline =
            IngestPipeline::new(&ingest_config, EventBus::in_memory(), Some(recovered_sink))
                .await
                .unwrap();
        let recovered_results = QueryExecutor::new(recovered.clone())
            .execute(&query)
            .await
            .unwrap();
        assert_eq!(recovered_results.rows.len(), 5);
        assert_eq!(recovered_alerts.count(), 1);
        assert_eq!(recovered_alerts.list(10)[0].event_ids.len(), 5);
        assert_eq!(std::fs::read_dir(&wal_dir).unwrap().count(), 0);
        drop(recovered_pipeline);
        drop(recovered);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        std::fs::remove_dir_all(index_dir).unwrap();
    }
}
