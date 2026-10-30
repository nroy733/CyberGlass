//! # Async Ingestion Pipeline with Backpressure and WAL Durability
//!
//! High-throughput ingestion pipeline that processes raw events through
//! parsing → normalization → enrichment → routing, with:
//! - **Async batch processor** with channel-based backpressure
//! - **Write-ahead log (WAL)** for crash durability
//! - **Per-source rate limiting** and circuit breaker
//! - **Comprehensive metrics** (accepted, rejected, processing latency)

use crate::enricher::EnricherChain;
use crate::error::{IngestError, Result};
use crate::normalizer::Normalizer;
use crate::parser::ParserRegistry;
use crate::router::EventRouter;
use crate::wal::{WalConfig, WriteAheadLog};
use bytes::Bytes;
use cg_bus::EventBus;
use cg_core::config::IngestConfig;
use cg_core::error::Result as CoreResult;
use cg_core::traits::{EventSink, HealthStatus, Service};
use cg_core::types::ParsedEvent;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};
use tracing::{debug, info};

const MAX_BATCH_SIZE: usize = 1_024;
const MAX_QUEUE_CAPACITY: usize = 4_096;
const MAX_TRACKED_SOURCES: usize = 1_024;
const OVERFLOW_SOURCE_KEY: &str = "<cyberglass-overflow-source>";

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Aggregated ingestion statistics exposed via the metrics endpoint.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IngestStats {
    pub accepted: u64,
    pub rejected: u64,
    pub parse_errors: u64,
    pub total_time_us: u128,
    pub events_per_second: f64,
    pub average_latency_us: u64,
    pub queue_depth: usize,
    pub queue_capacity: usize,
    pub backpressure_events: u64,
    pub wal_records: u64,
    pub wal_recovery_required: bool,
}

/// Per-source rate limiter using a token bucket.
struct RateLimiter {
    tokens: AtomicU64,
    last_refill: AtomicU64,
    max_eps: u64,
}

impl RateLimiter {
    fn new(max_eps: u64) -> Self {
        Self {
            tokens: AtomicU64::new(max_eps.max(1)),
            last_refill: AtomicU64::new(now_millis()),
            max_eps,
        }
    }

    fn tracked_source_key<T>(map: &DashMap<String, T>, source: &str) -> String {
        if map.contains_key(source) || map.len() < MAX_TRACKED_SOURCES - 1 {
            source.to_string()
        } else {
            OVERFLOW_SOURCE_KEY.to_string()
        }
    }

    /// Attempts to consume one token. Returns true if allowed.
    fn try_consume(&self) -> bool {
        if self.max_eps == 0 {
            return true; // unlimited
        }
        let now = now_millis();
        let last = self.last_refill.load(Ordering::Relaxed);
        if now > last {
            let elapsed = now.saturating_sub(last);
            let refill = elapsed * self.max_eps / 1000;
            if refill > 0 {
                let _ = self.last_refill.store(now, Ordering::Relaxed);
                let _ = self.tokens.fetch_add(refill, Ordering::Relaxed);
                let mut current = self.tokens.load(Ordering::Relaxed);
                while current > self.max_eps {
                    match self.tokens.compare_exchange(
                        current,
                        self.max_eps,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => break,
                        Err(actual) => current = actual,
                    }
                }
            }
        }
        let current = self.tokens.load(Ordering::Relaxed);
        if current > 0 {
            let _ = self.tokens.fetch_sub(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }
}

/// Circuit breaker state for a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CircuitState {
    Closed = 0,
    Open = 1,
    HalfOpen = 2,
}

struct CircuitBreaker {
    state: AtomicU64,
    failures: AtomicU64,
    last_failure: AtomicU64,
    max_failures: u64,
    reset_timeout_ms: u64,
}

impl CircuitBreaker {
    fn new() -> Self {
        Self {
            state: AtomicU64::new(CircuitState::Closed as u64),
            failures: AtomicU64::new(0),
            last_failure: AtomicU64::new(0),
            max_failures: 10,
            reset_timeout_ms: 30_000,
        }
    }

    fn is_allowed(&self) -> bool {
        let state = match self.state.load(Ordering::Relaxed) {
            0 => CircuitState::Closed,
            1 => CircuitState::Open,
            _ => CircuitState::HalfOpen,
        };
        match state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                let now = now_millis();
                let last = self.last_failure.load(Ordering::Relaxed);
                if now - last > self.reset_timeout_ms {
                    let _ = self.state.compare_exchange(
                        CircuitState::Open as u64,
                        CircuitState::HalfOpen as u64,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    );
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => true,
        }
    }

    fn record_success(&self) {
        let _ = self
            .state
            .store(CircuitState::Closed as u64, Ordering::Relaxed);
        let _ = self.failures.store(0, Ordering::Relaxed);
    }

    fn record_failure(&self) {
        let _ = self.failures.fetch_add(1, Ordering::Relaxed);
        let _ = self.last_failure.store(now_millis(), Ordering::Relaxed);
        let failures = self.failures.load(Ordering::Relaxed);
        if failures >= self.max_failures {
            let _ = self
                .state
                .store(CircuitState::Open as u64, Ordering::Relaxed);
        }
    }
}

/// A pending ingestion request waiting in the channel.
struct IngestRequest {
    raw: Bytes,
    source: String,
    source_type: String,
    index_override: Option<String>,
    replay_event: Option<ParsedEvent>,
    timestamp: Instant,
    respond_tx: mpsc::Sender<Result<ParsedEvent>>,
    _queue_slot: QueueSlot,
}

struct QueueSlot {
    depth: Arc<AtomicUsize>,
}

impl Drop for QueueSlot {
    fn drop(&mut self) {
        self.depth.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Atomic (lock-free) stats accumulator.
#[derive(Debug)]
struct IngestStatsAtomic {
    accepted: AtomicU64,
    rejected: AtomicU64,
    parse_errors: AtomicU64,
    total_time_us: AtomicU64,
    event_count_for_avg: AtomicU64,
    backpressure_events: AtomicU64,
    wal_records: AtomicU64,
    wal_recovery_required: AtomicBool,
    queue_depth: Arc<AtomicUsize>,
    started_at: Instant,
}

impl Default for IngestStatsAtomic {
    fn default() -> Self {
        Self {
            accepted: AtomicU64::default(),
            rejected: AtomicU64::default(),
            parse_errors: AtomicU64::default(),
            total_time_us: AtomicU64::default(),
            event_count_for_avg: AtomicU64::default(),
            backpressure_events: AtomicU64::default(),
            wal_records: AtomicU64::default(),
            wal_recovery_required: AtomicBool::default(),
            queue_depth: Arc::new(AtomicUsize::default()),
            started_at: Instant::now(),
        }
    }
}

impl IngestStatsAtomic {
    fn snapshot(&self, queue_capacity: usize) -> IngestStats {
        let accepted = self.accepted.load(Ordering::Relaxed);
        let rejected = self.rejected.load(Ordering::Relaxed);
        let parse_errors = self.parse_errors.load(Ordering::Relaxed);
        let total_time_us = self.total_time_us.load(Ordering::Relaxed) as u128;
        let count = self.event_count_for_avg.load(Ordering::Relaxed);
        let avg_latency = if count > 0 {
            total_time_us / count as u128
        } else {
            0
        };

        IngestStats {
            accepted,
            rejected,
            parse_errors,
            total_time_us,
            events_per_second: accepted as f64 / self.started_at.elapsed().as_secs_f64().max(0.001),
            average_latency_us: avg_latency as u64,
            queue_depth: self.queue_depth.load(Ordering::Relaxed),
            queue_capacity,
            backpressure_events: self.backpressure_events.load(Ordering::Relaxed),
            wal_records: self.wal_records.load(Ordering::Relaxed),
            wal_recovery_required: self.wal_recovery_required.load(Ordering::Relaxed),
        }
    }
}

/// High-performance async ingestion pipeline.
pub struct IngestPipeline {
    parser_registry: Arc<ParserRegistry>,
    normalizer: Arc<Normalizer>,
    enricher_chain: Arc<EnricherChain>,
    router: Arc<EventRouter>,
    default_index: String,

    // Async processing channel
    tx: mpsc::Sender<IngestRequest>,
    _dispatcher_handle: Option<tokio::task::JoinHandle<()>>,

    // WAL for durability
    wal: Option<Arc<WriteAheadLog>>,

    // Downstream storage/detection/graph fan-out
    sink: Option<Arc<dyn EventSink>>,

    // Stats
    stats: Arc<IngestStatsAtomic>,

    // Per-source rate limiters and circuit breakers
    rate_limiters: Arc<DashMap<String, RateLimiter>>,
    circuit_breakers: Arc<DashMap<String, CircuitBreaker>>,

    // Config
    max_eps: u64,
    queue_capacity: usize,
    max_event_size_bytes: usize,
    batch_size: usize,
    batch_timeout_ms: u64,
}

impl IngestPipeline {
    /// Creates a new pipeline from configuration and spawns the background
    /// dispatcher/worker task.
    pub async fn new(
        config: &IngestConfig,
        bus: EventBus,
        sink: Option<Arc<dyn EventSink>>,
    ) -> Result<Self> {
        let queue_capacity = config.queue_capacity.clamp(1, MAX_QUEUE_CAPACITY);
        let batch_size = config.batch_size.clamp(1, MAX_BATCH_SIZE);
        let batch_timeout_ms = config.batch_timeout_ms.max(1);
        let (tx, mut rx) = mpsc::channel::<IngestRequest>(queue_capacity);

        let wal = if config.wal_dir.is_empty() {
            None
        } else {
            Some(Arc::new(
                WriteAheadLog::open(WalConfig {
                    dir: std::path::PathBuf::from(&config.wal_dir),
                    max_total_size: config.wal_max_size as u64,
                    max_record_size: 2 * 1024 * 1024,
                    sync_on_write: true,
                    ..Default::default()
                })
                .map_err(|error| {
                    IngestError::Wal(format!(
                        "could not open configured WAL at {}: {}",
                        config.wal_dir, error
                    ))
                })?,
            ))
        };

        let pipeline = Self {
            parser_registry: Arc::new(ParserRegistry::new()),
            normalizer: Arc::new(Normalizer::new()),
            enricher_chain: Arc::new(EnricherChain::with_defaults()),
            router: Arc::new(EventRouter::new(bus)),
            default_index: config.default_index.clone(),
            tx,
            _dispatcher_handle: None,
            wal,
            sink,
            stats: Arc::new(IngestStatsAtomic::default()),
            rate_limiters: Arc::new(DashMap::new()),
            circuit_breakers: Arc::new(DashMap::new()),
            max_eps: config.max_eps,
            queue_capacity,
            max_event_size_bytes: config.max_event_size_bytes.max(1),
            batch_size,
            batch_timeout_ms,
        };

        let stats = pipeline.stats.clone();
        let wal_clone = pipeline.wal.clone();
        let rate_limiters = pipeline.rate_limiters.clone();
        let circuit_breakers = pipeline.circuit_breakers.clone();
        let parser_registry = pipeline.parser_registry.clone();
        let normalizer = pipeline.normalizer.clone();
        let enricher_chain = pipeline.enricher_chain.clone();
        let router = pipeline.router.clone();
        let default_index = pipeline.default_index.clone();
        let sink = pipeline.sink.clone();
        let max_eps = pipeline.max_eps;
        let batch_size = pipeline.batch_size;
        let batch_timeout_ms = pipeline.batch_timeout_ms;
        let queue_depth = pipeline.stats.queue_depth.clone();

        let dispatcher_handle = tokio::spawn(async move {
            let mut buffer: VecDeque<IngestRequest> = VecDeque::new();
            let mut wal_recovery_required = false;
            let mut flush_timer = Box::pin(sleep(Duration::from_millis(batch_timeout_ms)));
            loop {
                tokio::select! {
                    req = rx.recv() => {
                        match req {
                            Some(req) => {
                                buffer.push_back(req);
                                if buffer.len() >= batch_size {
                                    let batch: Vec<_> = buffer.drain(..).collect();
                                    let wal_batch_clean = process_batch_internal(
                                        &parser_registry,
                                        &normalizer,
                                        &enricher_chain,
                                        &router,
                                        &wal_clone,
                                        &sink,
                                        &stats,
                                        &rate_limiters,
                                        &circuit_breakers,
                                        &default_index,
                                        max_eps,
                                        &queue_depth,
                                        batch,
                                    )
                                    .await;
                                    acknowledge_wal_batch(
                                        &wal_clone,
                                        &mut wal_recovery_required,
                                        wal_batch_clean,
                                        &stats,
                                    );
                                }
                            }
                            None => {
                                if !buffer.is_empty() {
                                    let wal_batch_clean = process_batch_internal(
                                        &parser_registry,
                                        &normalizer,
                                        &enricher_chain,
                                        &router,
                                        &wal_clone,
                                        &sink,
                                        &stats,
                                        &rate_limiters,
                                        &circuit_breakers,
                                        &default_index,
                                        max_eps,
                                        &queue_depth,
                                        buffer.drain(..).collect(),
                                    )
                                    .await;
                                    acknowledge_wal_batch(
                                        &wal_clone,
                                        &mut wal_recovery_required,
                                        wal_batch_clean,
                                        &stats,
                                    );
                                }
                                break;
                            }
                        }
                    }
                    _ = &mut flush_timer => {
                        flush_timer = Box::pin(sleep(Duration::from_millis(batch_timeout_ms)));
                        if !buffer.is_empty() {
                            let wal_batch_clean = process_batch_internal(
                                &parser_registry,
                                &normalizer,
                                &enricher_chain,
                                &router,
                                &wal_clone,
                                &sink,
                                &stats,
                                &rate_limiters,
                                &circuit_breakers,
                                &default_index,
                                max_eps,
                                &queue_depth,
                                buffer.drain(..).collect(),
                            )
                            .await;
                            acknowledge_wal_batch(
                                &wal_clone,
                                &mut wal_recovery_required,
                                wal_batch_clean,
                                &stats,
                            );
                        }
                    }
                    else => break,
                }
            }
        });

        let pipeline = Self {
            _dispatcher_handle: Some(dispatcher_handle),
            ..pipeline
        };

        if let Some(wal) = &pipeline.wal {
            wal.replay_async(|record| {
                let pipeline = &pipeline;
                async move { pipeline.replay_record(record).await }
            })
            .await
            .map_err(|error| IngestError::Wal(format!("WAL startup replay failed: {error}")))?;
            wal.truncate_all()
                .map_err(|error| IngestError::Wal(format!("WAL cleanup failed: {error}")))?;
        }

        info!(
            "Ingestion pipeline initialized: wal={} max_eps={} queue_capacity={} batch_size={} max_event_bytes={}",
            pipeline.wal.is_some(),
            pipeline.max_eps,
            pipeline.queue_capacity,
            pipeline.batch_size,
            pipeline.max_event_size_bytes
        );

        Ok(pipeline)
    }

    async fn replay_record(
        &self,
        record: crate::wal::WalRecord,
    ) -> std::result::Result<(), crate::wal::WalError> {
        let event: ParsedEvent = serde_json::from_slice(&record.payload)
            .map_err(|error| crate::wal::WalError::Replay(error.to_string()))?;
        if event.source != record.source
            || event.source_type != record.source_type
            || event.index != record.index
        {
            return Err(crate::wal::WalError::Replay(format!(
                "WAL metadata mismatch at sequence {}",
                record.sequence
            )));
        }
        let (respond_tx, mut respond_rx) = mpsc::channel(1);
        self.stats.queue_depth.fetch_add(1, Ordering::Relaxed);
        let request = IngestRequest {
            raw: Bytes::new(),
            source: record.source,
            source_type: record.source_type,
            index_override: Some(record.index),
            replay_event: Some(event),
            timestamp: Instant::now(),
            respond_tx,
            _queue_slot: QueueSlot {
                depth: self.stats.queue_depth.clone(),
            },
        };
        self.tx
            .send(request)
            .await
            .map_err(|error| crate::wal::WalError::Replay(error.to_string()))?;
        respond_rx
            .recv()
            .await
            .ok_or_else(|| {
                crate::wal::WalError::Replay("ingest worker stopped during WAL replay".into())
            })?
            .map(|_| ())
            .map_err(|error| crate::wal::WalError::Replay(error.to_string()))
    }

    /// Process a single raw event through the full pipeline (synchronous API).
    pub async fn process_raw(
        &self,
        raw: Bytes,
        source: &str,
        source_type: &str,
    ) -> Result<ParsedEvent> {
        self.process_raw_indexed(raw, source, source_type, None)
            .await
    }

    /// Same as [`process_raw`], with an optional index override (used by HEC,
    /// whose tokens are scoped to an index).
    pub async fn process_raw_indexed(
        &self,
        raw: Bytes,
        source: &str,
        source_type: &str,
        index_override: Option<&str>,
    ) -> Result<ParsedEvent> {
        let mut response = self
            .submit_async_indexed(raw, source, source_type, index_override)
            .await?;
        response.recv().await.ok_or_else(|| {
            IngestError::Pipeline("ingest worker stopped before responding".into())
        })?
    }

    /// Submit an event for async processing via the channel. Returns a receiver
    /// for the result.
    pub async fn submit_async(
        &self,
        raw: Bytes,
        source: &str,
        source_type: &str,
    ) -> Result<mpsc::Receiver<Result<ParsedEvent>>> {
        self.submit_async_indexed(raw, source, source_type, None)
            .await
    }

    async fn submit_async_indexed(
        &self,
        raw: Bytes,
        source: &str,
        source_type: &str,
        index_override: Option<&str>,
    ) -> Result<mpsc::Receiver<Result<ParsedEvent>>> {
        if source.len() > 256 || source_type.len() > 128 {
            self.stats.rejected.fetch_add(1, Ordering::Relaxed);
            return Err(IngestError::Pipeline(
                "source and source_type exceed their maximum lengths".into(),
            ));
        }
        if raw.len() > self.max_event_size_bytes {
            self.stats.rejected.fetch_add(1, Ordering::Relaxed);
            return Err(IngestError::Pipeline(format!(
                "event exceeds maximum size of {} bytes",
                self.max_event_size_bytes
            )));
        }
        let (respond_tx, respond_rx) = mpsc::channel(1);
        self.stats.queue_depth.fetch_add(1, Ordering::Relaxed);
        let req = IngestRequest {
            raw,
            source: source.to_string(),
            source_type: source_type.to_string(),
            index_override: index_override
                .filter(|index| !index.is_empty())
                .map(str::to_string),
            replay_event: None,
            timestamp: Instant::now(),
            respond_tx,
            _queue_slot: QueueSlot {
                depth: self.stats.queue_depth.clone(),
            },
        };
        match self.tx.try_send(req) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.stats
                    .backpressure_events
                    .fetch_add(1, Ordering::Relaxed);
                self.stats.rejected.fetch_add(1, Ordering::Relaxed);
                return Err(IngestError::BackPressure {
                    queue_depth: self
                        .stats
                        .queue_depth
                        .load(Ordering::Relaxed)
                        .saturating_sub(1),
                });
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.stats.rejected.fetch_add(1, Ordering::Relaxed);
                return Err(IngestError::Pipeline("ingest worker stopped".into()));
            }
        }
        Ok(respond_rx)
    }

    /// Process a batch of raw events sequentially (used by batch API).
    pub async fn process_batch(
        &self,
        batch: Vec<Bytes>,
        source: &str,
        source_type: &str,
    ) -> Result<IngestStats> {
        let start = Instant::now();
        let mut stats = IngestStats::default();

        for raw in batch {
            match self.process_raw(raw.clone(), source, source_type).await {
                Ok(_) => stats.accepted += 1,
                Err(error) => {
                    stats.rejected += 1;
                    if matches!(error, IngestError::Parse { .. }) {
                        stats.parse_errors += 1;
                    }
                }
            }
        }

        stats.total_time_us = start.elapsed().as_micros();
        Ok(stats)
    }

    /// Returns current pipeline statistics.
    pub fn stats(&self) -> IngestStats {
        self.stats
            .snapshot(self.queue_capacity.saturating_add(self.batch_size))
    }

    /// Returns the WAL if enabled.
    pub fn wal(&self) -> Option<&Arc<WriteAheadLog>> {
        self.wal.as_ref()
    }
}

/// Internal batch processing used by the dispatcher worker.
async fn process_batch_internal(
    parser_registry: &Arc<ParserRegistry>,
    normalizer: &Arc<Normalizer>,
    enricher_chain: &Arc<EnricherChain>,
    router: &Arc<EventRouter>,
    wal: &Option<Arc<WriteAheadLog>>,
    sink: &Option<Arc<dyn EventSink>>,
    stats: &Arc<IngestStatsAtomic>,
    rate_limiters: &Arc<DashMap<String, RateLimiter>>,
    circuit_breakers: &Arc<DashMap<String, CircuitBreaker>>,
    default_index: &str,
    max_eps: u64,
    queue_depth: &Arc<AtomicUsize>,
    batch: Vec<IngestRequest>,
) -> bool {
    let mut pending_acks = Vec::new();
    let mut wal_batch_clean = true;
    for req in batch {
        let source = req.source.clone();
        let source_type = req.source_type.clone();

        let is_replay = req.replay_event.is_some();
        if !is_replay {
            let allowed = {
                let source_key = RateLimiter::tracked_source_key(rate_limiters, &source);
                let limiter = rate_limiters
                    .entry(source_key)
                    .or_insert_with(|| RateLimiter::new(max_eps));
                limiter.try_consume()
            };
            if !allowed {
                stats.backpressure_events.fetch_add(1, Ordering::Relaxed);
                stats.rejected.fetch_add(1, Ordering::Relaxed);
                let _ = req
                    .respond_tx
                    .send(Err(IngestError::BackPressure {
                        queue_depth: queue_depth.load(Ordering::Relaxed),
                    }))
                    .await;
                continue;
            }

            let breaker_allowed = {
                let source_key = RateLimiter::tracked_source_key(circuit_breakers, &source);
                let breaker = circuit_breakers
                    .entry(source_key)
                    .or_insert_with(CircuitBreaker::new);
                breaker.is_allowed()
            };
            if !breaker_allowed {
                stats.backpressure_events.fetch_add(1, Ordering::Relaxed);
                stats.rejected.fetch_add(1, Ordering::Relaxed);
                let _ = req
                    .respond_tx
                    .send(Err(IngestError::BackPressure {
                        queue_depth: queue_depth.load(Ordering::Relaxed),
                    }))
                    .await;
                continue;
            }
        }

        let mut has_wal_record = false;
        let event = if let Some(event) = req.replay_event {
            event
        } else {
            let mut event = match parser_registry.parse(&source_type, &req.raw) {
                Ok(event) => event,
                Err(error) => {
                    stats.parse_errors.fetch_add(1, Ordering::Relaxed);
                    stats.rejected.fetch_add(1, Ordering::Relaxed);
                    let _ = req.respond_tx.send(Err(error)).await;
                    continue;
                }
            };

            event.source = source.clone();
            if let Some(index) = req.index_override.as_deref() {
                event.index = index.to_string();
            } else if event.index.is_empty() {
                event.index = default_index.to_string();
            }

            if let Err(error) = normalizer.normalize(&mut event) {
                stats.rejected.fetch_add(1, Ordering::Relaxed);
                let _ = req
                    .respond_tx
                    .send(Err(IngestError::Normalize(error.to_string())))
                    .await;
                continue;
            }
            if let Err(error) = enricher_chain.enrich(&mut event) {
                stats.rejected.fetch_add(1, Ordering::Relaxed);
                let _ = req
                    .respond_tx
                    .send(Err(IngestError::Enrich {
                        enricher: "chain".into(),
                        message: error.to_string(),
                    }))
                    .await;
                continue;
            }

            if let Some(wal) = wal {
                let payload = match serde_json::to_vec(&event) {
                    Ok(payload) => payload,
                    Err(error) => {
                        stats.rejected.fetch_add(1, Ordering::Relaxed);
                        let _ = req
                            .respond_tx
                            .send(Err(IngestError::Wal(error.to_string())))
                            .await;
                        continue;
                    }
                };
                if let Err(error) =
                    wal.append(&event.source, &event.source_type, &event.index, &payload)
                {
                    stats.rejected.fetch_add(1, Ordering::Relaxed);
                    let _ = req
                        .respond_tx
                        .send(Err(IngestError::Wal(error.to_string())))
                        .await;
                    continue;
                }
                has_wal_record = true;
                stats.wal_records.fetch_add(1, Ordering::Relaxed);
            }
            event
        };

        if let Some(sink) = sink {
            if let Err(e) = sink.on_event(&event).await {
                if has_wal_record {
                    wal_batch_clean = false;
                    stats.wal_recovery_required.store(true, Ordering::Relaxed);
                }
                stats.rejected.fetch_add(1, Ordering::Relaxed);
                let breaker = circuit_breakers.get(&source);
                if let Some(b) = breaker {
                    b.record_failure();
                }
                let _ = req
                    .respond_tx
                    .send(Err(IngestError::Pipeline(format!("event sink: {}", e))))
                    .await;
                continue;
            }
        }

        debug!(
            event_id = %event.id,
            source = %source,
            latency_us = req.timestamp.elapsed().as_micros(),
            "Ingest event processed"
        );
        match router.route(&event).await {
            Ok(_) => {
                let cb = circuit_breakers.get(&source);
                if let Some(b) = cb {
                    b.record_success();
                }

                pending_acks.push((
                    req.respond_tx,
                    event,
                    req.timestamp,
                    req._queue_slot,
                    has_wal_record,
                ));
            }
            Err(e) => {
                if has_wal_record {
                    wal_batch_clean = false;
                    stats.wal_recovery_required.store(true, Ordering::Relaxed);
                }
                stats.rejected.fetch_add(1, Ordering::Relaxed);
                let cb = circuit_breakers.get(&source);
                if let Some(b) = cb {
                    b.record_failure();
                }
                let _ = req
                    .respond_tx
                    .send(Err(IngestError::Route(e.to_string())))
                    .await;
            }
        }
    }

    if let Some(sink) = sink {
        if !pending_acks.is_empty() {
            if let Err(error) = sink.flush().await {
                if pending_acks.iter().any(|entry| entry.4) {
                    stats.wal_recovery_required.store(true, Ordering::Relaxed);
                }
                for (respond_tx, _, _, _, _) in pending_acks {
                    stats.rejected.fetch_add(1, Ordering::Relaxed);
                    let _ = respond_tx
                        .send(Err(IngestError::Pipeline(format!(
                            "event sink flush: {}",
                            error
                        ))))
                        .await;
                }
                return false;
            }
        }
    }

    for (respond_tx, event, timestamp, _queue_slot, _) in pending_acks {
        stats.accepted.fetch_add(1, Ordering::Relaxed);
        let elapsed = timestamp.elapsed().as_micros();
        stats
            .total_time_us
            .fetch_add(elapsed as u64, Ordering::Relaxed);
        stats.event_count_for_avg.fetch_add(1, Ordering::Relaxed);
        let _ = respond_tx.send(Ok(event)).await;
    }
    wal_batch_clean
}

fn acknowledge_wal_batch(
    wal: &Option<Arc<WriteAheadLog>>,
    recovery_required: &mut bool,
    batch_clean: bool,
    stats: &IngestStatsAtomic,
) {
    if !batch_clean {
        *recovery_required = true;
        stats.wal_recovery_required.store(true, Ordering::Relaxed);
    }
    if *recovery_required {
        return;
    }
    if let Some(wal) = wal {
        if let Err(error) = wal.truncate_all() {
            *recovery_required = true;
            stats.wal_recovery_required.store(true, Ordering::Relaxed);
            tracing::error!(error = %error, "Failed to checkpoint acknowledged WAL records");
        }
    }
}

#[async_trait::async_trait]
impl Service for IngestPipeline {
    async fn start(&self) -> CoreResult<()> {
        Ok(())
    }

    async fn stop(&self) -> CoreResult<()> {
        Ok(())
    }

    fn health(&self) -> HealthStatus {
        HealthStatus {
            component: "ingest".into(),
            status: if self.wal.is_some()
                && self.sink.is_some()
                && !self.stats.wal_recovery_required.load(Ordering::Relaxed)
            {
                "healthy"
            } else {
                "degraded"
            }
            .into(),
            message: format!(
                "accepted={} rejected={} wal={} sink={} wal_recovery_required={}",
                self.stats.accepted.load(Ordering::Relaxed),
                self.stats.rejected.load(Ordering::Relaxed),
                self.wal.is_some(),
                self.sink.is_some(),
                self.stats.wal_recovery_required.load(Ordering::Relaxed)
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cg_bus::EventBus;
    use cg_core::config::IngestConfig;
    use cg_core::error::Result as CoreResult;
    use cg_core::traits::EventSink;
    use cg_core::types::ParsedEvent;
    use tokio::sync::{Notify, Semaphore};

    async fn make_pipeline() -> IngestPipeline {
        let config = IngestConfig {
            max_eps: 0,
            wal_dir: "".into(),
            ..Default::default()
        };
        IngestPipeline::new(&config, EventBus::in_memory(), None)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_process_raw_json() {
        let p = make_pipeline().await;
        let raw = Bytes::from(r#"{"src_ip": "10.0.0.1", "action": "allow"}"#);
        let event = p.process_raw(raw, "test", "json").await.unwrap();
        assert_eq!(event.fields.get("src_ip").unwrap(), "10.0.0.1");
        assert_eq!(event.source, "test");
        let stats = p.stats();
        assert_eq!(stats.accepted, 1);
        assert_eq!(stats.queue_depth, 0);
        assert_eq!(stats.queue_capacity, 1_280);
        assert!(stats.events_per_second > 0.0);
    }

    #[tokio::test]
    async fn test_process_raw_kv() {
        let p = make_pipeline().await;
        let raw = Bytes::from(b"src=192.168.1.1 dst=8.8.8.8 action=DENY".to_vec());
        let event = p.process_raw(raw, "test", "kv").await.unwrap();
        assert_eq!(event.fields.get("src").unwrap(), "192.168.1.1");
        assert_eq!(event.fields.get("action").unwrap(), "DENY");
    }

    #[tokio::test]
    async fn test_process_batch() {
        let p = make_pipeline().await;
        let batch = vec![
            Bytes::from(r#"{"a": 1}"#),
            Bytes::from(b"x=1 y=2".to_vec()),
            Bytes::from(b"CEF:0|Vendor|Product|1.0|event|test|5|src=1.2.3.4".to_vec()),
        ];
        let stats = p.process_batch(batch, "test", "json").await.unwrap();
        assert!(stats.accepted > 0);
    }

    #[tokio::test]
    async fn test_rate_limiter() {
        let rl = RateLimiter::new(2);
        assert!(rl.try_consume());
        assert!(rl.try_consume());
        assert!(!rl.try_consume());
    }

    #[tokio::test]
    async fn test_circuit_breaker() {
        let cb = CircuitBreaker::new();
        assert!(cb.is_allowed());
        for _ in 0..10 {
            cb.record_failure();
        }
        assert!(!cb.is_allowed());
        cb.record_success();
        assert!(cb.is_allowed());
    }

    struct BlockingSink {
        entered: Notify,
        release: Semaphore,
    }

    #[async_trait::async_trait]
    impl EventSink for BlockingSink {
        async fn on_event(&self, _event: &ParsedEvent) -> CoreResult<()> {
            self.entered.notify_one();
            self.release.acquire().await.unwrap().forget();
            Ok(())
        }

        async fn flush(&self) -> CoreResult<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_bounded_admission_and_live_queue_metrics() {
        let sink = Arc::new(BlockingSink {
            entered: Notify::new(),
            release: Semaphore::new(0),
        });
        let config = IngestConfig {
            max_eps: 0,
            wal_dir: String::new(),
            queue_capacity: 1,
            batch_size: 1,
            batch_timeout_ms: 10,
            ..Default::default()
        };
        let pipeline = Arc::new(
            IngestPipeline::new(&config, EventBus::in_memory(), Some(sink.clone()))
                .await
                .unwrap(),
        );

        let first_pipeline = pipeline.clone();
        let first = tokio::spawn(async move {
            first_pipeline
                .process_raw(Bytes::from(r#"{"action":"allow"}"#), "test", "json")
                .await
        });
        sink.entered.notified().await;

        let queued = pipeline
            .submit_async(Bytes::from(r#"{"action":"queued"}"#), "test", "json")
            .await
            .unwrap();
        let stats = pipeline.stats();
        assert_eq!(stats.queue_depth, 2);
        assert_eq!(stats.queue_capacity, 2);

        let rejected = pipeline
            .submit_async(Bytes::from(r#"{"action":"rejected"}"#), "test", "json")
            .await;
        assert!(matches!(rejected, Err(IngestError::BackPressure { .. })));
        assert_eq!(pipeline.stats().backpressure_events, 1);

        sink.release.add_permits(2);
        first.await.unwrap().unwrap();
        let mut queued = queued;
        queued.recv().await.unwrap().unwrap();
        assert_eq!(pipeline.stats().queue_depth, 0);
    }

    #[tokio::test]
    async fn test_oversized_event_rejected_before_queueing() {
        let config = IngestConfig {
            max_eps: 0,
            wal_dir: String::new(),
            max_event_size_bytes: 8,
            ..Default::default()
        };
        let pipeline = IngestPipeline::new(&config, EventBus::in_memory(), None)
            .await
            .unwrap();
        let result = pipeline
            .process_raw(Bytes::from_static(b"0123456789"), "test", "json")
            .await;
        assert!(matches!(result, Err(IngestError::Pipeline(_))));
        assert_eq!(pipeline.stats().queue_depth, 0);
        assert_eq!(pipeline.stats().rejected, 1);
    }

    struct FailingFlushSink;

    #[async_trait::async_trait]
    impl EventSink for FailingFlushSink {
        async fn on_event(&self, _event: &ParsedEvent) -> CoreResult<()> {
            Ok(())
        }

        async fn flush(&self) -> CoreResult<()> {
            Err(cg_core::error::CyberGlassError::Internal(
                "simulated commit failure".into(),
            ))
        }
    }

    #[tokio::test]
    async fn test_event_is_not_acknowledged_when_sink_commit_fails() {
        let wal_dir = std::env::temp_dir().join(format!(
            "cyberglass_failed_flush_wal_{}",
            uuid::Uuid::new_v4()
        ));
        let config = IngestConfig {
            wal_dir: wal_dir.to_string_lossy().into_owned(),
            wal_max_size: 1024 * 1024,
            batch_size: 1,
            batch_timeout_ms: 10,
            ..Default::default()
        };
        let pipeline = IngestPipeline::new(
            &config,
            EventBus::in_memory(),
            Some(Arc::new(FailingFlushSink)),
        )
        .await
        .unwrap();
        let result = pipeline
            .process_raw(Bytes::from(r#"{"action":"allow"}"#), "test", "json")
            .await;

        assert!(matches!(result, Err(IngestError::Pipeline(_))));
        let stats = pipeline.stats();
        assert_eq!(stats.accepted, 0);
        assert_eq!(stats.rejected, 1);
        assert_eq!(stats.queue_depth, 0);
        assert!(stats.wal_recovery_required);
        assert!(std::fs::read_dir(&wal_dir).unwrap().next().is_some());
        drop(pipeline);
        std::fs::remove_dir_all(wal_dir).unwrap();
    }
}
