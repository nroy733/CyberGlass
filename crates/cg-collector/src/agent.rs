use bytes::Bytes;
use cg_proto::common::{Event, EventBatch};
use cg_proto::ingest::ingest_service_client::IngestServiceClient;
use cg_proto::ingest::IngestBatchRequest;
use std::sync::atomic::AtomicU64;
use tokio::sync::mpsc;
use tonic::transport::Channel;

pub struct CollectorAgent {
    collector_id: String,
    _server_addr: String,
    tx: mpsc::Sender<Event>,
    _seq: AtomicU64,
}

impl CollectorAgent {
    pub fn new(
        collector_id: impl Into<String>,
        server_addr: impl Into<String>,
    ) -> (Self, mpsc::Receiver<Event>) {
        let (tx, rx) = mpsc::channel(50_000);
        let agent = Self {
            collector_id: collector_id.into(),
            _server_addr: server_addr.into(),
            tx,
            _seq: AtomicU64::new(0),
        };
        (agent, rx)
    }

    pub async fn submit_event(
        &self,
        raw: Bytes,
        source: &str,
        source_type: &str,
    ) -> Result<(), String> {
        let now = chrono::Utc::now();
        let ev = Event {
            id: uuid::Uuid::now_v7().to_string(),
            timestamp: Some(prost_types::Timestamp {
                seconds: now.timestamp(),
                nanos: now.timestamp_subsec_nanos() as i32,
            }),
            ingest_time: Some(prost_types::Timestamp {
                seconds: now.timestamp(),
                nanos: now.timestamp_subsec_nanos() as i32,
            }),
            source: source.to_string(),
            source_type: source_type.to_string(),
            index: "main".into(),
            raw: raw.to_vec(),
            fields: std::collections::HashMap::new(),
            metadata: std::collections::HashMap::new(),
            severity: 2, // Info
            tenant_id: "default".into(),
            collector_id: self.collector_id.clone(),
        };

        self.tx.send(ev).await.map_err(|e| e.to_string())
    }

    pub async fn run_sender_loop(
        server_addr: String,
        collector_id: String,
        mut rx: mpsc::Receiver<Event>,
    ) {
        tracing::info!("Connecting to CyberGlass gRPC core at {}", server_addr);
        let channel = match Channel::from_shared(server_addr.clone()) {
            Ok(c) => match c.connect().await {
                Ok(ch) => ch,
                Err(e) => {
                    tracing::error!("Could not connect to core: {}", e);
                    return;
                }
            },
            Err(e) => {
                tracing::error!("Invalid core URI: {}", e);
                return;
            }
        };

        let mut client = IngestServiceClient::new(channel);
        let mut buffer = Vec::new();
        let mut seq = 0i64;

        while let Some(event) = rx.recv().await {
            buffer.push(event);
            if buffer.len() >= 1000 {
                seq += 1;
                let batch = EventBatch {
                    events: std::mem::take(&mut buffer),
                    collector_id: collector_id.clone(),
                    sequence_number: seq,
                    compression: 0,
                };
                let req = tonic::Request::new(IngestBatchRequest {
                    batch: Some(batch),
                    wait_for_ack: false,
                });
                if let Err(e) = client.ingest_batch(req).await {
                    tracing::warn!("Failed to ship batch: {}", e);
                }
            }
        }
    }
}
