use crate::service_registry::ServiceRegistry;
use bytes::Bytes;
use cg_proto::common::{HealthRequest, HealthResponse, ServiceStatus};
use cg_proto::ingest::ingest_service_server::IngestService;
use cg_proto::ingest::{
    IngestBatchRequest, IngestBatchResponse, IngestError, IngestStreamResponse, IngestStreamStatus,
};
use std::pin::Pin;
use std::sync::Arc;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

pub struct IngestServiceImpl {
    registry: Arc<ServiceRegistry>,
}

impl IngestServiceImpl {
    pub fn new(registry: Arc<ServiceRegistry>) -> Self {
        Self { registry }
    }
}

#[tonic::async_trait]
impl IngestService for IngestServiceImpl {
    async fn ingest_batch(
        &self,
        request: Request<IngestBatchRequest>,
    ) -> Result<Response<IngestBatchResponse>, Status> {
        let req = request.into_inner();
        let batch = req.batch.unwrap_or_default();
        let mut accepted = 0;
        let mut rejected = 0;
        let mut errors = Vec::new();

        for event in batch.events {
            let raw_bytes = if event.raw.is_empty() {
                Bytes::from(serde_json::to_vec(&event.fields).unwrap_or_default())
            } else {
                Bytes::from(event.raw)
            };

            let source = if event.source.is_empty() {
                "grpc"
            } else {
                &event.source
            };
            let source_type = if event.source_type.is_empty() {
                "json"
            } else {
                &event.source_type
            };

            match self
                .registry
                .ingest_pipeline
                .process_raw(raw_bytes, source, source_type)
                .await
            {
                Ok(_) => {
                    accepted += 1;
                }
                Err(e) => {
                    rejected += 1;
                    errors.push(IngestError {
                        event_id: event.id,
                        error_code: "PARSE_ERROR".to_string(),
                        message: e.to_string(),
                    });
                }
            }
        }

        Ok(Response::new(IngestBatchResponse {
            accepted,
            rejected,
            errors,
            sequence_number: 1,
        }))
    }

    type IngestStreamStream =
        Pin<Box<dyn Stream<Item = Result<IngestStreamResponse, Status>> + Send + 'static>>;

    async fn ingest_stream(
        &self,
        request: Request<tonic::Streaming<cg_proto::common::EventBatch>>,
    ) -> Result<Response<Self::IngestStreamStream>, Status> {
        let mut stream = request.into_inner();
        let registry = self.registry.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(32);

        tokio::spawn(async move {
            let mut seq = 0;
            while let Ok(Some(batch)) = stream.message().await {
                seq += 1;
                let count = batch.events.len() as i64;
                for event in batch.events {
                    let raw = Bytes::from(event.raw);
                    let _ = registry
                        .ingest_pipeline
                        .process_raw(raw, "stream", "syslog")
                        .await;
                }

                let resp = IngestStreamResponse {
                    sequence_number: seq,
                    events_processed: count,
                    status: IngestStreamStatus::Ok as i32,
                    errors: vec![],
                };
                if tx.send(Ok(resp)).await.is_err() {
                    break;
                }
            }
        });

        let output = tokio_stream::wrappers::ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(output) as Self::IngestStreamStream))
    }

    async fn health(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse {
            status: ServiceStatus::Healthy as i32,
            version: "0.1.0".to_string(),
            node_id: "cyberglass-ingest".to_string(),
            uptime_seconds: 100,
            components: std::collections::HashMap::new(),
        }))
    }
}
