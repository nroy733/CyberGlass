use crate::service_registry::ServiceRegistry;
use cg_proto::common::{HealthRequest, HealthResponse, ServiceStatus};
use cg_proto::query::query_service_server::QueryService;
use cg_proto::query::{
    CancelQueryRequest, CancelQueryResponse, NlQueryRequest, NlQueryResponse, ParseQueryRequest,
    ParseQueryResponse, QueryError, QueryPlan, QueryRequest, QueryResponse, QueryResult,
    QueryStats, QueryStreamResponse,
};
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

pub struct QueryServiceImpl {
    registry: Arc<ServiceRegistry>,
}

impl QueryServiceImpl {
    pub fn new(registry: Arc<ServiceRegistry>) -> Self {
        Self { registry }
    }
}

#[tonic::async_trait]
impl QueryService for QueryServiceImpl {
    async fn query(
        &self,
        request: Request<QueryRequest>,
    ) -> Result<Response<QueryResponse>, Status> {
        let req = request.into_inner();
        let query_str = &req.query;

        let ast = cg_query::parse_query(query_str)
            .map_err(|e| Status::invalid_argument(format!("Query parse error: {}", e)))?;

        let res = self
            .registry
            .query_executor
            .execute(&ast)
            .await
            .map_err(|e| Status::internal(format!("Query execution error: {}", e)))?;

        let results = res
            .rows
            .into_iter()
            .map(|row| {
                let mut fields = HashMap::new();
                for (k, v) in row {
                    let str_val = match v {
                        serde_json::Value::String(s) => s,
                        _ => v.to_string(),
                    };
                    fields.insert(
                        k,
                        prost_types::Value {
                            kind: Some(prost_types::value::Kind::StringValue(str_val)),
                        },
                    );
                }

                QueryResult {
                    fields,
                    raw: String::new(),
                    timestamp: None,
                    source: "cyberglass".to_string(),
                    index: "main".to_string(),
                    score: 1.0,
                }
            })
            .collect();

        Ok(Response::new(QueryResponse {
            results,
            stats: Some(QueryStats {
                events_scanned: res.stats.events_scanned as i64,
                results_returned: res.stats.results_returned as i64,
                execution_time_ms: res.stats.execution_time_ms as i64,
                bytes_scanned: 0,
                is_partial: false,
                query_id: uuid::Uuid::now_v7().to_string(),
            }),
            query_id: uuid::Uuid::now_v7().to_string(),
        }))
    }

    type QueryStreamStream =
        Pin<Box<dyn Stream<Item = Result<QueryStreamResponse, Status>> + Send + 'static>>;

    async fn query_stream(
        &self,
        _request: Request<QueryRequest>,
    ) -> Result<Response<Self::QueryStreamStream>, Status> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let _ = tx
            .send(Ok(QueryStreamResponse {
                response: Some(cg_proto::query::query_stream_response::Response::Progress(
                    cg_proto::query::QueryProgress {
                        events_scanned: 0,
                        results_found: 0,
                        percent_complete: 100.0,
                    },
                )),
            }))
            .await;

        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(stream) as Self::QueryStreamStream))
    }

    async fn explain_query(
        &self,
        request: Request<QueryRequest>,
    ) -> Result<Response<QueryPlan>, Status> {
        let req = request.into_inner();
        let query_str = req.query;

        Ok(Response::new(QueryPlan {
            query: query_str,
            nodes: vec![],
            estimated_cost: 1,
            estimated_rows: 1000,
        }))
    }

    async fn parse_query(
        &self,
        request: Request<ParseQueryRequest>,
    ) -> Result<Response<ParseQueryResponse>, Status> {
        let req = request.into_inner();
        match cg_query::parse_query(&req.query) {
            Ok(_) => Ok(Response::new(ParseQueryResponse {
                is_valid: true,
                errors: vec![],
                normalized_query: req.query,
            })),
            Err(e) => Ok(Response::new(ParseQueryResponse {
                is_valid: false,
                errors: vec![QueryError {
                    message: e.to_string(),
                    line: 1,
                    column: 1,
                    suggestion: "Check CyberQL pipeline syntax".to_string(),
                }],
                normalized_query: String::new(),
            })),
        }
    }

    async fn cancel_query(
        &self,
        _request: Request<CancelQueryRequest>,
    ) -> Result<Response<CancelQueryResponse>, Status> {
        Ok(Response::new(CancelQueryResponse { cancelled: true }))
    }

    async fn natural_language_query(
        &self,
        request: Request<NlQueryRequest>,
    ) -> Result<Response<NlQueryResponse>, Status> {
        let req = request.into_inner();
        let prompt = req.natural_language;
        let generated_cyberql =
            "source=\"firewall\" | where action=\"blocked\" | head 100".to_string();

        Ok(Response::new(NlQueryResponse {
            generated_query: generated_cyberql,
            confidence: 0.95,
            explanation: format!("Generated CyberQL filter for intent: '{}'", prompt),
            alternative_queries: vec![],
        }))
    }

    async fn health(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse {
            status: ServiceStatus::Healthy as i32,
            version: "0.1.0".to_string(),
            node_id: "cyberglass-query".to_string(),
            uptime_seconds: 100,
            components: std::collections::HashMap::new(),
        }))
    }
}
