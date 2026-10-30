use crate::service_registry::ServiceRegistry;
use cg_proto::ai::ai_service_server::AiService;
use cg_proto::ai::{
    ChatRequest, ChatResponse, GenerateQueryRequest, GenerateQueryResponse, ListModelsRequest,
    ListModelsResponse, ModelInfo as ProtoModelInfo, SuggestHuntsRequest, SuggestHuntsResponse,
    SummarizeIncidentRequest, SummarizeIncidentResponse, TriageAlertRequest, TriageAlertResponse,
};
use cg_proto::common::{HealthRequest, HealthResponse, ServiceStatus};
use std::pin::Pin;
use std::sync::Arc;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

pub struct AiServiceImpl {
    registry: Arc<ServiceRegistry>,
}

impl AiServiceImpl {
    pub fn new(registry: Arc<ServiceRegistry>) -> Self {
        Self { registry }
    }
}

#[tonic::async_trait]
impl AiService for AiServiceImpl {
    type ChatStream = Pin<Box<dyn Stream<Item = Result<ChatResponse, Status>> + Send + 'static>>;

    async fn chat(
        &self,
        request: Request<ChatRequest>,
    ) -> Result<Response<Self::ChatStream>, Status> {
        let req = request.into_inner();
        let prompt = req
            .messages
            .last()
            .map(|m| m.content.clone())
            .unwrap_or_default();

        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let _ = tx
            .send(Ok(ChatResponse {
                response: Some(cg_proto::ai::chat_response::Response::TextDelta(format!(
                    "CyberGlass AI responding to: '{}'",
                    prompt
                ))),
            }))
            .await;

        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(stream) as Self::ChatStream))
    }

    async fn generate_query(
        &self,
        request: Request<GenerateQueryRequest>,
    ) -> Result<Response<GenerateQueryResponse>, Status> {
        let req = request.into_inner();
        let prompt = req.natural_language;
        let generated = "source=\"firewall\" | where action=\"blocked\" | head 100".to_string();

        Ok(Response::new(GenerateQueryResponse {
            query: generated,
            explanation: format!("Generated CyberQL pipeline query for request: '{}'", prompt),
            confidence: 0.95,
            alternatives: vec![],
        }))
    }

    async fn triage_alert(
        &self,
        _request: Request<TriageAlertRequest>,
    ) -> Result<Response<TriageAlertResponse>, Status> {
        Ok(Response::new(TriageAlertResponse {
            summary: "High confidence true positive based on multiple failed authentications."
                .to_string(),
            recommended_action: "Isolate source host and rotate user credentials.".to_string(),
            confidence: 0.9,
            likely_false_positive: false,
            reasoning: "Correlated credential access attempt against multiple target accounts."
                .to_string(),
            suggested_queries: vec![
                "source=\"auth\" action=\"failure\" | stats count by src_ip".to_string()
            ],
            related_mitre_techniques: vec!["T1110".to_string()],
        }))
    }

    async fn summarize_incident(
        &self,
        _request: Request<SummarizeIncidentRequest>,
    ) -> Result<Response<SummarizeIncidentResponse>, Status> {
        Ok(Response::new(SummarizeIncidentResponse {
            summary: "Detected brute force attack originating from external IP.".to_string(),
            timeline_narrative: "An unauthorized entity attempted credential stuffing; detection rules contained the event.".to_string(),
            affected_entities: vec![],
            recommended_actions: "Review perimeter firewall rules and verify MFA enforcement.".to_string(),
            iocs: vec![],
        }))
    }

    async fn suggest_hunts(
        &self,
        _request: Request<SuggestHuntsRequest>,
    ) -> Result<Response<SuggestHuntsResponse>, Status> {
        Ok(Response::new(SuggestHuntsResponse {
            suggestions: vec![],
        }))
    }

    async fn list_models(
        &self,
        _request: Request<ListModelsRequest>,
    ) -> Result<Response<ListModelsResponse>, Status> {
        let models = self.registry.ai_router.list_models().await;
        let proto_models: Vec<ProtoModelInfo> = models
            .into_iter()
            .map(|m| ProtoModelInfo {
                id: m.id.clone(),
                name: m.id.clone(),
                model_type: 0,
                location: 0,
                parameters: m.context_length as i64,
                quantization: "".to_string(),
                available: m.is_local,
            })
            .collect();

        Ok(Response::new(ListModelsResponse {
            models: proto_models,
        }))
    }

    async fn health(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse {
            status: ServiceStatus::Healthy as i32,
            version: "0.1.0".to_string(),
            node_id: "cyberglass-ai".to_string(),
            uptime_seconds: 100,
            components: std::collections::HashMap::new(),
        }))
    }
}
