use crate::service_registry::ServiceRegistry;
use cg_proto::common::{HealthRequest, HealthResponse, ServiceStatus};
use cg_proto::ontology::ontology_service_server::OntologyService;
use cg_proto::ontology::{
    Entity, EntityRisk, GetEntityRequest, GetEntityRiskRequest, GetEntityTimelineRequest,
    GetEntityTimelineResponse, GetRelationshipsRequest, GetRelationshipsResponse,
    MergeEntityRequest, SearchEntitiesRequest, SearchEntitiesResponse, TraverseGraphRequest,
    TraverseGraphResponse,
};
use std::pin::Pin;
use std::sync::Arc;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

pub struct OntologyServiceImpl {
    registry: Arc<ServiceRegistry>,
}

impl OntologyServiceImpl {
    pub fn new(registry: Arc<ServiceRegistry>) -> Self {
        Self { registry }
    }
}

#[tonic::async_trait]
impl OntologyService for OntologyServiceImpl {
    async fn get_entity(
        &self,
        request: Request<GetEntityRequest>,
    ) -> Result<Response<Entity>, Status> {
        let req = request.into_inner();
        let entity_uuid = uuid::Uuid::parse_str(&req.id)
            .map_err(|e| Status::invalid_argument(format!("Invalid UUID: {}", e)))?;

        let ent = self
            .registry
            .knowledge_graph
            .get_entity(&entity_uuid)
            .map_err(|e| Status::not_found(e.to_string()))?;

        Ok(Response::new(Entity {
            id: ent.id.to_string(),
            entity_type: 0,
            display_name: ent.display_name,
            properties: std::collections::HashMap::new(),
            confidence: ent.confidence,
            first_seen: None,
            last_seen: None,
            event_count: ent.event_count as i64,
            tags: ent.tags,
            source_event_ids: vec![],
            risk: None,
        }))
    }

    async fn search_entities(
        &self,
        request: Request<SearchEntitiesRequest>,
    ) -> Result<Response<SearchEntitiesResponse>, Status> {
        let req = request.into_inner();
        let results = self
            .registry
            .knowledge_graph
            .search_entities(&req.query, None);

        let entities: Vec<Entity> = results
            .into_iter()
            .map(|ent| Entity {
                id: ent.id.to_string(),
                entity_type: 0,
                display_name: ent.display_name,
                properties: std::collections::HashMap::new(),
                confidence: ent.confidence,
                first_seen: None,
                last_seen: None,
                event_count: ent.event_count as i64,
                tags: ent.tags,
                source_event_ids: vec![],
                risk: None,
            })
            .collect();

        Ok(Response::new(SearchEntitiesResponse {
            entities,
            pagination: None,
        }))
    }

    async fn merge_entity(
        &self,
        request: Request<MergeEntityRequest>,
    ) -> Result<Response<Entity>, Status> {
        let req = request.into_inner();
        let ent_proto = req
            .entity
            .ok_or_else(|| Status::invalid_argument("Missing entity"))?;
        let entity_uuid = uuid::Uuid::parse_str(&ent_proto.id)
            .map_err(|e| Status::invalid_argument(format!("Invalid UUID: {}", e)))?;

        let ent = self
            .registry
            .knowledge_graph
            .get_entity(&entity_uuid)
            .map_err(|e| Status::not_found(e.to_string()))?;

        Ok(Response::new(Entity {
            id: ent.id.to_string(),
            entity_type: 0,
            display_name: ent.display_name,
            properties: std::collections::HashMap::new(),
            confidence: ent.confidence,
            first_seen: None,
            last_seen: None,
            event_count: ent.event_count as i64,
            tags: ent.tags,
            source_event_ids: vec![],
            risk: None,
        }))
    }

    async fn get_relationships(
        &self,
        _request: Request<GetRelationshipsRequest>,
    ) -> Result<Response<GetRelationshipsResponse>, Status> {
        Ok(Response::new(GetRelationshipsResponse {
            relationships: vec![],
        }))
    }

    type TraverseGraphStream =
        Pin<Box<dyn Stream<Item = Result<TraverseGraphResponse, Status>> + Send + 'static>>;

    async fn traverse_graph(
        &self,
        _request: Request<TraverseGraphRequest>,
    ) -> Result<Response<Self::TraverseGraphStream>, Status> {
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(stream) as Self::TraverseGraphStream))
    }

    async fn get_entity_timeline(
        &self,
        _request: Request<GetEntityTimelineRequest>,
    ) -> Result<Response<GetEntityTimelineResponse>, Status> {
        Ok(Response::new(GetEntityTimelineResponse { entries: vec![] }))
    }

    async fn get_entity_risk(
        &self,
        request: Request<GetEntityRiskRequest>,
    ) -> Result<Response<EntityRisk>, Status> {
        let req = request.into_inner();
        let entity_uuid = uuid::Uuid::parse_str(&req.entity_id)
            .map_err(|e| Status::invalid_argument(format!("Invalid UUID: {}", e)))?;

        let ent = self
            .registry
            .knowledge_graph
            .get_entity(&entity_uuid)
            .map_err(|e| Status::not_found(e.to_string()))?;

        Ok(Response::new(EntityRisk {
            score: ent.risk_score,
            level: 0,
            contributors: vec![],
            calculated_at: None,
        }))
    }

    async fn health(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse {
            status: ServiceStatus::Healthy as i32,
            version: "0.1.0".to_string(),
            node_id: "cyberglass-ontology".to_string(),
            uptime_seconds: 100,
            components: std::collections::HashMap::new(),
        }))
    }
}
