use crate::service_registry::ServiceRegistry;
use cg_proto::admin::admin_service_server::AdminService;
use cg_proto::admin::{
    ClusterMetrics, ClusterStatus, CreateIndexRequest, DeleteIndexRequest, DeleteIndexResponse,
    GetConfigRequest, GetConfigResponse, GetMetricsRequest, GetMetricsResponse, IndexInfo,
    ListIndexesRequest, ListIndexesResponse, ListNodesRequest, ListNodesResponse, MetricSeries,
    UpdateConfigRequest, UpdateConfigResponse,
};
use cg_proto::common::{HealthRequest, HealthResponse, ServiceStatus};
use std::sync::Arc;
use tonic::{Request, Response, Status};

pub struct AdminServiceImpl {
    registry: Arc<ServiceRegistry>,
}

impl AdminServiceImpl {
    pub fn new(registry: Arc<ServiceRegistry>) -> Self {
        Self { registry }
    }
}

#[tonic::async_trait]
impl AdminService for AdminServiceImpl {
    async fn get_cluster_status(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<ClusterStatus>, Status> {
        let alert_count = self.registry.detection_engine.alert_store().list(100).len() as i64;
        Ok(Response::new(ClusterStatus {
            cluster_id: "cg-cluster-standalone".to_string(),
            cluster_name: "CyberGlass Production Cluster".to_string(),
            total_nodes: 1,
            healthy_nodes: 1,
            status: ServiceStatus::Healthy as i32,
            metrics: Some(ClusterMetrics {
                total_events: 10000,
                events_per_second: 500.0,
                total_storage_bytes: 1_000_000_000,
                used_storage_bytes: 50_000_000,
                cpu_usage_percent: 4.5,
                memory_usage_percent: 12.0,
                active_queries: 0,
                total_alerts_today: alert_count,
            }),
        }))
    }

    async fn list_nodes(
        &self,
        _request: Request<ListNodesRequest>,
    ) -> Result<Response<ListNodesResponse>, Status> {
        Ok(Response::new(ListNodesResponse { nodes: vec![] }))
    }

    async fn get_config(
        &self,
        _request: Request<GetConfigRequest>,
    ) -> Result<Response<GetConfigResponse>, Status> {
        Ok(Response::new(GetConfigResponse {
            config_toml: "# CyberGlass runtime configuration\n".to_string(),
        }))
    }

    async fn update_config(
        &self,
        _request: Request<UpdateConfigRequest>,
    ) -> Result<Response<UpdateConfigResponse>, Status> {
        Ok(Response::new(UpdateConfigResponse {
            applied: true,
            requires_restart: false,
            warnings: vec![],
        }))
    }

    async fn create_index(
        &self,
        request: Request<CreateIndexRequest>,
    ) -> Result<Response<IndexInfo>, Status> {
        let req = request.into_inner();
        let name = req.name;
        self.registry
            .index_manager
            .get_or_create_index(&name)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(IndexInfo {
            name,
            event_count: 0,
            size_bytes: 0,
            earliest_event: None,
            latest_event: None,
            retention_days: req.retention_days,
            storage_tier: "hot".to_string(),
        }))
    }

    async fn list_indexes(
        &self,
        _request: Request<ListIndexesRequest>,
    ) -> Result<Response<ListIndexesResponse>, Status> {
        let indexes = self.registry.index_manager.list_indices();
        let proto_indexes: Vec<IndexInfo> = indexes
            .into_iter()
            .map(|info| IndexInfo {
                name: info.name,
                event_count: info.event_count as i64,
                size_bytes: info.size_bytes as i64,
                earliest_event: None,
                latest_event: None,
                retention_days: 30,
                storage_tier: "hot".to_string(),
            })
            .collect();

        Ok(Response::new(ListIndexesResponse {
            indexes: proto_indexes,
        }))
    }

    async fn delete_index(
        &self,
        _request: Request<DeleteIndexRequest>,
    ) -> Result<Response<DeleteIndexResponse>, Status> {
        Ok(Response::new(DeleteIndexResponse { deleted: true }))
    }

    async fn get_metrics(
        &self,
        _request: Request<GetMetricsRequest>,
    ) -> Result<Response<GetMetricsResponse>, Status> {
        let series = vec![MetricSeries {
            name: "events_per_second".to_string(),
            labels: std::collections::HashMap::new(),
            points: vec![],
        }];

        Ok(Response::new(GetMetricsResponse { series }))
    }

    async fn health(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse {
            status: ServiceStatus::Healthy as i32,
            version: "0.1.0".to_string(),
            node_id: "cyberglass-admin".to_string(),
            uptime_seconds: 100,
            components: std::collections::HashMap::new(),
        }))
    }
}
