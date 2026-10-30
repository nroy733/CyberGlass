pub mod admin_service;
pub mod ai_service;
pub mod detection_service;
pub mod ingest_service;
pub mod ontology_service;
pub mod query_service;

pub use admin_service::AdminServiceImpl;
pub use ai_service::AiServiceImpl;
pub use detection_service::DetectionServiceImpl;
pub use ingest_service::IngestServiceImpl;
pub use ontology_service::OntologyServiceImpl;
pub use query_service::QueryServiceImpl;

use crate::service_registry::ServiceRegistry;
use std::net::SocketAddr;
use std::sync::Arc;
use tonic::transport::Server;
use tracing::info;

pub async fn start_grpc_server(
    registry: Arc<ServiceRegistry>,
    addr: SocketAddr,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), tonic::transport::Error> {
    info!("CyberGlass gRPC Gateway listening on {}", addr);

    let ingest_svc = cg_proto::ingest::ingest_service_server::IngestServiceServer::new(
        IngestServiceImpl::new(registry.clone()),
    );
    let query_svc = cg_proto::query::query_service_server::QueryServiceServer::new(
        QueryServiceImpl::new(registry.clone()),
    );
    let detection_svc = cg_proto::detection::detection_service_server::DetectionServiceServer::new(
        DetectionServiceImpl::new(registry.clone()),
    );
    let ontology_svc = cg_proto::ontology::ontology_service_server::OntologyServiceServer::new(
        OntologyServiceImpl::new(registry.clone()),
    );
    let ai_svc =
        cg_proto::ai::ai_service_server::AiServiceServer::new(AiServiceImpl::new(registry.clone()));
    let admin_svc = cg_proto::admin::admin_service_server::AdminServiceServer::new(
        AdminServiceImpl::new(registry.clone()),
    );

    Server::builder()
        .add_service(ingest_svc)
        .add_service(query_svc)
        .add_service(detection_svc)
        .add_service(ontology_svc)
        .add_service(ai_svc)
        .add_service(admin_svc)
        .serve_with_shutdown(addr, shutdown)
        .await
}
