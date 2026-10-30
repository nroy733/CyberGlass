use crate::service_registry::ServiceRegistry;
use cg_detect::SigmaConverter;
use cg_proto::common::{HealthRequest, HealthResponse, ServiceStatus};
use cg_proto::detection::detection_service_server::DetectionService;
use cg_proto::detection::{
    Alert, BacktestRequest, BacktestResponse, CreateRuleRequest, DeleteRuleRequest,
    DeleteRuleResponse, GetAlertRequest, GetRuleRequest, ImportSigmaRequest, ImportSigmaResponse,
    ListAlertsRequest, ListAlertsResponse, ListRulesRequest, ListRulesResponse, Rule,
    RuleSeverity as ProtoSeverity, SubscribeAlertsRequest, UpdateAlertStatusRequest,
    UpdateRuleRequest,
};
use std::pin::Pin;
use std::sync::Arc;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

pub struct DetectionServiceImpl {
    registry: Arc<ServiceRegistry>,
}

impl DetectionServiceImpl {
    pub fn new(registry: Arc<ServiceRegistry>) -> Self {
        Self { registry }
    }
}

#[tonic::async_trait]
impl DetectionService for DetectionServiceImpl {
    async fn create_rule(
        &self,
        request: Request<CreateRuleRequest>,
    ) -> Result<Response<Rule>, Status> {
        let req = request.into_inner();
        let rule_data = req
            .rule
            .ok_or_else(|| Status::invalid_argument("Missing rule"))?;

        let rule = cg_detect::DetectionRule::new(
            rule_data.id.clone(),
            rule_data.name.clone(),
            rule_data.query.clone(),
            cg_detect::RuleSeverity::Medium,
        );

        self.registry
            .detection_engine
            .add_rule(rule)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(rule_data))
    }

    async fn update_rule(
        &self,
        request: Request<UpdateRuleRequest>,
    ) -> Result<Response<Rule>, Status> {
        let req = request.into_inner();
        let rule_data = req
            .rule
            .ok_or_else(|| Status::invalid_argument("Missing rule"))?;
        let rule = cg_detect::DetectionRule::new(
            rule_data.id.clone(),
            rule_data.name.clone(),
            rule_data.query.clone(),
            cg_detect::RuleSeverity::Medium,
        );
        self.registry
            .detection_engine
            .add_rule(rule)
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(rule_data))
    }

    async fn delete_rule(
        &self,
        request: Request<DeleteRuleRequest>,
    ) -> Result<Response<DeleteRuleResponse>, Status> {
        let req = request.into_inner();
        let _ = self.registry.detection_engine.remove_rule(&req.id);
        Ok(Response::new(DeleteRuleResponse { deleted: true }))
    }

    async fn get_rule(&self, request: Request<GetRuleRequest>) -> Result<Response<Rule>, Status> {
        let req = request.into_inner();
        let r = self
            .registry
            .detection_engine
            .get_rule(&req.id)
            .ok_or_else(|| Status::not_found("Rule not found"))?;

        Ok(Response::new(Rule {
            id: r.id,
            name: r.name,
            description: r.description,
            query: r.query,
            severity: ProtoSeverity::Medium as i32,
            enabled: r.enabled,
            mitre_techniques: r.mitre_techniques,
            tags: r.tags,
            schedule: None,
            metadata: std::collections::HashMap::new(),
            created_at: None,
            updated_at: None,
            author: r.author,
            rule_type: 0,
            thresholds: vec![],
            correlation: None,
            risk_score: r.risk_score,
        }))
    }

    async fn list_rules(
        &self,
        _request: Request<ListRulesRequest>,
    ) -> Result<Response<ListRulesResponse>, Status> {
        let rules: Vec<Rule> = self
            .registry
            .detection_engine
            .list_rules()
            .into_iter()
            .map(|r| Rule {
                id: r.id,
                name: r.name,
                description: r.description,
                query: r.query,
                severity: ProtoSeverity::Medium as i32,
                enabled: r.enabled,
                mitre_techniques: r.mitre_techniques,
                tags: r.tags,
                schedule: None,
                metadata: std::collections::HashMap::new(),
                created_at: None,
                updated_at: None,
                author: r.author,
                rule_type: 0,
                thresholds: vec![],
                correlation: None,
                risk_score: r.risk_score,
            })
            .collect();

        Ok(Response::new(ListRulesResponse {
            rules,
            pagination: None,
        }))
    }

    async fn import_sigma_rules(
        &self,
        request: Request<ImportSigmaRequest>,
    ) -> Result<Response<ImportSigmaResponse>, Status> {
        let req = request.into_inner();
        let mut imported = 0;
        let mut failed = 0;
        let mut errors = Vec::new();

        for yaml in req.yaml_contents {
            match SigmaConverter::convert(&yaml) {
                Ok(rule) => {
                    let _ = self.registry.detection_engine.add_rule(rule);
                    imported += 1;
                }
                Err(e) => {
                    failed += 1;
                    errors.push(e.to_string());
                }
            }
        }

        Ok(Response::new(ImportSigmaResponse {
            imported,
            failed,
            errors,
        }))
    }

    type BacktestRuleStream =
        Pin<Box<dyn Stream<Item = Result<BacktestResponse, Status>> + Send + 'static>>;

    async fn backtest_rule(
        &self,
        _request: Request<BacktestRequest>,
    ) -> Result<Response<Self::BacktestRuleStream>, Status> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let _ = tx
            .send(Ok(BacktestResponse {
                response: Some(cg_proto::detection::backtest_response::Response::Stats(
                    cg_proto::detection::BacktestStats {
                        events_scanned: 0,
                        alerts_generated: 0,
                        execution_time_ms: 0,
                    },
                )),
            }))
            .await;
        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(stream) as Self::BacktestRuleStream))
    }

    async fn list_alerts(
        &self,
        _request: Request<ListAlertsRequest>,
    ) -> Result<Response<ListAlertsResponse>, Status> {
        let alerts: Vec<Alert> = self
            .registry
            .detection_engine
            .alert_store()
            .list(100)
            .into_iter()
            .map(|a| Alert {
                id: a.id.to_string(),
                rule_id: a.rule_id,
                rule_name: a.rule_name,
                severity: ProtoSeverity::High as i32,
                status: 0,
                description: a.description,
                triggered_at: None,
                event_ids: a.event_ids,
                mitre_techniques: a.mitre_techniques,
                fields: a.fields,
                risk_score: a.risk_score,
                assignee: a.assignee.unwrap_or_default(),
                incident_id: a.incident_id.unwrap_or_default(),
                entity_ids: a.entity_ids,
                comments: vec![],
            })
            .collect();

        Ok(Response::new(ListAlertsResponse {
            alerts,
            pagination: None,
        }))
    }

    async fn get_alert(
        &self,
        request: Request<GetAlertRequest>,
    ) -> Result<Response<Alert>, Status> {
        let req = request.into_inner();
        let alert_uuid = uuid::Uuid::parse_str(&req.id)
            .map_err(|e| Status::invalid_argument(format!("Invalid UUID: {}", e)))?;

        let a = self
            .registry
            .detection_engine
            .alert_store()
            .get(&alert_uuid)
            .ok_or_else(|| Status::not_found("Alert not found"))?;

        Ok(Response::new(Alert {
            id: a.id.to_string(),
            rule_id: a.rule_id,
            rule_name: a.rule_name,
            severity: ProtoSeverity::High as i32,
            status: 0,
            description: a.description,
            triggered_at: None,
            event_ids: a.event_ids,
            mitre_techniques: a.mitre_techniques,
            fields: a.fields,
            risk_score: a.risk_score,
            assignee: a.assignee.unwrap_or_default(),
            incident_id: a.incident_id.unwrap_or_default(),
            entity_ids: a.entity_ids,
            comments: vec![],
        }))
    }

    async fn update_alert_status(
        &self,
        request: Request<UpdateAlertStatusRequest>,
    ) -> Result<Response<Alert>, Status> {
        let req = request.into_inner();
        let alert_uuid = uuid::Uuid::parse_str(&req.id)
            .map_err(|e| Status::invalid_argument(format!("Invalid UUID: {}", e)))?;

        let a = self
            .registry
            .detection_engine
            .alert_store()
            .get(&alert_uuid)
            .ok_or_else(|| Status::not_found("Alert not found"))?;

        Ok(Response::new(Alert {
            id: a.id.to_string(),
            rule_id: a.rule_id,
            rule_name: a.rule_name,
            severity: ProtoSeverity::High as i32,
            status: req.status,
            description: a.description,
            triggered_at: None,
            event_ids: a.event_ids,
            mitre_techniques: a.mitre_techniques,
            fields: a.fields,
            risk_score: a.risk_score,
            assignee: a.assignee.unwrap_or_default(),
            incident_id: a.incident_id.unwrap_or_default(),
            entity_ids: a.entity_ids,
            comments: vec![],
        }))
    }

    type SubscribeAlertsStream =
        Pin<Box<dyn Stream<Item = Result<Alert, Status>> + Send + 'static>>;

    async fn subscribe_alerts(
        &self,
        _request: Request<SubscribeAlertsRequest>,
    ) -> Result<Response<Self::SubscribeAlertsStream>, Status> {
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        Ok(Response::new(
            Box::pin(stream) as Self::SubscribeAlertsStream
        ))
    }

    async fn health(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse {
            status: ServiceStatus::Healthy as i32,
            version: "0.1.0".to_string(),
            node_id: "cyberglass-detection".to_string(),
            uptime_seconds: 100,
            components: std::collections::HashMap::new(),
        }))
    }
}
