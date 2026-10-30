pub mod handlers;
pub mod mcp;
pub mod xdr;

use crate::auth::auth_middleware;
use crate::service_registry::ServiceRegistry;
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware;
use axum::routing::{delete, get, post, put};
use axum::Router;
use cg_core::config::RestConfig;
use std::sync::Arc;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

/// Build the CORS layer from configuration.
///
/// `cors_enabled = false` denies all cross-origin requests. When enabled with
/// an empty origin list or `"*"`, any origin is allowed. Credentials are never
/// allowed because authentication uses bearer headers, not cookies.
pub fn cors_layer(rest: &RestConfig) -> CorsLayer {
    let layer = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ACCEPT,
            header::HeaderName::from_static("x-api-key"),
        ])
        .max_age(std::time::Duration::from_secs(600));

    if !rest.cors_enabled {
        return layer;
    }

    if rest.cors_origins.iter().any(|origin| origin == "*") {
        return layer.allow_origin(AllowOrigin::any());
    }

    let origins: Vec<HeaderValue> = rest
        .cors_origins
        .iter()
        .filter_map(|origin| origin.parse::<HeaderValue>().ok())
        .collect();
    if origins.is_empty() {
        layer
    } else {
        layer.allow_origin(AllowOrigin::list(origins))
    }
}

pub fn create_rest_router(registry: Arc<ServiceRegistry>, rest: &RestConfig) -> Router {
    let rbac = registry.rbac.clone();

    // Unauthenticated endpoints. Collector routes authenticate with a HEC
    // token inside the handler rather than a user session.
    let public = Router::new()
        .route("/", get(handlers::root_handler))
        .route("/ui", get(handlers::ui_handler))
        .route("/favicon.ico", get(|| async { StatusCode::NO_CONTENT }))
        .route("/docs/commands", get(handlers::commands_doc_handler))
        .route("/api/v1/info", get(handlers::info_handler))
        .route("/api/v1/health", get(handlers::health_handler))
        .route("/api/v1/auth/login", post(handlers::auth_login_handler))
        .route("/api/v1/auth/refresh", post(handlers::auth_refresh_handler))
        .route("/services/collector", post(handlers::hec_handler))
        .route("/services/collector/event", post(handlers::hec_handler))
        .route("/services/collector/health", get(handlers::health_handler));

    // Everything else requires authentication and route-level authorization.
    let protected = Router::new()
        .route("/api/v1/mcp", post(mcp::mcp_jsonrpc_handler))
        .route("/api/v1/mcp/tools", get(mcp::list_mcp_tools_handler))
        .route("/api/v1/mcp/call", post(mcp::call_mcp_tool_handler))
        .route(
            "/api/v1/mitre/techniques",
            get(handlers::list_mitre_techniques_handler),
        )
        .route(
            "/api/v1/soar/playbooks",
            get(handlers::list_soar_playbooks_handler),
        )
        .route(
            "/api/v1/soar/execute",
            post(handlers::execute_soar_playbook_handler),
        )
        .route("/api/v1/stream/tail", get(handlers::stream_tail_handler))
        // XDR & fleet endpoints
        .route(
            "/api/v1/xdr/agents",
            get(xdr::list_agents_handler).post(xdr::register_agent_handler),
        )
        .route(
            "/api/v1/xdr/agents/:id",
            get(xdr::get_agent_handler).delete(xdr::delete_agent_handler),
        )
        .route(
            "/api/v1/xdr/agents/:id/restart",
            post(xdr::restart_agent_handler),
        )
        .route(
            "/api/v1/xdr/agents/:id/upgrade",
            post(xdr::upgrade_agent_handler),
        )
        .route("/api/v1/xdr/groups", get(xdr::list_agent_groups_handler))
        .route(
            "/api/v1/xdr/agent/installer",
            get(xdr::agent_install_script_handler),
        )
        .route("/api/v1/xdr/fim/events", get(xdr::list_fim_events_handler))
        .route("/api/v1/xdr/fim/scan", post(xdr::trigger_fim_scan_handler))
        .route(
            "/api/v1/xdr/sca/policies",
            get(xdr::list_sca_policies_handler),
        )
        .route("/api/v1/xdr/sca/checks", get(xdr::list_sca_checks_handler))
        .route("/api/v1/xdr/sca/scan", post(xdr::trigger_sca_scan_handler))
        .route(
            "/api/v1/xdr/vulnerabilities",
            get(xdr::list_vulnerabilities_handler),
        )
        .route(
            "/api/v1/xdr/vulnerabilities/summary",
            get(xdr::get_vulnerability_summary_handler),
        )
        .route(
            "/api/v1/xdr/syscollector/:agent_id",
            get(xdr::get_syscollector_inventory_handler),
        )
        .route(
            "/api/v1/xdr/active-response/actions",
            get(xdr::list_active_response_actions_handler),
        )
        .route(
            "/api/v1/xdr/active-response/history",
            get(xdr::list_active_response_history_handler),
        )
        .route(
            "/api/v1/xdr/active-response/execute",
            post(xdr::execute_active_response_handler),
        )
        .route(
            "/api/v1/xdr/compliance",
            get(xdr::get_compliance_matrix_handler),
        )
        .route("/api/v1/xdr/decoders", get(xdr::list_decoders_handler))
        .route("/api/v1/xdr/rules", get(xdr::list_rules_catalog_handler))
        .route("/api/v1/auth/logout", post(handlers::auth_logout_handler))
        .route("/api/v1/auth/me", get(handlers::auth_me_handler))
        .route("/api/v1/metrics", get(handlers::metrics_handler))
        .route(
            "/api/v1/indices",
            get(handlers::list_indices_handler).post(handlers::create_index_handler),
        )
        .route(
            "/api/v1/indices/clear",
            post(handlers::clear_indexes_handler),
        )
        .route(
            "/api/v1/indices/:name",
            delete(handlers::delete_index_handler),
        )
        .route(
            "/api/v1/hec/tokens",
            get(handlers::list_hec_tokens_handler).post(handlers::create_hec_token_handler),
        )
        .route(
            "/api/v1/hec/tokens/:id",
            delete(handlers::delete_hec_token_handler),
        )
        .route(
            "/api/v1/monitors",
            get(handlers::list_monitors_handler).post(handlers::create_monitor_handler),
        )
        .route(
            "/api/v1/monitors/:id",
            delete(handlers::delete_monitor_handler),
        )
        .route(
            "/api/v1/listeners",
            get(handlers::list_listeners_handler).post(handlers::create_listener_handler),
        )
        .route(
            "/api/v1/listeners/:id",
            delete(handlers::delete_listener_handler),
        )
        .route("/api/v1/events", get(handlers::list_events_handler))
        .route("/api/v1/ingest", post(handlers::ingest_handler))
        .route("/api/v1/ingest/batch", post(handlers::batch_ingest_handler))
        .route("/api/v1/ingest/upload", post(handlers::upload_file_handler))
        .route("/api/v1/query", post(handlers::query_handler))
        .route("/api/v1/alerts", get(handlers::list_alerts_handler))
        .route(
            "/api/v1/alerts/status",
            post(handlers::update_alert_status_handler),
        )
        .route(
            "/api/v1/rules",
            get(handlers::list_rules_handler).post(handlers::create_rule_handler),
        )
        .route("/api/v1/entities", get(handlers::search_entities_handler))
        .route("/api/v1/graph", get(handlers::graph_data_handler))
        .route(
            "/api/v1/ontology/threat-rank",
            get(handlers::threat_rank_report_handler),
        )
        .route(
            "/api/v1/ontology/threat-rank/simulate",
            post(handlers::simulate_lateral_movement_handler),
        )
        .route(
            "/api/v1/autonomous/contain",
            post(handlers::autonomous_soc_contain_handler),
        )
        .route("/api/v1/ai/chat", post(handlers::ai_chat_handler))
        .route("/api/v1/ws", get(handlers::ws_handler))
        .route("/api/v1/auth/users", get(handlers::list_users_handler))
        .route("/api/v1/auth/users", post(handlers::create_user_handler))
        .route(
            "/api/v1/auth/users/:username",
            get(handlers::get_user_handler),
        )
        .route(
            "/api/v1/auth/users/:username",
            put(handlers::update_user_handler),
        )
        .route(
            "/api/v1/auth/users/:username",
            delete(handlers::delete_user_handler),
        )
        .route("/api/v1/auth/roles", get(handlers::list_roles_handler))
        .route("/api/v1/auth/roles", post(handlers::create_role_handler))
        .route(
            "/api/v1/auth/roles/:name",
            get(handlers::get_role_handler)
                .put(handlers::update_role_handler)
                .delete(handlers::delete_role_handler),
        )
        .route(
            "/api/v1/agent/script",
            get(handlers::agent_script_download_handler),
        )
        .route(
            "/api/v1/internal/logs",
            get(handlers::list_internal_logs_handler),
        )
        .route(
            "/api/v1/auth/api-keys",
            get(handlers::list_api_keys_handler),
        )
        .route(
            "/api/v1/auth/api-keys",
            post(handlers::create_api_key_handler),
        )
        .route(
            "/api/v1/auth/api-keys/:key_id",
            delete(handlers::revoke_api_key_handler),
        )
        .route(
            "/api/v1/dashboards",
            get(handlers::list_dashboards_handler).post(handlers::create_dashboard_handler),
        )
        .route(
            "/api/v1/dashboards/:id",
            get(handlers::get_dashboard_handler).delete(handlers::delete_dashboard_handler),
        )
        .route(
            "/api/v1/dashboards/:id/widgets/:widget_id/data",
            get(handlers::widget_data_handler),
        )
        .route(
            "/api/v1/internal/audit",
            get(handlers::list_audit_logs_handler),
        )
        .route(
            "/api/v1/internal/introspection",
            get(handlers::list_introspection_logs_handler),
        )
        .route(
            "/api/v1/sidebar/widget",
            get(handlers::get_sidebar_widget_handler)
                .put(handlers::update_sidebar_widget_config_handler),
        )
        .route("/api/v1/settings", get(handlers::get_settings_handler))
        .route("/api/v1/settings", put(handlers::update_settings_handler))
        .route(
            "/api/v1/settings/ai-providers",
            get(handlers::list_ai_providers_handler),
        )
        .route(
            "/api/v1/settings/ai-providers",
            post(handlers::add_ai_provider_handler),
        )
        .layer(middleware::from_fn_with_state(rbac, auth_middleware))
        .layer(middleware::from_fn_with_state(
            registry.clone(),
            handlers::api_activity_middleware,
        ));

    Router::new()
        .merge(public)
        .merge(protected)
        .layer(cors_layer(rest))
        .layer(TraceLayer::new_for_http())
        .with_state(registry)
}
