use anyhow::Result;
use cg_ai::AiRouter;
use cg_bus::EventBus;
use cg_core::config::CyberGlassConfig;
use cg_core::telemetry::init_tracing;
use cg_core::traits::EventSink;
use cg_dashboards::DashboardManager;
use cg_detect::{AlertStore, DetectionEngine};
use cg_gateway::create_rest_router;
use cg_gateway::service_registry::RuntimeInfo;
use cg_gateway::{HecTokenStore, ServiceRegistry};
use cg_index::IndexManager;
use cg_ingest::IngestPipeline;
use cg_internal::{
    AuditLogger, HostMetricsCollector, InternalIndexConfig, InternalIndexManager, InternalLogEntry,
    IntrospectionLogger, StorageIndexMetrics,
};
use cg_ontology::KnowledgeGraph;
use cg_query::QueryExecutor;
use cg_rbac::RbacManager;
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;

mod sink;

#[derive(Parser, Debug)]
#[command(name = "cyberglass-server")]
#[command(author = "CyberGlass Engineering")]
#[command(version)]
#[command(about = "Next-Gen cyberglass native SIEM & Data Fusion Platform", long_about = None)]
struct Cli {
    /// Path to configuration file (auto-detected across Linux, macOS, and Windows if omitted)
    #[arg(short, long)]
    config: Option<String>,

    /// Override the root installation/data directory ($CYBERGLASS_HOME)
    #[arg(long)]
    home: Option<String>,

    /// Run in volatile in-memory mode for rapid testing and demonstrations
    #[arg(long)]
    in_memory: bool,

    /// Verify configuration syntax and exit
    #[arg(long)]
    check_config: bool,
}

const BANNER: &str = r#"
   ______      __                 ________                 
  / ____/_  __/ /_  ___  _____   / ____/ /___ ___________  
 / /   / / / / __ \/ _ \/ ___/  / / __/ / __ `/ ___/ ___/  
/ /___/ /_/ / /_/ /  __/ /     / /_/ / / /_/ (__  |__  )   
\____/\__, /_.___/\___/_/      \____/_/\__,_/____/____/    
     /____/                                                
  >> CYBERGLASS SECURITY PLATFORM <<
  >> Rust Engine | Zero-GC | CyberGlass Ontology | High Speed <<
"#;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    println!("{}", BANNER);

    // 1. Load Configuration with multi-OS auto-discovery
    let (mut config, discovered_path) = CyberGlassConfig::discover_and_load(cli.config.as_deref());

    if let Some(path) = discovered_path {
        println!("Loaded configuration from: {}", path.display());
    } else {
        println!("No explicit config file found. Operating with production defaults.");
    }

    // Apply --home override if provided
    if let Some(ref home_dir) = cli.home {
        println!("Base directory overridden to: {}", home_dir);
        config.adapt_to_home(std::path::Path::new(home_dir));
    }

    if cli.check_config {
        println!("Configuration syntax verified successfully. Ready for deployment.");
        return Ok(());
    }

    // 2. Initialize Telemetry
    init_tracing(&config.node.log_level, &config.node.log_format)?;
    tracing::info!(
        "Starting CyberGlass Node: '{}' [Role: {}]",
        config.node.name,
        config.node.role
    );

    // 3. Initialize Core Subsystems
    tracing::info!("[1/8] Initializing High-Speed Event Bus...");
    let bus = if cli.in_memory {
        EventBus::in_memory()
    } else {
        EventBus::connect(&config.bus).await?
    };
    let bus = Arc::new(bus);

    tracing::info!("[2/8] Initializing Tantivy Full-Text & Arrow ColumnStore Index Manager...");
    let index_manager = Arc::new(if cli.in_memory {
        IndexManager::in_memory()?
    } else {
        IndexManager::new(&config.index)?
    });

    let data_dir = std::path::PathBuf::from(&config.node.data_dir);
    std::fs::create_dir_all(&data_dir)?;

    tracing::info!("[3/8] Initializing CyberQL Pipeline & Query Executor...");
    let query_executor = Arc::new(QueryExecutor::new(index_manager.clone()));

    tracing::info!("[4/8] Initializing Knowledge Graph / CyberGlass Ontology Engine...");
    let knowledge_graph = Arc::new(KnowledgeGraph::new());

    tracing::info!("[5/8] Initializing Detection & Correlation Engine...");
    let alert_store = if cli.in_memory {
        Arc::new(AlertStore::new())
    } else {
        Arc::new(AlertStore::open(
            data_dir.join("alerts").join("alerts.journal"),
            100_000,
            1024 * 1024 * 1024,
        )?)
    };
    let detection_engine = Arc::new(DetectionEngine::with_alert_store(
        &config.detection,
        alert_store,
    )?);

    tracing::info!("[6/8] Initializing CyberGlass Local & Federated AI Engine...");
    let ai_router = Arc::new(AiRouter::new());

    tracing::info!("[7/8] Initializing RBAC Authentication & Authorization...");
    let auth_config = cg_rbac::AuthConfig::resolve(&data_dir)?;
    let rbac_config = cg_rbac::RbacConfig {
        auth: auth_config,
        audit_log_path: Some(data_dir.join("audit").join("rbac.jsonl")),
        ..Default::default()
    };
    let rbac = Arc::new(RbacManager::new(rbac_config));
    bootstrap_initial_admin(&rbac, &data_dir)?;

    tracing::info!("[8/8] Initializing Internal Indexing & Dashboards...");
    let internal_index = Arc::new(InternalIndexManager::new(InternalIndexConfig {
        base_dir: data_dir.join("internal_index"),
        ..Default::default()
    })?);
    internal_index.log_entry(InternalLogEntry::new(
        "cyberglass.server",
        "runtime",
        "INFO",
        "Internal logging initialized",
    ))?;
    internal_index.log_entry(InternalLogEntry::new(
        "cyberglass.server",
        "runtime",
        "INFO",
        "Host resource, ingestion, and API activity telemetry enabled (15-second cadence)",
    ))?;
    let introspection_logger = Arc::new(IntrospectionLogger::new(internal_index.clone()));
    let audit_logger = Arc::new(AuditLogger::new(internal_index.clone()));
    let dashboards = Arc::new(DashboardManager::open(
        data_dir.join("custom_dashboards.json"),
    )?);

    let hec_tokens = Arc::new(HecTokenStore::new(Some(data_dir.join("hec_tokens.json")))?);
    if hec_tokens.is_empty() {
        tracing::warn!(
            "No HEC tokens configured. Create one through POST /api/v1/hec/tokens \
             or set CYBERGLASS_HEC_TOKEN before starting the server."
        );
    }

    let sink = Arc::new(sink::PipelineSink::new(
        index_manager.clone(),
        detection_engine.clone(),
        knowledge_graph.clone(),
    ));
    let mut ingest_config = config.ingest.clone();
    if cli.in_memory {
        ingest_config.wal_dir.clear();
    }
    let ingest_pipeline = Arc::new(
        IngestPipeline::new(&ingest_config, bus.as_ref().clone(), Some(sink.clone())).await?,
    );

    // Build unified service registry
    let runtime = RuntimeInfo {
        instance_name: config.node.name.clone(),
        node_role: config.node.role.clone(),
        log_level: config.node.log_level.clone(),
        rest_listen_addr: config.rest.listen_addr.clone(),
        grpc_listen_addr: config.grpc.listen_addr.clone(),
        syslog_tcp_addr: "0.0.0.0:1514".to_string(),
        syslog_udp_addr: "0.0.0.0:1514".to_string(),
        file_monitor_path: "./data/import".to_string(),
        hec_path: "/services/collector".to_string(),
        default_index: config.ingest.default_index.clone(),
        commit_interval_seconds: config.index.commit_interval_seconds,
        hot_retention_days: config.storage.hot.retention_days,
        warm_retention_days: config.storage.warm.retention_days,
        cold_retention_days: config.storage.cold.retention_days,
        frozen_retention_days: config.storage.frozen.retention_days,
        max_eps: config.ingest.max_eps,
        ai_enabled: config.ai.enabled,
    };

    let registry = Arc::new(ServiceRegistry::new(
        ingest_pipeline,
        index_manager.clone(),
        query_executor,
        detection_engine,
        ai_router,
        knowledge_graph,
        bus,
        rbac,
        internal_index,
        audit_logger,
        dashboards,
        hec_tokens,
        data_dir.clone(),
        runtime,
    ));

    let telemetry_logger = introspection_logger.clone();
    let telemetry_registry = registry.clone();
    tokio::spawn(async move {
        let mut host_metrics = match tokio::task::spawn_blocking(HostMetricsCollector::new).await {
            Ok(collector) => collector,
            Err(error) => {
                tracing::error!(error = %error, "Failed to initialize host metrics collector");
                return;
            }
        };
        let period = std::time::Duration::from_secs(15);
        let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
        loop {
            ticker.tick().await;

            let collection = tokio::task::spawn_blocking(move || {
                let metrics = host_metrics.collect();
                (host_metrics, metrics)
            })
            .await;
            let metrics = match collection {
                Ok((collector, metrics)) => {
                    host_metrics = collector;
                    metrics
                }
                Err(error) => {
                    tracing::error!(error = %error, "Host resource metrics collection failed");
                    host_metrics =
                        match tokio::task::spawn_blocking(HostMetricsCollector::new).await {
                            Ok(collector) => collector,
                            Err(error) => {
                                tracing::error!(
                                    error = %error,
                                    "Failed to reinitialize host metrics collector"
                                );
                                return;
                            }
                        };
                    continue;
                }
            };
            if let Err(error) = telemetry_logger.log_resource_metrics(&metrics) {
                tracing::error!(error = %error, "Failed to persist host resource metrics");
            }

            let ingest = telemetry_registry.ingest_pipeline.stats();
            if let Err(error) = telemetry_logger.log_ingest_metrics(
                ingest.accepted,
                ingest.rejected,
                ingest.parse_errors,
                ingest.events_per_second,
                ingest.average_latency_us,
                ingest.queue_depth,
                ingest.queue_capacity,
                ingest.backpressure_events,
                ingest.wal_records,
            ) {
                tracing::error!(error = %error, "Failed to persist ingestion performance metrics");
            }

            let external_indexes = telemetry_registry.index_manager.list_indices();
            match telemetry_registry.internal_index.get_stats() {
                Ok(internal_indexes) => {
                    let storage_indexes: Vec<StorageIndexMetrics> = external_indexes
                        .iter()
                        .map(|index| StorageIndexMetrics {
                            name: index.name.clone(),
                            kind: "external".to_string(),
                            event_count: index.event_count,
                            size_bytes: index.size_bytes,
                        })
                        .chain(internal_indexes.iter().map(|index| StorageIndexMetrics {
                            name: index.name.clone(),
                            kind: "internal".to_string(),
                            event_count: index.doc_count,
                            size_bytes: index.size_bytes,
                        }))
                        .collect();
                    let total_event_count = storage_indexes
                        .iter()
                        .map(|index| index.event_count)
                        .fold(0u64, u64::saturating_add);
                    let total_size_bytes = storage_indexes
                        .iter()
                        .map(|index| index.size_bytes)
                        .fold(0u64, u64::saturating_add);
                    if let Err(error) = telemetry_logger.log_storage_metrics(
                        &storage_indexes,
                        external_indexes.len(),
                        internal_indexes.len(),
                        total_event_count,
                        total_size_bytes,
                    ) {
                        tracing::error!(error = %error, "Failed to persist index storage metrics");
                    }
                }
                Err(error) => {
                    tracing::error!(error = %error, "Failed to collect internal index storage metrics");
                }
            }

            let activity = telemetry_registry.api_activity.take_snapshot();
            if activity.requests > 0 {
                if let Err(error) = telemetry_logger.log_api_activity(
                    activity.requests,
                    activity.failed_requests,
                    activity.ingest_requests,
                    activity.query_requests,
                    activity.average_latency_ms,
                    activity.max_latency_ms,
                    activity.query_average_latency_ms,
                    activity.query_max_latency_ms,
                    15,
                ) {
                    tracing::error!(error = %error, "Failed to persist API activity metrics");
                }
            }
        }
    });

    // Make indexed events searchable within one second without paying a
    // Tantivy commit per event.
    let index_committer = index_manager.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            ticker.tick().await;
            if let Err(error) = index_committer.commit_all() {
                tracing::error!(error = %error, "Index commit failed");
            }
        }
    });

    // 4. Start HTTP & REST Gateway and gRPC Service
    let rest_addr: SocketAddr = config
        .rest
        .listen_addr
        .parse()
        .unwrap_or_else(|_| "127.0.0.1:9401".parse().unwrap());
    let grpc_addr: SocketAddr = config
        .grpc
        .listen_addr
        .parse()
        .unwrap_or_else(|_| "127.0.0.1:9400".parse().unwrap());

    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(2);
    let mut grpc_shutdown_rx = shutdown_tx.subscribe();
    let reg_for_grpc = registry.clone();

    tokio::spawn(async move {
        let shutdown_fut = async move {
            let _ = grpc_shutdown_rx.recv().await;
        };
        if let Err(e) = cg_gateway::start_grpc_server(reg_for_grpc, grpc_addr, shutdown_fut).await {
            tracing::error!("gRPC server error: {}", e);
        }
    });

    let app = create_rest_router(registry.clone(), &config.rest);

    // 5. Start Data Onboarding Listeners (TCP/UDP Syslog + File Monitor)
    let ingest_pipeline_for_receivers = registry.ingest_pipeline.clone();
    let shutdown_for_receivers = shutdown_tx.subscribe();

    // TCP Syslog listener on port 1514
    let tcp_pipeline = ingest_pipeline_for_receivers.clone();
    let tcp_shutdown = shutdown_for_receivers.resubscribe();
    tokio::spawn(async move {
        let receiver = cg_ingest::SyslogReceiver::new(tcp_pipeline);
        if let Err(e) = receiver
            .listen_tcp("0.0.0.0:1514".parse().unwrap(), tcp_shutdown)
            .await
        {
            tracing::error!("TCP Syslog listener error: {}", e);
        }
    });

    // UDP Syslog listener on port 1514
    let udp_pipeline = ingest_pipeline_for_receivers.clone();
    let udp_shutdown = shutdown_for_receivers.resubscribe();
    tokio::spawn(async move {
        let receiver = cg_ingest::SyslogReceiver::new(udp_pipeline);
        if let Err(e) = receiver
            .listen_udp("0.0.0.0:1514".parse().unwrap(), udp_shutdown)
            .await
        {
            tracing::error!("UDP Syslog listener error: {}", e);
        }
    });

    // File Monitor for directory-based data onboarding
    let monitor_pipeline = ingest_pipeline_for_receivers.clone();
    let monitor_shutdown = shutdown_for_receivers.resubscribe();
    tokio::spawn(async move {
        let config = cg_ingest::monitor::MonitorConfig {
            path: std::path::PathBuf::from("./data/import"),
            source: "file_monitor".into(),
            source_type: "json".into(),
            file_extension: "log".into(),
            tail: true,
            poll_interval_ms: 5000,
            index: "main".into(),
        };
        let monitor = cg_ingest::FileMonitor::new(monitor_pipeline, config);
        if let Err(e) = Arc::new(monitor).run(monitor_shutdown).await {
            tracing::error!("File monitor error: {}", e);
        }
    });

    tracing::info!("CyberGlass gRPC Gateway running on {}", grpc_addr);
    tracing::info!(
        "CyberGlass REST & Search Gateway running on http://{}",
        rest_addr
    );
    tracing::info!("Syslog TCP listener on 0.0.0.0:1514");
    tracing::info!("Syslog UDP listener on 0.0.0.0:1514");
    tracing::info!("File monitor watching ./data/import");
    tracing::info!("HEC endpoint available at /services/collector");
    tracing::info!("CyberGlass operation confirmed. Ready for ingestion and threat hunting.");

    let listener = tokio::net::TcpListener::bind(rest_addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            let _ = shutdown_tx.send(());
        })
        .await?;

    sink.flush().await?;
    if let Err(error) = registry.internal_index.log_entry(InternalLogEntry::new(
        "cyberglass.server",
        "runtime",
        "INFO",
        "Server shutdown complete",
    )) {
        tracing::error!(error = %error, "Failed to persist shutdown event");
    }
    if let Err(error) = registry.hec_tokens.flush() {
        tracing::warn!(error = %error, "Failed to persist HEC token usage");
    }
    tracing::info!("CyberGlass shutdown complete. All indexes committed.");
    Ok(())
}

/// Create the first administrator on a fresh installation.
///
/// The password comes from `CYBERGLASS_ADMIN_PASSWORD` when set (minimum 12
/// characters). Otherwise a high-entropy password is generated once and
/// written to `<data_dir>/initial-admin-password` with owner-only permissions.
fn bootstrap_initial_admin(rbac: &RbacManager, data_dir: &std::path::Path) -> Result<()> {
    if rbac.list_users().iter().any(|user| user.is_active) {
        return Ok(());
    }

    let username =
        std::env::var("CYBERGLASS_ADMIN_USERNAME").unwrap_or_else(|_| "admin".to_string());
    let password_path = data_dir.join("initial-admin-password");

    let password = match std::env::var("CYBERGLASS_ADMIN_PASSWORD") {
        Ok(password) => {
            if password.chars().count() < 12 {
                anyhow::bail!("CYBERGLASS_ADMIN_PASSWORD must be at least 12 characters long");
            }
            password
        }
        Err(_) if password_path.exists() => {
            let password = std::fs::read_to_string(&password_path)?;
            let password = password.trim().to_string();
            if password.chars().count() < 12 {
                anyhow::bail!(
                    "{} is too short; delete it to generate a new administrator password",
                    password_path.display()
                );
            }
            password
        }
        Err(_) => {
            let password = format!(
                "cg-{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            );
            std::fs::create_dir_all(data_dir)?;
            std::fs::write(&password_path, &password)?;
            restrict_permissions(&password_path)?;
            tracing::warn!(
                path = %password_path.display(),
                "Generated an initial administrator password. Move it to a secret \
                 manager and delete this file after the first login."
            );
            password
        }
    };

    match rbac.bootstrap_admin(&username, &password)? {
        Some(_) => tracing::warn!(
            username = %username,
            "Initial administrator created. Change the password after first login."
        ),
        None => {}
    }
    Ok(())
}

#[cfg(unix)]
fn restrict_permissions(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    println!("\nReceived shutdown signal. Gracefully stopping services...");
}
