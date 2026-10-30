//! # CyberGlass Scripted Input Agent
//!
//! A lightweight, modifiable, and deployable data onboarding agent that collects
//! data from scripts, files, and other sources and forwards it to a CyberGlass
//! server via REST/HEC API.
//!
//! ## Usage
//!
//! ```bash
//! # Run with a config file
//! cg-agent --config /etc/cyberglass/agent.toml
//!
//! # Run a script input inline
//! cg-agent --script "/usr/local/bin/collect_logs.sh" --source my_source --source-type json
//!
//! # Tail a log file
//! cg-agent --tail /var/log/app.log --source app --source-type json
//!
//! # Deploy as a system service (Linux)
//! sudo cp cg-agent /usr/local/bin/
//! sudo cg-agent --install-service
//! ```

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal;
use tracing::info;

mod config;
mod input;
mod sender;

use config::AgentConfig;
use input::InputManager;
use sender::EventSender;

#[derive(Parser, Debug)]
#[command(name = "cg-agent")]
#[command(author = "CyberGlass Engineering")]
#[command(version = "0.1.0")]
#[command(about = "CyberGlass Scripted Input Agent — data onboarding agent", long_about = None)]
struct Cli {
    /// Path to agent configuration file (TOML)
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// CyberGlass server URL (e.g., http://localhost:9401)
    #[arg(long, default_value = "http://localhost:9401")]
    server: String,

    /// HEC token for authentication (optional)
    #[arg(long)]
    hec_token: Option<String>,

    /// Run a script/command and forward its output
    #[arg(long)]
    script: Option<String>,

    /// Source name for script/tail inputs
    #[arg(long, default_value = "script")]
    source: String,

    /// Source type for parsing (json, syslog, cef, kv, etc.)
    #[arg(long, default_value = "json")]
    source_type: String,

    /// Tail a log file (follow new lines)
    #[arg(long)]
    tail: Option<PathBuf>,

    /// Index to write events to
    #[arg(long, default_value = "main")]
    index: String,

    /// Poll interval in milliseconds for tail/watch
    #[arg(long, default_value = "5000")]
    poll_interval_ms: u64,

    /// Install as a system service (Linux systemd)
    #[arg(long)]
    install_service: bool,

    /// Run in foreground (default)
    #[arg(long, default_value = "true")]
    foreground: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(true)
        .init();

    // Load configuration
    let config = if let Some(config_path) = &cli.config {
        AgentConfig::load(config_path).context("Failed to load agent config")?
    } else {
        AgentConfig::from_cli(&cli)
    };

    // Override config with CLI args if provided
    let config = config.merge_cli(&cli);

    if config.install_service {
        return install_system_service().await;
    }

    info!("CyberGlass Agent starting...");
    info!("Server: {}", config.server());
    info!("Inputs: {:?}", config.inputs.len());

    // Create HTTP sender
    let sender = Arc::new(EventSender::new(
        config.server().to_string(),
        config.hec_token.clone(),
        config.timeout_secs,
    )?);

    // Test connectivity
    sender.ping().await?;

    // Create input manager
    let mut input_mgr = InputManager::new(sender.clone(), config.index().to_string());

    // Register inputs from config
    for input_cfg in &config.inputs {
        input_mgr.register_input(input_cfg.clone()).await?;
    }

    // Register inline CLI inputs (from command line)
    if let Some(script) = &cli.script {
        input_mgr
            .register_script(script.clone(), cli.source.clone(), cli.source_type.clone())
            .await?;
    }
    if let Some(tail_path) = &cli.tail {
        input_mgr
            .register_tail(
                tail_path.clone(),
                cli.source.clone(),
                cli.source_type.clone(),
            )
            .await?;
    }

    // Start all inputs
    input_mgr.start_all().await?;

    info!("Agent running. Press Ctrl+C to stop.");

    // Wait for shutdown signal
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        signal(SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Shutting down agent...");
    input_mgr.stop_all().await?;
    info!("Agent stopped.");

    Ok(())
}

/// Install the agent as a systemd service on Linux.
async fn install_system_service() -> Result<()> {
    let exe_path = std::env::current_exe()?;
    let service_content = format!(
        r#"[Unit]
Description=CyberGlass Scripted Input Agent
After=network.target

[Service]
Type=simple
ExecStart={} --foreground
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"#,
        exe_path.display()
    );

    let service_path = "/etc/systemd/system/cyberglass-agent.service";
    std::fs::write(service_path, &service_content)?;
    info!("Service file written to {}", service_path);

    // Reload systemd
    let _ = std::process::Command::new("systemctl")
        .args(["daemon-reload"])
        .output();

    info!("To enable and start: sudo systemctl enable --now cyberglass-agent");
    Ok(())
}
