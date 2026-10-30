//! # Input Sources
//!
//! Defines configurable input sources: scripts, file tails, and directory monitors.

use crate::sender::EventSender;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};

/// Type of input source.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum InputType {
    /// Execute a script/command and forward stdout lines as events.
    Script,
    /// Tail a file for new lines.
    Tail,
    /// Watch a directory for new files.
    Directory,
}

/// Configuration for a single input source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputConfig {
    #[serde(rename = "type")]
    pub input_type: InputType,
    /// Command to execute (for Script) or path (for Tail/Directory).
    pub command: String,
    /// Source name to tag events with.
    #[serde(default = "default_source")]
    pub source: String,
    /// Source type for parsing.
    #[serde(default = "default_source_type")]
    pub source_type: String,
    /// Index to write to.
    #[serde(default = "default_index")]
    pub index: String,
    /// Interval between script executions (ms). Only for Script type.
    #[serde(default = "default_interval_ms")]
    pub interval_ms: u64,
}

fn default_source() -> String {
    "agent".into()
}
fn default_source_type() -> String {
    "json".into()
}
fn default_index() -> String {
    "main".into()
}
fn default_interval_ms() -> u64 {
    60000
}

impl Default for InputConfig {
    fn default() -> Self {
        Self {
            input_type: InputType::Script,
            command: String::new(),
            source: default_source(),
            source_type: default_source_type(),
            index: default_index(),
            interval_ms: default_interval_ms(),
        }
    }
}

/// Manages all input sources and runs them concurrently.
pub struct InputManager {
    sender: Arc<EventSender>,
    default_index: String,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl InputManager {
    pub fn new(sender: Arc<EventSender>, default_index: String) -> Self {
        Self {
            sender,
            default_index,
            handles: Vec::new(),
        }
    }

    /// Register an input from configuration.
    pub async fn register_input(&mut self, cfg: InputConfig) -> Result<()> {
        match cfg.input_type {
            InputType::Script => {
                self.register_script(cfg.command, cfg.source, cfg.source_type)
                    .await?;
            }
            InputType::Tail => {
                self.register_tail(PathBuf::from(&cfg.command), cfg.source, cfg.source_type)
                    .await?;
            }
            InputType::Directory => {
                self.register_directory(PathBuf::from(&cfg.command), cfg.source, cfg.source_type)
                    .await?;
            }
        }
        Ok(())
    }

    /// Register a script input that runs periodically.
    pub async fn register_script(
        &mut self,
        command: String,
        source: String,
        source_type: String,
    ) -> Result<()> {
        let sender = self.sender.clone();
        let index = self.default_index.clone();
        let interval_ms = 60000;

        let handle = tokio::spawn(async move {
            info!(
                "Starting script input: {} (interval={}ms)",
                command, interval_ms
            );
            loop {
                if let Err(e) =
                    run_script_once(&sender, &command, &source, &source_type, &index).await
                {
                    error!("Script input error: {}", e);
                }
                sleep(Duration::from_millis(interval_ms)).await;
            }
        });
        self.handles.push(handle);
        Ok(())
    }

    /// Register a file tail input.
    pub async fn register_tail(
        &mut self,
        path: PathBuf,
        source: String,
        source_type: String,
    ) -> Result<()> {
        let sender = self.sender.clone();
        let index = self.default_index.clone();

        let handle = tokio::spawn(async move {
            info!("Starting file tail: {}", path.display());
            if let Err(e) = tail_file(&sender, &path, &source, &source_type, &index).await {
                error!("Tail input error for {}: {}", path.display(), e);
            }
        });
        self.handles.push(handle);
        Ok(())
    }

    /// Register a directory monitor input.
    pub async fn register_directory(
        &mut self,
        path: PathBuf,
        source: String,
        source_type: String,
    ) -> Result<()> {
        let sender = self.sender.clone();
        let index = self.default_index.clone();

        let handle = tokio::spawn(async move {
            info!("Starting directory monitor: {}", path.display());
            if let Err(e) = monitor_directory(&sender, &path, &source, &source_type, &index).await {
                error!("Directory monitor error for {}: {}", path.display(), e);
            }
        });
        self.handles.push(handle);
        Ok(())
    }

    /// Start all registered inputs (they are already spawned as tasks).
    pub async fn start_all(&mut self) -> Result<()> {
        info!("Starting {} input sources", self.handles.len());
        Ok(())
    }

    /// Stop all inputs.
    pub async fn stop_all(&mut self) -> Result<()> {
        for handle in self.handles.drain(..) {
            handle.abort();
        }
        Ok(())
    }
}

/// Run a script once and send each stdout line as an event.
async fn run_script_once(
    sender: &EventSender,
    command: &str,
    source: &str,
    source_type: &str,
    index: &str,
) -> Result<()> {
    let output = match tokio::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .output()
        .await
    {
        Ok(o) => o,
        Err(_e) => {
            // Try directly on Windows
            tokio::process::Command::new(command)
                .output()
                .await
                .context("Failed to execute script command")?
        }
    };

    if !output.status.success() {
        warn!(
            "Script '{}' exited with code {:?}",
            command,
            output.status.code()
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut fields = serde_json::Map::new();
        fields.insert(
            "raw".to_string(),
            serde_json::Value::String(line.to_string()),
        );
        let event = serde_json::Value::Object(fields);
        if let Err(e) = sender.send_event(source, source_type, index, event).await {
            warn!("Failed to send script event: {}", e);
        }
    }

    Ok(())
}

/// Tail a file for new lines.
async fn tail_file(
    sender: &EventSender,
    path: &std::path::Path,
    source: &str,
    source_type: &str,
    index: &str,
) -> Result<()> {
    use tokio::fs::File;
    use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};

    let file = File::open(path).await?;
    let mut reader = BufReader::new(file);

    // Seek to end initially
    reader.seek(std::io::SeekFrom::End(0)).await?;

    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            sleep(Duration::from_millis(1000)).await;
            continue;
        }
        let line = line.trim_end_matches(['\n', '\r']);
        if line.is_empty() {
            continue;
        }
        let mut fields = serde_json::Map::new();
        fields.insert(
            "raw".to_string(),
            serde_json::Value::String(line.to_string()),
        );
        let event = serde_json::Value::Object(fields);
        if let Err(e) = sender.send_event(source, source_type, index, event).await {
            warn!("Failed to send tail event: {}", e);
        }
    }
}

/// Monitor a directory for new files.
async fn monitor_directory(
    sender: &EventSender,
    path: &std::path::Path,
    source: &str,
    source_type: &str,
    index: &str,
) -> Result<()> {
    use std::collections::HashSet;
    use std::fs;

    let mut seen: HashSet<std::path::PathBuf> = HashSet::new();

    loop {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_file() && seen.insert(p.clone()) {
                    info!("Directory monitor: new file {}", p.display());
                    if let Ok(content) = fs::read_to_string(&p) {
                        for line in content.lines() {
                            let line = line.trim();
                            if line.is_empty() {
                                continue;
                            }
                            let mut fields = serde_json::Map::new();
                            fields.insert(
                                "raw".to_string(),
                                serde_json::Value::String(line.to_string()),
                            );
                            fields.insert(
                                "file".to_string(),
                                serde_json::Value::String(
                                    p.file_name()
                                        .unwrap_or_default()
                                        .to_string_lossy()
                                        .to_string(),
                                ),
                            );
                            let event = serde_json::Value::Object(fields);
                            if let Err(e) =
                                sender.send_event(source, source_type, index, event).await
                            {
                                warn!("Failed to send directory event: {}", e);
                            }
                        }
                    }
                }
            }
        }
        sleep(Duration::from_secs(5)).await;
    }
}
