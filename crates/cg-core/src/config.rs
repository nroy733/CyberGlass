use crate::error::{CyberGlassError, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CyberGlassConfig {
    pub node: NodeConfig,
    pub grpc: GrpcConfig,
    pub rest: RestConfig,
    pub ingest: IngestConfig,
    pub index: IndexConfig,
    pub storage: StorageConfig,
    pub ontology: OntologyConfig,
    pub detection: DetectionConfig,
    pub ai: AiConfig,
    pub bus: BusConfig,
    pub cluster: ClusterConfig,
}

impl CyberGlassConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref()).map_err(|e| {
            CyberGlassError::Config(format!(
                "Failed to read '{}': {}",
                path.as_ref().display(),
                e
            ))
        })?;
        let mut config: Self = toml::from_str(&content)
            .map_err(|e| CyberGlassError::Config(format!("Failed to parse config: {}", e)))?;

        // If CYBERGLASS_HOME is set in the environment, adapt relative paths
        if let Ok(home) = std::env::var("CYBERGLASS_HOME") {
            config.adapt_to_home(Path::new(&home));
        }

        Ok(config)
    }

    /// Auto-discovers configuration file across standard multi-OS locations:
    /// 1. $CYBERGLASS_CONFIG
    /// 2. ./config/cyberglass.toml
    /// 3. /etc/cyberglass/cyberglass.toml (Linux / macOS standard)
    /// 4. /usr/local/etc/cyberglass/cyberglass.toml (macOS Homebrew / BSD)
    /// 5. $HOME/.cyberglass/cyberglass.toml
    /// 6. Fallback to default
    pub fn discover_and_load(explicit_path: Option<&str>) -> (Self, Option<std::path::PathBuf>) {
        if let Some(path) = explicit_path {
            if Path::new(path).exists() {
                if let Ok(cfg) = Self::load(path) {
                    return (cfg, Some(std::path::PathBuf::from(path)));
                }
            }
        }

        if let Ok(env_path) = std::env::var("CYBERGLASS_CONFIG") {
            if Path::new(&env_path).exists() {
                if let Ok(cfg) = Self::load(&env_path) {
                    return (cfg, Some(std::path::PathBuf::from(env_path)));
                }
            }
        }

        let candidates = [
            "config/cyberglass.toml",
            "cyberglass.toml",
            "/etc/cyberglass/cyberglass.toml",
            "/usr/local/etc/cyberglass/cyberglass.toml",
            "/opt/cyberglass/config/cyberglass.toml",
        ];

        for candidate in candidates {
            let p = Path::new(candidate);
            if p.exists() {
                if let Ok(cfg) = Self::load(p) {
                    return (cfg, Some(p.to_path_buf()));
                }
            }
        }

        // Check user home directory across Linux/macOS/Windows
        if let Some(home) = dirs_home() {
            let user_cfg = home.join(".cyberglass").join("cyberglass.toml");
            if user_cfg.exists() {
                if let Ok(cfg) = Self::load(&user_cfg) {
                    return (cfg, Some(user_cfg));
                }
            }
        }

        let mut default_cfg = Self::default();
        if let Ok(home) = std::env::var("CYBERGLASS_HOME") {
            default_cfg.adapt_to_home(Path::new(&home));
        }
        (default_cfg, None)
    }

    /// Adapts all internal storage and data paths to be subdirectories of `home`.
    /// Perfect for portable, non-root, and custom directory installations.
    pub fn adapt_to_home(&mut self, home: &Path) {
        let to_str = |p: std::path::PathBuf| p.to_string_lossy().to_string();

        self.node.data_dir = to_str(home.join("data"));
        self.index.index_dir = to_str(home.join("index"));
        self.ingest.wal_dir = to_str(home.join("wal"));
        self.detection.rules_dir = to_str(home.join("rules"));
        self.ontology.db_path = to_str(home.join("ontology"));
        self.ai.local.models_dir = to_str(home.join("models"));
        self.bus.store_dir = to_str(home.join("jetstream"));

        self.storage.hot.path = to_str(home.join("storage").join("hot"));
        self.storage.warm.path = to_str(home.join("storage").join("warm"));
        self.storage.cold.path = to_str(home.join("storage").join("cold"));
        self.storage.frozen.path = to_str(home.join("storage").join("frozen"));
    }
}

fn dirs_home() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    #[serde(default)]
    pub id: String,
    #[serde(default = "default_node_name")]
    pub name: String,
    #[serde(default = "default_role")]
    pub role: String,
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_log_format")]
    pub log_format: String,
}

fn default_node_name() -> String {
    "cyberglass-node-1".into()
}
fn default_role() -> String {
    "all".into()
}
fn default_data_dir() -> String {
    "/var/lib/cyberglass".into()
}
fn default_log_level() -> String {
    "info".into()
}
fn default_log_format() -> String {
    "json".into()
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: default_node_name(),
            role: default_role(),
            data_dir: default_data_dir(),
            log_level: default_log_level(),
            log_format: default_log_format(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrpcConfig {
    #[serde(default = "default_grpc_listen")]
    pub listen_addr: String,
    #[serde(default = "default_max_msg_size")]
    pub max_message_size: usize,
    #[serde(default)]
    pub tls_enabled: bool,
    #[serde(default)]
    pub tls_cert: String,
    #[serde(default)]
    pub tls_key: String,
    #[serde(default)]
    pub tls_ca: String,
    #[serde(default)]
    pub mtls_enabled: bool,
}

fn default_grpc_listen() -> String {
    "0.0.0.0:9400".into()
}
fn default_max_msg_size() -> usize {
    67108864
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_grpc_listen(),
            max_message_size: default_max_msg_size(),
            tls_enabled: false,
            tls_cert: String::new(),
            tls_key: String::new(),
            tls_ca: String::new(),
            mtls_enabled: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestConfig {
    #[serde(default = "default_rest_listen")]
    pub listen_addr: String,
    #[serde(default = "default_true")]
    pub cors_enabled: bool,
    #[serde(default)]
    pub cors_origins: Vec<String>,
}

fn default_rest_listen() -> String {
    "0.0.0.0:9401".into()
}
fn default_true() -> bool {
    true
}

impl Default for RestConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_rest_listen(),
            cors_enabled: true,
            cors_origins: vec!["*".into()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestConfig {
    #[serde(default)]
    pub max_eps: u64,
    #[serde(default = "default_queue_capacity")]
    pub queue_capacity: usize,
    #[serde(default = "default_max_event_size")]
    pub max_event_size_bytes: usize,
    #[serde(default = "default_wal_dir")]
    pub wal_dir: String,
    #[serde(default = "default_wal_max_size")]
    pub wal_max_size: usize,
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    #[serde(default = "default_batch_timeout")]
    pub batch_timeout_ms: u64,
    #[serde(default)]
    pub num_workers: usize,
    #[serde(default = "default_index")]
    pub default_index: String,
    #[serde(default = "default_true")]
    pub geoip_enabled: bool,
    #[serde(default)]
    pub geoip_database: String,
}

fn default_wal_dir() -> String {
    "/var/lib/cyberglass/wal".into()
}
fn default_wal_max_size() -> usize {
    1073741824
}
fn default_queue_capacity() -> usize {
    1024
}
fn default_max_event_size() -> usize {
    262144
}
fn default_batch_size() -> usize {
    256
}
fn default_batch_timeout() -> u64 {
    10
}
fn default_index() -> String {
    "main".into()
}

impl Default for IngestConfig {
    fn default() -> Self {
        Self {
            max_eps: 0,
            queue_capacity: default_queue_capacity(),
            max_event_size_bytes: default_max_event_size(),
            wal_dir: default_wal_dir(),
            wal_max_size: default_wal_max_size(),
            batch_size: default_batch_size(),
            batch_timeout_ms: default_batch_timeout(),
            num_workers: 0,
            default_index: default_index(),
            geoip_enabled: false,
            geoip_database: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexConfig {
    #[serde(default = "default_index_dir")]
    pub index_dir: String,
    #[serde(default = "default_mem_budget")]
    pub memory_budget: usize,
    #[serde(default)]
    pub num_threads: usize,
    #[serde(default = "default_commit_interval")]
    pub commit_interval_seconds: u64,
    #[serde(default = "default_true")]
    pub columnar_enabled: bool,
}

fn default_index_dir() -> String {
    "/var/lib/cyberglass/index".into()
}
fn default_mem_budget() -> usize {
    536870912
}
fn default_commit_interval() -> u64 {
    5
}

impl Default for IndexConfig {
    fn default() -> Self {
        Self {
            index_dir: default_index_dir(),
            memory_budget: default_mem_budget(),
            num_threads: 0,
            commit_interval_seconds: default_commit_interval(),
            columnar_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StorageConfig {
    #[serde(default)]
    pub hot: TierSettings,
    #[serde(default)]
    pub warm: TierSettings,
    #[serde(default)]
    pub cold: TierSettings,
    #[serde(default)]
    pub frozen: TierSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierSettings {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub max_size: String,
    #[serde(default)]
    pub retention_days: u64,
    #[serde(default)]
    pub compression: String,
    #[serde(default = "default_compression_level")]
    pub compression_level: u32,
}

fn default_compression_level() -> u32 {
    3
}

impl Default for TierSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            path: String::new(),
            max_size: "100GB".into(),
            retention_days: 30,
            compression: "zstd".into(),
            compression_level: 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OntologyConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub num_workers: usize,
    #[serde(default = "default_true")]
    pub auto_extract: bool,
    #[serde(default)]
    pub auto_extract_types: Vec<String>,
    #[serde(default = "default_decay")]
    pub risk_decay_rate: f64,
    #[serde(default = "default_ontology_path")]
    pub db_path: String,
}

fn default_decay() -> f64 {
    0.95
}
fn default_ontology_path() -> String {
    "/var/lib/cyberglass/ontology".into()
}

impl Default for OntologyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            num_workers: 0,
            auto_extract: true,
            auto_extract_types: vec![
                "ip_address".into(),
                "domain".into(),
                "url".into(),
                "user".into(),
                "host".into(),
                "file_hash".into(),
            ],
            risk_decay_rate: default_decay(),
            db_path: default_ontology_path(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_rules_dir")]
    pub rules_dir: String,
    #[serde(default = "default_detect_interval")]
    pub default_interval: u64,
    #[serde(default = "default_true")]
    pub risk_based_alerting: bool,
    #[serde(default)]
    pub mitre_attack_file: String,
}

fn default_rules_dir() -> String {
    "/etc/cyberglass/rules".into()
}
fn default_detect_interval() -> u64 {
    60
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rules_dir: default_rules_dir(),
            default_interval: default_detect_interval(),
            risk_based_alerting: true,
            mitre_attack_file: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AiConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub local: LocalAiConfig,
    #[serde(default)]
    pub remote: RemoteAiConfig,
    #[serde(default)]
    pub cgap: CgapConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalAiConfig {
    #[serde(default = "default_models_dir")]
    pub models_dir: String,
    #[serde(default = "default_model_name")]
    pub default_model: String,
    #[serde(default)]
    pub gpu_layers: u32,
    #[serde(default = "default_ctx")]
    pub context_size: usize,
    #[serde(default)]
    pub num_threads: usize,
}

fn default_models_dir() -> String {
    "/var/lib/cyberglass/models".into()
}
fn default_model_name() -> String {
    "phi-4-mini-q4".into()
}
fn default_ctx() -> usize {
    4096
}

impl Default for LocalAiConfig {
    fn default() -> Self {
        Self {
            models_dir: default_models_dir(),
            default_model: default_model_name(),
            gpu_layers: 0,
            context_size: default_ctx(),
            num_threads: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RemoteAiConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default)]
    pub default_model: String,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
}

fn default_timeout() -> u64 {
    30000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CgapConfig {
    #[serde(default = "default_cgap_listen")]
    pub listen_addr: String,
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: usize,
    #[serde(default = "default_tool_timeout")]
    pub tool_timeout_ms: u64,
    #[serde(default = "default_true")]
    pub wasm_sandbox: bool,
    #[serde(default = "default_true")]
    pub audit_log: bool,
}

fn default_cgap_listen() -> String {
    "0.0.0.0:9402".into()
}
fn default_max_concurrent() -> usize {
    10
}
fn default_tool_timeout() -> u64 {
    60000
}

impl Default for CgapConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_cgap_listen(),
            max_concurrent: default_max_concurrent(),
            tool_timeout_ms: default_tool_timeout(),
            wasm_sandbox: true,
            audit_log: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusConfig {
    #[serde(default = "default_bus_listen")]
    pub listen_addr: String,
    #[serde(default)]
    pub cluster_peers: Vec<String>,
    #[serde(default = "default_store_dir")]
    pub store_dir: String,
    #[serde(default = "default_max_memory")]
    pub max_memory: String,
    #[serde(default = "default_max_file")]
    pub max_file_store: String,
}

fn default_bus_listen() -> String {
    "0.0.0.0:9403".into()
}
fn default_store_dir() -> String {
    "/var/lib/cyberglass/jetstream".into()
}
fn default_max_memory() -> String {
    "1GB".into()
}
fn default_max_file() -> String {
    "10GB".into()
}

impl Default for BusConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_bus_listen(),
            cluster_peers: Vec::new(),
            store_dir: default_store_dir(),
            max_memory: default_max_memory(),
            max_file_store: default_max_file(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClusterConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_discovery")]
    pub discovery: String,
    #[serde(default)]
    pub peers: Vec<String>,
    #[serde(default = "default_cluster_bind")]
    pub bind_addr: String,
    #[serde(default)]
    pub secret: String,
}

fn default_discovery() -> String {
    "static".into()
}
fn default_cluster_bind() -> String {
    "0.0.0.0:9404".into()
}
