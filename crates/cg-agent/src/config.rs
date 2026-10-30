//! # Agent Configuration
//!
//! Supports loading from TOML config files and CLI arguments.

use anyhow::{Context as _, Result as AnyhowResult};
use serde::{Deserialize, Serialize};

use crate::input::InputConfig;
/// Agent configuration loaded from TOML file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// CyberGlass server URL
    pub server: Option<String>,
    /// HEC token
    pub hec_token: Option<String>,
    /// Default index
    pub index: Option<String>,
    /// Request timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// List of input configurations
    #[serde(default)]
    pub inputs: Vec<InputConfig>,
    /// Install as service
    #[serde(default)]
    pub install_service: bool,
}

fn default_timeout() -> u64 {
    30
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            server: None,
            hec_token: None,
            index: None,
            timeout_secs: 30,
            inputs: Vec::new(),
            install_service: false,
        }
    }
}

impl AgentConfig {
    /// Load configuration from a TOML file.
    pub fn load(path: &std::path::Path) -> AnyhowResult<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        let config: Self = toml::from_str(&content)
            .with_context(|| format!("Failed to parse config: {}", path.display()))?;
        Ok(config)
    }

    /// Save configuration to a TOML file.
    pub fn save(&self, path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize config: {}", e))?;
        std::fs::write(path, content).map_err(|e| format!("Failed to write config: {}", e))?;
        Ok(())
    }

    /// Create config from CLI arguments.
    pub fn from_cli(cli: &crate::Cli) -> Self {
        Self {
            server: Some(cli.server.clone()),
            hec_token: cli.hec_token.clone(),
            index: Some(cli.index.clone()),
            timeout_secs: 30,
            inputs: Vec::new(),
            install_service: cli.install_service,
        }
    }

    /// Merge CLI arguments over config file values.
    pub fn merge_cli(mut self, cli: &crate::Cli) -> Self {
        if cli.server != "http://localhost:9401" {
            self.server = Some(cli.server.clone());
        }
        if cli.hec_token.is_some() {
            self.hec_token = cli.hec_token.clone();
        }
        if cli.index != "main" {
            self.index = Some(cli.index.clone());
        }
        self.install_service = cli.install_service;
        self
    }
}

impl AgentConfig {
    pub fn server(&self) -> &str {
        self.server.as_deref().unwrap_or("http://localhost:9401")
    }

    pub fn index(&self) -> &str {
        self.index.as_deref().unwrap_or("main")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AgentConfig::default();
        assert_eq!(config.server(), "http://localhost:9401");
        assert_eq!(config.index(), "main");
        assert_eq!(config.timeout_secs, 30);
    }
}
