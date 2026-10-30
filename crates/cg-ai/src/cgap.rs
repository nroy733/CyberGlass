use crate::error::{AiError, Result};
use async_trait::async_trait;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSecurity {
    pub required_permissions: Vec<String>,
    pub requires_approval: bool,
    pub sandboxed: bool,
    pub audit_logged: bool,
}

impl Default for ToolSecurity {
    fn default() -> Self {
        Self {
            required_permissions: Vec::new(),
            requires_approval: false,
            sandboxed: true,
            audit_logged: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CGAPTool {
    pub name: String,
    pub description: String,
    pub version: String,
    pub input_schema: Value,
    pub output_schema: Value,
    pub security: ToolSecurity,
}

#[async_trait]
pub trait ToolHandler: Send + Sync {
    async fn execute(&self, args: Value) -> Result<Value>;
}

pub struct CGAPRegistry {
    tools: DashMap<String, CGAPTool>,
    handlers: DashMap<String, Arc<dyn ToolHandler>>,
}

impl Default for CGAPRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl CGAPRegistry {
    pub fn new() -> Self {
        let registry = Self {
            tools: DashMap::new(),
            handlers: DashMap::new(),
        };

        // Register default investigate_ip tool
        let tool = CGAPTool {
            name: "investigate_ip".into(),
            description: "Deep dive on IP address across knowledge graph and raw index".into(),
            version: "1.0.0".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "ip": { "type": "string" }
                },
                "required": ["ip"]
            }),
            output_schema: serde_json::json!({ "type": "object" }),
            security: ToolSecurity::default(),
        };

        struct IpHandler;
        #[async_trait]
        impl ToolHandler for IpHandler {
            async fn execute(&self, args: Value) -> Result<Value> {
                let ip = args["ip"].as_str().unwrap_or("unknown");
                Ok(serde_json::json!({
                    "ip": ip,
                    "reputation": "suspicious",
                    "threat_intel_matches": 1,
                    "historical_events": 14
                }))
            }
        }

        registry.register_tool(tool, Arc::new(IpHandler));

        registry
    }

    pub fn register_tool(&self, tool: CGAPTool, handler: Arc<dyn ToolHandler>) {
        let name = tool.name.clone();
        self.tools.insert(name.clone(), tool);
        self.handlers.insert(name, handler);
    }

    pub fn list_tools(&self) -> Vec<CGAPTool> {
        self.tools.iter().map(|t| t.value().clone()).collect()
    }

    pub async fn execute_tool(&self, name: &str, args: Value) -> Result<Value> {
        let handler = self
            .handlers
            .get(name)
            .ok_or_else(|| AiError::ToolExecution(format!("Tool '{}' not found", name)))?;

        tracing::info!("CGAP executing tool: {} with args: {:?}", name, args);
        handler.execute(args).await
    }
}
