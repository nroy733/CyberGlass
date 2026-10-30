//! # AI Models
//!
//! Model definitions and inference configuration.

use serde::{Deserialize, Serialize};

/// Inference configuration for AI requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceConfig {
    pub temperature: f32,
    pub max_tokens: Option<u32>,
    pub top_p: Option<f32>,
    pub stream: bool,
}

impl Default for InferenceConfig {
    fn default() -> Self {
        Self {
            temperature: 0.7,
            max_tokens: None,
            top_p: None,
            stream: false,
        }
    }
}

/// Chat message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

impl ChatMessage {
    pub fn user(content: String) -> Self {
        Self {
            role: "user".to_string(),
            content,
        }
    }

    pub fn system(content: String) -> Self {
        Self {
            role: "system".to_string(),
            content,
        }
    }

    pub fn assistant(content: String) -> Self {
        Self {
            role: "assistant".to_string(),
            content,
        }
    }
}

/// Chat response from AI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatResponse {
    pub content: String,
    pub usage: TokenUsage,
    pub provider: String,
    pub model: String,
}

/// Token usage.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

/// Model information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    pub id: String,
    pub provider: crate::vendor::AIProvider,
    pub context_length: u32,
    pub supports_streaming: bool,
    pub supports_tools: bool,
    pub is_local: bool,
}

/// Available model providers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AiProvider {
    Local,
    OpenAI,
    Anthropic,
    Google,
    OpenRouter,
    Custom(String),
}

/// Model provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelProviderConfig {
    pub provider: AiProvider,
    pub api_key: Option<String>,
    pub model: String,
    pub enabled: bool,
}

impl Default for ModelProviderConfig {
    fn default() -> Self {
        Self {
            provider: AiProvider::Local,
            api_key: None,
            model: "phi-4-mini-q4".to_string(),
            enabled: true,
        }
    }
}
