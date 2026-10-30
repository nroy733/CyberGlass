//! # AI Vendors
//!
//! Support for multiple AI providers:
//! - Local (offline GGUF)
//! - OpenAI / GPT
//! - Anthropic Claude
//! - Google Gemini
//! - OpenRouter
//! - Custom OpenAI-compatible endpoints

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Supported AI providers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AIProvider {
    /// Local offline model (cyberglass)
    Local,
    /// OpenAI GPT models
    OpenAI,
    /// Anthropic Claude models
    Anthropic,
    /// Google Gemini models
    Google,
    /// OpenRouter aggregator
    OpenRouter,
    /// Custom OpenAI-compatible endpoint
    Custom(String),
}

impl AIProvider {
    pub fn name(&self) -> &str {
        match self {
            AIProvider::Local => "Local (CyberGlass)",
            AIProvider::OpenAI => "OpenAI",
            AIProvider::Anthropic => "Anthropic Claude",
            AIProvider::Google => "Google Gemini",
            AIProvider::OpenRouter => "OpenRouter",
            AIProvider::Custom(name) => name,
        }
    }

    pub fn default_model(&self) -> &str {
        match self {
            AIProvider::Local => "phi-4-mini-q4",
            AIProvider::OpenAI => "gpt-4o-mini",
            AIProvider::Anthropic => "claude-3-haiku-20240307",
            AIProvider::Google => "gemini-1.5-flash",
            AIProvider::OpenRouter => "openrouter/auto",
            AIProvider::Custom(_) => "default",
        }
    }

    pub fn api_base_url(&self) -> &str {
        match self {
            AIProvider::OpenAI => "https://api.openai.com/v1",
            AIProvider::Anthropic => "https://api.anthropic.com/v1",
            AIProvider::Google => "https://generativelanguage.googleapis.com/v1beta",
            AIProvider::OpenRouter => "https://openrouter.ai/api/v1",
            _ => "",
        }
    }
}

/// AI provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIProviderConfig {
    pub provider: AIProvider,
    pub api_key: Option<String>,
    pub api_base_url: Option<String>,
    pub model: String,
    pub enabled: bool,
    pub temperature: f32,
    pub max_tokens: Option<u32>,
    pub timeout_seconds: u64,
}

impl Default for AIProviderConfig {
    fn default() -> Self {
        Self {
            provider: AIProvider::Local,
            api_key: None,
            api_base_url: None,
            model: AIProvider::Local.default_model().to_string(),
            enabled: true,
            temperature: 0.7,
            max_tokens: None,
            timeout_seconds: 60,
        }
    }
}

/// Chat message in vendor-neutral format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: ChatRole,
    pub content: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChatRole {
    System,
    User,
    Assistant,
    Tool,
}

impl std::fmt::Display for ChatRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChatRole::System => write!(f, "system"),
            ChatRole::User => write!(f, "user"),
            ChatRole::Assistant => write!(f, "assistant"),
            ChatRole::Tool => write!(f, "tool"),
        }
    }
}

/// AI chat request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRequest {
    pub messages: Vec<ChatMessage>,
    pub provider: Option<AIProvider>,
    pub model: Option<String>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
    pub stream: bool,
    pub prefer_local: bool,
}

/// AI chat response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatResponse {
    pub content: String,
    pub provider: AIProvider,
    pub model: String,
    pub usage: TokenUsage,
    pub latency_ms: u64,
    pub finish_reason: String,
}

/// Token usage statistics.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

/// Available models from a provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    pub id: String,
    pub provider: AIProvider,
    pub context_length: u32,
    pub supports_streaming: bool,
    pub supports_tools: bool,
    pub is_local: bool,
}

/// OpenAI-compatible chat completion request.
#[derive(Debug, Serialize)]
pub struct OpenAIChatRequest {
    pub model: String,
    pub messages: Vec<OpenAIMessage>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
    pub stream: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenAIMessage {
    pub role: String,
    pub content: String,
}

/// OpenAI-compatible chat completion response.
#[derive(Debug, Deserialize)]
pub struct OpenAIChatResponse {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub model: String,
    pub choices: Vec<OpenAIChoice>,
    pub usage: Option<OpenAIUsage>,
}

#[derive(Debug, Deserialize)]
pub struct OpenAIChoice {
    pub index: u32,
    pub message: OpenAIMessage,
    pub finish_reason: String,
}

#[derive(Debug, Deserialize)]
pub struct OpenAIUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

/// Anthropic Claude API request.
#[derive(Debug, Serialize)]
pub struct ClaudeRequest {
    pub model: String,
    pub max_tokens: u32,
    pub temperature: Option<f32>,
    pub system: Option<String>,
    pub messages: Vec<ClaudeMessage>,
}

#[derive(Debug, Serialize)]
pub struct ClaudeMessage {
    pub role: String,
    pub content: String,
}

/// Anthropic Claude API response.
#[derive(Debug, Deserialize)]
pub struct ClaudeResponse {
    pub id: String,
    pub r#type: String,
    pub role: String,
    pub content: Vec<ClaudeContent>,
    pub model: String,
    pub stop_reason: Option<String>,
    pub usage: ClaudeUsage,
}

#[derive(Debug, Deserialize)]
pub struct ClaudeContent {
    pub r#type: String,
    pub text: String,
}

#[derive(Debug, Deserialize)]
pub struct ClaudeUsage {
    pub input_tokens: u32,
    pub output_tokens: u32,
}

/// Google Gemini API request.
#[derive(Debug, Serialize)]
pub struct GeminiRequest {
    pub contents: Vec<GeminiContent>,
    pub generation_config: Option<GeminiConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GeminiContent {
    pub parts: Vec<GeminiPart>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GeminiPart {
    pub text: String,
}

#[derive(Debug, Serialize)]
pub struct GeminiConfig {
    pub temperature: Option<f32>,
    pub max_output_tokens: Option<u32>,
}

/// Google Gemini API response.
#[derive(Debug, Deserialize)]
pub struct GeminiResponse {
    pub candidates: Vec<GeminiCandidate>,
    pub usage_metadata: Option<GeminiUsage>,
}

#[derive(Debug, Deserialize)]
pub struct GeminiCandidate {
    pub content: GeminiContent,
    pub finish_reason: String,
}

#[derive(Debug, Deserialize)]
pub struct GeminiUsage {
    pub prompt_token_count: u32,
    pub candidates_token_count: u32,
    pub total_token_count: u32,
}
