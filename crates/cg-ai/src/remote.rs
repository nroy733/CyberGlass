//! # Remote AI Providers
//!
//! HTTP client implementations for OpenAI, Anthropic, Google Gemini, OpenRouter,
//! and custom OpenAI-compatible endpoints.

use crate::error::AiError;
use crate::vendor::*;
use reqwest::Client;
use serde_json::json;
use std::time::Duration;
use tracing::{debug, error, info};

/// Remote AI model provider supporting multiple vendors.
pub struct RemoteModelProvider {
    client: Client,
    config: AIProviderConfig,
}

impl RemoteModelProvider {
    pub fn new(config: AIProviderConfig) -> Result<Self, AiError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_seconds))
            .build()
            .map_err(|e| AiError::ProviderError(format!("Failed to create HTTP client: {}", e)))?;

        info!(
            "Remote AI provider initialized: {} ({})",
            config.provider.name(),
            config.model
        );

        Ok(Self { client, config })
    }

    /// Send a chat request to the configured AI provider.
    pub async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, AiError> {
        let start = std::time::Instant::now();

        let response = match self.config.provider {
            AIProvider::OpenAI => self.chat_openai(request).await?,
            AIProvider::Anthropic => self.chat_claude(request).await?,
            AIProvider::Google => self.chat_gemini(request).await?,
            AIProvider::OpenRouter => self.chat_openrouter(request).await?,
            AIProvider::Custom(ref url) => self.chat_custom(url, request).await?,
            AIProvider::Local => {
                return Err(AiError::ProviderError(
                    "Local provider should use LocalModelProvider".to_string(),
                ))
            }
        };

        let latency = start.elapsed().as_millis() as u64;
        debug!(
            "AI response from {} in {}ms",
            self.config.provider.name(),
            latency
        );

        Ok(response)
    }

    async fn chat_openai(&self, request: ChatRequest) -> Result<ChatResponse, AiError> {
        let api_key = self.config.api_key.as_deref().ok_or_else(|| {
            AiError::AuthenticationError("OpenAI API key not configured".to_string())
        })?;
        let base_url = self
            .config
            .api_base_url
            .as_deref()
            .unwrap_or("https://api.openai.com/v1");
        let model = request.model.unwrap_or_else(|| self.config.model.clone());

        let messages: Vec<OpenAIMessage> = request
            .messages
            .iter()
            .map(|m| OpenAIMessage {
                role: m.role.to_string(),
                content: m.content.clone(),
            })
            .collect();

        let req = OpenAIChatRequest {
            model,
            messages,
            temperature: request.temperature,
            max_tokens: request.max_tokens,
            stream: Some(false),
        };

        let resp: OpenAIChatResponse = self
            .client
            .post(format!("{}/chat/completions", base_url))
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(&req)
            .send()
            .await
            .map_err(|e| AiError::ProviderError(format!("OpenAI request failed: {}", e)))?
            .json()
            .await
            .map_err(|e| AiError::ProviderError(format!("OpenAI response parse failed: {}", e)))?;

        let content = resp
            .choices
            .first()
            .map(|c| c.message.content.clone())
            .unwrap_or_default();

        let usage = resp
            .usage
            .map(|u| TokenUsage {
                prompt_tokens: u.prompt_tokens,
                completion_tokens: u.completion_tokens,
                total_tokens: u.total_tokens,
            })
            .unwrap_or_default();

        Ok(ChatResponse {
            content,
            provider: AIProvider::OpenAI,
            model: resp.model,
            usage,
            latency_ms: 0, // Set by caller
            finish_reason: resp
                .choices
                .first()
                .map(|c| c.finish_reason.clone())
                .unwrap_or_default(),
        })
    }

    async fn chat_claude(&self, request: ChatRequest) -> Result<ChatResponse, AiError> {
        let api_key = self.config.api_key.as_deref().ok_or_else(|| {
            AiError::AuthenticationError("Anthropic API key not configured".to_string())
        })?;
        let base_url = self
            .config
            .api_base_url
            .as_deref()
            .unwrap_or("https://api.anthropic.com/v1");
        let model = request.model.unwrap_or_else(|| self.config.model.clone());

        let system_msg: Option<String> = request
            .messages
            .iter()
            .find(|m| matches!(m.role, ChatRole::System))
            .map(|m| m.content.clone());

        let messages: Vec<ClaudeMessage> = request
            .messages
            .iter()
            .filter(|m| !matches!(m.role, ChatRole::System))
            .map(|m| ClaudeMessage {
                role: m.role.to_string(),
                content: m.content.clone(),
            })
            .collect();

        let req = ClaudeRequest {
            model,
            max_tokens: request.max_tokens.unwrap_or(1000),
            temperature: request.temperature,
            system: system_msg,
            messages,
        };

        let resp: ClaudeResponse = self
            .client
            .post(format!("{}/messages", base_url))
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .header("Content-Type", "application/json")
            .json(&req)
            .send()
            .await
            .map_err(|e| AiError::ProviderError(format!("Anthropic request failed: {}", e)))?
            .json()
            .await
            .map_err(|e| {
                AiError::ProviderError(format!("Anthropic response parse failed: {}", e))
            })?;

        let content = resp
            .content
            .iter()
            .filter(|c| c.r#type == "text")
            .map(|c| c.text.clone())
            .collect::<Vec<_>>()
            .join("\n");

        Ok(ChatResponse {
            content,
            provider: AIProvider::Anthropic,
            model: resp.model,
            usage: TokenUsage {
                prompt_tokens: resp.usage.input_tokens,
                completion_tokens: resp.usage.output_tokens,
                total_tokens: resp.usage.input_tokens + resp.usage.output_tokens,
            },
            latency_ms: 0,
            finish_reason: resp.stop_reason.unwrap_or_default(),
        })
    }

    async fn chat_gemini(&self, request: ChatRequest) -> Result<ChatResponse, AiError> {
        let api_key = self.config.api_key.as_deref().ok_or_else(|| {
            AiError::AuthenticationError("Google API key not configured".to_string())
        })?;
        let base_url = self
            .config
            .api_base_url
            .as_deref()
            .unwrap_or("https://generativelanguage.googleapis.com/v1beta");
        let model = request.model.unwrap_or_else(|| self.config.model.clone());

        let contents: Vec<GeminiContent> = request
            .messages
            .iter()
            .map(|m| GeminiContent {
                parts: vec![GeminiPart {
                    text: format!("{}: {}", m.role, m.content),
                }],
            })
            .collect();

        let req = GeminiRequest {
            contents,
            generation_config: Some(GeminiConfig {
                temperature: request.temperature,
                max_output_tokens: request.max_tokens,
            }),
        };

        let resp: GeminiResponse = self
            .client
            .post(format!(
                "{}/models/{}:generateContent?key={}",
                base_url, model, api_key
            ))
            .header("Content-Type", "application/json")
            .json(&req)
            .send()
            .await
            .map_err(|e| AiError::ProviderError(format!("Gemini request failed: {}", e)))?
            .json()
            .await
            .map_err(|e| AiError::ProviderError(format!("Gemini response parse failed: {}", e)))?;

        let content = resp
            .candidates
            .first()
            .map(|c| {
                c.content
                    .parts
                    .iter()
                    .map(|p| p.text.clone())
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();

        Ok(ChatResponse {
            content,
            provider: AIProvider::Google,
            model,
            usage: resp
                .usage_metadata
                .map(|u| TokenUsage {
                    prompt_tokens: u.prompt_token_count,
                    completion_tokens: u.candidates_token_count,
                    total_tokens: u.total_token_count,
                })
                .unwrap_or_default(),
            latency_ms: 0,
            finish_reason: resp
                .candidates
                .first()
                .map(|c| c.finish_reason.clone())
                .unwrap_or_default(),
        })
    }

    async fn chat_openrouter(&self, request: ChatRequest) -> Result<ChatResponse, AiError> {
        let api_key = self.config.api_key.as_deref().ok_or_else(|| {
            AiError::AuthenticationError("OpenRouter API key not configured".to_string())
        })?;
        let base_url = self
            .config
            .api_base_url
            .as_deref()
            .unwrap_or("https://openrouter.ai/api/v1");
        let model = request.model.unwrap_or_else(|| self.config.model.clone());

        let messages: Vec<OpenAIMessage> = request
            .messages
            .iter()
            .map(|m| OpenAIMessage {
                role: m.role.to_string(),
                content: m.content.clone(),
            })
            .collect();

        let req = OpenAIChatRequest {
            model,
            messages,
            temperature: request.temperature,
            max_tokens: request.max_tokens,
            stream: Some(false),
        };

        let resp: OpenAIChatResponse = self
            .client
            .post(format!("{}/chat/completions", base_url))
            .header("Authorization", format!("Bearer {}", api_key))
            .header("HTTP-Referer", "https://cyberglass.local")
            .header("X-Title", "CyberGlass SIEM")
            .header("Content-Type", "application/json")
            .json(&req)
            .send()
            .await
            .map_err(|e| AiError::ProviderError(format!("OpenRouter request failed: {}", e)))?
            .json()
            .await
            .map_err(|e| {
                AiError::ProviderError(format!("OpenRouter response parse failed: {}", e))
            })?;

        let content = resp
            .choices
            .first()
            .map(|c| c.message.content.clone())
            .unwrap_or_default();

        let usage = resp
            .usage
            .map(|u| TokenUsage {
                prompt_tokens: u.prompt_tokens,
                completion_tokens: u.completion_tokens,
                total_tokens: u.total_tokens,
            })
            .unwrap_or_default();

        Ok(ChatResponse {
            content,
            provider: AIProvider::OpenRouter,
            model: resp.model,
            usage,
            latency_ms: 0,
            finish_reason: resp
                .choices
                .first()
                .map(|c| c.finish_reason.clone())
                .unwrap_or_default(),
        })
    }

    async fn chat_custom(
        &self,
        base_url: &str,
        request: ChatRequest,
    ) -> Result<ChatResponse, AiError> {
        let api_key = self.config.api_key.as_deref().unwrap_or("");
        let model = request.model.unwrap_or_else(|| self.config.model.clone());

        let messages: Vec<OpenAIMessage> = request
            .messages
            .iter()
            .map(|m| OpenAIMessage {
                role: m.role.to_string(),
                content: m.content.clone(),
            })
            .collect();

        let req = OpenAIChatRequest {
            model,
            messages,
            temperature: request.temperature,
            max_tokens: request.max_tokens,
            stream: Some(false),
        };

        let resp: OpenAIChatResponse = self
            .client
            .post(format!("{}/chat/completions", base_url))
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(&req)
            .send()
            .await
            .map_err(|e| AiError::ProviderError(format!("Custom provider request failed: {}", e)))?
            .json()
            .await
            .map_err(|e| {
                AiError::ProviderError(format!("Custom provider response parse failed: {}", e))
            })?;

        let content = resp
            .choices
            .first()
            .map(|c| c.message.content.clone())
            .unwrap_or_default();

        let usage = resp
            .usage
            .map(|u| TokenUsage {
                prompt_tokens: u.prompt_tokens,
                completion_tokens: u.completion_tokens,
                total_tokens: u.total_tokens,
            })
            .unwrap_or_default();

        Ok(ChatResponse {
            content,
            provider: AIProvider::Custom(base_url.to_string()),
            model: resp.model,
            usage,
            latency_ms: 0,
            finish_reason: resp
                .choices
                .first()
                .map(|c| c.finish_reason.clone())
                .unwrap_or_default(),
        })
    }

    /// List available models from the provider.
    pub async fn list_models(&self) -> Result<Vec<ModelInfo>, AiError> {
        // In a real implementation, this would query the provider's models endpoint
        // For now, return a default model
        Ok(vec![ModelInfo {
            id: self.config.model.clone(),
            provider: self.config.provider.clone(),
            context_length: 4096,
            supports_streaming: true,
            supports_tools: true,
            is_local: false,
        }])
    }

    pub fn config(&self) -> &AIProviderConfig {
        &self.config
    }
}
