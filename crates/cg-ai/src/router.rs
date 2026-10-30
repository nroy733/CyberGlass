//! # AI Router
//!
//! Routes chat requests to the appropriate AI provider (local or remote).

use crate::error::AiError;
use crate::model::{InferenceConfig, ModelInfo as ModelInfoModel};
use crate::remote::RemoteModelProvider;
use crate::vendor::{AIProvider, AIProviderConfig, ChatRequest, ChatResponse};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

/// AI router that manages multiple providers and routes requests.
pub struct AiRouter {
    local_provider: Option<Arc<crate::local::LocalModelProvider>>,
    remote_providers: Arc<tokio::sync::RwLock<HashMap<AIProvider, Arc<RemoteModelProvider>>>>,
    default_provider: AIProvider,
}

impl AiRouter {
    pub fn new() -> Self {
        Self {
            local_provider: Some(Arc::new(crate::local::LocalModelProvider::new())),
            remote_providers: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            default_provider: AIProvider::Local,
        }
    }

    /// Set the local (offline) provider.
    pub fn set_local_provider(&mut self, provider: crate::local::LocalModelProvider) {
        self.local_provider = Some(Arc::new(provider));
        info!("Local AI provider registered");
    }

    /// Add or update a remote provider.
    pub async fn add_remote_provider(&self, config: AIProviderConfig) -> Result<(), AiError> {
        let provider = Arc::new(RemoteModelProvider::new(config.clone())?);
        let provider_type = config.provider.clone();

        self.remote_providers
            .write()
            .await
            .insert(provider_type.clone(), provider);

        info!("Remote AI provider added: {}", provider_type.name());
        Ok(())
    }

    /// Remove a remote provider.
    pub async fn remove_remote_provider(&self, provider: &AIProvider) {
        self.remote_providers.write().await.remove(provider);
        info!("Remote AI provider removed: {}", provider.name());
    }

    /// Route a chat request to the best available provider.
    pub async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, AiError> {
        let provider = request
            .provider
            .clone()
            .unwrap_or_else(|| self.default_provider.clone());
        let prefer_local = request.prefer_local;

        // Try local first if preferred and available
        if prefer_local && self.local_provider.is_some() {
            debug!("Routing to local AI provider");
            let local = self.local_provider.as_ref().unwrap();
            let local_resp = local.chat(request).await?;
            return Ok(ChatResponse {
                content: local_resp.content,
                provider: AIProvider::Local,
                model: local_resp.model,
                usage: crate::vendor::TokenUsage {
                    prompt_tokens: local_resp.usage.prompt_tokens,
                    completion_tokens: local_resp.usage.completion_tokens,
                    total_tokens: local_resp.usage.total_tokens,
                },
                latency_ms: 0,
                finish_reason: String::new(),
            });
        }

        // Try remote provider
        {
            let providers = self.remote_providers.read().await;
            if let Some(remote) = providers.get(&provider) {
                debug!("Routing to remote AI provider: {}", provider.name());
                return remote.chat(request).await;
            }
        }

        // Fallback to local if remote not available
        if let Some(local) = &self.local_provider {
            debug!("Fallback to local AI provider");
            let local_resp = local.chat(request).await?;
            return Ok(ChatResponse {
                content: local_resp.content,
                provider: AIProvider::Local,
                model: local_resp.model,
                usage: crate::vendor::TokenUsage {
                    prompt_tokens: local_resp.usage.prompt_tokens,
                    completion_tokens: local_resp.usage.completion_tokens,
                    total_tokens: local_resp.usage.total_tokens,
                },
                latency_ms: 0,
                finish_reason: String::new(),
            });
        }

        Err(AiError::ModelNotFound(format!(
            "No AI provider available for {:?}",
            provider
        )))
    }

    /// List all available models from all providers.
    pub async fn list_models(&self) -> Vec<crate::model::ModelInfo> {
        let mut models = Vec::new();

        // Local models
        if let Some(local) = &self.local_provider {
            models.push(crate::model::ModelInfo {
                id: "phi-4-mini-q4".to_string(),
                provider: AIProvider::Local,
                context_length: 4096,
                supports_streaming: false,
                supports_tools: true,
                is_local: true,
            });
        }

        // Remote models
        let providers = self.remote_providers.read().await;
        for (_provider_type, remote) in providers.iter() {
            if let Ok(provider_models) = remote.list_models().await {
                for m in provider_models {
                    models.push(crate::model::ModelInfo {
                        id: m.id,
                        provider: m.provider,
                        context_length: m.context_length,
                        supports_streaming: m.supports_streaming,
                        supports_tools: m.supports_tools,
                        is_local: m.is_local,
                    });
                }
            }
        }

        models
    }

    /// Get the default provider.
    pub fn default_provider(&self) -> &AIProvider {
        &self.default_provider
    }

    /// Set the default provider.
    pub fn set_default_provider(&mut self, provider: AIProvider) {
        self.default_provider = provider;
    }

    /// Check if a provider is available.
    pub fn is_provider_available(&self, provider: &AIProvider) -> bool {
        match provider {
            AIProvider::Local => self.local_provider.is_some(),
            _ => true,
        }
    }

    /// Get available providers.
    pub fn available_providers(&self) -> Vec<AIProvider> {
        let mut providers = Vec::new();
        if self.local_provider.is_some() {
            providers.push(AIProvider::Local);
        }
        providers.push(AIProvider::OpenAI);
        providers.push(AIProvider::Anthropic);
        providers.push(AIProvider::Google);
        providers.push(AIProvider::OpenRouter);
        providers
    }

    pub fn stats(&self) -> AiRouterStats {
        let remote_count = self
            .remote_providers
            .try_read()
            .map(|p| p.len())
            .unwrap_or(0);
        AiRouterStats {
            local_available: self.local_provider.is_some(),
            remote_providers_count: remote_count,
            default_provider: self.default_provider.name().to_string(),
        }
    }
}

impl Default for AiRouter {
    fn default() -> Self {
        Self::new()
    }
}

/// AI router statistics.
#[derive(Debug, Clone)]
pub struct AiRouterStats {
    pub local_available: bool,
    pub remote_providers_count: usize,
    pub default_provider: String,
}
