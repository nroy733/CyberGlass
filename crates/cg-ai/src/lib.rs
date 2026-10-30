//! # CyberGlass AI Engine
//!
//! Multi-vendor AI abstraction with support for:
//! - **Local models** - Offline GGUF inference (cyberglass)
//! - **OpenAI/GPT** - OpenAI-compatible API
//! - **Anthropic Claude** - Claude API
//! - **Google Gemini** - Gemini API
//! - **OpenRouter** - OpenRouter aggregator
//! - **Custom vendors** - Any OpenAI-compatible endpoint
//!
//! CGAP (CyberGlass AI Protocol) for tool use and automated triage.

pub mod cgap;
pub mod error;
pub mod local;
pub mod model;
pub mod remote;
pub mod router;
pub mod vendor;

pub use error::AiError;
pub use model::{ChatMessage, ChatResponse, InferenceConfig, ModelInfo, TokenUsage};
pub use remote::RemoteModelProvider;
pub use router::AiRouter;
pub use vendor::{
    AIProvider, AIProviderConfig, ChatRequest, ClaudeRequest, ClaudeResponse, GeminiRequest,
    GeminiResponse, OpenAIChatRequest, OpenAIChatResponse,
};

pub use local::LocalModelProvider;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vendor_enum() {
        let vendors = vec![
            AIProvider::Local,
            AIProvider::OpenAI,
            AIProvider::Anthropic,
            AIProvider::Google,
            AIProvider::OpenRouter,
            AIProvider::Custom("my-endpoint".to_string()),
        ];

        assert_eq!(vendors.len(), 6);
        assert!(matches!(vendors[0], AIProvider::Local));
        assert!(matches!(vendors[5], AIProvider::Custom(ref s) if s == "my-endpoint"));
    }
}
