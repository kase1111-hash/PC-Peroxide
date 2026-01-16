//! LLM inference provider implementations.
//!
//! Supports multiple backends:
//! - Ollama (local LLM server)
//! - OpenAI-compatible APIs
//! - Mock provider for testing

mod ollama;
mod openai;

pub use ollama::OllamaProvider;
pub use openai::OpenAiProvider;

use super::inference::InferenceEngine;
use crate::core::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// LLM provider type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LlmProvider {
    /// Ollama local server
    #[default]
    Ollama,
    /// OpenAI API (or compatible)
    OpenAi,
    /// Mock provider for testing
    Mock,
    /// Disabled
    None,
}

impl LlmProvider {
    /// Parse provider from string.
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "ollama" => Self::Ollama,
            "openai" | "openai-compatible" | "api" => Self::OpenAi,
            "mock" | "test" => Self::Mock,
            "none" | "disabled" | "" => Self::None,
            _ => Self::None,
        }
    }
}

/// Configuration for LLM providers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// Provider type
    pub provider: LlmProvider,
    /// Model name/identifier
    pub model: String,
    /// API endpoint URL
    pub endpoint: String,
    /// API key (for OpenAI-compatible APIs)
    pub api_key: Option<String>,
    /// Maximum context length in tokens
    pub max_context_length: usize,
    /// Request timeout in seconds
    pub timeout_secs: u64,
    /// Confidence threshold for reporting (0.0 - 1.0)
    pub confidence_threshold: f32,
    /// Temperature for generation (0.0 - 2.0)
    pub temperature: f32,
    /// Local model path (for future local inference)
    pub model_path: Option<PathBuf>,
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            provider: LlmProvider::Ollama,
            model: "llama3.2".to_string(),
            endpoint: "http://localhost:11434".to_string(),
            api_key: None,
            max_context_length: 16384,
            timeout_secs: 120,
            confidence_threshold: 0.7,
            temperature: 0.3,
            model_path: None,
        }
    }
}

impl ProviderConfig {
    /// Create config for Ollama with default model.
    pub fn ollama(model: &str) -> Self {
        Self {
            provider: LlmProvider::Ollama,
            model: model.to_string(),
            endpoint: "http://localhost:11434".to_string(),
            ..Default::default()
        }
    }

    /// Create config for OpenAI-compatible API.
    pub fn openai(endpoint: &str, api_key: &str, model: &str) -> Self {
        Self {
            provider: LlmProvider::OpenAi,
            model: model.to_string(),
            endpoint: endpoint.to_string(),
            api_key: Some(api_key.to_string()),
            ..Default::default()
        }
    }

    /// Create a mock config for testing.
    pub fn mock() -> Self {
        Self {
            provider: LlmProvider::Mock,
            model: "mock".to_string(),
            ..Default::default()
        }
    }
}

/// Create an inference provider from configuration.
pub fn create_provider(config: &ProviderConfig) -> Result<Box<dyn InferenceEngine>> {
    match config.provider {
        LlmProvider::Ollama => {
            let provider = OllamaProvider::new(
                &config.endpoint,
                &config.model,
                config.max_context_length,
                config.timeout_secs,
                config.temperature,
            );
            Ok(Box::new(provider))
        }
        LlmProvider::OpenAi => {
            let api_key = config
                .api_key
                .as_ref()
                .ok_or_else(|| Error::ConfigInvalid {
                    field: "api_key".to_string(),
                    message: "API key required for OpenAI provider".to_string(),
                })?;

            let provider = OpenAiProvider::new(
                &config.endpoint,
                api_key,
                &config.model,
                config.max_context_length,
                config.timeout_secs,
                config.temperature,
            );
            Ok(Box::new(provider))
        }
        LlmProvider::Mock => Ok(Box::new(MockProvider::new())),
        LlmProvider::None => Err(Error::Custom("LLM provider is disabled".to_string())),
    }
}

/// Mock provider for testing.
pub struct MockProvider {
    available: bool,
}

impl MockProvider {
    /// Create a new mock provider.
    pub fn new() -> Self {
        Self { available: true }
    }

    /// Set availability for testing.
    pub fn set_available(&mut self, available: bool) {
        self.available = available;
    }
}

impl Default for MockProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl InferenceEngine for MockProvider {
    fn name(&self) -> &str {
        "mock"
    }

    async fn is_available(&self) -> bool {
        self.available
    }

    async fn analyze(
        &self,
        request: super::inference::AnalysisRequest,
    ) -> std::result::Result<super::inference::AnalysisResponse, super::inference::InferenceError>
    {
        use super::inference::*;

        if !self.available {
            return Err(InferenceError::Unavailable("Mock provider disabled".to_string()));
        }

        // Simulate analysis based on content
        let is_suspicious = request.content.to_lowercase().contains("malware")
            || request.content.to_lowercase().contains("virus")
            || request.content.to_lowercase().contains("powershell")
            || request.content.to_lowercase().contains("invoke-expression");

        let (explanation, confidence, classification) = if is_suspicious {
            (
                "Mock analysis: Suspicious patterns detected in the content.".to_string(),
                0.75,
                Some(MalwareClassification {
                    is_malicious: true,
                    intent: ThreatIntent::Unknown,
                    family: None,
                    reasoning: "Mock detection based on keywords".to_string(),
                }),
            )
        } else {
            (
                "Mock analysis: No suspicious patterns detected.".to_string(),
                0.85,
                Some(MalwareClassification {
                    is_malicious: false,
                    intent: ThreatIntent::Benign,
                    family: None,
                    reasoning: "No malicious indicators found".to_string(),
                }),
            )
        };

        Ok(AnalysisResponse::new(explanation, confidence)
            .with_classification(classification.unwrap())
            .with_raw("Mock response".to_string()))
    }

    fn model_name(&self) -> &str {
        "mock-model"
    }

    fn max_context_length(&self) -> usize {
        4096
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_config_default() {
        let config = ProviderConfig::default();
        assert_eq!(config.provider, LlmProvider::Ollama);
        assert_eq!(config.endpoint, "http://localhost:11434");
    }

    #[test]
    fn test_provider_config_ollama() {
        let config = ProviderConfig::ollama("mistral");
        assert_eq!(config.provider, LlmProvider::Ollama);
        assert_eq!(config.model, "mistral");
    }

    #[test]
    fn test_provider_config_openai() {
        let config = ProviderConfig::openai("https://api.openai.com", "sk-xxx", "gpt-4");
        assert_eq!(config.provider, LlmProvider::OpenAi);
        assert_eq!(config.model, "gpt-4");
        assert!(config.api_key.is_some());
    }

    #[test]
    fn test_llm_provider_from_str() {
        assert_eq!(LlmProvider::from_str("ollama"), LlmProvider::Ollama);
        assert_eq!(LlmProvider::from_str("openai"), LlmProvider::OpenAi);
        assert_eq!(LlmProvider::from_str("none"), LlmProvider::None);
    }

    #[tokio::test]
    async fn test_mock_provider() {
        use super::super::inference::*;

        let provider = MockProvider::new();
        assert!(provider.is_available().await);
        assert_eq!(provider.name(), "mock");

        let request = AnalysisRequest {
            analysis_type: AnalysisType::FileAnalysis,
            content: "normal content".to_string(),
            context: None,
            max_tokens: None,
        };

        let response = provider.analyze(request).await.unwrap();
        assert!(response.analyzed);
        assert!(response.classification.is_some());
    }

    #[tokio::test]
    async fn test_mock_provider_suspicious() {
        use super::super::inference::*;

        let provider = MockProvider::new();

        let request = AnalysisRequest {
            analysis_type: AnalysisType::ScriptAnalysis,
            content: "Invoke-Expression malware download".to_string(),
            context: Some("PowerShell".to_string()),
            max_tokens: None,
        };

        let response = provider.analyze(request).await.unwrap();
        assert!(response.analyzed);
        assert!(response.classification.as_ref().unwrap().is_malicious);
    }
}
