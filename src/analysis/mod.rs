//! LLM-powered malware analysis module.
//!
//! This module provides AI-enhanced analysis capabilities for malware detection:
//! - Code analysis and intent classification
//! - Behavioral log interpretation
//! - Script deobfuscation explanations
//! - MITRE ATT&CK TTP mapping
//! - Human-readable threat explanations
//!
//! Supports multiple inference backends:
//! - Local models via Ollama
//! - OpenAI-compatible APIs
//! - Direct local inference (future)

pub mod inference;
pub mod providers;

pub use inference::{
    AnalysisRequest, AnalysisResponse, AnalysisType, InferenceEngine, InferenceError,
    MalwareClassification, MitreMapping, ThreatIntent,
};
pub use providers::{create_provider, LlmProvider, ProviderConfig};

use crate::core::error::Result;
use crate::core::types::{Detection, Severity, ThreatCategory};
use std::path::Path;

/// LLM-based malware analyzer.
pub struct MalwareAnalyzer {
    /// The inference engine provider
    provider: Box<dyn InferenceEngine>,
    /// Whether analysis is enabled
    enabled: bool,
    /// Confidence threshold for reporting
    confidence_threshold: f32,
}

impl MalwareAnalyzer {
    /// Create a new malware analyzer with the given provider.
    pub fn new(provider: Box<dyn InferenceEngine>, confidence_threshold: f32) -> Self {
        Self {
            provider,
            enabled: true,
            confidence_threshold,
        }
    }

    /// Create an analyzer from configuration.
    pub fn from_config(config: &ProviderConfig) -> Result<Self> {
        let provider = create_provider(config)?;
        Ok(Self::new(provider, config.confidence_threshold))
    }

    /// Check if the analyzer is available and ready.
    pub async fn is_available(&self) -> bool {
        self.enabled && self.provider.is_available().await
    }

    /// Analyze a suspicious file for malware characteristics.
    pub async fn analyze_file(&self, path: &Path, content: &str) -> Result<AnalysisResponse> {
        if !self.enabled {
            return Ok(AnalysisResponse::unavailable());
        }

        let request = AnalysisRequest {
            analysis_type: AnalysisType::FileAnalysis,
            content: content.to_string(),
            context: Some(format!("File: {}", path.display())),
            max_tokens: Some(1024),
        };

        self.provider
            .analyze(request)
            .await
            .map_err(|e| crate::core::error::Error::Custom(e.to_string()))
    }

    /// Analyze a script (PowerShell, Python, JavaScript, etc.).
    pub async fn analyze_script(
        &self,
        script_type: &str,
        content: &str,
    ) -> Result<AnalysisResponse> {
        if !self.enabled {
            return Ok(AnalysisResponse::unavailable());
        }

        let request = AnalysisRequest {
            analysis_type: AnalysisType::ScriptAnalysis,
            content: content.to_string(),
            context: Some(format!("Script type: {}", script_type)),
            max_tokens: Some(1500),
        };

        self.provider
            .analyze(request)
            .await
            .map_err(|e| crate::core::error::Error::Custom(e.to_string()))
    }

    /// Analyze behavioral logs from sandbox or EDR.
    pub async fn analyze_behavior(&self, logs: &str) -> Result<AnalysisResponse> {
        if !self.enabled {
            return Ok(AnalysisResponse::unavailable());
        }

        let request = AnalysisRequest {
            analysis_type: AnalysisType::BehaviorAnalysis,
            content: logs.to_string(),
            context: None,
            max_tokens: Some(2000),
        };

        self.provider
            .analyze(request)
            .await
            .map_err(|e| crate::core::error::Error::Custom(e.to_string()))
    }

    /// Explain a detection in human-readable terms.
    pub async fn explain_detection(&self, detection: &Detection) -> Result<String> {
        if !self.enabled {
            return Ok("LLM analysis not available.".to_string());
        }

        let content = format!(
            "Threat: {}\nCategory: {:?}\nSeverity: {:?}\nPath: {}\nDescription: {}",
            detection.threat_name,
            detection.category,
            detection.severity,
            detection.path.display(),
            detection.description
        );

        let request = AnalysisRequest {
            analysis_type: AnalysisType::ExplainThreat,
            content,
            context: None,
            max_tokens: Some(512),
        };

        let response = self
            .provider
            .analyze(request)
            .await
            .map_err(|e| crate::core::error::Error::Custom(e.to_string()))?;

        Ok(response.explanation)
    }

    /// Enhance a detection with LLM analysis.
    pub async fn enhance_detection(&self, detection: &mut Detection) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        // Read file content if it exists and is small enough
        let content = if detection.path.exists() {
            let metadata = std::fs::metadata(&detection.path).ok();
            if metadata.map(|m| m.len() < 100_000).unwrap_or(false) {
                std::fs::read_to_string(&detection.path).ok()
            } else {
                None
            }
        } else {
            None
        };

        let analysis_content = content.unwrap_or_else(|| detection.description.clone());

        let response = self.analyze_file(&detection.path, &analysis_content).await?;

        // Update detection with LLM insights if confidence is high enough
        if response.confidence >= self.confidence_threshold {
            // Enhance description with LLM explanation
            if !response.explanation.is_empty() {
                detection.description = format!(
                    "{}\n\nAI Analysis: {}",
                    detection.description, response.explanation
                );
            }

            // Update severity if LLM suggests higher
            if let Some(ref classification) = response.classification {
                let llm_severity = intent_to_severity(&classification.intent);
                if llm_severity > detection.severity {
                    detection.severity = llm_severity;
                }

                // Update category if more specific
                if let Some(category) = intent_to_category(&classification.intent) {
                    detection.category = category;
                }
            }

            // Add MITRE ATT&CK info to description
            if !response.mitre_mappings.is_empty() {
                let ttps: Vec<String> = response
                    .mitre_mappings
                    .iter()
                    .map(|m| format!("{}: {}", m.technique_id, m.technique_name))
                    .collect();
                detection.description = format!(
                    "{}\n\nMITRE ATT&CK: {}",
                    detection.description,
                    ttps.join(", ")
                );
            }
        }

        Ok(())
    }

    /// Enable or disable the analyzer.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Get the current provider name.
    pub fn provider_name(&self) -> &str {
        self.provider.name()
    }
}

/// Convert threat intent to severity level.
fn intent_to_severity(intent: &ThreatIntent) -> Severity {
    match intent {
        ThreatIntent::Ransomware => Severity::Critical,
        ThreatIntent::Rootkit => Severity::Critical,
        ThreatIntent::Backdoor => Severity::Critical,
        ThreatIntent::Worm => Severity::High,
        ThreatIntent::Trojan => Severity::High,
        ThreatIntent::Spyware => Severity::High,
        ThreatIntent::Keylogger => Severity::High,
        ThreatIntent::Downloader => Severity::Medium,
        ThreatIntent::Dropper => Severity::Medium,
        ThreatIntent::Adware => Severity::Low,
        ThreatIntent::PotentiallyUnwanted => Severity::Low,
        ThreatIntent::Unknown => Severity::Medium,
        ThreatIntent::Benign => Severity::Low,
    }
}

/// Convert threat intent to category.
fn intent_to_category(intent: &ThreatIntent) -> Option<ThreatCategory> {
    match intent {
        ThreatIntent::Ransomware => Some(ThreatCategory::Ransomware),
        ThreatIntent::Trojan => Some(ThreatCategory::Trojan),
        ThreatIntent::Worm => Some(ThreatCategory::Worm),
        ThreatIntent::Rootkit => Some(ThreatCategory::Rootkit),
        ThreatIntent::Backdoor => Some(ThreatCategory::Backdoor),
        ThreatIntent::Spyware => Some(ThreatCategory::Spyware),
        ThreatIntent::Keylogger => Some(ThreatCategory::Spyware),
        ThreatIntent::Adware => Some(ThreatCategory::Adware),
        ThreatIntent::PotentiallyUnwanted => Some(ThreatCategory::Pup),
        ThreatIntent::Downloader => Some(ThreatCategory::Trojan),
        ThreatIntent::Dropper => Some(ThreatCategory::Trojan),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intent_to_severity() {
        assert_eq!(intent_to_severity(&ThreatIntent::Ransomware), Severity::Critical);
        assert_eq!(intent_to_severity(&ThreatIntent::Adware), Severity::Low);
        assert_eq!(intent_to_severity(&ThreatIntent::Unknown), Severity::Medium);
    }

    #[test]
    fn test_intent_to_category() {
        assert_eq!(
            intent_to_category(&ThreatIntent::Ransomware),
            Some(ThreatCategory::Ransomware)
        );
        assert_eq!(intent_to_category(&ThreatIntent::Benign), None);
    }
}
