//! Core inference engine trait and types.
//!
//! Defines the abstraction for LLM inference providers and the common
//! types used for malware analysis requests and responses.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Error type for inference operations.
#[derive(Debug, Clone)]
pub enum InferenceError {
    /// Provider is not available or not configured
    Unavailable(String),
    /// Network/connection error
    ConnectionError(String),
    /// Invalid request parameters
    InvalidRequest(String),
    /// Model error during inference
    ModelError(String),
    /// Response parsing error
    ParseError(String),
    /// Rate limit exceeded
    RateLimited,
    /// Request timeout
    Timeout,
}

impl fmt::Display for InferenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(msg) => write!(f, "Provider unavailable: {}", msg),
            Self::ConnectionError(msg) => write!(f, "Connection error: {}", msg),
            Self::InvalidRequest(msg) => write!(f, "Invalid request: {}", msg),
            Self::ModelError(msg) => write!(f, "Model error: {}", msg),
            Self::ParseError(msg) => write!(f, "Parse error: {}", msg),
            Self::RateLimited => write!(f, "Rate limit exceeded"),
            Self::Timeout => write!(f, "Request timeout"),
        }
    }
}

impl std::error::Error for InferenceError {}

/// Type of analysis to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnalysisType {
    /// Analyze a file for malware characteristics
    FileAnalysis,
    /// Analyze a script (PowerShell, Python, JS, etc.)
    ScriptAnalysis,
    /// Analyze behavioral logs
    BehaviorAnalysis,
    /// Explain a detected threat
    ExplainThreat,
    /// Deobfuscate and explain obfuscated code
    Deobfuscate,
    /// Map behaviors to MITRE ATT&CK
    MitreMapping,
    /// General malware classification
    Classify,
}

impl AnalysisType {
    /// Get the system prompt for this analysis type.
    pub fn system_prompt(&self) -> &'static str {
        match self {
            Self::FileAnalysis => {
                "You are a malware analyst AI. Analyze the provided file content and determine \
                 if it is malicious. Identify the threat type, intent, and potential impact. \
                 Be concise and technical."
            }
            Self::ScriptAnalysis => {
                "You are a security analyst specializing in script analysis. Examine the \
                 provided script for malicious patterns, obfuscation, suspicious API calls, \
                 and potential threats. Explain what the script does step by step."
            }
            Self::BehaviorAnalysis => {
                "You are a behavioral malware analyst. Analyze the provided system logs or \
                 sandbox output to identify malicious behaviors, persistence mechanisms, \
                 lateral movement, and data exfiltration attempts."
            }
            Self::ExplainThreat => {
                "You are a cybersecurity educator. Explain the detected threat in clear, \
                 understandable terms. Describe what it does, how it spreads, and what \
                 damage it can cause. Provide remediation suggestions."
            }
            Self::Deobfuscate => {
                "You are a reverse engineer specializing in code deobfuscation. Analyze \
                 the obfuscated code and explain its true functionality. Identify encoding \
                 schemes, string obfuscation, and control flow obfuscation techniques."
            }
            Self::MitreMapping => {
                "You are a threat intelligence analyst. Map the observed behaviors to \
                 MITRE ATT&CK techniques. Provide technique IDs (e.g., T1059.001) and \
                 explain how the behavior matches each technique."
            }
            Self::Classify => {
                "You are a malware classifier. Categorize the provided sample into one of: \
                 ransomware, trojan, worm, rootkit, backdoor, spyware, adware, downloader, \
                 dropper, or benign. Provide confidence level and reasoning."
            }
        }
    }

    /// Get the user prompt template for this analysis type.
    pub fn prompt_template(&self) -> &'static str {
        match self {
            Self::FileAnalysis => {
                "Analyze this file for malware:\n\n{context}\n\nContent:\n```\n{content}\n```\n\n\
                 Respond with:\n1. Classification (malicious/suspicious/benign)\n\
                 2. Threat type if malicious\n3. Confidence (0-100)\n4. Brief explanation"
            }
            Self::ScriptAnalysis => {
                "Analyze this {context} script:\n\n```\n{content}\n```\n\n\
                 Identify:\n1. What the script does\n2. Suspicious functions/APIs\n\
                 3. Obfuscation techniques\n4. Malicious indicators\n5. Overall verdict"
            }
            Self::BehaviorAnalysis => {
                "Analyze these behavioral logs:\n\n```\n{content}\n```\n\n\
                 Identify:\n1. Suspicious processes\n2. Network activity\n\
                 3. File system changes\n4. Registry modifications\n\
                 5. Persistence mechanisms\n6. Overall threat assessment"
            }
            Self::ExplainThreat => {
                "Explain this detected threat to a non-technical user:\n\n{content}\n\n\
                 Include:\n1. What it is\n2. How it works\n3. Potential damage\n\
                 4. How to remove it\n5. Prevention tips"
            }
            Self::Deobfuscate => {
                "Deobfuscate and explain this code:\n\n```\n{content}\n```\n\n\
                 Provide:\n1. Deobfuscation technique used\n2. Decoded/decrypted strings\n\
                 3. Actual functionality\n4. Malicious intent if any"
            }
            Self::MitreMapping => {
                "Map these behaviors to MITRE ATT&CK:\n\n{content}\n\n\
                 For each behavior provide:\n1. Technique ID (e.g., T1059.001)\n\
                 2. Technique name\n3. Tactic\n4. Confidence level"
            }
            Self::Classify => {
                "Classify this sample:\n\n{content}\n\n\
                 Respond with JSON:\n{{\n  \"classification\": \"<type>\",\n\
                   \"confidence\": <0-100>,\n  \"family\": \"<optional family name>\",\n\
                   \"reasoning\": \"<brief explanation>\"\n}}"
            }
        }
    }
}

/// Request for LLM analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisRequest {
    /// Type of analysis to perform
    pub analysis_type: AnalysisType,
    /// Content to analyze (code, logs, etc.)
    pub content: String,
    /// Additional context (file path, script type, etc.)
    pub context: Option<String>,
    /// Maximum tokens in response
    pub max_tokens: Option<usize>,
}

impl AnalysisRequest {
    /// Build the full prompt for this request.
    pub fn build_prompt(&self) -> String {
        let template = self.analysis_type.prompt_template();
        let context = self.context.as_deref().unwrap_or("unknown");

        template
            .replace("{content}", &self.content)
            .replace("{context}", context)
    }
}

/// Malware classification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareClassification {
    /// Whether the sample is malicious
    pub is_malicious: bool,
    /// Threat intent/type
    pub intent: ThreatIntent,
    /// Optional malware family name
    pub family: Option<String>,
    /// Classification reasoning
    pub reasoning: String,
}

/// Threat intent categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatIntent {
    /// Encrypts files for ransom
    Ransomware,
    /// Disguised malicious program
    Trojan,
    /// Self-replicating malware
    Worm,
    /// Hides deep in the system
    Rootkit,
    /// Provides remote access
    Backdoor,
    /// Steals information
    Spyware,
    /// Records keystrokes
    Keylogger,
    /// Downloads additional malware
    Downloader,
    /// Installs other malware
    Dropper,
    /// Displays unwanted ads
    Adware,
    /// Potentially unwanted program
    PotentiallyUnwanted,
    /// Unknown malicious intent
    Unknown,
    /// Not malicious
    Benign,
}

impl std::str::FromStr for ThreatIntent {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "ransomware" => Self::Ransomware,
            "trojan" => Self::Trojan,
            "worm" => Self::Worm,
            "rootkit" => Self::Rootkit,
            "backdoor" => Self::Backdoor,
            "spyware" => Self::Spyware,
            "keylogger" => Self::Keylogger,
            "downloader" => Self::Downloader,
            "dropper" => Self::Dropper,
            "adware" => Self::Adware,
            "pup" | "potentially unwanted" | "pua" => Self::PotentiallyUnwanted,
            "benign" | "clean" | "safe" => Self::Benign,
            _ => Self::Unknown,
        })
    }
}

impl fmt::Display for ThreatIntent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ransomware => write!(f, "Ransomware"),
            Self::Trojan => write!(f, "Trojan"),
            Self::Worm => write!(f, "Worm"),
            Self::Rootkit => write!(f, "Rootkit"),
            Self::Backdoor => write!(f, "Backdoor"),
            Self::Spyware => write!(f, "Spyware"),
            Self::Keylogger => write!(f, "Keylogger"),
            Self::Downloader => write!(f, "Downloader"),
            Self::Dropper => write!(f, "Dropper"),
            Self::Adware => write!(f, "Adware"),
            Self::PotentiallyUnwanted => write!(f, "PUP"),
            Self::Unknown => write!(f, "Unknown"),
            Self::Benign => write!(f, "Benign"),
        }
    }
}

/// MITRE ATT&CK technique mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreMapping {
    /// Technique ID (e.g., T1059.001)
    pub technique_id: String,
    /// Technique name
    pub technique_name: String,
    /// Tactic (e.g., Execution, Persistence)
    pub tactic: String,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f32,
    /// Description of how the behavior matches
    pub description: Option<String>,
}

/// Response from LLM analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResponse {
    /// Whether analysis was performed
    pub analyzed: bool,
    /// Overall confidence in the analysis (0.0 - 1.0)
    pub confidence: f32,
    /// Human-readable explanation
    pub explanation: String,
    /// Malware classification if applicable
    pub classification: Option<MalwareClassification>,
    /// MITRE ATT&CK mappings
    pub mitre_mappings: Vec<MitreMapping>,
    /// Raw model response (for debugging)
    pub raw_response: Option<String>,
    /// Tokens used in request/response
    pub tokens_used: Option<usize>,
}

impl AnalysisResponse {
    /// Create a response indicating analysis is unavailable.
    pub fn unavailable() -> Self {
        Self {
            analyzed: false,
            confidence: 0.0,
            explanation: "LLM analysis not available.".to_string(),
            classification: None,
            mitre_mappings: Vec::new(),
            raw_response: None,
            tokens_used: None,
        }
    }

    /// Create a new analyzed response.
    pub fn new(explanation: String, confidence: f32) -> Self {
        Self {
            analyzed: true,
            confidence,
            explanation,
            classification: None,
            mitre_mappings: Vec::new(),
            raw_response: None,
            tokens_used: None,
        }
    }

    /// Add classification to response.
    pub fn with_classification(mut self, classification: MalwareClassification) -> Self {
        self.classification = Some(classification);
        self
    }

    /// Add MITRE mappings to response.
    pub fn with_mitre(mut self, mappings: Vec<MitreMapping>) -> Self {
        self.mitre_mappings = mappings;
        self
    }

    /// Set raw response for debugging.
    pub fn with_raw(mut self, raw: String) -> Self {
        self.raw_response = Some(raw);
        self
    }
}

/// Trait for LLM inference providers.
///
/// Implementations should handle:
/// - Connection management
/// - Request formatting for the specific provider
/// - Response parsing
/// - Error handling
#[async_trait]
pub trait InferenceEngine: Send + Sync {
    /// Get the provider name.
    fn name(&self) -> &str;

    /// Check if the provider is available and ready.
    async fn is_available(&self) -> bool;

    /// Perform malware analysis on the given request.
    async fn analyze(&self, request: AnalysisRequest) -> Result<AnalysisResponse, InferenceError>;

    /// Get the model name/identifier being used.
    fn model_name(&self) -> &str;

    /// Get the maximum context length supported.
    fn max_context_length(&self) -> usize;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analysis_type_prompts() {
        let file_analysis = AnalysisType::FileAnalysis;
        assert!(!file_analysis.system_prompt().is_empty());
        assert!(file_analysis.prompt_template().contains("{content}"));
    }

    #[test]
    fn test_threat_intent_from_str() {
        assert_eq!(
            "ransomware".parse::<ThreatIntent>().unwrap(),
            ThreatIntent::Ransomware
        );
        assert_eq!(
            "TROJAN".parse::<ThreatIntent>().unwrap(),
            ThreatIntent::Trojan
        );
        assert_eq!(
            "benign".parse::<ThreatIntent>().unwrap(),
            ThreatIntent::Benign
        );
        assert_eq!(
            "unknown_type".parse::<ThreatIntent>().unwrap(),
            ThreatIntent::Unknown
        );
    }

    #[test]
    fn test_analysis_request_build_prompt() {
        let request = AnalysisRequest {
            analysis_type: AnalysisType::ScriptAnalysis,
            content: "print('hello')".to_string(),
            context: Some("Python".to_string()),
            max_tokens: Some(1000),
        };

        let prompt = request.build_prompt();
        assert!(prompt.contains("print('hello')"));
        assert!(prompt.contains("Python"));
    }

    #[test]
    fn test_analysis_response_builder() {
        let response = AnalysisResponse::new("Test explanation".to_string(), 0.85)
            .with_classification(MalwareClassification {
                is_malicious: true,
                intent: ThreatIntent::Trojan,
                family: Some("GenericTrojan".to_string()),
                reasoning: "Suspicious behavior".to_string(),
            })
            .with_mitre(vec![MitreMapping {
                technique_id: "T1059.001".to_string(),
                technique_name: "PowerShell".to_string(),
                tactic: "Execution".to_string(),
                confidence: 0.9,
                description: None,
            }]);

        assert!(response.analyzed);
        assert_eq!(response.confidence, 0.85);
        assert!(response.classification.is_some());
        assert_eq!(response.mitre_mappings.len(), 1);
    }

    #[test]
    fn test_inference_error_display() {
        let err = InferenceError::ConnectionError("timeout".to_string());
        assert!(err.to_string().contains("timeout"));
    }
}
