//! OpenAI-compatible API provider implementation.
//!
//! Supports:
//! - OpenAI API (https://api.openai.com/v1)
//! - Azure OpenAI
//! - Any OpenAI-compatible endpoint (LocalAI, text-generation-webui, etc.)
//!
//! Recommended models:
//! - gpt-4-turbo (best reasoning, expensive)
//! - gpt-4o-mini (good balance)
//! - gpt-3.5-turbo (fast, cheaper)

use super::super::inference::{
    AnalysisRequest, AnalysisResponse, AnalysisType, InferenceEngine, InferenceError,
    MalwareClassification, MitreMapping, ThreatIntent,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// OpenAI-compatible API provider.
pub struct OpenAiProvider {
    /// API endpoint URL
    endpoint: String,
    /// API key
    api_key: String,
    /// Model identifier
    model: String,
    /// Maximum context length
    max_context: usize,
    /// Request timeout
    timeout: Duration,
    /// Temperature for generation
    temperature: f32,
    /// HTTP client
    client: reqwest::Client,
}

impl OpenAiProvider {
    /// Create a new OpenAI provider.
    pub fn new(
        endpoint: &str,
        api_key: &str,
        model: &str,
        max_context: usize,
        timeout_secs: u64,
        temperature: f32,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .unwrap_or_default();

        Self {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            api_key: api_key.to_string(),
            model: model.to_string(),
            max_context,
            timeout: Duration::from_secs(timeout_secs),
            temperature,
            client,
        }
    }

    /// Build the chat completions endpoint URL.
    fn completions_url(&self) -> String {
        if self.endpoint.ends_with("/v1") {
            format!("{}/chat/completions", self.endpoint)
        } else {
            format!("{}/v1/chat/completions", self.endpoint)
        }
    }

    /// Build the models endpoint URL.
    fn models_url(&self) -> String {
        if self.endpoint.ends_with("/v1") {
            format!("{}/models", self.endpoint)
        } else {
            format!("{}/v1/models", self.endpoint)
        }
    }

    /// Parse the LLM response into structured analysis.
    fn parse_response(
        &self,
        raw: &str,
        analysis_type: AnalysisType,
    ) -> (
        String,
        f32,
        Option<MalwareClassification>,
        Vec<MitreMapping>,
    ) {
        let mut explanation = raw.to_string();
        let mut confidence = 0.5;
        let mut classification = None;

        let lower = raw.to_lowercase();

        // Determine confidence based on response certainty
        if lower.contains("definitely")
            || lower.contains("certainly")
            || lower.contains("clearly malicious")
        {
            confidence = 0.95;
        } else if lower.contains("highly likely")
            || lower.contains("strong indicators")
            || lower.contains("appears to be malicious")
        {
            confidence = 0.85;
        } else if lower.contains("likely") || lower.contains("probably") {
            confidence = 0.7;
        } else if lower.contains("possibly") || lower.contains("might be") {
            confidence = 0.5;
        } else if lower.contains("unlikely") || lower.contains("probably benign") {
            confidence = 0.3;
        } else if lower.contains("safe") || lower.contains("benign") || lower.contains("clean") {
            confidence = 0.85;
        }

        // Try to parse JSON response (GPT models often format nicely)
        if let Some(json_start) = raw.find('{') {
            if let Some(json_end) = raw.rfind('}') {
                let json_str = &raw[json_start..=json_end];
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(json_str) {
                    // Extract classification from JSON
                    if let Some(class_str) = parsed.get("classification").and_then(|v| v.as_str()) {
                        let is_malicious = !["benign", "clean", "safe"]
                            .iter()
                            .any(|s| class_str.to_lowercase().contains(s));

                        classification = Some(MalwareClassification {
                            is_malicious,
                            intent: class_str.parse().unwrap_or(ThreatIntent::Unknown),
                            family: parsed
                                .get("family")
                                .and_then(|v| v.as_str())
                                .map(String::from),
                            reasoning: parsed
                                .get("reasoning")
                                .and_then(|v| v.as_str())
                                .unwrap_or("Based on analysis")
                                .to_string(),
                        });
                    }

                    // Extract confidence from JSON
                    if let Some(conf) = parsed.get("confidence").and_then(|v| v.as_f64()) {
                        confidence = (conf as f32) / 100.0; // Normalize if 0-100
                        if confidence > 1.0 {
                            confidence = conf as f32 / 100.0;
                        }
                    }
                }
            }
        }

        // Fallback classification for non-JSON responses
        if classification.is_none()
            && (analysis_type == AnalysisType::Classify
                || analysis_type == AnalysisType::FileAnalysis
                || analysis_type == AnalysisType::ScriptAnalysis)
        {
            let is_malicious = lower.contains("malicious")
                || lower.contains("malware")
                || (lower.contains("suspicious") && !lower.contains("not suspicious"));

            let is_benign = lower.contains("benign")
                || lower.contains("safe")
                || lower.contains("clean")
                || lower.contains("legitimate")
                || lower.contains("not malicious");

            if is_malicious || is_benign {
                classification = Some(MalwareClassification {
                    is_malicious: is_malicious && !is_benign,
                    intent: self.detect_intent(&lower),
                    family: self.detect_family(&lower),
                    reasoning: self.extract_reasoning(raw),
                });
            }
        }

        // Extract MITRE ATT&CK references
        let mitre_mappings = self.extract_mitre_mappings(raw);

        // Clean explanation - use char-based truncation to avoid panic on UTF-8 boundaries
        if explanation.chars().count() > 2000 {
            explanation = format!("{}...", explanation.chars().take(1997).collect::<String>());
        }

        (explanation, confidence, classification, mitre_mappings)
    }

    /// Detect threat intent from response text.
    fn detect_intent(&self, lower: &str) -> ThreatIntent {
        if lower.contains("ransomware") {
            ThreatIntent::Ransomware
        } else if lower.contains("backdoor")
            || lower.contains("remote access trojan")
            || lower.contains("rat")
        {
            // Check for backdoor/RAT before generic trojan (RAT contains "trojan")
            ThreatIntent::Backdoor
        } else if lower.contains("trojan") {
            ThreatIntent::Trojan
        } else if lower.contains("worm") {
            ThreatIntent::Worm
        } else if lower.contains("rootkit") {
            ThreatIntent::Rootkit
        } else if lower.contains("spyware")
            || lower.contains("info stealer")
            || lower.contains("infostealer")
        {
            ThreatIntent::Spyware
        } else if lower.contains("keylogger") {
            ThreatIntent::Keylogger
        } else if lower.contains("downloader") {
            ThreatIntent::Downloader
        } else if lower.contains("dropper") {
            ThreatIntent::Dropper
        } else if lower.contains("adware") {
            ThreatIntent::Adware
        } else if lower.contains("pup") || lower.contains("potentially unwanted") {
            ThreatIntent::PotentiallyUnwanted
        } else if lower.contains("benign") || lower.contains("safe") || lower.contains("clean") {
            ThreatIntent::Benign
        } else {
            ThreatIntent::Unknown
        }
    }

    /// Detect malware family from response.
    fn detect_family(&self, lower: &str) -> Option<String> {
        let families = [
            "emotet",
            "trickbot",
            "ryuk",
            "conti",
            "lockbit",
            "revil",
            "sodinokibi",
            "wannacry",
            "petya",
            "notpetya",
            "maze",
            "dridex",
            "qbot",
            "icedid",
            "cobalt strike",
            "mimikatz",
            "asyncrat",
            "remcos",
            "njrat",
            "agent tesla",
        ];

        for family in families {
            if lower.contains(family) {
                return Some(family.to_string());
            }
        }
        None
    }

    /// Extract reasoning from response.
    fn extract_reasoning(&self, raw: &str) -> String {
        let lines: Vec<&str> = raw.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            let lower = line.to_lowercase();
            if lower.contains("reason")
                || lower.contains("because")
                || lower.contains("this is")
                || lower.contains("the script")
            {
                if i + 1 < lines.len() {
                    return format!("{} {}", line.trim(), lines[i + 1].trim());
                }
                return line.trim().to_string();
            }
        }

        raw.lines()
            .find(|l| l.len() > 30)
            .unwrap_or("Analysis complete")
            .trim()
            .chars()
            .take(200)
            .collect()
    }

    /// Extract MITRE ATT&CK technique references.
    fn extract_mitre_mappings(&self, raw: &str) -> Vec<MitreMapping> {
        let mut mappings = Vec::new();

        // Look for T#### patterns
        for word in raw.split_whitespace() {
            let clean = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '.');

            if clean.starts_with('T')
                && clean.len() >= 5
                && clean.chars().skip(1).take(4).all(|c| c.is_ascii_digit())
            {
                let id = clean.to_string();
                if !mappings.iter().any(|m: &MitreMapping| m.technique_id == id) {
                    let (name, tactic) = self.get_mitre_info(&id);
                    mappings.push(MitreMapping {
                        technique_id: id,
                        technique_name: name,
                        tactic,
                        confidence: 0.8,
                        description: None,
                    });
                }
            }
        }

        mappings
    }

    /// Get MITRE technique info.
    fn get_mitre_info(&self, id: &str) -> (String, String) {
        match id {
            "T1059" => (
                "Command and Scripting Interpreter".to_string(),
                "Execution".to_string(),
            ),
            "T1059.001" => ("PowerShell".to_string(), "Execution".to_string()),
            "T1059.003" => ("Windows Command Shell".to_string(), "Execution".to_string()),
            "T1059.005" => ("Visual Basic".to_string(), "Execution".to_string()),
            "T1059.006" => ("Python".to_string(), "Execution".to_string()),
            "T1059.007" => ("JavaScript".to_string(), "Execution".to_string()),
            "T1053.005" => ("Scheduled Task".to_string(), "Persistence".to_string()),
            "T1547.001" => ("Registry Run Keys".to_string(), "Persistence".to_string()),
            "T1003" => (
                "OS Credential Dumping".to_string(),
                "Credential Access".to_string(),
            ),
            "T1055" => (
                "Process Injection".to_string(),
                "Defense Evasion".to_string(),
            ),
            "T1027" => (
                "Obfuscated Files".to_string(),
                "Defense Evasion".to_string(),
            ),
            "T1071.001" => (
                "Web Protocols".to_string(),
                "Command and Control".to_string(),
            ),
            "T1566.001" => (
                "Spearphishing Attachment".to_string(),
                "Initial Access".to_string(),
            ),
            "T1486" => (
                "Data Encrypted for Impact".to_string(),
                "Impact".to_string(),
            ),
            _ => ("Unknown Technique".to_string(), "Unknown".to_string()),
        }
    }
}

/// OpenAI chat completion request.
#[derive(Debug, Serialize)]
struct ChatCompletionRequest {
    model: String,
    messages: Vec<ChatMessage>,
    temperature: f32,
    max_tokens: Option<usize>,
}

/// Chat message.
#[derive(Debug, Serialize, Deserialize)]
struct ChatMessage {
    role: String,
    content: String,
}

/// OpenAI chat completion response.
#[derive(Debug, Deserialize)]
struct ChatCompletionResponse {
    choices: Vec<ChatChoice>,
    usage: Option<ChatUsage>,
}

/// Chat choice.
#[derive(Debug, Deserialize)]
struct ChatChoice {
    message: ChatMessage,
}

/// Token usage.
#[derive(Debug, Deserialize)]
struct ChatUsage {
    total_tokens: usize,
}

/// Models list response.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ModelsResponse {
    data: Vec<ModelInfo>,
}

/// Model info.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ModelInfo {
    id: String,
}

#[async_trait]
impl InferenceEngine for OpenAiProvider {
    fn name(&self) -> &str {
        "openai"
    }

    async fn is_available(&self) -> bool {
        let result = self
            .client
            .get(self.models_url())
            .header("Authorization", format!("Bearer {}", self.api_key))
            .timeout(Duration::from_secs(10))
            .send()
            .await;

        match result {
            Ok(response) => response.status().is_success(),
            Err(_) => false,
        }
    }

    async fn analyze(&self, request: AnalysisRequest) -> Result<AnalysisResponse, InferenceError> {
        let prompt = request.build_prompt();
        let system = request.analysis_type.system_prompt().to_string();

        let chat_request = ChatCompletionRequest {
            model: self.model.clone(),
            messages: vec![
                ChatMessage {
                    role: "system".to_string(),
                    content: system,
                },
                ChatMessage {
                    role: "user".to_string(),
                    content: prompt,
                },
            ],
            temperature: self.temperature,
            max_tokens: request.max_tokens,
        };

        let response = self
            .client
            .post(self.completions_url())
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&chat_request)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    InferenceError::Timeout
                } else if e.is_connect() {
                    InferenceError::ConnectionError(format!("Cannot connect to API: {}", e))
                } else {
                    InferenceError::ConnectionError(e.to_string())
                }
            })?;

        let status = response.status();

        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(InferenceError::RateLimited);
        }

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(InferenceError::ModelError(format!(
                "API returned {}: {}",
                status, body
            )));
        }

        let chat_response: ChatCompletionResponse = response.json().await.map_err(|e| {
            InferenceError::ParseError(format!("Failed to parse API response: {}", e))
        })?;

        let raw_text = chat_response
            .choices
            .first()
            .map(|c| c.message.content.clone())
            .unwrap_or_default();

        let (explanation, confidence, classification, mitre_mappings) =
            self.parse_response(&raw_text, request.analysis_type);

        let mut result = AnalysisResponse::new(explanation, confidence)
            .with_mitre(mitre_mappings)
            .with_raw(raw_text);

        if let Some(class) = classification {
            result = result.with_classification(class);
        }

        result.tokens_used = chat_response.usage.map(|u| u.total_tokens);

        Ok(result)
    }

    fn model_name(&self) -> &str {
        &self.model
    }

    fn max_context_length(&self) -> usize {
        self.max_context
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openai_provider_creation() {
        let provider = OpenAiProvider::new(
            "https://api.openai.com",
            "sk-test",
            "gpt-4",
            16384,
            120,
            0.3,
        );
        assert_eq!(provider.name(), "openai");
        assert_eq!(provider.model_name(), "gpt-4");
    }

    #[test]
    fn test_completions_url() {
        let provider = OpenAiProvider::new(
            "https://api.openai.com/v1",
            "sk-test",
            "gpt-4",
            16384,
            120,
            0.3,
        );
        assert_eq!(
            provider.completions_url(),
            "https://api.openai.com/v1/chat/completions"
        );
    }

    #[test]
    fn test_detect_intent() {
        let provider = OpenAiProvider::new("", "key", "model", 4096, 60, 0.3);

        assert_eq!(
            provider.detect_intent("this is ransomware"),
            ThreatIntent::Ransomware
        );
        assert_eq!(
            provider.detect_intent("remote access trojan rat"),
            ThreatIntent::Backdoor
        );
        assert_eq!(
            provider.detect_intent("file is safe and benign"),
            ThreatIntent::Benign
        );
    }

    #[test]
    fn test_parse_json_response() {
        let provider = OpenAiProvider::new("", "key", "model", 4096, 60, 0.3);

        let json_response = r#"
Based on my analysis:
{
  "classification": "trojan",
  "confidence": 85,
  "family": "emotet",
  "reasoning": "Contains suspicious network calls"
}
"#;

        let (_, confidence, classification, _) =
            provider.parse_response(json_response, AnalysisType::Classify);

        assert!(confidence > 0.8);
        assert!(classification.is_some());
        let class = classification.unwrap();
        assert!(class.is_malicious);
        assert_eq!(class.family, Some("emotet".to_string()));
    }
}
