//! Ollama LLM provider implementation.
//!
//! Ollama is a local LLM server that can run various open-source models.
//! See: https://ollama.ai/
//!
//! Supported models for malware analysis:
//! - llama3.2 (default, good balance)
//! - mistral (fast, good for scripts)
//! - codellama (specialized for code)
//! - mixtral (larger, more capable)

use super::super::inference::{
    AnalysisRequest, AnalysisResponse, AnalysisType, InferenceEngine, InferenceError,
    MalwareClassification, MitreMapping, ThreatIntent,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Ollama API provider.
pub struct OllamaProvider {
    /// Base URL for Ollama API
    endpoint: String,
    /// Model to use
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

impl OllamaProvider {
    /// Create a new Ollama provider.
    pub fn new(
        endpoint: &str,
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
            model: model.to_string(),
            max_context,
            timeout: Duration::from_secs(timeout_secs),
            temperature,
            client,
        }
    }

    /// Build the generate endpoint URL.
    fn generate_url(&self) -> String {
        format!("{}/api/generate", self.endpoint)
    }

    /// Build the tags endpoint URL (for checking availability).
    fn tags_url(&self) -> String {
        format!("{}/api/tags", self.endpoint)
    }

    /// Parse the LLM response into structured analysis.
    fn parse_response(
        &self,
        raw: &str,
        analysis_type: AnalysisType,
    ) -> (String, f32, Option<MalwareClassification>, Vec<MitreMapping>) {
        let mut confidence = 0.5;
        let mut classification = None;

        // Try to extract structured data from the response
        let lower = raw.to_lowercase();

        // Determine confidence based on response certainty words
        if lower.contains("definitely") || lower.contains("certainly") || lower.contains("clearly") {
            confidence = 0.9;
        } else if lower.contains("likely") || lower.contains("probably") || lower.contains("appears to be") {
            confidence = 0.75;
        } else if lower.contains("possibly") || lower.contains("might be") || lower.contains("could be") {
            confidence = 0.5;
        } else if lower.contains("unlikely") || lower.contains("probably not") {
            confidence = 0.3;
        }

        // Try to detect classification
        if analysis_type == AnalysisType::Classify
            || analysis_type == AnalysisType::FileAnalysis
            || analysis_type == AnalysisType::ScriptAnalysis
        {
            let is_malicious = lower.contains("malicious")
                || lower.contains("malware")
                || lower.contains("suspicious")
                || lower.contains("dangerous");

            let is_benign = lower.contains("benign")
                || lower.contains("safe")
                || lower.contains("clean")
                || lower.contains("legitimate")
                || lower.contains("not malicious");

            let intent = self.detect_intent(&lower);

            if is_malicious && !is_benign {
                classification = Some(MalwareClassification {
                    is_malicious: true,
                    intent,
                    family: self.detect_family(&lower),
                    reasoning: self.extract_reasoning(raw),
                });
            } else if is_benign {
                classification = Some(MalwareClassification {
                    is_malicious: false,
                    intent: ThreatIntent::Benign,
                    family: None,
                    reasoning: self.extract_reasoning(raw),
                });
            }
        }

        // Extract MITRE ATT&CK references
        let mitre_mappings = self.extract_mitre_mappings(raw);

        // Clean up explanation
        let explanation = self.clean_explanation(raw);

        (explanation, confidence, classification, mitre_mappings)
    }

    /// Detect threat intent from response.
    fn detect_intent(&self, lower: &str) -> ThreatIntent {
        if lower.contains("ransomware") || lower.contains("encrypt") && lower.contains("ransom") {
            ThreatIntent::Ransomware
        } else if lower.contains("trojan") {
            ThreatIntent::Trojan
        } else if lower.contains("worm") || lower.contains("self-replicate") {
            ThreatIntent::Worm
        } else if lower.contains("rootkit") {
            ThreatIntent::Rootkit
        } else if lower.contains("backdoor") || lower.contains("remote access") {
            ThreatIntent::Backdoor
        } else if lower.contains("spyware") || lower.contains("steal") && lower.contains("data") {
            ThreatIntent::Spyware
        } else if lower.contains("keylogger") || lower.contains("keystroke") {
            ThreatIntent::Keylogger
        } else if lower.contains("downloader") || lower.contains("download") && lower.contains("payload") {
            ThreatIntent::Downloader
        } else if lower.contains("dropper") {
            ThreatIntent::Dropper
        } else if lower.contains("adware") || lower.contains("advertisement") {
            ThreatIntent::Adware
        } else if lower.contains("pup") || lower.contains("potentially unwanted") {
            ThreatIntent::PotentiallyUnwanted
        } else {
            ThreatIntent::Unknown
        }
    }

    /// Try to detect malware family name.
    fn detect_family(&self, lower: &str) -> Option<String> {
        // Common malware families - expand as needed
        let families = [
            "emotet", "trickbot", "ryuk", "conti", "lockbit", "revil", "sodinokibi",
            "wannacry", "petya", "notpetya", "maze", "dridex", "qbot", "icedid",
            "cobalt strike", "mimikatz", "metasploit", "empire", "covenant",
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
        // Try to find a reasoning section
        let lines: Vec<&str> = raw.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            let lower = line.to_lowercase();
            if lower.contains("reason") || lower.contains("because") || lower.contains("explanation") {
                // Return this line and possibly the next
                if i + 1 < lines.len() {
                    return format!("{} {}", line.trim(), lines[i + 1].trim());
                }
                return line.trim().to_string();
            }
        }

        // Return first meaningful sentence
        raw.lines()
            .find(|l| l.len() > 20)
            .unwrap_or("Analysis complete")
            .trim()
            .to_string()
    }

    /// Extract MITRE ATT&CK technique references.
    fn extract_mitre_mappings(&self, raw: &str) -> Vec<MitreMapping> {
        let mut mappings = Vec::new();

        // Regex-like pattern matching for T#### or T####.###
        let words: Vec<&str> = raw.split_whitespace().collect();

        for (i, word) in words.iter().enumerate() {
            let clean = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '.');

            // Check if it looks like a MITRE technique ID
            if clean.starts_with('T') && clean.len() >= 5 {
                let potential_id = clean.to_string();
                if potential_id
                    .chars()
                    .skip(1)
                    .take(4)
                    .all(|c| c.is_ascii_digit())
                {
                    // Try to get context for technique name
                    let context: String = words
                        .iter()
                        .skip(i.saturating_sub(3))
                        .take(7)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(" ");

                    let (name, tactic) = self.get_mitre_info(&potential_id);

                    mappings.push(MitreMapping {
                        technique_id: potential_id,
                        technique_name: name,
                        tactic,
                        confidence: 0.7,
                        description: Some(context),
                    });
                }
            }
        }

        // Also check for common technique names
        let common_techniques = [
            ("powershell", "T1059.001", "PowerShell", "Execution"),
            ("cmd", "T1059.003", "Windows Command Shell", "Execution"),
            ("scheduled task", "T1053.005", "Scheduled Task", "Persistence"),
            ("registry run", "T1547.001", "Registry Run Keys", "Persistence"),
            ("credential dump", "T1003", "OS Credential Dumping", "Credential Access"),
            ("process injection", "T1055", "Process Injection", "Defense Evasion"),
            ("dll injection", "T1055.001", "DLL Injection", "Defense Evasion"),
        ];

        let lower = raw.to_lowercase();
        for (pattern, id, name, tactic) in common_techniques {
            if lower.contains(pattern) && !mappings.iter().any(|m| m.technique_id == id) {
                mappings.push(MitreMapping {
                    technique_id: id.to_string(),
                    technique_name: name.to_string(),
                    tactic: tactic.to_string(),
                    confidence: 0.6,
                    description: None,
                });
            }
        }

        mappings
    }

    /// Get MITRE technique info from ID.
    fn get_mitre_info(&self, id: &str) -> (String, String) {
        // Basic lookup table - expand as needed
        match id {
            "T1059" => ("Command and Scripting Interpreter".to_string(), "Execution".to_string()),
            "T1059.001" => ("PowerShell".to_string(), "Execution".to_string()),
            "T1059.003" => ("Windows Command Shell".to_string(), "Execution".to_string()),
            "T1059.005" => ("Visual Basic".to_string(), "Execution".to_string()),
            "T1059.006" => ("Python".to_string(), "Execution".to_string()),
            "T1059.007" => ("JavaScript".to_string(), "Execution".to_string()),
            "T1053" => ("Scheduled Task/Job".to_string(), "Persistence".to_string()),
            "T1053.005" => ("Scheduled Task".to_string(), "Persistence".to_string()),
            "T1547.001" => ("Registry Run Keys".to_string(), "Persistence".to_string()),
            "T1003" => ("OS Credential Dumping".to_string(), "Credential Access".to_string()),
            "T1055" => ("Process Injection".to_string(), "Defense Evasion".to_string()),
            "T1055.001" => ("DLL Injection".to_string(), "Defense Evasion".to_string()),
            "T1027" => ("Obfuscated Files".to_string(), "Defense Evasion".to_string()),
            "T1071" => ("Application Layer Protocol".to_string(), "Command and Control".to_string()),
            "T1071.001" => ("Web Protocols".to_string(), "Command and Control".to_string()),
            "T1566" => ("Phishing".to_string(), "Initial Access".to_string()),
            "T1566.001" => ("Spearphishing Attachment".to_string(), "Initial Access".to_string()),
            _ => ("Unknown Technique".to_string(), "Unknown".to_string()),
        }
    }

    /// Clean up explanation text.
    fn clean_explanation(&self, raw: &str) -> String {
        // Remove common prefixes and clean up
        let mut result = raw.to_string();

        let prefixes = [
            "Based on my analysis,",
            "After analyzing the code,",
            "The analysis reveals that",
            "This appears to be",
        ];

        for prefix in prefixes {
            if result.to_lowercase().starts_with(&prefix.to_lowercase()) {
                result = result[prefix.len()..].trim().to_string();
            }
        }

        // Limit length
        if result.len() > 2000 {
            result = format!("{}...", &result[..1997]);
        }

        result
    }
}

/// Ollama generate request.
#[derive(Debug, Serialize)]
struct OllamaRequest {
    model: String,
    prompt: String,
    system: String,
    stream: bool,
    options: OllamaOptions,
}

/// Ollama generation options.
#[derive(Debug, Serialize)]
struct OllamaOptions {
    temperature: f32,
    num_ctx: usize,
}

/// Ollama generate response.
#[derive(Debug, Deserialize)]
struct OllamaResponse {
    response: String,
    #[serde(default)]
    #[allow(dead_code)]
    done: bool,
    #[serde(default)]
    #[allow(dead_code)]
    total_duration: Option<u64>,
    #[serde(default)]
    eval_count: Option<usize>,
}

/// Ollama tags response (for listing models).
#[derive(Debug, Deserialize)]
struct OllamaTagsResponse {
    models: Vec<OllamaModel>,
}

/// Ollama model info.
#[derive(Debug, Deserialize)]
struct OllamaModel {
    name: String,
}

#[async_trait]
impl InferenceEngine for OllamaProvider {
    fn name(&self) -> &str {
        "ollama"
    }

    async fn is_available(&self) -> bool {
        // Check if Ollama is running and has the model
        let result = self
            .client
            .get(self.tags_url())
            .timeout(Duration::from_secs(5))
            .send()
            .await;

        match result {
            Ok(response) if response.status().is_success() => {
                // Check if our model is available
                if let Ok(tags) = response.json::<OllamaTagsResponse>().await {
                    tags.models.iter().any(|m| m.name.starts_with(&self.model))
                } else {
                    true // Ollama is running, model status unknown
                }
            }
            _ => false,
        }
    }

    async fn analyze(&self, request: AnalysisRequest) -> Result<AnalysisResponse, InferenceError> {
        let prompt = request.build_prompt();
        let system = request.analysis_type.system_prompt().to_string();

        let ollama_request = OllamaRequest {
            model: self.model.clone(),
            prompt,
            system,
            stream: false,
            options: OllamaOptions {
                temperature: self.temperature,
                num_ctx: self.max_context,
            },
        };

        let response = self
            .client
            .post(self.generate_url())
            .json(&ollama_request)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    InferenceError::Timeout
                } else if e.is_connect() {
                    InferenceError::ConnectionError(format!("Cannot connect to Ollama: {}", e))
                } else {
                    InferenceError::ConnectionError(e.to_string())
                }
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(InferenceError::ModelError(format!(
                "Ollama returned {}: {}",
                status, body
            )));
        }

        let ollama_response: OllamaResponse = response.json().await.map_err(|e| {
            InferenceError::ParseError(format!("Failed to parse Ollama response: {}", e))
        })?;

        let (explanation, confidence, classification, mitre_mappings) =
            self.parse_response(&ollama_response.response, request.analysis_type);

        let mut result = AnalysisResponse::new(explanation, confidence)
            .with_mitre(mitre_mappings)
            .with_raw(ollama_response.response);

        if let Some(class) = classification {
            result = result.with_classification(class);
        }

        result.tokens_used = ollama_response.eval_count;

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
    fn test_ollama_provider_creation() {
        let provider = OllamaProvider::new(
            "http://localhost:11434",
            "llama3.2",
            16384,
            120,
            0.3,
        );
        assert_eq!(provider.name(), "ollama");
        assert_eq!(provider.model_name(), "llama3.2");
    }

    #[test]
    fn test_detect_intent() {
        let provider = OllamaProvider::new("", "test", 4096, 60, 0.3);

        assert_eq!(
            provider.detect_intent("this is ransomware that encrypts files"),
            ThreatIntent::Ransomware
        );
        assert_eq!(
            provider.detect_intent("trojan horse malware"),
            ThreatIntent::Trojan
        );
        assert_eq!(
            provider.detect_intent("provides remote access backdoor"),
            ThreatIntent::Backdoor
        );
    }

    #[test]
    fn test_extract_mitre_mappings() {
        let provider = OllamaProvider::new("", "test", 4096, 60, 0.3);

        let text = "This uses T1059.001 PowerShell for execution and T1055 process injection";
        let mappings = provider.extract_mitre_mappings(text);

        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|m| m.technique_id == "T1059.001"));
    }

    #[test]
    fn test_detect_family() {
        let provider = OllamaProvider::new("", "test", 4096, 60, 0.3);

        assert_eq!(
            provider.detect_family("this appears to be emotet malware"),
            Some("emotet".to_string())
        );
        assert_eq!(provider.detect_family("generic malware"), None);
    }

    #[test]
    fn test_generate_url() {
        let provider = OllamaProvider::new("http://localhost:11434/", "test", 4096, 60, 0.3);
        assert_eq!(
            provider.generate_url(),
            "http://localhost:11434/api/generate"
        );
    }
}
