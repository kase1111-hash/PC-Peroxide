//! Heuristic detection engine for behavioral and structural analysis.
//!
//! This module provides heuristic-based threat detection through:
//! - PE (Portable Executable) file analysis
//! - Entropy calculation for packing detection
//! - Import table analysis for suspicious APIs
//! - Packer/obfuscation detection
//! - Scoring system for threat assessment

pub mod entropy;
pub mod imports;
pub mod packer;
pub mod pe;
pub mod scoring;

pub use entropy::EntropyAnalyzer;
pub use imports::{ImportAnalyzer, SuspiciousImport};
pub use packer::{PackerDetector, PackerInfo};
pub use pe::{PeAnalyzer, PeInfo};
pub use scoring::{HeuristicResult, HeuristicScorer, ScoreCategory};

use crate::core::error::Result;
use crate::core::types::{Detection, DetectionMethod, Severity, ThreatCategory};
use std::path::Path;

/// Complete heuristic analysis engine.
pub struct HeuristicEngine {
    pe_analyzer: PeAnalyzer,
    entropy_analyzer: EntropyAnalyzer,
    import_analyzer: ImportAnalyzer,
    packer_detector: PackerDetector,
    scorer: HeuristicScorer,
}

impl Default for HeuristicEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl HeuristicEngine {
    /// Create a new heuristic engine with default settings.
    pub fn new() -> Self {
        Self {
            pe_analyzer: PeAnalyzer::new(),
            entropy_analyzer: EntropyAnalyzer::new(),
            import_analyzer: ImportAnalyzer::new(),
            packer_detector: PackerDetector::new(),
            scorer: HeuristicScorer::new(),
        }
    }

    /// Analyze a file and return heuristic results.
    pub fn analyze_file(&self, path: &Path) -> Result<HeuristicResult> {
        // Read file contents
        let data = std::fs::read(path).map_err(|e| {
            crate::core::error::Error::FileRead {
                path: path.to_path_buf(),
                source: e,
            }
        })?;

        self.analyze_bytes(&data, path)
    }

    /// Analyze raw bytes and return heuristic results.
    pub fn analyze_bytes(&self, data: &[u8], path: &Path) -> Result<HeuristicResult> {
        let mut result = HeuristicResult::new(path.to_path_buf());

        // Check if it's a PE file
        if !pe::is_pe(data) {
            // Not a PE file, return clean result
            return Ok(result);
        }

        // Parse PE structure
        if let Ok(pe_info) = self.pe_analyzer.analyze(data) {
            result.pe_info = Some(pe_info.clone());

            // Check for PE header anomalies
            let anomalies = self.pe_analyzer.check_anomalies(&pe_info);
            for anomaly in &anomalies {
                result.add_indicator(anomaly.to_string(), anomaly.score());
            }

            // Analyze imports
            let suspicious_imports = self.import_analyzer.analyze(&pe_info);
            for import in &suspicious_imports {
                result.add_indicator(
                    format!("Suspicious import: {} ({})", import.name, import.risk_level),
                    import.score,
                );
            }
            result.suspicious_imports = suspicious_imports;

            // Detect packers
            if let Some(packer_info) = self.packer_detector.detect(data, &pe_info) {
                result.add_indicator(
                    format!("Packed with: {}", packer_info.name),
                    packer_info.suspicion_score,
                );
                result.packer_info = Some(packer_info);
            }
        }

        // Calculate entropy (works on any file)
        let file_entropy = self.entropy_analyzer.calculate(data);
        result.entropy = file_entropy;

        // Check section entropies if PE
        // Note: Many legitimate compressed/encrypted files have high entropy
        // Only flag very high entropy (>7.5) and with reduced scores
        let section_indicators: Vec<(String, u8)> = result
            .pe_info
            .as_ref()
            .map(|pe_info| {
                pe_info
                    .sections
                    .iter()
                    .filter(|section| section.entropy > 7.5)  // Raised threshold from 7.0 to 7.5
                    .map(|section| {
                        (
                            format!(
                                "Very high entropy section: {} ({:.2})",
                                section.name, section.entropy
                            ),
                            8u8,  // Reduced from 15 to 8
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();

        for (desc, score) in section_indicators {
            result.add_indicator(desc, score);
        }

        // High overall entropy suggests packing/encryption
        // But many legitimate files (compressed assets, encrypted data) have high entropy
        if file_entropy > 7.8 {
            result.add_indicator(
                format!("Very high file entropy: {:.2}", file_entropy),
                10,  // Reduced from 20 to 10
            );
        } else if file_entropy > 7.5 {  // Raised threshold from 7.0 to 7.5
            result.add_indicator(
                format!("High file entropy: {:.2}", file_entropy),
                5,  // Reduced from 10 to 5
            );
        }

        // Calculate final score
        result.score = self.scorer.calculate_score(&result);
        result.category = self.scorer.categorize_score(result.score);

        Ok(result)
    }

    /// Convert heuristic result to a Detection if score is high enough.
    pub fn to_detection(&self, result: &HeuristicResult, threshold: u8) -> Option<Detection> {
        if result.score < threshold {
            return None;
        }

        let severity = match result.category {
            ScoreCategory::Clean => return None,
            ScoreCategory::Suspicious => Severity::Low,
            ScoreCategory::LikelyMalicious => Severity::Medium,
            ScoreCategory::Malicious => Severity::High,
        };

        let category = if result.packer_info.is_some() {
            ThreatCategory::Generic
        } else if result
            .suspicious_imports
            .iter()
            .any(|i| i.category == "ransomware")
        {
            ThreatCategory::Ransomware
        } else if result
            .suspicious_imports
            .iter()
            .any(|i| i.category == "keylogger")
        {
            ThreatCategory::Spyware
        } else if result
            .suspicious_imports
            .iter()
            .any(|i| i.category == "injection")
        {
            ThreatCategory::Trojan
        } else {
            ThreatCategory::Generic
        };

        let description = result
            .indicators
            .iter()
            .take(3)
            .map(|(s, _)| s.as_str())
            .collect::<Vec<_>>()
            .join("; ");

        Some(Detection {
            path: result.path.clone(),
            threat_name: format!("Heuristic.{}", result.category),
            severity,
            category,
            method: DetectionMethod::Heuristic,
            description,
            sha256: None,
            score: result.score,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heuristic_engine_creation() {
        let engine = HeuristicEngine::new();
        assert!(engine.scorer.calculate_score(&HeuristicResult::new("/test".into())) == 0);
    }

    #[test]
    fn test_non_pe_file() {
        let engine = HeuristicEngine::new();
        let data = b"This is not a PE file";
        let result = engine.analyze_bytes(data, Path::new("/test.txt")).unwrap();
        assert_eq!(result.score, 0);
        assert!(result.pe_info.is_none());
    }
}
