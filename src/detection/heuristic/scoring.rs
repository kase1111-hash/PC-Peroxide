//! Heuristic scoring system for threat assessment.
//!
//! Scoring thresholds:
//! - 0-20: Clean
//! - 21-50: Suspicious (flag for review)
//! - 51-80: Likely Malicious
//! - 81-100: Confirmed Malicious

use super::imports::SuspiciousImport;
use super::packer::PackerInfo;
use super::pe::PeInfo;
use std::path::PathBuf;

/// Score category based on heuristic analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScoreCategory {
    /// Score 0-20: No suspicious indicators
    Clean,
    /// Score 21-50: Some suspicious indicators, needs review
    Suspicious,
    /// Score 51-80: High likelihood of being malicious
    LikelyMalicious,
    /// Score 81-100: Almost certainly malicious
    Malicious,
}

impl std::fmt::Display for ScoreCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScoreCategory::Clean => write!(f, "Clean"),
            ScoreCategory::Suspicious => write!(f, "Suspicious"),
            ScoreCategory::LikelyMalicious => write!(f, "LikelyMalicious"),
            ScoreCategory::Malicious => write!(f, "Malicious"),
        }
    }
}

/// Complete heuristic analysis result.
#[derive(Debug, Clone)]
pub struct HeuristicResult {
    /// File path analyzed
    pub path: PathBuf,
    /// Final heuristic score (0-100)
    pub score: u8,
    /// Score category
    pub category: ScoreCategory,
    /// PE information (if applicable)
    pub pe_info: Option<PeInfo>,
    /// File entropy
    pub entropy: f64,
    /// Detected packer
    pub packer_info: Option<PackerInfo>,
    /// Suspicious imports found
    pub suspicious_imports: Vec<SuspiciousImport>,
    /// Individual indicators and their scores
    pub indicators: Vec<(String, u8)>,
}

impl HeuristicResult {
    /// Create a new empty heuristic result.
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            score: 0,
            category: ScoreCategory::Clean,
            pe_info: None,
            entropy: 0.0,
            packer_info: None,
            suspicious_imports: Vec::new(),
            indicators: Vec::new(),
        }
    }

    /// Add an indicator with its score.
    pub fn add_indicator(&mut self, description: String, score: u8) {
        self.indicators.push((description, score));
    }

    /// Get summary of findings.
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();

        parts.push(format!("Score: {} ({})", self.score, self.category));

        if let Some(ref packer) = self.packer_info {
            parts.push(format!("Packer: {}", packer.name));
        }

        if !self.suspicious_imports.is_empty() {
            parts.push(format!(
                "Suspicious APIs: {}",
                self.suspicious_imports.len()
            ));
        }

        if self.entropy > 7.0 {
            parts.push(format!("High entropy: {:.2}", self.entropy));
        }

        parts.join(", ")
    }
}

/// Heuristic scoring engine.
pub struct HeuristicScorer {
    /// Weight for PE anomalies
    pe_anomaly_weight: f32,
    /// Weight for suspicious imports
    import_weight: f32,
    /// Weight for packer detection
    packer_weight: f32,
    /// Weight for entropy analysis
    entropy_weight: f32,
    /// Score cap (maximum score possible)
    score_cap: u8,
}

impl Default for HeuristicScorer {
    fn default() -> Self {
        Self::new()
    }
}

impl HeuristicScorer {
    /// Create a new heuristic scorer with default weights.
    pub fn new() -> Self {
        Self {
            pe_anomaly_weight: 1.0,
            import_weight: 1.0,
            packer_weight: 1.0,
            entropy_weight: 0.8,
            score_cap: 100,
        }
    }

    /// Create a scorer with custom weights.
    pub fn with_weights(
        pe_anomaly_weight: f32,
        import_weight: f32,
        packer_weight: f32,
        entropy_weight: f32,
    ) -> Self {
        Self {
            pe_anomaly_weight,
            import_weight,
            packer_weight,
            entropy_weight,
            score_cap: 100,
        }
    }

    /// Calculate the final heuristic score.
    pub fn calculate_score(&self, result: &HeuristicResult) -> u8 {
        let mut total_score: f32 = 0.0;

        // Sum up all indicator scores with weights
        for (desc, score) in &result.indicators {
            let weight = self.get_indicator_weight(desc);
            total_score += *score as f32 * weight;
        }

        // Add import scores
        for import in &result.suspicious_imports {
            total_score += import.score as f32 * self.import_weight;
        }

        // Add packer score
        if let Some(ref packer) = result.packer_info {
            total_score += packer.suspicion_score as f32 * self.packer_weight;
        }

        // Apply diminishing returns for very high scores
        // This prevents small additional indicators from pushing score too high
        total_score = self.apply_diminishing_returns(total_score);

        // Cap the score
        (total_score.round() as u8).min(self.score_cap)
    }

    /// Get weight for a specific indicator based on description.
    fn get_indicator_weight(&self, description: &str) -> f32 {
        let desc_lower = description.to_lowercase();

        if desc_lower.contains("entropy") {
            self.entropy_weight
        } else if desc_lower.contains("rwx")
            || desc_lower.contains("entry point")
            || desc_lower.contains("section")
        {
            self.pe_anomaly_weight
        } else if desc_lower.contains("import") || desc_lower.contains("api") {
            self.import_weight
        } else if desc_lower.contains("pack") || desc_lower.contains("obfuscat") {
            self.packer_weight
        } else {
            1.0
        }
    }

    /// Apply diminishing returns to prevent score inflation.
    fn apply_diminishing_returns(&self, score: f32) -> f32 {
        if score <= 50.0 {
            score
        } else if score <= 100.0 {
            // Slower growth after 50
            50.0 + (score - 50.0) * 0.7
        } else if score <= 150.0 {
            // Even slower after 100
            85.0 + (score - 100.0) * 0.3
        } else {
            // Cap approaches 100 asymptotically
            100.0 - (100.0 / (1.0 + (score - 150.0) / 100.0))
        }
    }

    /// Categorize a score.
    pub fn categorize_score(&self, score: u8) -> ScoreCategory {
        match score {
            0..=20 => ScoreCategory::Clean,
            21..=50 => ScoreCategory::Suspicious,
            51..=80 => ScoreCategory::LikelyMalicious,
            _ => ScoreCategory::Malicious,
        }
    }

    /// Check if a score should trigger a detection.
    pub fn should_detect(&self, score: u8, threshold: u8) -> bool {
        score >= threshold
    }

    /// Get recommended action based on score.
    pub fn recommended_action(&self, score: u8) -> RecommendedAction {
        match score {
            0..=20 => RecommendedAction::None,
            21..=50 => RecommendedAction::Review,
            51..=80 => RecommendedAction::Quarantine,
            _ => RecommendedAction::Delete,
        }
    }
}

/// Recommended action based on heuristic score.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecommendedAction {
    /// No action needed
    None,
    /// Manual review recommended
    Review,
    /// Quarantine the file
    Quarantine,
    /// Delete the file
    Delete,
}

impl std::fmt::Display for RecommendedAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecommendedAction::None => write!(f, "None"),
            RecommendedAction::Review => write!(f, "Review"),
            RecommendedAction::Quarantine => write!(f, "Quarantine"),
            RecommendedAction::Delete => write!(f, "Delete"),
        }
    }
}

/// Builder for creating heuristic results with indicators.
pub struct HeuristicResultBuilder {
    result: HeuristicResult,
}

impl HeuristicResultBuilder {
    /// Create a new builder for the given path.
    pub fn new(path: PathBuf) -> Self {
        Self {
            result: HeuristicResult::new(path),
        }
    }

    /// Set PE information.
    pub fn pe_info(mut self, pe_info: PeInfo) -> Self {
        self.result.pe_info = Some(pe_info);
        self
    }

    /// Set entropy.
    pub fn entropy(mut self, entropy: f64) -> Self {
        self.result.entropy = entropy;
        self
    }

    /// Set packer information.
    pub fn packer(mut self, packer: PackerInfo) -> Self {
        self.result.packer_info = Some(packer);
        self
    }

    /// Add suspicious imports.
    pub fn suspicious_imports(mut self, imports: Vec<SuspiciousImport>) -> Self {
        self.result.suspicious_imports = imports;
        self
    }

    /// Add an indicator.
    pub fn add_indicator(mut self, description: impl Into<String>, score: u8) -> Self {
        self.result.add_indicator(description.into(), score);
        self
    }

    /// Build and calculate final score.
    pub fn build(mut self, scorer: &HeuristicScorer) -> HeuristicResult {
        self.result.score = scorer.calculate_score(&self.result);
        self.result.category = scorer.categorize_score(self.result.score);
        self.result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_score_categorization() {
        let scorer = HeuristicScorer::new();

        assert_eq!(scorer.categorize_score(0), ScoreCategory::Clean);
        assert_eq!(scorer.categorize_score(20), ScoreCategory::Clean);
        assert_eq!(scorer.categorize_score(21), ScoreCategory::Suspicious);
        assert_eq!(scorer.categorize_score(50), ScoreCategory::Suspicious);
        assert_eq!(scorer.categorize_score(51), ScoreCategory::LikelyMalicious);
        assert_eq!(scorer.categorize_score(80), ScoreCategory::LikelyMalicious);
        assert_eq!(scorer.categorize_score(81), ScoreCategory::Malicious);
        assert_eq!(scorer.categorize_score(100), ScoreCategory::Malicious);
    }

    #[test]
    fn test_recommended_action() {
        let scorer = HeuristicScorer::new();

        assert_eq!(scorer.recommended_action(10), RecommendedAction::None);
        assert_eq!(scorer.recommended_action(30), RecommendedAction::Review);
        assert_eq!(scorer.recommended_action(60), RecommendedAction::Quarantine);
        assert_eq!(scorer.recommended_action(90), RecommendedAction::Delete);
    }

    #[test]
    fn test_score_calculation() {
        let scorer = HeuristicScorer::new();

        let mut result = HeuristicResult::new("/test".into());
        result.add_indicator("High entropy section".to_string(), 15);
        result.add_indicator("RWX section".to_string(), 20);

        let score = scorer.calculate_score(&result);
        assert!(score > 0);
        assert!(score <= 100);
    }

    #[test]
    fn test_diminishing_returns() {
        let scorer = HeuristicScorer::new();

        // Low scores should pass through unchanged
        assert_eq!(scorer.apply_diminishing_returns(30.0), 30.0);
        assert_eq!(scorer.apply_diminishing_returns(50.0), 50.0);

        // Medium-high scores should be reduced but still increase
        let medium_high = scorer.apply_diminishing_returns(100.0);
        assert!(medium_high > 50.0 && medium_high < 100.0);

        // Very high scores should be capped and reduced significantly
        let high_score = scorer.apply_diminishing_returns(200.0);
        assert!(high_score < 100.0);
    }

    #[test]
    fn test_builder() {
        let scorer = HeuristicScorer::new();

        let result = HeuristicResultBuilder::new("/test/file.exe".into())
            .entropy(7.5)
            .add_indicator("Test indicator", 30)
            .build(&scorer);

        assert!(result.score > 0);
        assert_eq!(result.entropy, 7.5);
    }

    #[test]
    fn test_clean_file_score() {
        let scorer = HeuristicScorer::new();
        let result = HeuristicResult::new("/clean/file.exe".into());

        let score = scorer.calculate_score(&result);
        assert_eq!(score, 0);
        assert_eq!(scorer.categorize_score(score), ScoreCategory::Clean);
    }
}
