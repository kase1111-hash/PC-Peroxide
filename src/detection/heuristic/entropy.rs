//! Entropy calculation for detecting packed/encrypted content.
//!
//! High entropy (close to 8.0 for byte data) typically indicates:
//! - Encrypted content
//! - Compressed/packed executables
//! - Random or obfuscated data
//!
//! Normal executable code typically has entropy between 5.0-6.5.

/// Entropy thresholds for classification.
pub const ENTROPY_LOW: f64 = 5.0;
pub const ENTROPY_NORMAL: f64 = 6.5;
pub const ENTROPY_HIGH: f64 = 7.0;
pub const ENTROPY_VERY_HIGH: f64 = 7.5;
pub const ENTROPY_MAX: f64 = 8.0;

/// Entropy analyzer for detecting packed/encrypted content.
#[derive(Debug, Clone)]
pub struct EntropyAnalyzer {
    /// Minimum data size to analyze
    min_size: usize,
    /// Block size for windowed analysis
    block_size: usize,
}

impl Default for EntropyAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl EntropyAnalyzer {
    /// Create a new entropy analyzer with default settings.
    pub fn new() -> Self {
        Self {
            min_size: 256,
            block_size: 256,
        }
    }

    /// Create an entropy analyzer with custom block size.
    pub fn with_block_size(mut self, block_size: usize) -> Self {
        self.block_size = block_size.max(64);
        self
    }

    /// Calculate Shannon entropy of byte data.
    ///
    /// Returns a value between 0.0 (no randomness) and 8.0 (maximum randomness for bytes).
    pub fn calculate(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        // Count byte frequencies
        let mut frequencies = [0u64; 256];
        for &byte in data {
            frequencies[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &frequencies {
            if count > 0 {
                let probability = count as f64 / len;
                entropy -= probability * probability.log2();
            }
        }

        entropy
    }

    /// Calculate entropy with sliding window, returning min, max, and average.
    pub fn calculate_windowed(&self, data: &[u8]) -> EntropyStats {
        if data.len() < self.min_size {
            let entropy = self.calculate(data);
            return EntropyStats {
                min: entropy,
                max: entropy,
                average: entropy,
                blocks: 1,
            };
        }

        let mut min = f64::MAX;
        let mut max = f64::MIN;
        let mut sum = 0.0;
        let mut count = 0;

        let step = self.block_size / 2; // 50% overlap
        let mut offset = 0;

        while offset + self.block_size <= data.len() {
            let block = &data[offset..offset + self.block_size];
            let entropy = self.calculate(block);

            min = min.min(entropy);
            max = max.max(entropy);
            sum += entropy;
            count += 1;

            offset += step;
        }

        // Handle remaining data
        if offset < data.len() && data.len() - offset >= self.min_size / 2 {
            let entropy = self.calculate(&data[offset..]);
            min = min.min(entropy);
            max = max.max(entropy);
            sum += entropy;
            count += 1;
        }

        EntropyStats {
            min,
            max,
            average: if count > 0 { sum / count as f64 } else { 0.0 },
            blocks: count,
        }
    }

    /// Classify entropy level.
    pub fn classify(&self, entropy: f64) -> EntropyLevel {
        if entropy < ENTROPY_LOW {
            EntropyLevel::Low
        } else if entropy < ENTROPY_NORMAL {
            EntropyLevel::Normal
        } else if entropy < ENTROPY_HIGH {
            EntropyLevel::Elevated
        } else if entropy < ENTROPY_VERY_HIGH {
            EntropyLevel::High
        } else {
            EntropyLevel::VeryHigh
        }
    }

    /// Detect likely packed/encrypted regions in data.
    pub fn find_high_entropy_regions(&self, data: &[u8], threshold: f64) -> Vec<EntropyRegion> {
        let mut regions = Vec::new();

        if data.len() < self.min_size {
            return regions;
        }

        let step = self.block_size / 4;
        let mut in_high_region = false;
        let mut region_start = 0;
        let mut region_max_entropy = 0.0;

        let mut offset = 0;
        while offset + self.block_size <= data.len() {
            let block = &data[offset..offset + self.block_size];
            let entropy = self.calculate(block);

            if entropy >= threshold {
                if !in_high_region {
                    in_high_region = true;
                    region_start = offset;
                    region_max_entropy = entropy;
                } else {
                    region_max_entropy = region_max_entropy.max(entropy);
                }
            } else if in_high_region {
                // End of high entropy region
                regions.push(EntropyRegion {
                    start: region_start,
                    end: offset,
                    max_entropy: region_max_entropy,
                });
                in_high_region = false;
            }

            offset += step;
        }

        // Handle region extending to end
        if in_high_region {
            regions.push(EntropyRegion {
                start: region_start,
                end: data.len(),
                max_entropy: region_max_entropy,
            });
        }

        // Merge adjacent regions
        Self::merge_regions(&mut regions, self.block_size);

        regions
    }

    /// Merge adjacent or overlapping regions.
    fn merge_regions(regions: &mut Vec<EntropyRegion>, gap: usize) {
        if regions.len() < 2 {
            return;
        }

        regions.sort_by_key(|r| r.start);

        let mut merged = Vec::with_capacity(regions.len());
        let mut current = regions[0].clone();

        for region in regions.iter().skip(1) {
            if region.start <= current.end + gap {
                // Merge
                current.end = current.end.max(region.end);
                current.max_entropy = current.max_entropy.max(region.max_entropy);
            } else {
                merged.push(current);
                current = region.clone();
            }
        }
        merged.push(current);

        *regions = merged;
    }

    /// Calculate chi-square statistic for randomness testing.
    ///
    /// Lower values indicate more uniform distribution (more random).
    /// Higher values indicate patterns or structure.
    pub fn chi_square(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut frequencies = [0u64; 256];
        for &byte in data {
            frequencies[byte as usize] += 1;
        }

        let expected = data.len() as f64 / 256.0;
        let mut chi_sq = 0.0;

        for &observed in &frequencies {
            let diff = observed as f64 - expected;
            chi_sq += (diff * diff) / expected;
        }

        chi_sq
    }

    /// Estimate if data is likely encrypted/compressed based on entropy and chi-square.
    pub fn is_likely_encrypted(&self, data: &[u8]) -> bool {
        let entropy = self.calculate(data);
        let chi_sq = self.chi_square(data);

        // High entropy and relatively uniform distribution
        entropy > ENTROPY_HIGH && chi_sq < 300.0
    }
}

/// Entropy statistics from windowed analysis.
#[derive(Debug, Clone)]
pub struct EntropyStats {
    /// Minimum entropy found
    pub min: f64,
    /// Maximum entropy found
    pub max: f64,
    /// Average entropy across blocks
    pub average: f64,
    /// Number of blocks analyzed
    pub blocks: usize,
}

/// Classification of entropy level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyLevel {
    /// Low entropy (< 5.0) - structured data, text
    Low,
    /// Normal entropy (5.0-6.5) - typical executable code
    Normal,
    /// Elevated entropy (6.5-7.0) - some compression or encoding
    Elevated,
    /// High entropy (7.0-7.5) - likely packed or partially encrypted
    High,
    /// Very high entropy (> 7.5) - likely encrypted or compressed
    VeryHigh,
}

impl std::fmt::Display for EntropyLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EntropyLevel::Low => write!(f, "Low"),
            EntropyLevel::Normal => write!(f, "Normal"),
            EntropyLevel::Elevated => write!(f, "Elevated"),
            EntropyLevel::High => write!(f, "High"),
            EntropyLevel::VeryHigh => write!(f, "Very High"),
        }
    }
}

/// A region of high entropy in the data.
#[derive(Debug, Clone)]
pub struct EntropyRegion {
    /// Start offset
    pub start: usize,
    /// End offset
    pub end: usize,
    /// Maximum entropy in region
    pub max_entropy: f64,
}

impl EntropyRegion {
    /// Get region size.
    pub fn size(&self) -> usize {
        self.end - self.start
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_entropy() {
        let analyzer = EntropyAnalyzer::new();
        // All same bytes = zero entropy
        let data = vec![0u8; 1000];
        let entropy = analyzer.calculate(&data);
        assert!(entropy < 0.01);
    }

    #[test]
    fn test_max_entropy() {
        let analyzer = EntropyAnalyzer::new();
        // All different bytes evenly distributed = max entropy
        let mut data: Vec<u8> = (0..=255).collect();
        // Repeat to get more data
        data = data.repeat(4);
        let entropy = analyzer.calculate(&data);
        // Should be close to 8.0
        assert!(entropy > 7.9);
    }

    #[test]
    fn test_text_entropy() {
        let analyzer = EntropyAnalyzer::new();
        // English text typically has entropy around 4.0-5.0
        let text = b"The quick brown fox jumps over the lazy dog. This is sample text for testing entropy calculation.";
        let entropy = analyzer.calculate(text);
        assert!(entropy > 3.5 && entropy < 5.5);
    }

    #[test]
    fn test_entropy_classification() {
        let analyzer = EntropyAnalyzer::new();
        assert_eq!(analyzer.classify(3.0), EntropyLevel::Low);
        assert_eq!(analyzer.classify(5.5), EntropyLevel::Normal);
        assert_eq!(analyzer.classify(6.8), EntropyLevel::Elevated);
        assert_eq!(analyzer.classify(7.2), EntropyLevel::High);
        assert_eq!(analyzer.classify(7.8), EntropyLevel::VeryHigh);
    }

    #[test]
    fn test_windowed_analysis() {
        let analyzer = EntropyAnalyzer::new().with_block_size(128);

        // Create data with varying entropy
        let mut data = Vec::new();
        // Low entropy section
        data.extend(vec![0u8; 512]);
        // High entropy section
        for i in 0..512 {
            data.push((i % 256) as u8);
        }

        let stats = analyzer.calculate_windowed(&data);
        assert!(stats.min < stats.max);
    }

    #[test]
    fn test_high_entropy_regions() {
        let analyzer = EntropyAnalyzer::new().with_block_size(128);

        // Create data with a high entropy region in the middle
        let mut data = vec![0u8; 256];
        for i in 0..512 {
            data.push(((i * 17) % 256) as u8); // Pseudo-random
        }
        data.extend(vec![0u8; 256]);

        let regions = analyzer.find_high_entropy_regions(&data, 6.0);
        assert!(!regions.is_empty());
    }
}
