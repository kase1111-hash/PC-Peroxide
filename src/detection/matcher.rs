//! Hash matching engine for signature-based detection.

use crate::core::error::Result;
use crate::core::types::{Detection, DetectionMethod, Severity, ThreatCategory};
use crate::detection::database::SignatureDatabase;
use crate::detection::signature::Signature;
use crate::utils::hash::{FileHashes, HashCalculator};
use std::path::Path;
use std::sync::Arc;

/// EICAR test file standard string.
/// This is the industry-standard test file for antivirus software.
const EICAR_STRING: &str = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

/// EICAR test file SHA256 hash.
const EICAR_SHA256: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

/// EICAR test file MD5 hash.
const EICAR_MD5: &str = "44d88612fea8a8f36de82e1278abb02f";

/// Hash-based malware matcher.
pub struct HashMatcher {
    db: Arc<SignatureDatabase>,
    enable_eicar: bool,
}

impl HashMatcher {
    /// Create a new hash matcher.
    pub fn new(db: Arc<SignatureDatabase>) -> Self {
        Self {
            db,
            enable_eicar: true,
        }
    }

    /// Create a hash matcher with EICAR detection enabled/disabled.
    pub fn with_eicar(db: Arc<SignatureDatabase>, enable_eicar: bool) -> Self {
        Self { db, enable_eicar }
    }

    /// Check if file content matches the EICAR test string.
    pub fn is_eicar_content(content: &[u8]) -> bool {
        // EICAR can have optional trailing whitespace
        let trimmed = content
            .iter()
            .rev()
            .skip_while(|&&b| b == b'\r' || b == b'\n' || b == b' ')
            .count();
        let content_trimmed = &content[..trimmed];

        content_trimmed == EICAR_STRING.as_bytes()
    }

    /// Check if a file is the EICAR test file by hash.
    pub fn is_eicar_hash(sha256: &str) -> bool {
        sha256.eq_ignore_ascii_case(EICAR_SHA256)
    }

    /// Match a file against the signature database.
    pub fn match_file(&self, path: &Path) -> Result<Option<MatchResult>> {
        // Calculate file hashes
        let hashes = HashCalculator::hash_file(path)?;

        // Check for EICAR first (quick test)
        if self.enable_eicar && Self::is_eicar_hash(&hashes.sha256) {
            return Ok(Some(MatchResult {
                signature: create_eicar_signature(),
                hashes,
                detection_method: DetectionMethod::Signature,
            }));
        }

        // Look up in database
        if let Some(sig) = self.db.lookup_hash(&hashes.sha256, &hashes.md5)? {
            return Ok(Some(MatchResult {
                signature: sig,
                hashes,
                detection_method: DetectionMethod::Signature,
            }));
        }

        Ok(None)
    }

    /// Match file hashes against the signature database.
    pub fn match_hashes(&self, hashes: &FileHashes) -> Result<Option<MatchResult>> {
        // Check for EICAR first
        if self.enable_eicar && Self::is_eicar_hash(&hashes.sha256) {
            return Ok(Some(MatchResult {
                signature: create_eicar_signature(),
                hashes: hashes.clone(),
                detection_method: DetectionMethod::Signature,
            }));
        }

        // Look up in database
        if let Some(sig) = self.db.lookup_hash(&hashes.sha256, &hashes.md5)? {
            return Ok(Some(MatchResult {
                signature: sig,
                hashes: hashes.clone(),
                detection_method: DetectionMethod::Signature,
            }));
        }

        Ok(None)
    }

    /// Match a SHA256 hash against the signature database.
    pub fn match_sha256(&self, sha256: &str) -> Result<Option<Signature>> {
        // Check for EICAR first
        if self.enable_eicar && Self::is_eicar_hash(sha256) {
            return Ok(Some(create_eicar_signature()));
        }

        self.db.lookup_sha256(sha256)
    }

    /// Batch match multiple hashes.
    pub fn match_batch(&self, hashes: &[FileHashes]) -> Result<Vec<Option<MatchResult>>> {
        let mut results = Vec::with_capacity(hashes.len());
        for hash in hashes {
            results.push(self.match_hashes(hash)?);
        }
        Ok(results)
    }

    /// Check if any match exists for quick scanning.
    pub fn has_match(&self, sha256: &str, md5: &str) -> Result<bool> {
        if self.enable_eicar && Self::is_eicar_hash(sha256) {
            return Ok(true);
        }

        if self.db.lookup_sha256(sha256)?.is_some() {
            return Ok(true);
        }

        if self.db.lookup_md5(md5)?.is_some() {
            return Ok(true);
        }

        Ok(false)
    }
}

/// Result of a hash match.
#[derive(Debug, Clone)]
pub struct MatchResult {
    /// The matching signature
    pub signature: Signature,
    /// The file hashes that matched
    pub hashes: FileHashes,
    /// Detection method used
    pub detection_method: DetectionMethod,
}

impl MatchResult {
    /// Convert to a Detection.
    pub fn to_detection(&self, path: &Path) -> Detection {
        Detection {
            path: path.to_path_buf(),
            threat_name: self.signature.name.clone(),
            severity: self.signature.severity,
            category: self.signature.category,
            method: self.detection_method,
            description: self.signature.description.clone(),
            sha256: Some(self.hashes.sha256.clone()),
            score: severity_to_score(self.signature.severity),
        }
    }
}

/// Convert severity to a heuristic-style score.
fn severity_to_score(severity: Severity) -> u8 {
    match severity {
        Severity::Low => 30,
        Severity::Medium => 50,
        Severity::High => 75,
        Severity::Critical => 100,
    }
}

/// Create the EICAR test signature.
fn create_eicar_signature() -> Signature {
    Signature {
        id: "EICAR-TEST".to_string(),
        name: "EICAR-Test-File".to_string(),
        sig_type: crate::detection::signature::SignatureType::Hash,
        hash_sha256: Some(EICAR_SHA256.to_string()),
        hash_md5: Some(EICAR_MD5.to_string()),
        pattern: None,
        offset: None,
        severity: Severity::Low,
        category: ThreatCategory::TestFile,
        description: "EICAR Anti-Virus Test File - This is a harmless test file used to verify antivirus functionality.".to_string(),
        remediation: crate::detection::signature::RemediationAction::Report,
        enabled: true,
        tags: vec!["test".to_string(), "eicar".to_string()],
    }
}

/// High-level detection engine combining all detection methods.
pub struct DetectionEngine {
    hash_matcher: HashMatcher,
    heuristic_engine: crate::detection::heuristic::HeuristicEngine,
    /// Heuristic score threshold for detection (0-100)
    heuristic_threshold: u8,
    /// Whether heuristic analysis is enabled
    heuristic_enabled: bool,
}

impl DetectionEngine {
    /// Create a new detection engine.
    pub fn new(db: Arc<SignatureDatabase>) -> Self {
        Self {
            hash_matcher: HashMatcher::new(db),
            heuristic_engine: crate::detection::heuristic::HeuristicEngine::new(),
            heuristic_threshold: 50,
            heuristic_enabled: true,
        }
    }

    /// Create a detection engine with custom settings.
    pub fn with_settings(
        db: Arc<SignatureDatabase>,
        heuristic_threshold: u8,
        heuristic_enabled: bool,
    ) -> Self {
        Self {
            hash_matcher: HashMatcher::new(db),
            heuristic_engine: crate::detection::heuristic::HeuristicEngine::new(),
            heuristic_threshold,
            heuristic_enabled,
        }
    }

    /// Enable or disable heuristic analysis.
    pub fn set_heuristic_enabled(&mut self, enabled: bool) {
        self.heuristic_enabled = enabled;
    }

    /// Set the heuristic detection threshold.
    pub fn set_heuristic_threshold(&mut self, threshold: u8) {
        self.heuristic_threshold = threshold;
    }

    /// Scan a file for threats using all detection methods.
    pub fn scan_file(&self, path: &Path) -> Result<Option<Detection>> {
        // 1. Hash-based detection (fastest, check first)
        if let Some(match_result) = self.hash_matcher.match_file(path)? {
            return Ok(Some(match_result.to_detection(path)));
        }

        // 2. Heuristic analysis (if enabled)
        if self.heuristic_enabled {
            if let Ok(heuristic_result) = self.heuristic_engine.analyze_file(path) {
                if let Some(detection) = self
                    .heuristic_engine
                    .to_detection(&heuristic_result, self.heuristic_threshold)
                {
                    return Ok(Some(detection));
                }
            }
        }

        // 3. Future: YARA rules, behavioral analysis

        Ok(None)
    }

    /// Scan file with detailed results from all engines.
    pub fn scan_file_detailed(&self, path: &Path) -> Result<ScanDetails> {
        let mut details = ScanDetails::new(path.to_path_buf());

        // Hash-based detection
        if let Some(match_result) = self.hash_matcher.match_file(path)? {
            details.signature_match = Some(match_result);
        }

        // Heuristic analysis
        if self.heuristic_enabled {
            if let Ok(heuristic_result) = self.heuristic_engine.analyze_file(path) {
                details.heuristic_result = Some(heuristic_result);
            }
        }

        Ok(details)
    }

    /// Quick check if a file might be malicious (hash only).
    pub fn quick_check(&self, path: &Path) -> Result<bool> {
        let hashes = HashCalculator::hash_file(path)?;
        self.hash_matcher.has_match(&hashes.sha256, &hashes.md5)
    }

    /// Get the underlying hash matcher.
    pub fn hash_matcher(&self) -> &HashMatcher {
        &self.hash_matcher
    }

    /// Get the heuristic engine.
    pub fn heuristic_engine(&self) -> &crate::detection::heuristic::HeuristicEngine {
        &self.heuristic_engine
    }
}

/// Detailed scan results from all detection engines.
#[derive(Debug)]
pub struct ScanDetails {
    /// File path scanned
    pub path: std::path::PathBuf,
    /// Signature match result
    pub signature_match: Option<MatchResult>,
    /// Heuristic analysis result
    pub heuristic_result: Option<crate::detection::heuristic::HeuristicResult>,
}

impl ScanDetails {
    /// Create new scan details.
    pub fn new(path: std::path::PathBuf) -> Self {
        Self {
            path,
            signature_match: None,
            heuristic_result: None,
        }
    }

    /// Check if any detection method found a threat.
    pub fn has_detection(&self, heuristic_threshold: u8) -> bool {
        if self.signature_match.is_some() {
            return true;
        }
        if let Some(ref heuristic) = self.heuristic_result {
            return heuristic.score >= heuristic_threshold;
        }
        false
    }

    /// Get the primary detection (signature takes priority).
    pub fn primary_detection(&self, heuristic_threshold: u8) -> Option<Detection> {
        // Signature matches take priority
        if let Some(ref match_result) = self.signature_match {
            return Some(match_result.to_detection(&self.path));
        }

        // Then heuristic
        if let Some(ref heuristic) = self.heuristic_result {
            if heuristic.score >= heuristic_threshold {
                let engine = crate::detection::heuristic::HeuristicEngine::new();
                return engine.to_detection(heuristic, heuristic_threshold);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::{tempdir, NamedTempFile};

    fn test_db() -> Arc<SignatureDatabase> {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.db");
        std::mem::forget(dir);
        Arc::new(SignatureDatabase::open(&path).unwrap())
    }

    #[test]
    fn test_eicar_detection() {
        // Create EICAR test file
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(EICAR_STRING.as_bytes()).unwrap();

        let db = test_db();
        let matcher = HashMatcher::new(db);

        let result = matcher.match_file(file.path()).unwrap();
        assert!(result.is_some());

        let match_result = result.unwrap();
        assert_eq!(match_result.signature.id, "EICAR-TEST");
        assert_eq!(match_result.signature.category, ThreatCategory::TestFile);
    }

    #[test]
    fn test_eicar_content_check() {
        assert!(HashMatcher::is_eicar_content(EICAR_STRING.as_bytes()));
        assert!(HashMatcher::is_eicar_content(
            format!("{}\n", EICAR_STRING).as_bytes()
        ));
        assert!(HashMatcher::is_eicar_content(
            format!("{}\r\n", EICAR_STRING).as_bytes()
        ));
        assert!(!HashMatcher::is_eicar_content(b"not eicar"));
    }

    #[test]
    fn test_eicar_hash_check() {
        assert!(HashMatcher::is_eicar_hash(EICAR_SHA256));
        assert!(HashMatcher::is_eicar_hash(&EICAR_SHA256.to_uppercase()));
        assert!(!HashMatcher::is_eicar_hash("not_a_hash"));
    }

    #[test]
    fn test_database_signature_match() {
        let db = test_db();

        // Add a test signature
        let sig = Signature::new_hash(
            "TEST-MAL-001",
            "Test.Malware.Hash",
            "deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678",
            Severity::High,
            ThreatCategory::Trojan,
            "Test malware signature",
        );
        db.upsert_signature(&sig).unwrap();

        let matcher = HashMatcher::new(Arc::clone(&db));

        // Match by SHA256
        let result = matcher
            .match_sha256("DEADBEEF12345678DEADBEEF12345678DEADBEEF12345678DEADBEEF12345678")
            .unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().id, "TEST-MAL-001");

        // No match for unknown hash
        let no_match = matcher.match_sha256("0000000000000000").unwrap();
        assert!(no_match.is_none());
    }

    #[test]
    fn test_detection_engine() {
        let db = test_db();
        let engine = DetectionEngine::new(db);

        // Test with EICAR
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(EICAR_STRING.as_bytes()).unwrap();

        let detection = engine.scan_file(file.path()).unwrap();
        assert!(detection.is_some());

        let det = detection.unwrap();
        assert_eq!(det.threat_name, "EICAR-Test-File");
        assert_eq!(det.method, DetectionMethod::Signature);
    }

    #[test]
    fn test_clean_file() {
        let db = test_db();
        let engine = DetectionEngine::new(db);

        // Create a clean file
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"This is a clean file with no malware")
            .unwrap();

        let detection = engine.scan_file(file.path()).unwrap();
        assert!(detection.is_none());
    }
}
