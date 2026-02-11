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

/// Convert a YARA RuleMatch to a Detection.
fn yara_match_to_detection(path: &Path, rule_match: &crate::detection::yara::RuleMatch) -> Detection {
    let severity = rule_match
        .meta
        .severity
        .as_deref()
        .and_then(Severity::parse)
        .unwrap_or(Severity::High);

    let category = rule_match
        .meta
        .category
        .as_deref()
        .and_then(ThreatCategory::parse)
        .unwrap_or(ThreatCategory::Generic);

    let description = rule_match
        .meta
        .description
        .clone()
        .unwrap_or_default();

    Detection {
        path: path.to_path_buf(),
        threat_name: rule_match.rule_name.clone(),
        severity,
        category,
        method: DetectionMethod::Yara,
        description,
        sha256: None,
        score: severity.score(),
    }
}

/// Pick the highest-severity YARA match from a list.
fn pick_best_yara_match(matches: &[crate::detection::yara::RuleMatch]) -> Option<&crate::detection::yara::RuleMatch> {
    matches.iter().max_by_key(|m| {
        m.meta
            .severity
            .as_deref()
            .and_then(Severity::parse)
            .unwrap_or(Severity::High)
    })
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
    /// YARA rule engine (None if disabled or failed to load)
    yara_engine: Option<crate::detection::yara::YaraEngine>,
}

impl DetectionEngine {
    /// Create a new detection engine.
    pub fn new(db: Arc<SignatureDatabase>) -> Self {
        Self {
            hash_matcher: HashMatcher::new(db),
            heuristic_engine: crate::detection::heuristic::HeuristicEngine::new(),
            heuristic_threshold: 70,
            heuristic_enabled: true,
            yara_engine: crate::detection::yara::YaraEngine::with_default_rules().ok(),
        }
    }

    /// Create a detection engine with custom settings.
    pub fn with_settings(
        db: Arc<SignatureDatabase>,
        heuristic_threshold: u8,
        heuristic_enabled: bool,
        yara_enabled: bool,
    ) -> Self {
        Self {
            hash_matcher: HashMatcher::new(db),
            heuristic_engine: crate::detection::heuristic::HeuristicEngine::new(),
            heuristic_threshold,
            heuristic_enabled,
            yara_engine: if yara_enabled {
                crate::detection::yara::YaraEngine::with_default_rules().ok()
            } else {
                None
            },
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

    /// Get the heuristic detection threshold.
    pub fn heuristic_threshold(&self) -> u8 {
        self.heuristic_threshold
    }

    /// Scan a file for threats using all detection methods.
    pub fn scan_file(&self, path: &Path) -> Result<Option<Detection>> {
        // 1. Hash-based detection (fastest, check first)
        // Hash-based detection always runs regardless of trusted path status
        // because known malware should always be detected
        if let Some(match_result) = self.hash_matcher.match_file(path)? {
            return Ok(Some(match_result.to_detection(path)));
        }

        // 2. Heuristic analysis (if enabled)
        // Trusted path score reduction is now handled in the scoring module
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

        // 3. YARA rules
        if let Some(ref yara) = self.yara_engine {
            if let Ok(matches) = yara.scan_file(path) {
                if let Some(best) = pick_best_yara_match(&matches) {
                    return Ok(Some(yara_match_to_detection(path, best)));
                }
            }
        }

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

        // YARA rules
        if let Some(ref yara) = self.yara_engine {
            if let Ok(matches) = yara.scan_file(path) {
                details.yara_matches = matches;
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

    /// Get the YARA engine (if available).
    pub fn yara_engine(&self) -> Option<&crate::detection::yara::YaraEngine> {
        self.yara_engine.as_ref()
    }

    /// Get a mutable reference to the YARA engine, initializing it if needed.
    ///
    /// If YARA was disabled but the caller needs to load custom rules,
    /// this creates a new empty engine and returns a mutable reference.
    pub fn yara_engine_mut(&mut self) -> &mut crate::detection::yara::YaraEngine {
        self.yara_engine
            .get_or_insert_with(crate::detection::yara::YaraEngine::new)
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
    /// YARA rule matches
    pub yara_matches: Vec<crate::detection::yara::RuleMatch>,
}

impl ScanDetails {
    /// Create new scan details.
    pub fn new(path: std::path::PathBuf) -> Self {
        Self {
            path,
            signature_match: None,
            heuristic_result: None,
            yara_matches: Vec::new(),
        }
    }

    /// Check if any detection method found a threat.
    pub fn has_detection(&self, heuristic_threshold: u8) -> bool {
        if self.signature_match.is_some() {
            return true;
        }
        if let Some(ref heuristic) = self.heuristic_result {
            if heuristic.score >= heuristic_threshold {
                return true;
            }
        }
        if !self.yara_matches.is_empty() {
            return true;
        }
        false
    }

    /// Get the primary detection (signature takes priority, then YARA, then heuristic).
    pub fn primary_detection(&self, heuristic_threshold: u8) -> Option<Detection> {
        // Signature matches take priority
        if let Some(ref match_result) = self.signature_match {
            return Some(match_result.to_detection(&self.path));
        }

        // Then YARA rules
        if let Some(best) = pick_best_yara_match(&self.yara_matches) {
            return Some(yara_match_to_detection(&self.path, best));
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
    use tempfile::{tempdir, NamedTempFile, TempDir};

    /// Test database fixture that keeps the temp directory alive.
    struct TestDb {
        #[allow(dead_code)]
        dir: TempDir,
        db: Arc<SignatureDatabase>,
    }

    impl TestDb {
        fn new() -> Self {
            let dir = tempdir().unwrap();
            let path = dir.path().join("test.db");
            let db = Arc::new(SignatureDatabase::open(&path).unwrap());
            Self { dir, db }
        }

        fn db(&self) -> Arc<SignatureDatabase> {
            Arc::clone(&self.db)
        }
    }

    #[test]
    fn test_eicar_detection() {
        // Create EICAR test file
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(EICAR_STRING.as_bytes()).unwrap();

        let test_db = TestDb::new();
        let matcher = HashMatcher::new(test_db.db());

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
        let test_db = TestDb::new();

        // Add a test signature
        let sig = Signature::new_hash(
            "TEST-MAL-001",
            "Test.Malware.Hash",
            "deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678",
            Severity::High,
            ThreatCategory::Trojan,
            "Test malware signature",
        );
        test_db.db().upsert_signature(&sig).unwrap();

        let matcher = HashMatcher::new(test_db.db());

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
        let test_db = TestDb::new();
        let engine = DetectionEngine::new(test_db.db());

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
        let test_db = TestDb::new();
        let engine = DetectionEngine::new(test_db.db());

        // Create a clean file
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"This is a clean file with no malware")
            .unwrap();

        let detection = engine.scan_file(file.path()).unwrap();
        assert!(detection.is_none());
    }

    #[test]
    fn test_yara_ransomware_detection() {
        let test_db = TestDb::new();
        let engine = DetectionEngine::new(test_db.db());

        // Create a file with PE header + ransomware strings (not in hash DB)
        let mut file = NamedTempFile::new().unwrap();
        let mut data = vec![0x4D, 0x5A]; // MZ header
        data.extend(vec![0u8; 100]);
        data.extend(b"Your files have been encrypted. Pay bitcoin to restore your files.");
        file.write_all(&data).unwrap();

        let detection = engine.scan_file(file.path()).unwrap();
        assert!(detection.is_some(), "YARA should detect ransomware strings in PE");

        let det = detection.unwrap();
        assert_eq!(det.method, DetectionMethod::Yara);
        assert_eq!(det.threat_name, "Ransomware_Generic");
    }

    #[test]
    fn test_yara_crypto_miner_detection() {
        let test_db = TestDb::new();
        let engine = DetectionEngine::new(test_db.db());

        // Create a file with mining pool strings (no PE header needed for this rule)
        let mut file = NamedTempFile::new().unwrap();
        let data = b"connecting to stratum+tcp://pool.example.com xmrig --threads=4";
        file.write_all(data).unwrap();

        let detection = engine.scan_file(file.path()).unwrap();
        assert!(detection.is_some(), "YARA should detect crypto miner strings");

        let det = detection.unwrap();
        assert_eq!(det.method, DetectionMethod::Yara);
        assert_eq!(det.threat_name, "CryptoMiner_Generic");
    }

    #[test]
    fn test_yara_in_detailed_scan() {
        let test_db = TestDb::new();
        let engine = DetectionEngine::new(test_db.db());

        // File with ransomware strings + MZ header
        let mut file = NamedTempFile::new().unwrap();
        let mut data = vec![0x4D, 0x5A];
        data.extend(vec![0u8; 100]);
        data.extend(b"Your files have been encrypted. Pay bitcoin now.");
        file.write_all(&data).unwrap();

        let details = engine.scan_file_detailed(file.path()).unwrap();
        assert!(!details.yara_matches.is_empty(), "Detailed scan should include YARA matches");
        assert!(details.yara_matches.iter().any(|m| m.rule_name == "Ransomware_Generic"));
    }

    #[test]
    fn test_yara_helper_conversion() {
        use crate::detection::yara::rules::{RuleMatch, RuleMeta};
        use std::collections::HashMap;

        let rule_match = RuleMatch {
            rule_name: "TestRule".to_string(),
            meta: RuleMeta {
                description: Some("Test description".to_string()),
                severity: Some("critical".to_string()),
                category: Some("ransomware".to_string()),
                ..Default::default()
            },
            matches: HashMap::new(),
        };

        let det = yara_match_to_detection(Path::new("/test/file.exe"), &rule_match);
        assert_eq!(det.threat_name, "TestRule");
        assert_eq!(det.severity, Severity::Critical);
        assert_eq!(det.category, ThreatCategory::Ransomware);
        assert_eq!(det.method, DetectionMethod::Yara);
        assert_eq!(det.description, "Test description");
        assert_eq!(det.score, 100); // Critical score
    }
}
