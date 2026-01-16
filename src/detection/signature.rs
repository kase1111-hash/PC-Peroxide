//! Signature database types and structures.

use crate::core::types::{Severity, ThreatCategory};
use serde::{Deserialize, Serialize};

/// Type of signature for detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignatureType {
    /// SHA256 hash match
    Hash,
    /// MD5 hash match (legacy compatibility)
    Md5,
    /// Byte pattern match
    Pattern,
    /// YARA rule reference
    Yara,
    /// Fuzzy hash (ssdeep)
    Fuzzy,
}

impl SignatureType {
    /// Get string representation for database storage.
    pub fn as_str(&self) -> &'static str {
        match self {
            SignatureType::Hash => "hash",
            SignatureType::Md5 => "md5",
            SignatureType::Pattern => "pattern",
            SignatureType::Yara => "yara",
            SignatureType::Fuzzy => "fuzzy",
        }
    }

    /// Parse from string.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "hash" | "sha256" => Some(SignatureType::Hash),
            "md5" => Some(SignatureType::Md5),
            "pattern" => Some(SignatureType::Pattern),
            "yara" => Some(SignatureType::Yara),
            "fuzzy" | "ssdeep" => Some(SignatureType::Fuzzy),
            _ => None,
        }
    }
}

/// Recommended remediation action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RemediationAction {
    /// Delete the file
    Delete,
    /// Quarantine the file
    Quarantine,
    /// Report only, no action
    Report,
    /// Block execution
    Block,
}

impl RemediationAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            RemediationAction::Delete => "delete",
            RemediationAction::Quarantine => "quarantine",
            RemediationAction::Report => "report",
            RemediationAction::Block => "block",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "delete" => Some(RemediationAction::Delete),
            "quarantine" => Some(RemediationAction::Quarantine),
            "report" => Some(RemediationAction::Report),
            "block" => Some(RemediationAction::Block),
            _ => None,
        }
    }
}

/// A malware signature for detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    /// Unique identifier (e.g., "MAL-00001")
    pub id: String,
    /// Human-readable name (e.g., "Trojan.GenericKD")
    pub name: String,
    /// Type of signature
    #[serde(rename = "type")]
    pub sig_type: SignatureType,
    /// SHA256 hash (for hash-based signatures)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_sha256: Option<String>,
    /// MD5 hash (for legacy compatibility)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_md5: Option<String>,
    /// Byte pattern (hex string for pattern-based signatures)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// Pattern offset hint (e.g., "entry_point", "0x100", "any")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<String>,
    /// Threat severity
    pub severity: Severity,
    /// Threat category
    pub category: ThreatCategory,
    /// Description of the threat
    pub description: String,
    /// Recommended action
    pub remediation: RemediationAction,
    /// Whether this signature is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Additional metadata/tags
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_true() -> bool {
    true
}

impl Signature {
    /// Create a new hash-based signature.
    pub fn new_hash(
        id: impl Into<String>,
        name: impl Into<String>,
        sha256: impl Into<String>,
        severity: Severity,
        category: ThreatCategory,
        description: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            sig_type: SignatureType::Hash,
            hash_sha256: Some(sha256.into().to_lowercase()),
            hash_md5: None,
            pattern: None,
            offset: None,
            severity,
            category,
            description: description.into(),
            remediation: RemediationAction::Quarantine,
            enabled: true,
            tags: Vec::new(),
        }
    }

    /// Create a new pattern-based signature.
    pub fn new_pattern(
        id: impl Into<String>,
        name: impl Into<String>,
        pattern: impl Into<String>,
        offset: Option<String>,
        severity: Severity,
        category: ThreatCategory,
        description: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            sig_type: SignatureType::Pattern,
            hash_sha256: None,
            hash_md5: None,
            pattern: Some(pattern.into()),
            offset,
            severity,
            category,
            description: description.into(),
            remediation: RemediationAction::Quarantine,
            enabled: true,
            tags: Vec::new(),
        }
    }

    /// Check if this signature matches a given SHA256 hash.
    pub fn matches_sha256(&self, hash: &str) -> bool {
        if self.sig_type != SignatureType::Hash {
            return false;
        }
        self.hash_sha256
            .as_ref()
            .map(|h| h.eq_ignore_ascii_case(hash))
            .unwrap_or(false)
    }

    /// Check if this signature matches a given MD5 hash.
    pub fn matches_md5(&self, hash: &str) -> bool {
        if self.sig_type != SignatureType::Md5 {
            return false;
        }
        self.hash_md5
            .as_ref()
            .map(|h| h.eq_ignore_ascii_case(hash))
            .unwrap_or(false)
    }
}

/// Signature database file format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureFile {
    /// Database version (e.g., "2025.01.15")
    pub version: String,
    /// Database format version
    #[serde(default = "default_format_version")]
    pub format_version: u32,
    /// Timestamp of last update
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// List of signatures
    pub signatures: Vec<Signature>,
}

fn default_format_version() -> u32 {
    1
}

impl SignatureFile {
    /// Create a new empty signature file.
    pub fn new(version: impl Into<String>) -> Self {
        Self {
            version: version.into(),
            format_version: 1,
            updated_at: Some(chrono::Utc::now().to_rfc3339()),
            signatures: Vec::new(),
        }
    }

    /// Load signatures from a JSON file.
    pub fn load(path: &std::path::Path) -> crate::core::error::Result<Self> {
        let contents = std::fs::read_to_string(path).map_err(|e| {
            crate::core::error::Error::file_read(path, e)
        })?;
        serde_json::from_str(&contents).map_err(|e| {
            crate::core::error::Error::SignatureLoad(format!(
                "Failed to parse signature file: {}",
                e
            ))
        })
    }

    /// Save signatures to a JSON file.
    pub fn save(&self, path: &std::path::Path) -> crate::core::error::Result<()> {
        let contents = serde_json::to_string_pretty(self)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                crate::core::error::Error::file_write(path, e)
            })?;
        }
        std::fs::write(path, contents).map_err(|e| {
            crate::core::error::Error::file_write(path, e)
        })
    }

    /// Get the number of enabled signatures.
    pub fn enabled_count(&self) -> usize {
        self.signatures.iter().filter(|s| s.enabled).count()
    }

    /// Add a signature.
    pub fn add(&mut self, sig: Signature) {
        self.signatures.push(sig);
    }
}

/// Database metadata for versioning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseInfo {
    /// Current database version
    pub version: String,
    /// Number of signatures
    pub signature_count: u64,
    /// Number of hash signatures
    pub hash_count: u64,
    /// Number of pattern signatures
    pub pattern_count: u64,
    /// Last update timestamp
    pub last_updated: Option<chrono::DateTime<chrono::Utc>>,
    /// Database creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_type_parsing() {
        assert_eq!(SignatureType::from_str("hash"), Some(SignatureType::Hash));
        assert_eq!(SignatureType::from_str("SHA256"), Some(SignatureType::Hash));
        assert_eq!(SignatureType::from_str("pattern"), Some(SignatureType::Pattern));
        assert_eq!(SignatureType::from_str("invalid"), None);
    }

    #[test]
    fn test_signature_hash_match() {
        let sig = Signature::new_hash(
            "TEST-001",
            "Test.Malware",
            "abc123def456",
            Severity::High,
            ThreatCategory::Trojan,
            "Test malware signature",
        );

        assert!(sig.matches_sha256("ABC123DEF456")); // Case insensitive
        assert!(sig.matches_sha256("abc123def456"));
        assert!(!sig.matches_sha256("different_hash"));
    }

    #[test]
    fn test_signature_file_serialization() {
        let mut file = SignatureFile::new("2025.01.15");
        file.add(Signature::new_hash(
            "MAL-00001",
            "Trojan.Generic",
            "a1b2c3d4e5f6",
            Severity::High,
            ThreatCategory::Trojan,
            "Generic trojan",
        ));

        let json = serde_json::to_string(&file).unwrap();
        let parsed: SignatureFile = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.signatures.len(), 1);
        assert_eq!(parsed.signatures[0].id, "MAL-00001");
    }
}
