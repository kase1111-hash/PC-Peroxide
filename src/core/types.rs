//! Core type definitions used throughout PC-Peroxide.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Severity level of a detected threat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Low risk - potentially unwanted but not necessarily malicious
    Low,
    /// Medium risk - suspicious behavior detected
    Medium,
    /// High risk - likely malicious
    High,
    /// Critical risk - confirmed malware
    Critical,
}

impl Severity {
    /// Get a numeric score for the severity (0-100).
    pub fn score(&self) -> u8 {
        match self {
            Severity::Low => 25,
            Severity::Medium => 50,
            Severity::High => 75,
            Severity::Critical => 100,
        }
    }

    /// Create severity from a heuristic score.
    pub fn from_score(score: u8) -> Self {
        match score {
            0..=20 => Severity::Low,
            21..=50 => Severity::Medium,
            51..=80 => Severity::High,
            _ => Severity::Critical,
        }
    }

    /// Get string representation for database storage.
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// Parse from string.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "low" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Category of malware threat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThreatCategory {
    /// Trojan horse malware
    Trojan,
    /// Ransomware / crypto-locker
    Ransomware,
    /// Virus that replicates
    Virus,
    /// Worm that spreads automatically
    Worm,
    /// Spyware / keylogger
    Spyware,
    /// Adware / unwanted advertisements
    Adware,
    /// Rootkit / system-level hiding
    Rootkit,
    /// Backdoor / remote access
    Backdoor,
    /// Cryptocurrency miner
    Miner,
    /// Potentially unwanted program
    Pup,
    /// Exploit / vulnerability abuse
    Exploit,
    /// Dropper / downloader
    Dropper,
    /// Generic / unclassified
    Generic,
    /// Test file (e.g., EICAR)
    TestFile,
    /// Unknown category
    Unknown,
}

impl ThreatCategory {
    /// Get string representation for database storage.
    pub fn as_str(&self) -> &'static str {
        match self {
            ThreatCategory::Trojan => "trojan",
            ThreatCategory::Ransomware => "ransomware",
            ThreatCategory::Virus => "virus",
            ThreatCategory::Worm => "worm",
            ThreatCategory::Spyware => "spyware",
            ThreatCategory::Adware => "adware",
            ThreatCategory::Rootkit => "rootkit",
            ThreatCategory::Backdoor => "backdoor",
            ThreatCategory::Miner => "miner",
            ThreatCategory::Pup => "pup",
            ThreatCategory::Exploit => "exploit",
            ThreatCategory::Dropper => "dropper",
            ThreatCategory::Generic => "generic",
            ThreatCategory::TestFile => "testfile",
            ThreatCategory::Unknown => "unknown",
        }
    }

    /// Parse from string.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "trojan" => Some(ThreatCategory::Trojan),
            "ransomware" => Some(ThreatCategory::Ransomware),
            "virus" => Some(ThreatCategory::Virus),
            "worm" => Some(ThreatCategory::Worm),
            "spyware" => Some(ThreatCategory::Spyware),
            "adware" => Some(ThreatCategory::Adware),
            "rootkit" => Some(ThreatCategory::Rootkit),
            "backdoor" => Some(ThreatCategory::Backdoor),
            "miner" => Some(ThreatCategory::Miner),
            "pup" => Some(ThreatCategory::Pup),
            "exploit" => Some(ThreatCategory::Exploit),
            "dropper" => Some(ThreatCategory::Dropper),
            "generic" => Some(ThreatCategory::Generic),
            "testfile" | "test" => Some(ThreatCategory::TestFile),
            "unknown" => Some(ThreatCategory::Unknown),
            _ => None,
        }
    }
}

impl std::fmt::Display for ThreatCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatCategory::Trojan => write!(f, "Trojan"),
            ThreatCategory::Ransomware => write!(f, "Ransomware"),
            ThreatCategory::Virus => write!(f, "Virus"),
            ThreatCategory::Worm => write!(f, "Worm"),
            ThreatCategory::Spyware => write!(f, "Spyware"),
            ThreatCategory::Adware => write!(f, "Adware"),
            ThreatCategory::Rootkit => write!(f, "Rootkit"),
            ThreatCategory::Backdoor => write!(f, "Backdoor"),
            ThreatCategory::Miner => write!(f, "Miner"),
            ThreatCategory::Pup => write!(f, "PUP"),
            ThreatCategory::Exploit => write!(f, "Exploit"),
            ThreatCategory::Dropper => write!(f, "Dropper"),
            ThreatCategory::Generic => write!(f, "Generic"),
            ThreatCategory::TestFile => write!(f, "Test File"),
            ThreatCategory::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Type of detection method used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DetectionMethod {
    /// Hash signature match (SHA256, MD5)
    Signature,
    /// Byte pattern match
    Pattern,
    /// YARA rule match
    Yara,
    /// Heuristic analysis
    Heuristic,
    /// Behavioral analysis
    Behavioral,
    /// Cloud lookup
    Cloud,
}

impl std::fmt::Display for DetectionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DetectionMethod::Signature => write!(f, "Signature"),
            DetectionMethod::Pattern => write!(f, "Pattern"),
            DetectionMethod::Yara => write!(f, "YARA"),
            DetectionMethod::Heuristic => write!(f, "Heuristic"),
            DetectionMethod::Behavioral => write!(f, "Behavioral"),
            DetectionMethod::Cloud => write!(f, "Cloud"),
        }
    }
}

/// Recommended remediation action for a threat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RemediationAction {
    /// Move to quarantine vault
    Quarantine,
    /// Permanently delete
    Delete,
    /// Terminate process and quarantine
    TerminateAndQuarantine,
    /// Clean/repair the file
    Clean,
    /// Ignore (user whitelisted)
    Ignore,
    /// Manual review required
    Review,
}

impl std::fmt::Display for RemediationAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RemediationAction::Quarantine => write!(f, "Quarantine"),
            RemediationAction::Delete => write!(f, "Delete"),
            RemediationAction::TerminateAndQuarantine => write!(f, "Terminate & Quarantine"),
            RemediationAction::Clean => write!(f, "Clean"),
            RemediationAction::Ignore => write!(f, "Ignore"),
            RemediationAction::Review => write!(f, "Review"),
        }
    }
}

/// Type of scan to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanType {
    /// Quick scan of common malware locations
    Quick,
    /// Full system scan
    Full,
    /// Custom scan of user-selected paths
    Custom,
    /// Memory/process scan only
    Memory,
    /// Registry scan only
    Registry,
    /// Boot-time scan (before Windows loads)
    BootTime,
}

impl std::fmt::Display for ScanType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanType::Quick => write!(f, "Quick Scan"),
            ScanType::Full => write!(f, "Full Scan"),
            ScanType::Custom => write!(f, "Custom Scan"),
            ScanType::Memory => write!(f, "Memory Scan"),
            ScanType::Registry => write!(f, "Registry Scan"),
            ScanType::BootTime => write!(f, "Boot-Time Scan"),
        }
    }
}

/// Current status of a scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    /// Scan is pending / not started
    Pending,
    /// Scan is currently running
    Running,
    /// Scan is paused
    Paused,
    /// Scan completed successfully
    Completed,
    /// Scan was cancelled by user
    Cancelled,
    /// Scan failed with error
    Failed,
}

/// File priority for scanning (determines scan order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FilePriority {
    /// Highest priority - executables, scripts
    Critical,
    /// High priority - installers, archives with executables
    High,
    /// Medium priority - documents with macros
    Medium,
    /// Low priority - archives, data files
    Low,
    /// Skip this file type
    Skip,
}

impl FilePriority {
    /// Determine file priority based on extension.
    pub fn from_extension(ext: &str) -> Self {
        match ext.to_lowercase().as_str() {
            // Critical - executables and scripts
            "exe" | "dll" | "sys" | "scr" | "com" | "bat" | "cmd" | "ps1" | "vbs" | "js"
            | "jse" | "vbe" | "wsf" | "wsh" => FilePriority::Critical,

            // High - installers and special formats
            "msi" | "jar" | "hta" | "lnk" | "pif" | "cpl" | "msc" => FilePriority::High,

            // Medium - documents that can contain macros
            "doc" | "docm" | "xls" | "xlsm" | "ppt" | "pptm" | "pdf" | "rtf" => {
                FilePriority::Medium
            }

            // Low - archives
            "zip" | "rar" | "7z" | "tar" | "gz" | "bz2" | "xz" | "cab" => FilePriority::Low,

            // Skip - known safe/large formats
            "iso" | "vmdk" | "vhd" | "mp3" | "mp4" | "avi" | "mkv" | "jpg" | "jpeg" | "png"
            | "gif" | "bmp" => FilePriority::Skip,

            _ => FilePriority::Low,
        }
    }
}

/// A detected threat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    /// Path to the detected file
    pub path: PathBuf,
    /// Name of the detected threat
    pub threat_name: String,
    /// Severity level
    pub severity: Severity,
    /// Category of threat
    pub category: ThreatCategory,
    /// How the threat was detected
    pub method: DetectionMethod,
    /// Description of the threat
    pub description: String,
    /// SHA256 hash of the file (if available)
    pub sha256: Option<String>,
    /// Heuristic score (0-100)
    pub score: u8,
}

impl Detection {
    /// Create a new detection.
    pub fn new(
        path: PathBuf,
        threat_name: impl Into<String>,
        severity: Severity,
        category: ThreatCategory,
        method: DetectionMethod,
    ) -> Self {
        Self {
            path,
            threat_name: threat_name.into(),
            severity,
            category,
            method,
            description: String::new(),
            sha256: None,
            score: severity.score(),
        }
    }

    /// Set the description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Set the SHA256 hash.
    pub fn with_sha256(mut self, sha256: impl Into<String>) -> Self {
        self.sha256 = Some(sha256.into());
        self
    }

    /// Set the heuristic score.
    pub fn with_score(mut self, score: u8) -> Self {
        self.score = score;
        self
    }
}

/// Summary of a completed scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    /// Unique scan identifier
    pub scan_id: String,
    /// Type of scan performed
    pub scan_type: ScanType,
    /// When the scan started
    pub start_time: DateTime<Utc>,
    /// When the scan ended
    pub end_time: Option<DateTime<Utc>>,
    /// Final status
    pub status: ScanStatus,
    /// Total files scanned
    pub files_scanned: u64,
    /// Total directories scanned
    pub directories_scanned: u64,
    /// Total bytes scanned
    pub bytes_scanned: u64,
    /// Number of threats found
    pub threats_found: u32,
    /// Number of threats quarantined
    pub threats_quarantined: u32,
    /// Number of threats deleted
    pub threats_deleted: u32,
    /// Number of errors during scan
    pub errors: u32,
    /// List of detections
    pub detections: Vec<Detection>,
}

impl ScanSummary {
    /// Create a new scan summary.
    pub fn new(scan_type: ScanType) -> Self {
        Self {
            scan_id: uuid::Uuid::new_v4().to_string(),
            scan_type,
            start_time: Utc::now(),
            end_time: None,
            status: ScanStatus::Pending,
            files_scanned: 0,
            directories_scanned: 0,
            bytes_scanned: 0,
            threats_found: 0,
            threats_quarantined: 0,
            threats_deleted: 0,
            errors: 0,
            detections: Vec::new(),
        }
    }

    /// Calculate scan duration in seconds.
    pub fn duration_secs(&self) -> Option<i64> {
        self.end_time
            .map(|end| (end - self.start_time).num_seconds())
    }

    /// Mark the scan as completed.
    pub fn complete(&mut self) {
        self.end_time = Some(Utc::now());
        self.status = ScanStatus::Completed;
    }

    /// Mark the scan as failed.
    pub fn fail(&mut self) {
        self.end_time = Some(Utc::now());
        self.status = ScanStatus::Failed;
    }
}

/// Application-wide statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppStats {
    /// Total scans performed
    pub total_scans: u64,
    /// Total files scanned across all scans
    pub total_files_scanned: u64,
    /// Total threats detected
    pub total_threats_detected: u64,
    /// Total threats quarantined
    pub total_threats_quarantined: u64,
    /// Last scan timestamp
    pub last_scan: Option<DateTime<Utc>>,
    /// Signature database version
    pub signature_version: Option<String>,
    /// Last signature update
    pub last_signature_update: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn test_severity_from_score() {
        assert_eq!(Severity::from_score(10), Severity::Low);
        assert_eq!(Severity::from_score(35), Severity::Medium);
        assert_eq!(Severity::from_score(65), Severity::High);
        assert_eq!(Severity::from_score(95), Severity::Critical);
    }

    #[test]
    fn test_file_priority() {
        assert_eq!(FilePriority::from_extension("exe"), FilePriority::Critical);
        assert_eq!(FilePriority::from_extension("msi"), FilePriority::High);
        assert_eq!(FilePriority::from_extension("docm"), FilePriority::Medium);
        assert_eq!(FilePriority::from_extension("zip"), FilePriority::Low);
        assert_eq!(FilePriority::from_extension("mp4"), FilePriority::Skip);
    }
}
