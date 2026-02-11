//! Persistence mechanism scanner for detecting malware survival techniques.
//!
//! This module provides detection for common persistence mechanisms:
//! - Registry autorun locations (Run, RunOnce, Services)
//! - Image File Execution Options (IFEO) hijacking
//! - AppInit_DLLs injection
//! - Winlogon and LSA persistence
//! - Scheduled tasks
//! - Startup folder entries
//! - WMI event subscriptions

pub mod registry;
pub mod startup;
pub mod tasks;

pub use registry::{AutorunEntry, RegistryEntry, RegistryScanner};
pub use startup::{StartupEntry, StartupScanner};
pub use tasks::{ScheduledTask, TaskScanner};

use crate::core::error::Result;
use crate::core::types::{Detection, DetectionMethod, Severity, ThreatCategory};
use std::path::PathBuf;

/// Types of persistence mechanisms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistenceType {
    /// Registry Run/RunOnce keys
    RegistryRun,
    /// Windows Services
    Service,
    /// Image File Execution Options (debugger hijacking)
    Ifeo,
    /// AppInit_DLLs
    AppInitDll,
    /// Shell extensions and handlers
    ShellExtension,
    /// Winlogon notification packages
    Winlogon,
    /// LSA authentication packages
    LsaPackage,
    /// Scheduled tasks
    ScheduledTask,
    /// Startup folder
    StartupFolder,
    /// WMI event subscription
    WmiSubscription,
    /// Browser extension/addon
    BrowserExtension,
}

impl std::fmt::Display for PersistenceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PersistenceType::RegistryRun => write!(f, "Registry Run"),
            PersistenceType::Service => write!(f, "Service"),
            PersistenceType::Ifeo => write!(f, "IFEO"),
            PersistenceType::AppInitDll => write!(f, "AppInit_DLLs"),
            PersistenceType::ShellExtension => write!(f, "Shell Extension"),
            PersistenceType::Winlogon => write!(f, "Winlogon"),
            PersistenceType::LsaPackage => write!(f, "LSA Package"),
            PersistenceType::ScheduledTask => write!(f, "Scheduled Task"),
            PersistenceType::StartupFolder => write!(f, "Startup Folder"),
            PersistenceType::WmiSubscription => write!(f, "WMI Subscription"),
            PersistenceType::BrowserExtension => write!(f, "Browser Extension"),
        }
    }
}

/// A detected persistence entry.
#[derive(Debug, Clone)]
pub struct PersistenceEntry {
    /// Type of persistence mechanism
    pub persistence_type: PersistenceType,
    /// Name/identifier of the entry
    pub name: String,
    /// Path to executable or script
    pub path: Option<PathBuf>,
    /// Command line arguments
    pub arguments: Option<String>,
    /// Registry key or location where found
    pub location: String,
    /// Whether the file exists
    pub file_exists: bool,
    /// Whether this entry is suspicious
    pub suspicious: bool,
    /// Reason for suspicion (if any)
    pub suspicion_reason: Option<String>,
    /// Severity score (0-100)
    pub severity_score: u8,
}

impl PersistenceEntry {
    /// Create a new persistence entry.
    pub fn new(
        persistence_type: PersistenceType,
        name: impl Into<String>,
        location: impl Into<String>,
    ) -> Self {
        Self {
            persistence_type,
            name: name.into(),
            path: None,
            arguments: None,
            location: location.into(),
            file_exists: true,
            suspicious: false,
            suspicion_reason: None,
            severity_score: 0,
        }
    }

    /// Set the executable path.
    pub fn with_path(mut self, path: impl Into<PathBuf>) -> Self {
        let p = path.into();
        self.file_exists = p.exists();
        self.path = Some(p);
        self
    }

    /// Set command line arguments.
    pub fn with_arguments(mut self, args: impl Into<String>) -> Self {
        self.arguments = Some(args.into());
        self
    }

    /// Mark as suspicious with a reason.
    pub fn mark_suspicious(mut self, reason: impl Into<String>, score: u8) -> Self {
        self.suspicious = true;
        self.suspicion_reason = Some(reason.into());
        self.severity_score = score;
        self
    }

    /// Convert to a Detection if suspicious.
    pub fn to_detection(&self) -> Option<Detection> {
        if !self.suspicious {
            return None;
        }

        let severity = match self.severity_score {
            0..=30 => Severity::Low,
            31..=60 => Severity::Medium,
            61..=80 => Severity::High,
            _ => Severity::Critical,
        };

        Some(Detection {
            path: self
                .path
                .clone()
                .unwrap_or_else(|| PathBuf::from(&self.location)),
            threat_name: format!("Persistence.{}", self.persistence_type),
            severity,
            category: ThreatCategory::Generic,
            method: DetectionMethod::Behavioral,
            description: self.suspicion_reason.clone().unwrap_or_default(),
            sha256: None,
            score: self.severity_score,
        })
    }
}

/// Complete persistence scanner combining all detection methods.
pub struct PersistenceScanner {
    registry_scanner: RegistryScanner,
    startup_scanner: StartupScanner,
    task_scanner: TaskScanner,
}

impl Default for PersistenceScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl PersistenceScanner {
    /// Create a new persistence scanner.
    pub fn new() -> Self {
        Self {
            registry_scanner: RegistryScanner::new(),
            startup_scanner: StartupScanner::new(),
            task_scanner: TaskScanner::new(),
        }
    }

    /// Scan all persistence locations and return entries.
    pub fn scan_all(&self) -> Result<Vec<PersistenceEntry>> {
        let mut entries = Vec::new();

        // Scan registry
        entries.extend(self.registry_scanner.scan_all()?);

        // Scan startup folders
        entries.extend(self.startup_scanner.scan_all()?);

        // Scan scheduled tasks
        entries.extend(self.task_scanner.scan_all()?);

        Ok(entries)
    }

    /// Scan and return only suspicious entries.
    pub fn scan_suspicious(&self) -> Result<Vec<PersistenceEntry>> {
        Ok(self
            .scan_all()?
            .into_iter()
            .filter(|e| e.suspicious)
            .collect())
    }

    /// Convert suspicious entries to detections.
    pub fn get_detections(&self) -> Result<Vec<Detection>> {
        Ok(self
            .scan_suspicious()?
            .iter()
            .filter_map(|e| e.to_detection())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_persistence_entry() {
        let entry = PersistenceEntry::new(
            PersistenceType::RegistryRun,
            "TestApp",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        )
        .with_path("/path/to/app.exe")
        .mark_suspicious("Unknown executable in autorun", 50);

        assert!(entry.suspicious);
        assert_eq!(entry.severity_score, 50);
        assert!(entry.to_detection().is_some());
    }

    #[test]
    fn test_persistence_type_display() {
        assert_eq!(format!("{}", PersistenceType::RegistryRun), "Registry Run");
        assert_eq!(format!("{}", PersistenceType::Ifeo), "IFEO");
    }
}
