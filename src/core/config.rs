//! Configuration management for PC-Peroxide.

use crate::core::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Main configuration structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Scan-related settings
    pub scan: ScanConfig,
    /// Detection sensitivity settings
    pub detection: DetectionConfig,
    /// Default actions for threats
    pub actions: ActionConfig,
    /// Signature update settings
    pub updates: UpdateConfig,
    /// Logging settings
    pub logging: LoggingConfig,
    /// Quarantine settings
    pub quarantine: QuarantineConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            scan: ScanConfig::default(),
            detection: DetectionConfig::default(),
            actions: ActionConfig::default(),
            updates: UpdateConfig::default(),
            logging: LoggingConfig::default(),
            quarantine: QuarantineConfig::default(),
        }
    }
}

impl Config {
    /// Load configuration from a JSON file.
    pub fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path).map_err(|e| {
            Error::ConfigLoad(format!("Failed to read config file: {}", e))
        })?;

        serde_json::from_str(&contents).map_err(|e| {
            Error::ConfigLoad(format!("Failed to parse config file: {}", e))
        })
    }

    /// Save configuration to a JSON file.
    pub fn save(&self, path: &Path) -> Result<()> {
        let contents = serde_json::to_string_pretty(self)?;

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                Error::ConfigSave(format!("Failed to create config directory: {}", e))
            })?;
        }

        std::fs::write(path, contents).map_err(|e| {
            Error::ConfigSave(format!("Failed to write config file: {}", e))
        })
    }

    /// Load configuration from default location, or create default if not exists.
    pub fn load_or_default() -> Self {
        let config_path = Self::default_config_path();

        if config_path.exists() {
            match Self::load(&config_path) {
                Ok(config) => return config,
                Err(e) => {
                    log::warn!("Failed to load config, using defaults: {}", e);
                }
            }
        }

        let config = Self::default();

        // Try to save default config
        if let Err(e) = config.save(&config_path) {
            log::warn!("Failed to save default config: {}", e);
        }

        config
    }

    /// Get the default configuration file path.
    pub fn default_config_path() -> PathBuf {
        Self::data_dir().join("config.json")
    }

    /// Get the application data directory.
    pub fn data_dir() -> PathBuf {
        #[cfg(windows)]
        {
            dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from("C:\\ProgramData"))
                .join("PC-Peroxide")
        }

        #[cfg(not(windows))]
        {
            dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from("/tmp"))
                .join("pc-peroxide")
        }
    }

    /// Validate the configuration values.
    pub fn validate(&self) -> Result<()> {
        if self.scan.skip_large_files_mb == 0 {
            return Err(Error::ConfigInvalid {
                field: "scan.skip_large_files_mb".to_string(),
                message: "Must be greater than 0".to_string(),
            });
        }

        if self.scan.max_archive_depth == 0 || self.scan.max_archive_depth > 10 {
            return Err(Error::ConfigInvalid {
                field: "scan.max_archive_depth".to_string(),
                message: "Must be between 1 and 10".to_string(),
            });
        }

        if self.logging.keep_logs_days == 0 {
            return Err(Error::ConfigInvalid {
                field: "logging.keep_logs_days".to_string(),
                message: "Must be greater than 0".to_string(),
            });
        }

        Ok(())
    }
}

/// Scan-related configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Skip files larger than this size (MB)
    pub skip_large_files_mb: u64,
    /// Skip archives larger than this size (MB)
    pub skip_archives_larger_than_mb: u64,
    /// Whether to scan inside archives
    pub scan_archives: bool,
    /// Maximum archive nesting depth
    pub max_archive_depth: u8,
    /// Whether to follow symbolic links
    pub follow_symlinks: bool,
    /// Paths to exclude from scanning
    pub exclude_paths: Vec<String>,
    /// File extensions to exclude
    pub exclude_extensions: Vec<String>,
    /// Number of parallel scan threads
    pub scan_threads: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            skip_large_files_mb: 100,
            skip_archives_larger_than_mb: 50,
            scan_archives: true,
            max_archive_depth: 3,
            follow_symlinks: false,
            exclude_paths: vec![
                #[cfg(windows)]
                "C:\\Windows\\WinSxS".to_string(),
                #[cfg(windows)]
                "C:\\$Recycle.Bin".to_string(),
                #[cfg(not(windows))]
                "/proc".to_string(),
                #[cfg(not(windows))]
                "/sys".to_string(),
            ],
            exclude_extensions: vec!["iso".to_string(), "vmdk".to_string(), "vhd".to_string()],
            scan_threads: num_cpus(),
        }
    }
}

/// Detection sensitivity configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    /// Heuristic sensitivity level
    pub heuristic_sensitivity: Sensitivity,
    /// Enable YARA rules scanning
    pub enable_yara: bool,
    /// Enable cloud hash lookup
    pub enable_cloud_lookup: bool,
    /// Detect potentially unwanted programs
    pub pup_detection: bool,
    /// Minimum heuristic score to flag as suspicious
    pub heuristic_threshold: u8,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            heuristic_sensitivity: Sensitivity::Medium,
            enable_yara: true,
            enable_cloud_lookup: false,
            pup_detection: true,
            heuristic_threshold: 50,
        }
    }
}

/// Sensitivity level for heuristic detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Sensitivity {
    /// Low sensitivity - fewer false positives, may miss some threats
    Low,
    /// Medium sensitivity - balanced
    Medium,
    /// High sensitivity - more aggressive, may have false positives
    High,
}

impl Sensitivity {
    /// Get the score multiplier for this sensitivity level.
    pub fn multiplier(&self) -> f32 {
        match self {
            Sensitivity::Low => 0.75,
            Sensitivity::Medium => 1.0,
            Sensitivity::High => 1.25,
        }
    }
}

/// Default action configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionConfig {
    /// Default action for detected threats
    pub default_action: DefaultAction,
    /// Automatically quarantine critical threats
    pub auto_quarantine_critical: bool,
    /// Prompt user for low severity threats
    pub prompt_for_low_severity: bool,
}

impl Default for ActionConfig {
    fn default() -> Self {
        Self {
            default_action: DefaultAction::Quarantine,
            auto_quarantine_critical: true,
            prompt_for_low_severity: true,
        }
    }
}

/// Default action to take on detected threats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultAction {
    /// Move to quarantine
    Quarantine,
    /// Delete immediately
    Delete,
    /// Report only, no action
    ReportOnly,
    /// Always prompt user
    Prompt,
}

/// Signature update configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateConfig {
    /// Automatically check for signature updates
    pub auto_update_signatures: bool,
    /// Hours between update checks
    pub update_check_interval_hours: u32,
    /// URL for update manifest
    pub update_url: String,
    /// Allow offline operation
    pub allow_offline: bool,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            auto_update_signatures: true,
            update_check_interval_hours: 24,
            update_url: "https://updates.pc-peroxide.example.com/manifest.json".to_string(),
            allow_offline: true,
        }
    }
}

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    pub log_level: String,
    /// Days to keep log files
    pub keep_logs_days: u32,
    /// Path for log files
    pub log_path: Option<PathBuf>,
    /// Enable verbose console output
    pub verbose_console: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            log_level: "info".to_string(),
            keep_logs_days: 30,
            log_path: None,
            verbose_console: false,
        }
    }
}

impl LoggingConfig {
    /// Get the effective log directory.
    pub fn log_dir(&self) -> PathBuf {
        self.log_path
            .clone()
            .unwrap_or_else(|| Config::data_dir().join("logs"))
    }
}

/// Quarantine configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineConfig {
    /// Path for quarantine vault
    pub vault_path: Option<PathBuf>,
    /// Days to keep quarantined items before auto-delete
    pub retention_days: u32,
    /// Maximum vault size in MB (0 = unlimited)
    pub max_vault_size_mb: u64,
    /// Encrypt quarantined files
    pub encrypt_vault: bool,
}

impl Default for QuarantineConfig {
    fn default() -> Self {
        Self {
            vault_path: None,
            retention_days: 30,
            max_vault_size_mb: 0,
            encrypt_vault: true,
        }
    }
}

impl QuarantineConfig {
    /// Get the effective quarantine directory.
    pub fn quarantine_dir(&self) -> PathBuf {
        self.vault_path
            .clone()
            .unwrap_or_else(|| Config::data_dir().join("quarantine"))
    }
}

/// Get the number of CPUs, with a reasonable default.
fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_save_load() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_config.json");

        let config = Config::default();
        config.save(&path).unwrap();

        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded.scan.skip_large_files_mb, config.scan.skip_large_files_mb);
    }

    #[test]
    fn test_sensitivity_multiplier() {
        assert!(Sensitivity::Low.multiplier() < Sensitivity::Medium.multiplier());
        assert!(Sensitivity::Medium.multiplier() < Sensitivity::High.multiplier());
    }

    #[test]
    fn test_invalid_config() {
        let mut config = Config::default();
        config.scan.skip_large_files_mb = 0;
        assert!(config.validate().is_err());
    }
}
