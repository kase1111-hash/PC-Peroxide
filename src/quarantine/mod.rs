//! Quarantine vault management.
//!
//! This module handles:
//! - Secure file quarantine with AES-256-GCM encryption
//! - Quarantine metadata tracking in SQLite
//! - File restoration
//! - Safe deletion with secure overwrite
//! - Whitelist management

pub mod encryption;
pub mod metadata;
pub mod operations;
pub mod vault;
pub mod whitelist;

pub use encryption::EncryptionManager;
pub use metadata::{QuarantineItem, QuarantineMetadata};
pub use operations::SecureOperations;
pub use vault::QuarantineVault;
pub use whitelist::{WhitelistEntry, WhitelistManager, WhitelistType};

use std::path::PathBuf;

/// Default quarantine directory name
pub const QUARANTINE_DIR: &str = "PC-Peroxide";
/// Subdirectory for encrypted quarantine items
pub const VAULT_DIR: &str = "Quarantine";
/// Subdirectory for item data files
pub const ITEMS_DIR: &str = "items";
/// Extension for quarantine vault files
pub const VAULT_EXTENSION: &str = "qvault";

/// Get the default quarantine base path.
///
/// On Windows: %PROGRAMDATA%\PC-Peroxide\Quarantine
/// On Linux: ~/.local/share/pc-peroxide/quarantine
/// On macOS: ~/Library/Application Support/PC-Peroxide/Quarantine
pub fn get_quarantine_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Some(program_data) = std::env::var_os("PROGRAMDATA") {
            PathBuf::from(program_data)
                .join(QUARANTINE_DIR)
                .join(VAULT_DIR)
        } else {
            PathBuf::from("C:\\ProgramData")
                .join(QUARANTINE_DIR)
                .join(VAULT_DIR)
        }
    }

    #[cfg(target_os = "linux")]
    {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("~/.local/share"))
            .join("pc-peroxide")
            .join("quarantine")
    }

    #[cfg(target_os = "macos")]
    {
        dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("~/Library/Application Support"))
            .join(QUARANTINE_DIR)
            .join(VAULT_DIR)
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        PathBuf::from("./quarantine")
    }
}

/// Result of a quarantine operation
#[derive(Debug, Clone)]
pub struct QuarantineResult {
    /// Unique ID of the quarantined item
    pub id: String,
    /// Original path of the file
    pub original_path: PathBuf,
    /// Path in the quarantine vault
    pub vault_path: PathBuf,
    /// Whether the operation succeeded
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
}

impl QuarantineResult {
    /// Create a successful quarantine result
    pub fn success(id: String, original_path: PathBuf, vault_path: PathBuf) -> Self {
        Self {
            id,
            original_path,
            vault_path,
            success: true,
            error: None,
        }
    }

    /// Create a failed quarantine result
    pub fn failure(original_path: PathBuf, error: String) -> Self {
        Self {
            id: String::new(),
            original_path,
            vault_path: PathBuf::new(),
            success: false,
            error: Some(error),
        }
    }
}

/// Result of a restore operation
#[derive(Debug, Clone)]
pub struct RestoreResult {
    /// ID of the restored item
    pub id: String,
    /// Path where the file was restored
    pub restored_path: PathBuf,
    /// Whether the operation succeeded
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
}

impl RestoreResult {
    /// Create a successful restore result
    pub fn success(id: String, restored_path: PathBuf) -> Self {
        Self {
            id,
            restored_path,
            success: true,
            error: None,
        }
    }

    /// Create a failed restore result
    pub fn failure(id: String, error: String) -> Self {
        Self {
            id,
            restored_path: PathBuf::new(),
            success: false,
            error: Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_quarantine_path() {
        let path = get_quarantine_path();
        assert!(!path.as_os_str().is_empty());
    }

    #[test]
    fn test_quarantine_result_success() {
        let result = QuarantineResult::success(
            "test-id".to_string(),
            PathBuf::from("/original/path"),
            PathBuf::from("/vault/path"),
        );
        assert!(result.success);
        assert!(result.error.is_none());
        assert_eq!(result.id, "test-id");
    }

    #[test]
    fn test_quarantine_result_failure() {
        let result =
            QuarantineResult::failure(PathBuf::from("/original/path"), "Test error".to_string());
        assert!(!result.success);
        assert_eq!(result.error, Some("Test error".to_string()));
    }

    #[test]
    fn test_restore_result_success() {
        let result = RestoreResult::success("test-id".to_string(), PathBuf::from("/restored/path"));
        assert!(result.success);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_restore_result_failure() {
        let result = RestoreResult::failure("test-id".to_string(), "Restore failed".to_string());
        assert!(!result.success);
        assert!(result.error.is_some());
    }
}
