//! Error types and result handling for PC-Peroxide.

use std::path::PathBuf;
use thiserror::Error;

/// Result type alias using our custom Error type.
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type for PC-Peroxide operations.
#[derive(Error, Debug)]
pub enum Error {
    // ===== I/O Errors =====
    #[error("Failed to read file: {path}")]
    FileRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to write file: {path}")]
    FileWrite {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to delete file: {path}")]
    FileDelete {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to access directory: {path}")]
    DirectoryAccess {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Path not found: {0}")]
    PathNotFound(PathBuf),

    #[error("Permission denied: {path}")]
    PermissionDenied {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    // ===== Configuration Errors =====
    #[error("Failed to load configuration: {0}")]
    ConfigLoad(String),

    #[error("Failed to save configuration: {0}")]
    ConfigSave(String),

    #[error("Invalid configuration value: {field} - {message}")]
    ConfigInvalid { field: String, message: String },

    // ===== Database Errors =====
    #[error("Database error: {0}")]
    DatabaseSql(#[from] rusqlite::Error),

    #[error("Database operation failed: {0}")]
    Database(String),

    #[error("Failed to initialize database: {0}")]
    DatabaseInit(String),

    #[error("Signature not found: {0}")]
    SignatureNotFound(String),

    #[error("Failed to load signatures: {0}")]
    SignatureLoad(String),

    // ===== Scanning Errors =====
    #[error("Scan was cancelled")]
    ScanCancelled,

    #[error("Scan timeout exceeded")]
    ScanTimeout,

    #[error("Failed to scan file: {path} - {reason}")]
    ScanError { path: PathBuf, reason: String },

    #[error("Archive extraction failed: {path}")]
    ArchiveError {
        path: PathBuf,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    // ===== Quarantine Errors =====
    #[error("Failed to quarantine file: {path}")]
    QuarantineFailed {
        path: PathBuf,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("Failed to restore file: {id}")]
    RestoreFailed {
        id: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("Quarantine item not found: {0}")]
    QuarantineItemNotFound(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    // ===== Process Errors =====
    #[error("Failed to enumerate processes: {0}")]
    ProcessEnumeration(String),

    #[error("Failed to terminate process: {pid}")]
    ProcessTermination { pid: u32, reason: String },

    #[error("Process not found: {0}")]
    ProcessNotFound(u32),

    // ===== Registry Errors =====
    #[error("Registry access error: {key}")]
    RegistryAccess {
        key: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("Registry key not found: {0}")]
    RegistryKeyNotFound(String),

    // ===== Network Errors =====
    #[error("Network error: {0}")]
    Network(String),

    #[error("Update failed: {0}")]
    UpdateFailed(String),

    #[error("Download failed: {url}")]
    DownloadFailed {
        url: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    // ===== Detection Errors =====
    #[error("YARA rule compilation failed: {0}")]
    YaraCompilation(String),

    #[error("YARA scan failed: {0}")]
    YaraScan(String),

    #[error("Heuristic analysis failed: {0}")]
    HeuristicError(String),

    // ===== Serialization Errors =====
    #[error("JSON serialization error")]
    JsonSerialize(#[from] serde_json::Error),

    // ===== Generic Errors =====
    #[error("I/O error: {0}")]
    Io(String),

    #[error("Custom error: {0}")]
    Custom(String),

    #[error("Operation not supported: {0}")]
    NotSupported(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err.to_string())
    }
}

impl Error {
    /// Create a file read error.
    pub fn file_read(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::FileRead {
            path: path.into(),
            source,
        }
    }

    /// Create a file write error.
    pub fn file_write(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::FileWrite {
            path: path.into(),
            source,
        }
    }

    /// Create a permission denied error.
    pub fn permission_denied(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::PermissionDenied {
            path: path.into(),
            source,
        }
    }

    /// Create a scan error.
    pub fn scan_error(path: impl Into<PathBuf>, reason: impl Into<String>) -> Self {
        Self::ScanError {
            path: path.into(),
            reason: reason.into(),
        }
    }

    /// Check if this error is recoverable (scan can continue).
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Error::FileRead { .. }
                | Error::PermissionDenied { .. }
                | Error::ScanError { .. }
                | Error::ArchiveError { .. }
        )
    }

    /// Check if this error is a cancellation.
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Error::ScanCancelled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = Error::PathNotFound(PathBuf::from("/test/path"));
        assert_eq!(err.to_string(), "Path not found: /test/path");
    }

    #[test]
    fn test_recoverable_errors() {
        let err = Error::scan_error("/test", "test reason");
        assert!(err.is_recoverable());

        let err = Error::ScanCancelled;
        assert!(!err.is_recoverable());
    }
}
