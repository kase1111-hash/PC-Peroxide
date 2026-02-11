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

    #[error("Network request timed out after {timeout_secs}s: {operation}")]
    NetworkTimeout {
        operation: String,
        timeout_secs: u64,
    },

    #[error("Network request failed after {attempts} attempts: {operation}")]
    NetworkRetryExhausted {
        operation: String,
        attempts: u32,
        last_error: String,
    },

    // ===== LLM/Analysis Errors =====
    #[error("LLM provider unavailable: {provider}")]
    LlmUnavailable { provider: String },

    #[error("LLM analysis failed: {reason}")]
    LlmAnalysis { reason: String },

    #[error("LLM request timed out: {provider}")]
    LlmTimeout { provider: String },

    #[error("LLM rate limited: retry after {retry_after_secs}s")]
    LlmRateLimited { retry_after_secs: u64 },

    #[error("LLM response parsing failed: {reason}")]
    LlmParsing { reason: String },

    // ===== Detection Errors =====
    #[error("YARA rule compilation failed: {0}")]
    YaraCompilation(String),

    #[error("YARA scan failed: {0}")]
    YaraScan(String),

    #[error("Heuristic analysis failed: {0}")]
    HeuristicError(String),

    // ===== Concurrency Errors =====
    #[error("Lock poisoned: {context}")]
    LockPoisoned { context: String },

    #[error("Channel send failed: {context}")]
    ChannelSend { context: String },

    #[error("Channel receive failed: {context}")]
    ChannelRecv { context: String },

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

    /// Create a lock poisoned error.
    pub fn lock_poisoned(context: impl Into<String>) -> Self {
        Self::LockPoisoned {
            context: context.into(),
        }
    }

    /// Create an LLM unavailable error.
    pub fn llm_unavailable(provider: impl Into<String>) -> Self {
        Self::LlmUnavailable {
            provider: provider.into(),
        }
    }

    /// Create an LLM analysis error.
    pub fn llm_analysis(reason: impl Into<String>) -> Self {
        Self::LlmAnalysis {
            reason: reason.into(),
        }
    }

    /// Create a network timeout error.
    pub fn network_timeout(operation: impl Into<String>, timeout_secs: u64) -> Self {
        Self::NetworkTimeout {
            operation: operation.into(),
            timeout_secs,
        }
    }

    /// Create a network retry exhausted error.
    pub fn network_retry_exhausted(
        operation: impl Into<String>,
        attempts: u32,
        last_error: impl Into<String>,
    ) -> Self {
        Self::NetworkRetryExhausted {
            operation: operation.into(),
            attempts,
            last_error: last_error.into(),
        }
    }

    /// Check if this error is network-related and potentially retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Error::Network(_)
                | Error::NetworkTimeout { .. }
                | Error::LlmTimeout { .. }
                | Error::DownloadFailed { .. }
        )
    }

    /// Check if this is an LLM-related error.
    pub fn is_llm_error(&self) -> bool {
        matches!(
            self,
            Error::LlmUnavailable { .. }
                | Error::LlmAnalysis { .. }
                | Error::LlmTimeout { .. }
                | Error::LlmRateLimited { .. }
                | Error::LlmParsing { .. }
        )
    }

    /// Get a user-friendly suggestion for how to resolve this error.
    pub fn suggestion(&self) -> Option<&'static str> {
        match self {
            Error::PermissionDenied { .. } => {
                Some("Try running with elevated privileges (sudo/administrator)")
            }
            Error::PathNotFound(_) => Some("Check that the path exists and is accessible"),
            Error::ConfigLoad(_) | Error::ConfigInvalid { .. } => {
                Some("Check your configuration file for syntax errors or missing fields")
            }
            Error::DatabaseInit(_) | Error::Database(_) => {
                Some("Try deleting the database file and letting it be recreated")
            }
            Error::LlmUnavailable { .. } => {
                Some("Ensure the LLM server (Ollama) is running: ollama serve")
            }
            Error::LlmTimeout { .. } => {
                Some("Try increasing the timeout in configuration or use a smaller model")
            }
            Error::LlmRateLimited { .. } => {
                Some("Wait before retrying, or reduce request frequency")
            }
            Error::NetworkTimeout { .. } | Error::NetworkRetryExhausted { .. } => {
                Some("Check your network connection and try again")
            }
            Error::LockPoisoned { .. } => Some("Internal error: restart the application"),
            Error::ScanCancelled => Some("Scan was interrupted by user request"),
            Error::QuarantineItemNotFound(_) => {
                Some("The quarantine item may have been deleted or restored")
            }
            _ => None,
        }
    }

    /// Get the error category for logging/metrics.
    pub fn category(&self) -> ErrorCategory {
        match self {
            Error::FileRead { .. }
            | Error::FileWrite { .. }
            | Error::FileDelete { .. }
            | Error::DirectoryAccess { .. }
            | Error::PathNotFound(_)
            | Error::PermissionDenied { .. }
            | Error::Io(_) => ErrorCategory::Io,

            Error::ConfigLoad(_) | Error::ConfigSave(_) | Error::ConfigInvalid { .. } => {
                ErrorCategory::Configuration
            }

            Error::DatabaseSql(_)
            | Error::Database(_)
            | Error::DatabaseInit(_)
            | Error::SignatureNotFound(_)
            | Error::SignatureLoad(_) => ErrorCategory::Database,

            Error::ScanCancelled
            | Error::ScanTimeout
            | Error::ScanError { .. }
            | Error::ArchiveError { .. } => ErrorCategory::Scanning,

            Error::QuarantineFailed { .. }
            | Error::RestoreFailed { .. }
            | Error::QuarantineItemNotFound(_)
            | Error::Encryption(_)
            | Error::Decryption(_) => ErrorCategory::Quarantine,

            Error::ProcessEnumeration(_)
            | Error::ProcessTermination { .. }
            | Error::ProcessNotFound(_) => ErrorCategory::Process,

            Error::RegistryAccess { .. } | Error::RegistryKeyNotFound(_) => ErrorCategory::Registry,

            Error::Network(_)
            | Error::UpdateFailed(_)
            | Error::DownloadFailed { .. }
            | Error::NetworkTimeout { .. }
            | Error::NetworkRetryExhausted { .. } => ErrorCategory::Network,

            Error::LlmUnavailable { .. }
            | Error::LlmAnalysis { .. }
            | Error::LlmTimeout { .. }
            | Error::LlmRateLimited { .. }
            | Error::LlmParsing { .. } => ErrorCategory::Llm,

            Error::YaraCompilation(_) | Error::YaraScan(_) | Error::HeuristicError(_) => {
                ErrorCategory::Detection
            }

            Error::LockPoisoned { .. } | Error::ChannelSend { .. } | Error::ChannelRecv { .. } => {
                ErrorCategory::Concurrency
            }

            Error::JsonSerialize(_) => ErrorCategory::Serialization,

            Error::Custom(_) | Error::NotSupported(_) | Error::Internal(_) | Error::Other(_) => {
                ErrorCategory::Other
            }
        }
    }
}

/// Error category for classification and metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCategory {
    Io,
    Configuration,
    Database,
    Scanning,
    Quarantine,
    Process,
    Registry,
    Network,
    Llm,
    Detection,
    Concurrency,
    Serialization,
    Other,
}

impl std::fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io => write!(f, "I/O"),
            Self::Configuration => write!(f, "Configuration"),
            Self::Database => write!(f, "Database"),
            Self::Scanning => write!(f, "Scanning"),
            Self::Quarantine => write!(f, "Quarantine"),
            Self::Process => write!(f, "Process"),
            Self::Registry => write!(f, "Registry"),
            Self::Network => write!(f, "Network"),
            Self::Llm => write!(f, "LLM Analysis"),
            Self::Detection => write!(f, "Detection"),
            Self::Concurrency => write!(f, "Concurrency"),
            Self::Serialization => write!(f, "Serialization"),
            Self::Other => write!(f, "Other"),
        }
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
