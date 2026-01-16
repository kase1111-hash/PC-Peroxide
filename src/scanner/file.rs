//! File system scanner implementation.

use crate::core::config::Config;
use crate::core::error::Result;
use crate::core::types::{Detection, FilePriority, ScanSummary, ScanType};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// Quick scan paths for Windows systems.
#[cfg(windows)]
pub const QUICK_SCAN_PATHS: &[&str] = &[
    "%TEMP%",
    "%APPDATA%",
    "%LOCALAPPDATA%",
    "%PROGRAMDATA%",
    "C:\\Users\\*\\Downloads",
    "C:\\Windows\\Temp",
    "C:\\Windows\\Prefetch",
    "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
];

/// Quick scan paths for non-Windows systems (for testing).
#[cfg(not(windows))]
pub const QUICK_SCAN_PATHS: &[&str] = &[
    "/tmp",
    "/var/tmp",
];

/// File system scanner.
pub struct FileScanner {
    config: Arc<Config>,
    cancelled: Arc<AtomicBool>,
    files_scanned: Arc<AtomicU64>,
    bytes_scanned: Arc<AtomicU64>,
}

impl FileScanner {
    /// Create a new file scanner with the given configuration.
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            config,
            cancelled: Arc::new(AtomicBool::new(false)),
            files_scanned: Arc::new(AtomicU64::new(0)),
            bytes_scanned: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Cancel the current scan.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Check if the scan has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Get the number of files scanned so far.
    pub fn files_scanned(&self) -> u64 {
        self.files_scanned.load(Ordering::Relaxed)
    }

    /// Get the number of bytes scanned so far.
    pub fn bytes_scanned(&self) -> u64 {
        self.bytes_scanned.load(Ordering::Relaxed)
    }

    /// Expand environment variables in a path (Windows).
    #[cfg(windows)]
    pub fn expand_path(path: &str) -> PathBuf {
        let expanded = path
            .replace("%TEMP%", &std::env::var("TEMP").unwrap_or_default())
            .replace("%APPDATA%", &std::env::var("APPDATA").unwrap_or_default())
            .replace("%LOCALAPPDATA%", &std::env::var("LOCALAPPDATA").unwrap_or_default())
            .replace("%PROGRAMDATA%", &std::env::var("PROGRAMDATA").unwrap_or_default())
            .replace("%USERPROFILE%", &std::env::var("USERPROFILE").unwrap_or_default());
        PathBuf::from(expanded)
    }

    /// Expand environment variables in a path (non-Windows stub).
    #[cfg(not(windows))]
    pub fn expand_path(path: &str) -> PathBuf {
        PathBuf::from(path)
    }

    /// Check if a path should be excluded from scanning.
    pub fn should_exclude(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();

        // Check excluded paths
        for excluded in &self.config.scan.exclude_paths {
            if path_str.contains(excluded) {
                return true;
            }
        }

        // Check excluded extensions
        if let Some(ext) = path.extension() {
            let ext_lower = ext.to_string_lossy().to_lowercase();
            if self.config.scan.exclude_extensions.contains(&ext_lower) {
                return true;
            }
        }

        false
    }

    /// Get the scan priority for a file.
    pub fn get_file_priority(&self, path: &Path) -> FilePriority {
        if let Some(ext) = path.extension() {
            FilePriority::from_extension(&ext.to_string_lossy())
        } else {
            FilePriority::Low
        }
    }

    /// Perform a quick scan of common malware locations.
    pub async fn quick_scan(&self) -> Result<ScanSummary> {
        log::info!("Starting quick scan");
        let mut summary = ScanSummary::new(ScanType::Quick);
        summary.status = crate::core::types::ScanStatus::Running;

        // TODO: Implement actual scanning in Phase 3
        // For now, just iterate through paths
        for path_pattern in QUICK_SCAN_PATHS {
            if self.is_cancelled() {
                summary.status = crate::core::types::ScanStatus::Cancelled;
                return Ok(summary);
            }

            let path = Self::expand_path(path_pattern);
            log::debug!("Scanning path: {:?}", path);
        }

        summary.complete();
        log::info!("Quick scan completed: {} files scanned", summary.files_scanned);
        Ok(summary)
    }

    /// Perform a full system scan.
    pub async fn full_scan(&self) -> Result<ScanSummary> {
        log::info!("Starting full system scan");
        let summary = ScanSummary::new(ScanType::Full);

        // TODO: Implement in Phase 3

        Ok(summary)
    }

    /// Perform a custom scan of specified paths.
    pub async fn custom_scan(&self, paths: Vec<PathBuf>) -> Result<ScanSummary> {
        log::info!("Starting custom scan of {} paths", paths.len());
        let summary = ScanSummary::new(ScanType::Custom);

        // TODO: Implement in Phase 3

        Ok(summary)
    }

    /// Scan a single file.
    pub async fn scan_file(&self, path: &Path) -> Result<Option<Detection>> {
        if self.should_exclude(path) {
            log::trace!("Skipping excluded file: {:?}", path);
            return Ok(None);
        }

        // TODO: Implement actual file scanning in Phase 3
        self.files_scanned.fetch_add(1, Ordering::Relaxed);

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_priority() {
        let config = Arc::new(Config::default());
        let scanner = FileScanner::new(config);

        assert_eq!(
            scanner.get_file_priority(Path::new("test.exe")),
            FilePriority::Critical
        );
        assert_eq!(
            scanner.get_file_priority(Path::new("test.zip")),
            FilePriority::Low
        );
    }

    #[test]
    fn test_cancellation() {
        let config = Arc::new(Config::default());
        let scanner = FileScanner::new(config);

        assert!(!scanner.is_cancelled());
        scanner.cancel();
        assert!(scanner.is_cancelled());
    }
}
