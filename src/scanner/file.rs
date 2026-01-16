//! File system scanner implementation.

use crate::core::config::Config;
use crate::core::error::{Error, Result};
use crate::core::types::{Detection, FilePriority, ScanStatus, ScanSummary, ScanType};
use crate::detection::{DetectionEngine, SignatureDatabase};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use walkdir::WalkDir;

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
pub const QUICK_SCAN_PATHS: &[&str] = &["/tmp", "/var/tmp"];

/// File system scanner.
pub struct FileScanner {
    config: Arc<Config>,
    detection_engine: Option<DetectionEngine>,
    cancelled: Arc<AtomicBool>,
    files_scanned: Arc<AtomicU64>,
    bytes_scanned: Arc<AtomicU64>,
}

impl FileScanner {
    /// Create a new file scanner with the given configuration.
    pub fn new(config: Arc<Config>) -> Self {
        // Try to open the signature database
        let detection_engine = match SignatureDatabase::open_default() {
            Ok(db) => {
                log::debug!("Signature database loaded");
                Some(DetectionEngine::new(Arc::new(db)))
            }
            Err(e) => {
                log::warn!("Failed to load signature database: {}", e);
                None
            }
        };

        Self {
            config,
            detection_engine,
            cancelled: Arc::new(AtomicBool::new(false)),
            files_scanned: Arc::new(AtomicU64::new(0)),
            bytes_scanned: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Create a scanner with a specific detection engine.
    pub fn with_detection_engine(config: Arc<Config>, engine: DetectionEngine) -> Self {
        Self {
            config,
            detection_engine: Some(engine),
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

    /// Reset scan counters.
    fn reset_counters(&self) {
        self.cancelled.store(false, Ordering::SeqCst);
        self.files_scanned.store(0, Ordering::Relaxed);
        self.bytes_scanned.store(0, Ordering::Relaxed);
    }

    /// Expand environment variables in a path (Windows).
    #[cfg(windows)]
    pub fn expand_path(path: &str) -> PathBuf {
        let expanded = path
            .replace("%TEMP%", &std::env::var("TEMP").unwrap_or_default())
            .replace("%APPDATA%", &std::env::var("APPDATA").unwrap_or_default())
            .replace(
                "%LOCALAPPDATA%",
                &std::env::var("LOCALAPPDATA").unwrap_or_default(),
            )
            .replace(
                "%PROGRAMDATA%",
                &std::env::var("PROGRAMDATA").unwrap_or_default(),
            )
            .replace(
                "%USERPROFILE%",
                &std::env::var("USERPROFILE").unwrap_or_default(),
            );
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

    /// Check if a file exceeds size limits.
    fn exceeds_size_limit(&self, path: &Path) -> bool {
        if let Ok(metadata) = path.metadata() {
            let size_mb = metadata.len() / (1024 * 1024);
            size_mb > self.config.scan.skip_large_files_mb
        } else {
            false
        }
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
        self.reset_counters();
        let mut summary = ScanSummary::new(ScanType::Quick);
        summary.status = ScanStatus::Running;

        for path_pattern in QUICK_SCAN_PATHS {
            if self.is_cancelled() {
                summary.status = ScanStatus::Cancelled;
                summary.end_time = Some(chrono::Utc::now());
                return Ok(summary);
            }

            let path = Self::expand_path(path_pattern);
            if path.exists() {
                self.scan_directory(&path, &mut summary).await?;
            }
        }

        summary.complete();
        log::info!(
            "Quick scan completed: {} files scanned, {} threats found",
            summary.files_scanned,
            summary.threats_found
        );
        Ok(summary)
    }

    /// Perform a full system scan.
    pub async fn full_scan(&self) -> Result<ScanSummary> {
        log::info!("Starting full system scan");
        self.reset_counters();
        let mut summary = ScanSummary::new(ScanType::Full);
        summary.status = ScanStatus::Running;

        // Scan all fixed drives
        #[cfg(windows)]
        let drives = vec!["C:\\", "D:\\", "E:\\"];

        #[cfg(not(windows))]
        let drives = vec!["/"];

        for drive in drives {
            if self.is_cancelled() {
                summary.status = ScanStatus::Cancelled;
                summary.end_time = Some(chrono::Utc::now());
                return Ok(summary);
            }

            let path = PathBuf::from(drive);
            if path.exists() {
                self.scan_directory(&path, &mut summary).await?;
            }
        }

        summary.complete();
        log::info!(
            "Full scan completed: {} files scanned, {} threats found",
            summary.files_scanned,
            summary.threats_found
        );
        Ok(summary)
    }

    /// Perform a custom scan of specified paths.
    pub async fn custom_scan(&self, paths: Vec<PathBuf>) -> Result<ScanSummary> {
        log::info!("Starting custom scan of {} paths", paths.len());
        self.reset_counters();
        let mut summary = ScanSummary::new(ScanType::Custom);
        summary.status = ScanStatus::Running;

        for path in paths {
            if self.is_cancelled() {
                summary.status = ScanStatus::Cancelled;
                summary.end_time = Some(chrono::Utc::now());
                return Ok(summary);
            }

            if path.is_file() {
                if let Some(detection) = self.scan_file(&path).await? {
                    summary.threats_found += 1;
                    summary.detections.push(detection);
                }
                summary.files_scanned += 1;
            } else if path.is_dir() {
                self.scan_directory(&path, &mut summary).await?;
            }
        }

        summary.complete();
        log::info!(
            "Custom scan completed: {} files scanned, {} threats found",
            summary.files_scanned,
            summary.threats_found
        );
        Ok(summary)
    }

    /// Scan a directory recursively.
    async fn scan_directory(&self, path: &Path, summary: &mut ScanSummary) -> Result<()> {
        log::debug!("Scanning directory: {:?}", path);

        let walker = WalkDir::new(path)
            .follow_links(self.config.scan.follow_symlinks)
            .into_iter()
            .filter_entry(|e| !self.should_exclude(e.path()));

        for entry in walker {
            if self.is_cancelled() {
                return Err(Error::ScanCancelled);
            }

            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    log::trace!("Failed to access entry: {}", e);
                    summary.errors += 1;
                    continue;
                }
            };

            let file_path = entry.path();

            if file_path.is_dir() {
                summary.directories_scanned += 1;
                continue;
            }

            if !file_path.is_file() {
                continue;
            }

            // Check file priority
            let priority = self.get_file_priority(file_path);
            if priority == FilePriority::Skip {
                continue;
            }

            // Check size limit
            if self.exceeds_size_limit(file_path) {
                log::trace!("Skipping large file: {:?}", file_path);
                continue;
            }

            // Scan the file
            match self.scan_file(file_path).await {
                Ok(Some(detection)) => {
                    log::info!(
                        "Threat detected: {} in {:?}",
                        detection.threat_name,
                        file_path
                    );
                    summary.threats_found += 1;
                    summary.detections.push(detection);
                }
                Ok(None) => {
                    // Clean file
                }
                Err(e) => {
                    if e.is_recoverable() {
                        log::trace!("Error scanning {:?}: {}", file_path, e);
                        summary.errors += 1;
                    } else {
                        return Err(e);
                    }
                }
            }

            summary.files_scanned += 1;
            self.files_scanned.fetch_add(1, Ordering::Relaxed);

            // Update bytes scanned
            if let Ok(metadata) = file_path.metadata() {
                summary.bytes_scanned += metadata.len();
                self.bytes_scanned.fetch_add(metadata.len(), Ordering::Relaxed);
            }
        }

        Ok(())
    }

    /// Scan a single file.
    pub async fn scan_file(&self, path: &Path) -> Result<Option<Detection>> {
        if self.should_exclude(path) {
            log::trace!("Skipping excluded file: {:?}", path);
            return Ok(None);
        }

        // Use detection engine if available
        if let Some(ref engine) = self.detection_engine {
            match engine.scan_file(path) {
                Ok(detection) => return Ok(detection),
                Err(e) => {
                    if e.is_recoverable() {
                        log::trace!("Error scanning {:?}: {}", path, e);
                        return Ok(None);
                    }
                    return Err(e);
                }
            }
        }

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
