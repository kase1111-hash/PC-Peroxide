//! File system scanner implementation.

use crate::core::config::Config;
use crate::core::error::{Error, Result};
use crate::core::types::{Detection, FilePriority, ScanStatus, ScanSummary, ScanType};
use crate::detection::{DetectionEngine, SignatureDatabase};
use crate::scanner::archive::ArchiveScanner;
use crate::scanner::progress::ProgressTracker;
use crate::utils::hash::HashCalculator;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
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

/// Scan result from a worker thread.
#[derive(Debug)]
enum ScanResult {
    /// A threat was detected
    Detection(Detection),
    /// An error occurred while scanning
    Error(String),
    /// A file was scanned successfully (no threat)
    FileScanned { size: u64 },
}

/// File system scanner.
pub struct FileScanner {
    config: Arc<Config>,
    detection_engine: Option<Arc<DetectionEngine>>,
    cancelled: Arc<AtomicBool>,
    progress: Arc<ProgressTracker>,
}

impl FileScanner {
    /// Create a new file scanner with the given configuration.
    pub fn new(config: Arc<Config>) -> Self {
        // Try to open the signature database
        let detection_engine = match SignatureDatabase::open_default() {
            Ok(db) => {
                log::debug!("Signature database loaded");
                Some(Arc::new(DetectionEngine::new(Arc::new(db))))
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
            progress: Arc::new(ProgressTracker::new()),
        }
    }

    /// Create a scanner with a specific detection engine.
    pub fn with_detection_engine(config: Arc<Config>, engine: DetectionEngine) -> Self {
        Self {
            config,
            detection_engine: Some(Arc::new(engine)),
            cancelled: Arc::new(AtomicBool::new(false)),
            progress: Arc::new(ProgressTracker::new()),
        }
    }

    /// Get the progress tracker.
    pub fn progress(&self) -> &Arc<ProgressTracker> {
        &self.progress
    }

    /// Set a progress callback.
    pub fn set_progress_callback<F>(&self, callback: F)
    where
        F: Fn(crate::scanner::progress::ScanProgress) + Send + Sync + 'static,
    {
        self.progress.set_callback(callback);
    }

    /// Cancel the current scan.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        self.progress.cancel();
    }

    /// Check if the scan has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Get the number of files scanned so far.
    pub fn files_scanned(&self) -> u64 {
        self.progress.snapshot().files_scanned
    }

    /// Get the number of bytes scanned so far.
    pub fn bytes_scanned(&self) -> u64 {
        self.progress.snapshot().bytes_scanned
    }

    /// Reset scan state for a new scan.
    fn reset(&self) {
        self.cancelled.store(false, Ordering::SeqCst);
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
    fn exceeds_size_limit(&self, size: u64) -> bool {
        let size_mb = size / (1024 * 1024);
        size_mb > self.config.scan.skip_large_files_mb
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
        self.reset();

        let mut paths_to_scan = Vec::new();
        for path_pattern in QUICK_SCAN_PATHS {
            let path = Self::expand_path(path_pattern);
            if path.exists() {
                paths_to_scan.push(path);
            }
        }

        self.scan_paths(paths_to_scan, ScanType::Quick).await
    }

    /// Perform a full system scan.
    pub async fn full_scan(&self) -> Result<ScanSummary> {
        log::info!("Starting full system scan");
        self.reset();

        #[cfg(windows)]
        let drives: Vec<PathBuf> = vec!["C:\\", "D:\\", "E:\\"]
            .into_iter()
            .map(PathBuf::from)
            .filter(|p| p.exists())
            .collect();

        #[cfg(not(windows))]
        let drives: Vec<PathBuf> = vec![PathBuf::from("/")];

        self.scan_paths(drives, ScanType::Full).await
    }

    /// Perform a custom scan of specified paths.
    pub async fn custom_scan(&self, paths: Vec<PathBuf>) -> Result<ScanSummary> {
        log::info!("Starting custom scan of {} paths", paths.len());
        self.reset();
        self.scan_paths(paths, ScanType::Custom).await
    }

    /// Scan multiple paths with parallel processing.
    async fn scan_paths(&self, paths: Vec<PathBuf>, scan_type: ScanType) -> Result<ScanSummary> {
        let mut summary = ScanSummary::new(scan_type);
        summary.status = ScanStatus::Running;

        // Collect all files to scan
        let file_queue = Arc::new(Mutex::new(VecDeque::new()));

        for path in &paths {
            if self.is_cancelled() {
                break;
            }

            if path.is_file() {
                if let Ok(metadata) = path.metadata() {
                    file_queue
                        .lock()
                        .map_err(|_| Error::lock_poisoned("file queue (add file)"))?
                        .push_back((path.clone(), metadata.len()));
                }
            } else if path.is_dir() {
                self.collect_files(path, &file_queue)?;
            }
        }

        let total_files = file_queue
            .lock()
            .map_err(|_| Error::lock_poisoned("file queue (count)"))?
            .len() as u64;
        log::info!("Found {} files to scan", total_files);

        // Set up channels for results
        let (tx, mut rx) = mpsc::channel::<ScanResult>(1000);

        // Spawn worker tasks
        let num_workers = self.config.scan.scan_threads.clamp(1, 8);
        let mut handles = Vec::new();

        for _ in 0..num_workers {
            let queue = Arc::clone(&file_queue);
            let engine = self.detection_engine.clone();
            let config = Arc::clone(&self.config);
            let cancelled = Arc::clone(&self.cancelled);
            let tx = tx.clone();

            let handle = tokio::spawn(async move {
                loop {
                    // Get next file from queue
                    let item = {
                        match queue.lock() {
                            Ok(mut q) => q.pop_front(),
                            Err(_) => {
                                log::error!("File queue lock poisoned in worker");
                                break;
                            }
                        }
                    };

                    let (path, size) = match item {
                        Some(item) => item,
                        None => break, // Queue empty
                    };

                    if cancelled.load(Ordering::SeqCst) {
                        break;
                    }

                    // Scan the file
                    let result = Self::scan_file_sync(&path, size, engine.as_ref(), &config);

                    match result {
                        Ok(Some(detection)) => {
                            let _ = tx.send(ScanResult::Detection(detection)).await;
                        }
                        Ok(None) => {
                            let _ = tx.send(ScanResult::FileScanned { size }).await;
                        }
                        Err(e) => {
                            let _ = tx.send(ScanResult::Error(e.to_string())).await;
                        }
                    }
                }
            });

            handles.push(handle);
        }

        // Drop the sender so the channel closes when workers finish
        drop(tx);

        // Collect results
        while let Some(result) = rx.recv().await {
            match result {
                ScanResult::Detection(detection) => {
                    log::info!(
                        "Threat detected: {} in {:?}",
                        detection.threat_name,
                        detection.path
                    );
                    summary.threats_found += 1;
                    summary.detections.push(detection);
                    self.progress.increment_threats();
                }
                ScanResult::FileScanned { size } => {
                    summary.files_scanned += 1;
                    summary.bytes_scanned += size;
                    self.progress.increment_files();
                    self.progress.add_bytes(size);
                }
                ScanResult::Error(msg) => {
                    log::trace!("Error scanning: {}", msg);
                    summary.errors += 1;
                    self.progress.increment_errors();
                }
            }
        }

        // Wait for all workers
        for handle in handles {
            let _ = handle.await;
        }

        if self.is_cancelled() {
            summary.status = ScanStatus::Cancelled;
        } else {
            summary.complete();
        }

        self.progress.complete();

        log::info!(
            "Scan completed: {} files scanned, {} threats found, {} errors",
            summary.files_scanned,
            summary.threats_found,
            summary.errors
        );

        Ok(summary)
    }

    /// Collect files from a directory into the queue.
    fn collect_files(
        &self,
        path: &Path,
        queue: &Arc<Mutex<VecDeque<(PathBuf, u64)>>>,
    ) -> Result<()> {
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
                Err(_) => continue,
            };

            let file_path = entry.path();

            if !file_path.is_file() {
                continue;
            }

            // Check file priority
            let priority = self.get_file_priority(file_path);
            if priority == FilePriority::Skip {
                continue;
            }

            // Get file size
            let size = match file_path.metadata() {
                Ok(m) => m.len(),
                Err(_) => continue,
            };

            // Check size limit
            if self.exceeds_size_limit(size) {
                continue;
            }

            if let Ok(mut q) = queue.lock() {
                q.push_back((file_path.to_path_buf(), size));
            } else {
                return Err(Error::lock_poisoned("file queue (collect)"));
            }
        }

        Ok(())
    }

    /// Scan a single file synchronously (for worker threads).
    fn scan_file_sync(
        path: &Path,
        _size: u64,
        engine: Option<&Arc<DetectionEngine>>,
        config: &Config,
    ) -> Result<Option<Detection>> {
        // Use detection engine if available
        if let Some(engine) = engine {
            let detection = engine.scan_file(path)?;

            // If no detection and it's an archive, scan contents
            if detection.is_none() && config.scan.scan_archives && ArchiveScanner::is_supported_archive(path)
            {
                return Self::scan_archive_sync(path, engine, config);
            }

            return Ok(detection);
        }

        Ok(None)
    }

    /// Scan an archive's contents.
    fn scan_archive_sync(
        path: &Path,
        engine: &Arc<DetectionEngine>,
        config: &Config,
    ) -> Result<Option<Detection>> {
        let scanner = ArchiveScanner::new()
            .with_max_size(config.scan.skip_archives_larger_than_mb * 1024 * 1024)
            .with_max_depth(config.scan.max_archive_depth);

        let mut found_detection: Option<Detection> = None;

        scanner.scan_zip(path, |entry| {
            if let Some(content) = &entry.content {
                // Hash the content
                let sha256 = HashCalculator::sha256_bytes(content);

                // Check against engine
                if let Some(sig) = engine.hash_matcher().match_sha256(&sha256)? {
                    let mut detection = Detection::new(
                        path.to_path_buf(),
                        &sig.name,
                        sig.severity,
                        sig.category,
                        crate::core::types::DetectionMethod::Signature,
                    );
                    detection.description = format!(
                        "{} (in archive: {})",
                        sig.description, entry.name
                    );
                    detection.sha256 = Some(sha256);
                    found_detection = Some(detection);
                }
            }
            Ok(())
        }).ok();

        Ok(found_detection)
    }

    /// Scan a single file (async interface).
    pub async fn scan_file(&self, path: &Path) -> Result<Option<Detection>> {
        if self.should_exclude(path) {
            return Ok(None);
        }

        let size = path.metadata().map(|m| m.len()).unwrap_or(0);
        Self::scan_file_sync(path, size, self.detection_engine.as_ref(), &self.config)
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

    #[test]
    fn test_path_expansion() {
        #[cfg(not(windows))]
        {
            let path = FileScanner::expand_path("/tmp");
            assert_eq!(path, PathBuf::from("/tmp"));
        }
    }

    #[test]
    fn test_size_limit() {
        let config = Arc::new(Config::default());
        let scanner = FileScanner::new(config);

        // Default limit is 100 MB
        assert!(!scanner.exceeds_size_limit(50 * 1024 * 1024)); // 50 MB
        assert!(scanner.exceeds_size_limit(150 * 1024 * 1024)); // 150 MB
    }
}
