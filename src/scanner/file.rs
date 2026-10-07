//! File system scanner implementation.

use crate::core::config::Config;
use crate::core::error::{Error, Result};
use crate::core::types::{Detection, FilePriority, ScanStatus, ScanSummary, ScanType};
use crate::detection::{DetectionEngine, SignatureDatabase};
use crate::quarantine::WhitelistManager;
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
    Detection { detection: Detection, size: u64 },
    /// An error occurred while scanning
    Error(String),
    /// A file was scanned successfully (no threat)
    FileScanned { size: u64 },
}

/// Callback invoked for each reported (non-whitelisted) detection.
type DetectionCallback = Box<dyn Fn(&Detection) + Send + Sync>;

/// File system scanner.
pub struct FileScanner {
    config: Arc<Config>,
    detection_engine: Option<Arc<DetectionEngine>>,
    cancelled: Arc<AtomicBool>,
    progress: Arc<ProgressTracker>,
    whitelist_path: PathBuf,
    detection_callback: Option<DetectionCallback>,
}

impl FileScanner {
    /// Create a new file scanner with the given configuration.
    pub fn new(config: Arc<Config>) -> Self {
        // Try to open the signature database
        let detection_engine = match SignatureDatabase::open_default() {
            Ok(db) => {
                // Auto-import bundled signatures if database is empty
                Self::auto_import_signatures(&db);

                log::debug!("Signature database loaded");
                Some(Arc::new(DetectionEngine::with_settings(
                    Arc::new(db),
                    config.detection.heuristic_threshold,
                    true, // heuristic always enabled
                    config.detection.enable_yara,
                )))
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
            whitelist_path: WhitelistManager::default_path(),
            detection_callback: None,
        }
    }

    /// Create a scanner with a specific detection engine.
    pub fn with_detection_engine(config: Arc<Config>, engine: DetectionEngine) -> Self {
        Self {
            config,
            detection_engine: Some(Arc::new(engine)),
            cancelled: Arc::new(AtomicBool::new(false)),
            progress: Arc::new(ProgressTracker::new()),
            whitelist_path: WhitelistManager::default_path(),
            detection_callback: None,
        }
    }

    /// Use a whitelist database other than the default one.
    pub fn with_whitelist_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.whitelist_path = path.into();
        self
    }

    /// Open the whitelist if the user has created one (scanning never creates it).
    fn open_whitelist(&self) -> Option<WhitelistManager> {
        if !self.whitelist_path.is_file() {
            return None;
        }
        match WhitelistManager::open(&self.whitelist_path) {
            Ok(manager) => Some(manager),
            Err(e) => {
                log::warn!(
                    "Failed to open whitelist {}: {}",
                    self.whitelist_path.display(),
                    e
                );
                None
            }
        }
    }

    /// Check a detection against the whitelist, logging suppressed ones.
    fn is_whitelisted(whitelist: Option<&WhitelistManager>, detection: &Detection) -> bool {
        let Some(whitelist) = whitelist else {
            return false;
        };
        match whitelist.is_whitelisted(detection) {
            Ok(true) => {
                log::info!(
                    "Whitelisted, not reporting: {} in {:?}",
                    detection.threat_name,
                    detection.path
                );
                true
            }
            Ok(false) => false,
            Err(e) => {
                log::warn!("Whitelist check failed for {:?}: {}", detection.path, e);
                false
            }
        }
    }

    /// Load custom YARA rules from a file into the detection engine.
    ///
    /// Must be called before scanning begins (before the Arc is cloned).
    pub fn load_yara_rules(&mut self, path: &Path) -> Result<()> {
        if let Some(ref mut engine_arc) = self.detection_engine {
            let engine = Arc::get_mut(engine_arc).ok_or_else(|| {
                Error::Custom("Cannot load YARA rules: engine already shared".to_string())
            })?;
            engine.yara_engine_mut().load_rules_file(path)?;
            log::info!("Loaded custom YARA rules from: {}", path.display());
            Ok(())
        } else {
            Err(Error::Custom(
                "Cannot load YARA rules: no detection engine available".to_string(),
            ))
        }
    }

    /// Auto-import bundled signatures if the database is empty.
    ///
    /// Looks for `data/signatures.json` next to the executable, then
    /// in the current working directory.
    fn auto_import_signatures(db: &SignatureDatabase) {
        let info = match db.info() {
            Ok(info) => info,
            Err(_) => return,
        };
        if info.signature_count > 0 {
            return;
        }

        // Search for bundled signature file
        let candidates = [
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("data/signatures.json"))),
            Some(PathBuf::from("data/signatures.json")),
        ];

        for candidate in candidates.iter().flatten() {
            if candidate.is_file() {
                match db.import_file(candidate) {
                    Ok(result) => {
                        log::info!(
                            "Auto-imported bundled signatures: {} imported, {} skipped",
                            result.imported,
                            result.skipped
                        );
                        return;
                    }
                    Err(e) => {
                        log::warn!(
                            "Failed to auto-import signatures from {}: {}",
                            candidate.display(),
                            e
                        );
                    }
                }
            }
        }

        log::debug!("No bundled signature file found for auto-import");
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

    /// Set a callback invoked as each detection is reported during a scan.
    pub fn set_detection_callback<F>(&mut self, callback: F)
    where
        F: Fn(&Detection) + Send + Sync + 'static,
    {
        self.detection_callback = Some(Box::new(callback));
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
        // Check excluded paths
        for excluded in &self.config.scan.exclude_paths {
            if Self::path_matches_exclusion(path, excluded) {
                return true;
            }
        }

        // Check excluded extensions ("iso" and ".iso" are both accepted)
        if let Some(ext) = path.extension() {
            let ext = ext.to_string_lossy();
            if self
                .config
                .scan
                .exclude_extensions
                .iter()
                .any(|e| e.trim_start_matches('.').eq_ignore_ascii_case(&ext))
            {
                return true;
            }
        }

        false
    }

    /// Match a path against an exclusion by whole path components.
    ///
    /// An absolute exclusion covers that directory tree; a relative one (such
    /// as "node_modules") matches wherever it appears. "/proc" therefore
    /// excludes "/proc/1/maps" but not "/home/user/process_dumps".
    fn path_matches_exclusion(path: &Path, excluded: &str) -> bool {
        // Windows paths are case-insensitive.
        #[cfg(windows)]
        let (path, excluded) = (
            PathBuf::from(path.to_string_lossy().to_lowercase()),
            excluded.to_lowercase(),
        );
        #[cfg(windows)]
        let (path, excluded) = (path.as_path(), excluded.as_str());

        let excluded = Path::new(excluded);
        if excluded.is_absolute() {
            return path.starts_with(excluded);
        }

        let wanted: Vec<_> = excluded.components().collect();
        if wanted.is_empty() {
            return false;
        }
        let components: Vec<_> = path.components().collect();
        components
            .windows(wanted.len())
            .any(|window| window == wanted.as_slice())
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
            paths_to_scan.extend(Self::expand_wildcards(&Self::expand_path(path_pattern)));
        }

        self.scan_paths(paths_to_scan, ScanType::Quick).await
    }

    /// Expand `*` path components (as in `C:\Users\*\Downloads`) into the
    /// existing directories they match.
    fn expand_wildcards(pattern: &Path) -> Vec<PathBuf> {
        let mut matches = vec![PathBuf::new()];
        for component in pattern.components() {
            if component.as_os_str() == "*" {
                matches = matches
                    .iter()
                    .filter_map(|dir| std::fs::read_dir(dir).ok())
                    .flatten()
                    .filter_map(|entry| entry.ok())
                    .map(|entry| entry.path())
                    .filter(|path| path.is_dir())
                    .collect();
            } else {
                for path in &mut matches {
                    path.push(component);
                }
            }
        }
        matches.retain(|path| path.exists());
        matches
    }

    /// Drop duplicate roots and roots inside another root, which would
    /// otherwise have their files scanned and reported twice (for example
    /// %TEMP% lives inside %LOCALAPPDATA%).
    fn dedupe_roots(mut paths: Vec<PathBuf>) -> Vec<PathBuf> {
        paths.sort();
        paths.dedup();
        let roots = paths.clone();
        paths.retain(|path| {
            !roots
                .iter()
                .any(|root| root != path && path.starts_with(root))
        });
        paths
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

        // A mistyped path must not produce a "clean" result.
        if let Some(missing) = paths.iter().find(|p| !p.exists()) {
            return Err(Error::PathNotFound(missing.clone()));
        }

        self.scan_paths(paths, ScanType::Custom).await
    }

    /// Scan multiple paths with parallel processing.
    async fn scan_paths(&self, paths: Vec<PathBuf>, scan_type: ScanType) -> Result<ScanSummary> {
        let mut summary = ScanSummary::new(scan_type);
        summary.status = ScanStatus::Running;
        let paths = Self::dedupe_roots(paths);

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
                summary.directories_scanned += self.collect_files(path, &file_queue)?;
            }
        }

        let total_files = file_queue
            .lock()
            .map_err(|_| Error::lock_poisoned("file queue (count)"))?
            .len() as u64;
        log::info!("Found {} files to scan", total_files);
        self.progress.set_total_files(total_files);

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
            let progress = Arc::clone(&self.progress);
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
                    progress.set_current_path(Some(path.clone()));

                    // Scan the file
                    let result = Self::scan_file_sync(&path, size, engine.as_ref(), &config);

                    match result {
                        Ok(Some(detection)) => {
                            let _ = tx.send(ScanResult::Detection { detection, size }).await;
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

        let whitelist = self.open_whitelist();

        // Collect results
        while let Some(result) = rx.recv().await {
            match result {
                ScanResult::Detection { detection, size } => {
                    summary.files_scanned += 1;
                    summary.bytes_scanned += size;
                    self.progress.increment_files();
                    self.progress.add_bytes(size);

                    if Self::is_whitelisted(whitelist.as_ref(), &detection) {
                        continue;
                    }
                    log::info!(
                        "Threat detected: {} in {:?}",
                        detection.threat_name,
                        detection.path
                    );
                    if let Some(ref callback) = self.detection_callback {
                        callback(&detection);
                    }
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
            summary.end_time = Some(chrono::Utc::now());
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

    /// Collect files from a directory into the queue, returning the number of
    /// directories visited.
    fn collect_files(
        &self,
        path: &Path,
        queue: &Arc<Mutex<VecDeque<(PathBuf, u64)>>>,
    ) -> Result<u64> {
        let mut directories = 0;
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

            if entry.file_type().is_dir() {
                // Lets a UI show discovery progress before scanning starts.
                directories += 1;
                self.progress.increment_directories();
                self.progress
                    .set_current_path(Some(file_path.to_path_buf()));
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

        Ok(directories)
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
            // Run all detection engines and pick the highest-priority result
            let details = engine.scan_file_detailed(path)?;
            let detection = details.primary_detection(engine.heuristic_threshold());

            // Also scan archive contents if enabled, even if the archive itself was detected
            if config.scan.scan_archives && ArchiveScanner::is_supported_archive(path) {
                if let Ok(Some(archive_detection)) = Self::scan_archive_sync(path, engine, config) {
                    // Prefer archive detection if it has higher severity, or if
                    // the outer file had no detection
                    match &detection {
                        Some(outer) => {
                            if archive_detection.severity > outer.severity {
                                return Ok(Some(archive_detection));
                            }
                        }
                        None => return Ok(Some(archive_detection)),
                    }
                }
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

        if let Err(e) = scanner.scan_zip(path, |entry| {
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
                    detection.description =
                        format!("{} (in archive: {})", sig.description, entry.name);
                    detection.sha256 = Some(sha256);
                    found_detection = Some(detection);
                }
            }
            Ok(())
        }) {
            log::warn!("Failed to scan archive {:?}: {}", path, e);
        }

        Ok(found_detection)
    }

    /// Scan a single file (async interface).
    pub async fn scan_file(&self, path: &Path) -> Result<Option<Detection>> {
        if self.should_exclude(path) {
            return Ok(None);
        }

        let size = path.metadata().map(|m| m.len()).unwrap_or(0);
        let detection =
            Self::scan_file_sync(path, size, self.detection_engine.as_ref(), &self.config)?;
        Ok(detection.filter(|d| !Self::is_whitelisted(self.open_whitelist().as_ref(), d)))
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

    const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    /// A scanner backed by a throwaway signature database and whitelist.
    fn test_scanner(dir: &Path) -> FileScanner {
        let db = SignatureDatabase::open(&dir.join("sigs.db")).unwrap();
        let engine = DetectionEngine::new(Arc::new(db));
        FileScanner::with_detection_engine(Arc::new(Config::default()), engine)
            .with_whitelist_path(dir.join("whitelist.db"))
    }

    #[tokio::test]
    async fn test_detected_files_count_as_scanned() {
        let state = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        std::fs::write(target.path().join("eicar.com"), EICAR).unwrap();
        std::fs::write(target.path().join("clean.txt"), b"hello").unwrap();

        let summary = test_scanner(state.path())
            .custom_scan(vec![target.path().to_path_buf()])
            .await
            .unwrap();

        assert_eq!(summary.threats_found, 1);
        assert_eq!(summary.files_scanned, 2);
        assert_eq!(summary.bytes_scanned, EICAR.len() as u64 + 5);
    }

    #[tokio::test]
    async fn test_whitelist_suppresses_detection() {
        use crate::quarantine::WhitelistEntry;

        let state = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let eicar = target.path().join("eicar.com");
        std::fs::write(&eicar, EICAR).unwrap();

        let scanner = test_scanner(state.path());
        let summary = scanner
            .custom_scan(vec![target.path().to_path_buf()])
            .await
            .unwrap();
        assert_eq!(summary.threats_found, 1);

        WhitelistManager::open(&state.path().join("whitelist.db"))
            .unwrap()
            .add(&WhitelistEntry::by_path(
                "1".to_string(),
                eicar.display().to_string(),
                "test".to_string(),
            ))
            .unwrap();

        let summary = scanner
            .custom_scan(vec![target.path().to_path_buf()])
            .await
            .unwrap();
        assert_eq!(summary.threats_found, 0);
        assert_eq!(summary.files_scanned, 1);
        assert!(scanner.scan_file(&eicar).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_custom_scan_missing_path_is_error() {
        let state = tempfile::tempdir().unwrap();
        let missing = state.path().join("does-not-exist");

        let result = test_scanner(state.path())
            .custom_scan(vec![state.path().to_path_buf(), missing.clone()])
            .await;

        assert!(matches!(result, Err(Error::PathNotFound(p)) if p == missing));
    }

    #[test]
    fn test_scan_future_is_send() {
        fn assert_send<T: Send>(_: &T) {}
        let state = tempfile::tempdir().unwrap();
        let scanner = test_scanner(state.path());
        assert_send(&scanner.custom_scan(Vec::new()));
    }

    #[test]
    fn test_exclusions_match_whole_components() {
        let mut config = Config::default();
        config.scan.exclude_paths = vec!["/proc".to_string(), "node_modules".to_string()];
        config.scan.exclude_extensions = vec!["iso".to_string(), ".VMDK".to_string()];
        let state = tempfile::tempdir().unwrap();
        let db = SignatureDatabase::open(&state.path().join("sigs.db")).unwrap();
        let scanner = FileScanner::with_detection_engine(
            Arc::new(config),
            DetectionEngine::new(Arc::new(db)),
        );

        assert!(scanner.should_exclude(Path::new("/proc")));
        assert!(scanner.should_exclude(Path::new("/proc/1/maps")));
        assert!(!scanner.should_exclude(Path::new("/home/user/process_dumps/a.exe")));
        assert!(!scanner.should_exclude(Path::new("/srv/proc/a.exe")));

        assert!(scanner.should_exclude(Path::new("/app/node_modules/x/index.js")));
        assert!(!scanner.should_exclude(Path::new("/app/node_modules_backup/a.exe")));

        assert!(scanner.should_exclude(Path::new("/data/disk.iso")));
        assert!(scanner.should_exclude(Path::new("/data/disk.vmdk")));
        assert!(!scanner.should_exclude(Path::new("/data/disk.exe")));
    }

    #[test]
    fn test_expand_wildcards() {
        let root = tempfile::tempdir().unwrap();
        for user in ["alice", "bob", "carol"] {
            std::fs::create_dir(root.path().join(user)).unwrap();
        }
        std::fs::create_dir(root.path().join("alice/Downloads")).unwrap();
        std::fs::create_dir(root.path().join("bob/Downloads")).unwrap();

        let mut found = FileScanner::expand_wildcards(&root.path().join("*").join("Downloads"));
        found.sort();
        assert_eq!(
            found,
            [
                root.path().join("alice/Downloads"),
                root.path().join("bob/Downloads")
            ]
        );

        assert_eq!(
            FileScanner::expand_wildcards(root.path()),
            [root.path().to_path_buf()]
        );
        assert!(FileScanner::expand_wildcards(&root.path().join("missing")).is_empty());
    }

    #[tokio::test]
    async fn test_nested_paths_scanned_once() {
        let state = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let sub = target.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("eicar.com"), EICAR).unwrap();

        let summary = test_scanner(state.path())
            .custom_scan(vec![sub.clone(), target.path().to_path_buf(), sub])
            .await
            .unwrap();

        assert_eq!(summary.threats_found, 1);
        assert_eq!(summary.files_scanned, 1);
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
