//! Run a file scan on a background thread.
//!
//! A UI must never block on a scan, so [`BackgroundScan`] runs a
//! [`FileScanner`] on its own thread with its own Tokio runtime and exposes
//! progress, detections found so far, and the final outcome for polling.

use crate::core::error::{Error, Result};
use crate::core::types::{Detection, ScanSummary, ScanType};
use crate::scanner::file::FileScanner;
use crate::scanner::progress::ScanProgress;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::Duration;

/// How often a pending cancellation is re-applied while a scan runs.
///
/// `FileScanner` clears its cancel flag when a scan starts, so a cancel that
/// lands just before that would otherwise be lost.
const CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// What a background scan should cover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanRequest {
    /// Common malware locations.
    Quick,
    /// All drives.
    Full,
    /// Specific files or folders.
    Custom(Vec<PathBuf>),
}

impl ScanRequest {
    /// The scan type recorded in the summary.
    pub fn scan_type(&self) -> ScanType {
        match self {
            Self::Quick => ScanType::Quick,
            Self::Full => ScanType::Full,
            Self::Custom(_) => ScanType::Custom,
        }
    }
}

/// A scan running on a background thread.
pub struct BackgroundScan {
    request: ScanRequest,
    cancel_requested: Arc<AtomicBool>,
    scanner: Arc<OnceLock<Arc<FileScanner>>>,
    detections: Arc<Mutex<Vec<Detection>>>,
    outcome_rx: Receiver<Result<ScanSummary>>,
    outcome: Option<Result<ScanSummary>>,
    outcome_taken: bool,
    thread: Option<JoinHandle<()>>,
}

impl BackgroundScan {
    /// Start a scan on a new thread.
    ///
    /// `make_scanner` runs on that thread, so opening databases never blocks
    /// the caller. `on_complete` also runs there, after the scan returns a
    /// summary (completed or cancelled), for work such as saving history.
    pub fn spawn<M, C>(request: ScanRequest, make_scanner: M, on_complete: C) -> Self
    where
        M: FnOnce() -> FileScanner + Send + 'static,
        C: FnOnce(&ScanSummary) + Send + 'static,
    {
        let cancel_requested = Arc::new(AtomicBool::new(false));
        let scanner = Arc::new(OnceLock::new());
        let detections = Arc::new(Mutex::new(Vec::new()));
        let (outcome_tx, outcome_rx) = mpsc::channel();

        let thread = {
            let request = request.clone();
            let cancel_requested = Arc::clone(&cancel_requested);
            let scanner = Arc::clone(&scanner);
            let detections = Arc::clone(&detections);
            std::thread::Builder::new()
                .name("background-scan".to_string())
                .spawn(move || {
                    let outcome = run_scan(
                        request,
                        make_scanner,
                        &cancel_requested,
                        &scanner,
                        detections,
                    );
                    if let Ok(ref summary) = outcome {
                        on_complete(summary);
                    }
                    // The receiver is gone only if the BackgroundScan was dropped.
                    let _ = outcome_tx.send(outcome);
                })
        };

        let (thread, outcome) = match thread {
            Ok(handle) => (Some(handle), None),
            Err(e) => (
                None,
                Some(Err(Error::Internal(format!(
                    "Failed to start scan thread: {}",
                    e
                )))),
            ),
        };

        Self {
            request,
            cancel_requested,
            scanner,
            detections,
            outcome_rx,
            outcome,
            outcome_taken: false,
            thread,
        }
    }

    /// The request this scan is running.
    pub fn request(&self) -> &ScanRequest {
        &self.request
    }

    /// Ask the scan to stop. It finishes with a cancelled outcome shortly after.
    pub fn cancel(&self) {
        self.cancel_requested.store(true, Ordering::SeqCst);
        if let Some(scanner) = self.scanner.get() {
            scanner.cancel();
        }
    }

    /// Whether [`cancel`](Self::cancel) has been called.
    pub fn is_cancel_requested(&self) -> bool {
        self.cancel_requested.load(Ordering::SeqCst)
    }

    /// Current progress, once the scanner has started.
    pub fn progress(&self) -> Option<ScanProgress> {
        self.scanner
            .get()
            .map(|scanner| scanner.progress().snapshot())
    }

    /// Detections reported so far.
    pub fn detections(&self) -> Vec<Detection> {
        self.detections
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Whether the scan has finished (successfully, cancelled or failed).
    pub fn is_finished(&mut self) -> bool {
        self.poll();
        self.outcome.is_some() || self.outcome_taken
    }

    /// Take the outcome once the scan has finished.
    ///
    /// Returns `None` while the scan is still running, and after the outcome
    /// has been taken.
    pub fn take_outcome(&mut self) -> Option<Result<ScanSummary>> {
        self.poll();
        let outcome = self.outcome.take()?;
        self.outcome_taken = true;
        if let Some(thread) = self.thread.take() {
            // The thread has already sent its outcome, so this returns at once.
            let _ = thread.join();
        }
        Some(outcome)
    }

    /// Block until the scan finishes, then take its outcome.
    pub fn wait(&mut self) -> Result<ScanSummary> {
        if self.outcome.is_none() && !self.outcome_taken {
            self.outcome = Some(self.outcome_rx.recv().unwrap_or_else(|_| {
                Err(Error::Internal("Scan thread exited unexpectedly".into()))
            }));
        }
        self.take_outcome()
            .unwrap_or_else(|| Err(Error::Internal("Scan outcome already taken".into())))
    }

    fn poll(&mut self) {
        if self.outcome.is_some() || self.outcome_taken {
            return;
        }
        match self.outcome_rx.try_recv() {
            Ok(outcome) => self.outcome = Some(outcome),
            Err(TryRecvError::Empty) => {}
            // The thread panicked before sending an outcome.
            Err(TryRecvError::Disconnected) => {
                self.outcome = Some(Err(Error::Internal(
                    "Scan thread exited unexpectedly".into(),
                )))
            }
        }
    }
}

impl Drop for BackgroundScan {
    fn drop(&mut self) {
        // Don't leave an orphaned scan running when its owner goes away.
        if self.outcome.is_none() && !self.outcome_taken {
            self.cancel();
        }
    }
}

/// Body of the scan thread.
fn run_scan<M>(
    request: ScanRequest,
    make_scanner: M,
    cancel_requested: &Arc<AtomicBool>,
    published: &OnceLock<Arc<FileScanner>>,
    detections: Arc<Mutex<Vec<Detection>>>,
) -> Result<ScanSummary>
where
    M: FnOnce() -> FileScanner,
{
    let mut scanner = make_scanner();
    scanner.set_detection_callback(move |detection| {
        detections
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(detection.clone());
    });
    let scanner = Arc::new(scanner);
    let _ = published.set(Arc::clone(&scanner));

    if cancel_requested.load(Ordering::SeqCst) {
        return Err(Error::ScanCancelled);
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::Internal(format!("Failed to start scan runtime: {}", e)))?;

    runtime.block_on(async {
        let watcher = {
            let scanner = Arc::clone(&scanner);
            let cancel_requested = Arc::clone(cancel_requested);
            tokio::spawn(async move {
                loop {
                    if cancel_requested.load(Ordering::SeqCst) {
                        scanner.cancel();
                    }
                    tokio::time::sleep(CANCEL_POLL_INTERVAL).await;
                }
            })
        };

        let outcome = match request {
            ScanRequest::Quick => scanner.quick_scan().await,
            ScanRequest::Full => scanner.full_scan().await,
            ScanRequest::Custom(paths) => scanner.custom_scan(paths).await,
        };
        watcher.abort();
        outcome
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config::Config;
    use crate::core::types::ScanStatus;
    use crate::detection::{DetectionEngine, SignatureDatabase};
    use std::path::Path;
    use std::time::Instant;

    const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    /// Build scanners against a throwaway signature database and whitelist.
    fn scanner_factory(state: &Path) -> impl FnOnce() -> FileScanner + Send + 'static {
        let state = state.to_path_buf();
        move || {
            let db = SignatureDatabase::open(&state.join("sigs.db")).unwrap();
            FileScanner::with_detection_engine(
                Arc::new(Config::default()),
                DetectionEngine::new(Arc::new(db)),
            )
            .with_whitelist_path(state.join("whitelist.db"))
        }
    }

    fn wait_until(mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(60);
        while !condition() {
            assert!(Instant::now() < deadline, "timed out waiting");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn test_background_scan_reports_progress_and_detections() {
        let state = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        std::fs::write(target.path().join("eicar.com"), EICAR).unwrap();
        std::fs::write(target.path().join("clean.txt"), b"hello").unwrap();

        let completed = Arc::new(Mutex::new(None));
        let completed_hook = Arc::clone(&completed);
        let mut scan = BackgroundScan::spawn(
            ScanRequest::Custom(vec![target.path().to_path_buf()]),
            scanner_factory(state.path()),
            move |summary| *completed_hook.lock().unwrap() = Some(summary.scan_id.clone()),
        );

        wait_until(|| scan.is_finished());
        let progress = scan.progress().expect("progress published");
        assert_eq!(progress.total_files, Some(2));
        assert_eq!(progress.files_scanned, 2);
        assert_eq!(scan.detections().len(), 1);

        let summary = scan.take_outcome().unwrap().unwrap();
        assert_eq!(summary.status, ScanStatus::Completed);
        assert_eq!(summary.scan_type, ScanType::Custom);
        assert_eq!(summary.threats_found, 1);
        assert_eq!(summary.detections[0].threat_name, "EICAR-Test-File");
        assert_eq!(
            completed.lock().unwrap().as_deref(),
            Some(summary.scan_id.as_str())
        );
        assert!(scan.take_outcome().is_none());
    }

    #[test]
    fn test_cancel_before_start() {
        let state = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        std::fs::write(target.path().join("eicar.com"), EICAR).unwrap();

        let ran_hook = Arc::new(AtomicBool::new(false));
        let ran = Arc::clone(&ran_hook);
        let mut scan = BackgroundScan::spawn(
            ScanRequest::Custom(vec![target.path().to_path_buf()]),
            scanner_factory(state.path()),
            move |_| ran.store(true, Ordering::SeqCst),
        );
        scan.cancel();

        let outcome = scan.wait();
        match outcome {
            Err(Error::ScanCancelled) => {}
            Ok(summary) => assert_eq!(summary.status, ScanStatus::Cancelled),
            Err(e) => panic!("unexpected error: {}", e),
        }
    }

    #[test]
    fn test_cancel_during_scan() {
        let state = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let total = 3000;
        for i in 0..total {
            std::fs::write(target.path().join(format!("f{}.txt", i)), b"data").unwrap();
        }

        let mut scan = BackgroundScan::spawn(
            ScanRequest::Custom(vec![target.path().to_path_buf()]),
            scanner_factory(state.path()),
            |_| {},
        );
        wait_until(|| {
            scan.progress()
                .is_some_and(|p| p.files_scanned > 0 || p.total_files.is_some())
        });
        scan.cancel();

        let summary = scan.wait().unwrap();
        assert_eq!(summary.status, ScanStatus::Cancelled);
        assert!(summary.files_scanned < total);
    }

    #[test]
    fn test_missing_path_is_reported() {
        let state = tempfile::tempdir().unwrap();
        let missing = state.path().join("missing");
        let mut scan = BackgroundScan::spawn(
            ScanRequest::Custom(vec![missing.clone()]),
            scanner_factory(state.path()),
            |_| panic!("on_complete must not run for a failed scan"),
        );
        assert!(matches!(scan.wait(), Err(Error::PathNotFound(p)) if p == missing));
    }

    #[test]
    fn test_scan_request_type() {
        assert_eq!(ScanRequest::Quick.scan_type(), ScanType::Quick);
        assert_eq!(ScanRequest::Full.scan_type(), ScanType::Full);
        assert_eq!(ScanRequest::Custom(vec![]).scan_type(), ScanType::Custom);
    }
}
