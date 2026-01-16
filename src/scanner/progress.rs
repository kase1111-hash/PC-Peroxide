//! Scan progress tracking and reporting.

use crate::core::types::Detection;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Scan progress information.
#[derive(Debug, Clone)]
pub struct ScanProgress {
    /// Number of files scanned
    pub files_scanned: u64,
    /// Number of directories scanned
    pub directories_scanned: u64,
    /// Number of bytes scanned
    pub bytes_scanned: u64,
    /// Number of threats found
    pub threats_found: u32,
    /// Number of errors encountered
    pub errors: u32,
    /// Currently scanning path
    pub current_path: Option<PathBuf>,
    /// Estimated total files (if known)
    pub total_files: Option<u64>,
    /// Scan start time
    pub start_time: Instant,
    /// Whether scan is complete
    pub is_complete: bool,
    /// Whether scan was cancelled
    pub is_cancelled: bool,
}

impl ScanProgress {
    /// Calculate elapsed time.
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Calculate scan rate (files per second).
    pub fn files_per_second(&self) -> f64 {
        let elapsed = self.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.files_scanned as f64 / elapsed
        } else {
            0.0
        }
    }

    /// Calculate scan rate (bytes per second).
    pub fn bytes_per_second(&self) -> f64 {
        let elapsed = self.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.bytes_scanned as f64 / elapsed
        } else {
            0.0
        }
    }

    /// Estimate remaining time based on progress.
    pub fn estimated_remaining(&self) -> Option<Duration> {
        if let Some(total) = self.total_files {
            if self.files_scanned > 0 && self.files_scanned < total {
                let remaining_files = total - self.files_scanned;
                let rate = self.files_per_second();
                if rate > 0.0 {
                    let remaining_secs = remaining_files as f64 / rate;
                    return Some(Duration::from_secs_f64(remaining_secs));
                }
            }
        }
        None
    }

    /// Calculate completion percentage.
    pub fn percentage(&self) -> Option<f64> {
        self.total_files.map(|total| {
            if total > 0 {
                (self.files_scanned as f64 / total as f64) * 100.0
            } else {
                100.0
            }
        })
    }
}

/// Progress tracker for real-time scan monitoring.
#[allow(clippy::type_complexity)]
pub struct ProgressTracker {
    files_scanned: AtomicU64,
    directories_scanned: AtomicU64,
    bytes_scanned: AtomicU64,
    threats_found: AtomicU64,
    errors: AtomicU64,
    current_path: RwLock<Option<PathBuf>>,
    total_files: RwLock<Option<u64>>,
    start_time: Instant,
    is_complete: AtomicBool,
    is_cancelled: AtomicBool,
    callback: RwLock<Option<Box<dyn Fn(ScanProgress) + Send + Sync>>>,
    callback_interval: Duration,
    last_callback: RwLock<Instant>,
}

impl Default for ProgressTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgressTracker {
    /// Create a new progress tracker.
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            files_scanned: AtomicU64::new(0),
            directories_scanned: AtomicU64::new(0),
            bytes_scanned: AtomicU64::new(0),
            threats_found: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            current_path: RwLock::new(None),
            total_files: RwLock::new(None),
            start_time: now,
            is_complete: AtomicBool::new(false),
            is_cancelled: AtomicBool::new(false),
            callback: RwLock::new(None),
            callback_interval: Duration::from_millis(100),
            last_callback: RwLock::new(now),
        }
    }

    /// Set a progress callback function.
    pub fn set_callback<F>(&self, callback: F)
    where
        F: Fn(ScanProgress) + Send + Sync + 'static,
    {
        let mut cb = self.callback.write().unwrap();
        *cb = Some(Box::new(callback));
    }

    /// Set the callback interval.
    pub fn set_interval(&mut self, interval: Duration) {
        self.callback_interval = interval;
    }

    /// Set the estimated total number of files.
    pub fn set_total_files(&self, total: u64) {
        let mut t = self.total_files.write().unwrap();
        *t = Some(total);
    }

    /// Increment files scanned counter.
    pub fn increment_files(&self) {
        self.files_scanned.fetch_add(1, Ordering::Relaxed);
        self.maybe_callback();
    }

    /// Increment directories scanned counter.
    pub fn increment_directories(&self) {
        self.directories_scanned.fetch_add(1, Ordering::Relaxed);
    }

    /// Add bytes scanned.
    pub fn add_bytes(&self, bytes: u64) {
        self.bytes_scanned.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Increment threats found counter.
    pub fn increment_threats(&self) {
        self.threats_found.fetch_add(1, Ordering::Relaxed);
        self.maybe_callback();
    }

    /// Increment error counter.
    pub fn increment_errors(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Update the current path being scanned.
    pub fn set_current_path(&self, path: Option<PathBuf>) {
        let mut current = self.current_path.write().unwrap();
        *current = path;
    }

    /// Mark scan as complete.
    pub fn complete(&self) {
        self.is_complete.store(true, Ordering::SeqCst);
        self.force_callback();
    }

    /// Mark scan as cancelled.
    pub fn cancel(&self) {
        self.is_cancelled.store(true, Ordering::SeqCst);
        self.force_callback();
    }

    /// Check if scan should stop.
    pub fn should_stop(&self) -> bool {
        self.is_cancelled.load(Ordering::SeqCst)
    }

    /// Get current progress snapshot.
    pub fn snapshot(&self) -> ScanProgress {
        ScanProgress {
            files_scanned: self.files_scanned.load(Ordering::Relaxed),
            directories_scanned: self.directories_scanned.load(Ordering::Relaxed),
            bytes_scanned: self.bytes_scanned.load(Ordering::Relaxed),
            threats_found: self.threats_found.load(Ordering::Relaxed) as u32,
            errors: self.errors.load(Ordering::Relaxed) as u32,
            current_path: self.current_path.read().unwrap().clone(),
            total_files: *self.total_files.read().unwrap(),
            start_time: self.start_time,
            is_complete: self.is_complete.load(Ordering::SeqCst),
            is_cancelled: self.is_cancelled.load(Ordering::SeqCst),
        }
    }

    /// Reset all counters for a new scan.
    pub fn reset(&mut self) {
        self.files_scanned.store(0, Ordering::Relaxed);
        self.directories_scanned.store(0, Ordering::Relaxed);
        self.bytes_scanned.store(0, Ordering::Relaxed);
        self.threats_found.store(0, Ordering::Relaxed);
        self.errors.store(0, Ordering::Relaxed);
        *self.current_path.write().unwrap() = None;
        *self.total_files.write().unwrap() = None;
        self.start_time = Instant::now();
        self.is_complete.store(false, Ordering::SeqCst);
        self.is_cancelled.store(false, Ordering::SeqCst);
        *self.last_callback.write().unwrap() = Instant::now();
    }

    /// Trigger callback if interval has passed.
    fn maybe_callback(&self) {
        let should_call = {
            let last = self.last_callback.read().unwrap();
            last.elapsed() >= self.callback_interval
        };

        if should_call {
            self.force_callback();
        }
    }

    /// Force a callback invocation.
    fn force_callback(&self) {
        {
            let mut last = self.last_callback.write().unwrap();
            *last = Instant::now();
        }

        let callback = self.callback.read().unwrap();
        if let Some(ref cb) = *callback {
            cb(self.snapshot());
        }
    }
}

/// Console progress reporter.
pub struct ConsoleProgressReporter {
    last_line_length: std::sync::atomic::AtomicUsize,
    verbose: bool,
}

impl Default for ConsoleProgressReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsoleProgressReporter {
    /// Create a new console reporter.
    pub fn new() -> Self {
        Self {
            last_line_length: std::sync::atomic::AtomicUsize::new(0),
            verbose: false,
        }
    }

    /// Enable verbose output.
    pub fn verbose(mut self) -> Self {
        self.verbose = true;
        self
    }

    /// Report progress to console.
    pub fn report(&self, progress: &ScanProgress) {
        let status = if progress.is_cancelled {
            "Cancelled"
        } else if progress.is_complete {
            "Complete"
        } else {
            "Scanning"
        };

        let rate = progress.files_per_second();
        let elapsed = progress.elapsed().as_secs();

        let message = if let Some(pct) = progress.percentage() {
            format!(
                "\r[{}] {:.1}% | Files: {} | Threats: {} | Rate: {:.0}/s | Time: {}s",
                status,
                pct,
                progress.files_scanned,
                progress.threats_found,
                rate,
                elapsed
            )
        } else {
            format!(
                "\r[{}] Files: {} | Threats: {} | Rate: {:.0}/s | Time: {}s",
                status, progress.files_scanned, progress.threats_found, rate, elapsed
            )
        };

        // Clear previous line and print new one
        let last_len = self.last_line_length.load(Ordering::Relaxed);
        let padding = if message.len() < last_len {
            " ".repeat(last_len - message.len())
        } else {
            String::new()
        };

        eprint!("{}{}", message, padding);
        self.last_line_length.store(message.len(), Ordering::Relaxed);

        if progress.is_complete || progress.is_cancelled {
            eprintln!(); // New line at end
        }
    }

    /// Report a detection.
    pub fn report_detection(&self, detection: &Detection) {
        if self.verbose {
            eprintln!(
                "\n  [!] Found: {} - {} ({})",
                detection.threat_name,
                detection.path.display(),
                detection.severity
            );
        }
    }
}

/// Create a shared progress tracker.
pub fn shared_tracker() -> Arc<ProgressTracker> {
    Arc::new(ProgressTracker::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_progress_tracker() {
        let tracker = ProgressTracker::new();

        tracker.increment_files();
        tracker.increment_files();
        tracker.add_bytes(1000);
        tracker.increment_threats();

        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.files_scanned, 2);
        assert_eq!(snapshot.bytes_scanned, 1000);
        assert_eq!(snapshot.threats_found, 1);
    }

    #[test]
    fn test_progress_callback() {
        let tracker = Arc::new(ProgressTracker::new());
        let callback_count = Arc::new(AtomicU64::new(0));

        let count_clone = callback_count.clone();
        tracker.set_callback(move |_progress| {
            count_clone.fetch_add(1, Ordering::Relaxed);
        });

        // Force callback
        tracker.complete();

        assert!(callback_count.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn test_scan_rate() {
        let progress = ScanProgress {
            files_scanned: 100,
            directories_scanned: 10,
            bytes_scanned: 10000,
            threats_found: 0,
            errors: 0,
            current_path: None,
            total_files: Some(200),
            start_time: Instant::now() - Duration::from_secs(10),
            is_complete: false,
            is_cancelled: false,
        };

        assert!((progress.files_per_second() - 10.0).abs() < 1.0);
        assert_eq!(progress.percentage(), Some(50.0));
    }

    #[test]
    fn test_cancellation() {
        let tracker = ProgressTracker::new();
        assert!(!tracker.should_stop());

        tracker.cancel();
        assert!(tracker.should_stop());

        let snapshot = tracker.snapshot();
        assert!(snapshot.is_cancelled);
    }
}
