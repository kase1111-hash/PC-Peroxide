//! Error reporting and aggregation for user feedback.

use crate::core::error::{Error, ErrorCategory};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

/// Error metrics tracker for monitoring error patterns.
#[derive(Debug, Default)]
pub struct ErrorMetrics {
    /// Total error count.
    total: AtomicU64,
    /// Errors by category.
    by_category: RwLock<HashMap<ErrorCategory, u64>>,
    /// Recent error samples (for debugging).
    recent_errors: RwLock<Vec<ErrorSample>>,
    /// Maximum recent errors to keep.
    max_recent: usize,
}

/// A sample of an error for debugging.
#[derive(Debug, Clone)]
pub struct ErrorSample {
    pub message: String,
    pub category: ErrorCategory,
    pub timestamp: std::time::Instant,
    pub suggestion: Option<String>,
}

impl ErrorMetrics {
    /// Create a new error metrics tracker.
    pub fn new() -> Self {
        Self {
            max_recent: 100,
            ..Default::default()
        }
    }

    /// Record an error.
    pub fn record(&self, error: &Error) {
        self.total.fetch_add(1, Ordering::Relaxed);

        let category = error.category();

        // Update category count
        if let Ok(mut counts) = self.by_category.write() {
            *counts.entry(category).or_insert(0) += 1;
        }

        // Store sample
        if let Ok(mut recent) = self.recent_errors.write() {
            if recent.len() >= self.max_recent {
                recent.remove(0);
            }
            recent.push(ErrorSample {
                message: error.to_string(),
                category,
                timestamp: std::time::Instant::now(),
                suggestion: error.suggestion().map(String::from),
            });
        }
    }

    /// Get total error count.
    pub fn total_count(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    /// Get error counts by category.
    pub fn counts_by_category(&self) -> HashMap<ErrorCategory, u64> {
        self.by_category
            .read()
            .map(|c| c.clone())
            .unwrap_or_default()
    }

    /// Get recent error samples.
    pub fn recent_errors(&self) -> Vec<ErrorSample> {
        self.recent_errors
            .read()
            .map(|r| r.clone())
            .unwrap_or_default()
    }

    /// Reset all metrics.
    pub fn reset(&self) {
        self.total.store(0, Ordering::Relaxed);
        if let Ok(mut counts) = self.by_category.write() {
            counts.clear();
        }
        if let Ok(mut recent) = self.recent_errors.write() {
            recent.clear();
        }
    }

    /// Generate a summary report.
    pub fn summary(&self) -> ErrorSummary {
        let counts = self.counts_by_category();
        let total = self.total_count();

        let most_common = counts
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(cat, count)| (*cat, *count));

        ErrorSummary {
            total_errors: total,
            errors_by_category: counts,
            most_common_category: most_common,
        }
    }
}

/// Summary of error metrics.
#[derive(Debug)]
pub struct ErrorSummary {
    pub total_errors: u64,
    pub errors_by_category: HashMap<ErrorCategory, u64>,
    pub most_common_category: Option<(ErrorCategory, u64)>,
}

impl std::fmt::Display for ErrorSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Error Summary")?;
        writeln!(f, "=============")?;
        writeln!(f, "Total errors: {}", self.total_errors)?;

        if !self.errors_by_category.is_empty() {
            writeln!(f, "\nBy category:")?;
            let mut sorted: Vec<_> = self.errors_by_category.iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(a.1));
            for (category, count) in sorted {
                writeln!(f, "  {}: {}", category, count)?;
            }
        }

        if let Some((category, count)) = &self.most_common_category {
            writeln!(f, "\nMost common: {} ({} occurrences)", category, count)?;
        }

        Ok(())
    }
}

/// Format an error with full context for user display.
pub fn format_error_for_user(error: &Error) -> String {
    let mut output = String::new();

    // Main error message
    output.push_str(&format!("Error: {}\n", error));

    // Category
    output.push_str(&format!("Category: {}\n", error.category()));

    // Suggestion if available
    if let Some(suggestion) = error.suggestion() {
        output.push_str(&format!("\nSuggestion: {}\n", suggestion));
    }

    // Source chain
    let mut source = std::error::Error::source(error);
    if source.is_some() {
        output.push_str("\nCaused by:\n");
        let mut depth = 1;
        while let Some(err) = source {
            output.push_str(&format!("  {}: {}\n", depth, err));
            source = err.source();
            depth += 1;
        }
    }

    output
}

/// Format an error concisely for logging.
pub fn format_error_for_log(error: &Error) -> String {
    let category = error.category();
    let message = error.to_string();

    // Include source if available
    if let Some(source) = std::error::Error::source(error) {
        format!("[{}] {}: {}", category, message, source)
    } else {
        format!("[{}] {}", category, message)
    }
}

/// Create a user-friendly error report for CLI output.
pub fn create_cli_error_report(error: &Error) -> CliErrorReport {
    CliErrorReport {
        message: error.to_string(),
        category: error.category(),
        suggestion: error.suggestion().map(String::from),
        is_recoverable: error.is_recoverable(),
        exit_code: error_to_exit_code(error),
    }
}

/// CLI error report structure.
#[derive(Debug)]
pub struct CliErrorReport {
    pub message: String,
    pub category: ErrorCategory,
    pub suggestion: Option<String>,
    pub is_recoverable: bool,
    pub exit_code: i32,
}

impl std::fmt::Display for CliErrorReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Use colored output if terminal supports it
        writeln!(f, "Error: {}", self.message)?;

        if let Some(suggestion) = &self.suggestion {
            writeln!(f, "  Tip: {}", suggestion)?;
        }

        Ok(())
    }
}

/// Map errors to appropriate exit codes.
pub fn error_to_exit_code(error: &Error) -> i32 {
    match error.category() {
        ErrorCategory::Io => 2,
        ErrorCategory::Configuration => 3,
        ErrorCategory::Database => 4,
        ErrorCategory::Scanning => 5,
        ErrorCategory::Quarantine => 6,
        ErrorCategory::Process => 7,
        ErrorCategory::Registry => 8,
        ErrorCategory::Network => 9,
        ErrorCategory::Llm => 10,
        ErrorCategory::Detection => 11,
        ErrorCategory::Concurrency => 12,
        ErrorCategory::Serialization => 13,
        ErrorCategory::Other => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_error_metrics() {
        let metrics = ErrorMetrics::new();

        let error1 = Error::PathNotFound(PathBuf::from("/test"));
        let error2 = Error::Network("connection failed".to_string());
        let error3 = Error::PathNotFound(PathBuf::from("/test2"));

        metrics.record(&error1);
        metrics.record(&error2);
        metrics.record(&error3);

        assert_eq!(metrics.total_count(), 3);

        let counts = metrics.counts_by_category();
        assert_eq!(counts.get(&ErrorCategory::Io), Some(&2));
        assert_eq!(counts.get(&ErrorCategory::Network), Some(&1));
    }

    #[test]
    fn test_error_suggestions() {
        let err = Error::llm_unavailable("ollama");
        assert!(err.suggestion().is_some());

        let err = Error::PathNotFound(PathBuf::from("/test"));
        assert!(err.suggestion().is_some());
    }

    #[test]
    fn test_exit_codes() {
        let io_err = Error::Io("test".to_string());
        assert_eq!(error_to_exit_code(&io_err), 2);

        let net_err = Error::Network("test".to_string());
        assert_eq!(error_to_exit_code(&net_err), 9);
    }

    #[test]
    fn test_cli_error_report() {
        let error = Error::llm_unavailable("ollama");
        let report = create_cli_error_report(&error);

        assert!(report.suggestion.is_some());
        assert_eq!(report.category, ErrorCategory::Llm);
        assert_eq!(report.exit_code, 10);
    }
}
