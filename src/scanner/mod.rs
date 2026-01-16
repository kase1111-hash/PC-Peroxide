//! File system and process scanning functionality.
//!
//! This module provides the core scanning capabilities including:
//! - File system traversal and scanning
//! - Archive extraction and scanning (ZIP)
//! - File type detection via magic bytes
//! - Progress tracking and reporting
//! - Registry scanning (Windows) - Phase 5
//! - Process memory scanning - Phase 6
//! - Browser extension scanning - Phase 8

pub mod archive;
pub mod file;
pub mod filetype;
pub mod progress;
pub mod results;

pub use archive::{ArchiveScanner, ArchiveType, ArchivedFile};
pub use file::FileScanner;
pub use filetype::{FileType, FileTypeDetector};
pub use progress::{ConsoleProgressReporter, ProgressTracker, ScanProgress};
pub use results::{ScanResultStore, ScanStatistics};
