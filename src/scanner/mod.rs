//! File system and process scanning functionality.
//!
//! This module provides the core scanning capabilities including:
//! - File system traversal and scanning
//! - Archive extraction and scanning (ZIP)
//! - File type detection via magic bytes
//! - Progress tracking and reporting
//! - Registry and persistence scanning (Windows)
//! - Process memory scanning
//! - Browser extension scanning
//! - Network connection scanning

pub mod archive;
pub mod browser;
pub mod file;
pub mod filetype;
pub mod network;
pub mod persistence;
pub mod process;
pub mod progress;
pub mod results;

pub use archive::{ArchiveScanner, ArchiveType, ArchivedFile};
pub use browser::{BrowserExtension, BrowserScanner, BrowserScanResult, BrowserType, ExtensionRisk, HijackType};
pub use file::FileScanner;
pub use filetype::{FileType, FileTypeDetector};
pub use network::{Connection, ConnectionState, NetworkScanner, NetworkScanResult, PortCategory};
pub use persistence::{PersistenceEntry, PersistenceScanner, PersistenceType};
pub use process::{ProcessScanner, ProcessScanResult, ProcessInfo};
pub use progress::{ConsoleProgressReporter, ProgressTracker, ScanProgress};
pub use results::{ScanResultStore, ScanStatistics};
