//! File system and process scanning functionality.
//!
//! This module provides the core scanning capabilities including:
//! - File system traversal and scanning
//! - Registry scanning (Windows)
//! - Process memory scanning
//! - Browser extension scanning

pub mod file;

pub use file::FileScanner;
