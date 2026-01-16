//! Browser extension and hijack scanner.
//!
//! This module provides:
//! - Browser extension enumeration (Chrome, Edge, Firefox)
//! - Suspicious extension detection
//! - Browser hijack detection (homepage, search engine, new tab)
//! - Browser settings analysis

pub mod extensions;
pub mod hijack;

pub use extensions::{
    BrowserExtension, BrowserType, ExtensionPermission, ExtensionRisk, ExtensionScanner,
};
pub use hijack::{BrowserHijack, HijackScanner, HijackType};

use crate::core::error::Result;
use serde::{Deserialize, Serialize};

/// Combined browser scanner for extensions and hijacks.
pub struct BrowserScanner {
    extension_scanner: ExtensionScanner,
    hijack_scanner: HijackScanner,
}

/// Result of a browser scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserScanResult {
    /// Installed extensions
    pub extensions: Vec<BrowserExtension>,
    /// Detected hijacks
    pub hijacks: Vec<BrowserHijack>,
    /// Number of suspicious extensions
    pub suspicious_extensions: usize,
    /// Number of hijacks detected
    pub hijack_count: usize,
    /// Overall risk score (0-100)
    pub risk_score: u8,
}

impl BrowserScanner {
    /// Create a new browser scanner.
    pub fn new() -> Self {
        Self {
            extension_scanner: ExtensionScanner::new(),
            hijack_scanner: HijackScanner::new(),
        }
    }

    /// Scan all browsers for extensions and hijacks.
    pub fn scan_all(&self) -> Result<BrowserScanResult> {
        let extensions = self.extension_scanner.scan_all_browsers()?;
        let hijacks = self.hijack_scanner.scan_all_browsers()?;

        let suspicious_extensions = extensions
            .iter()
            .filter(|e| e.risk == ExtensionRisk::High || e.risk == ExtensionRisk::Critical)
            .count();

        let hijack_count = hijacks.len();

        // Calculate overall risk score
        let ext_risk: u8 = extensions
            .iter()
            .map(|e| match e.risk {
                ExtensionRisk::Critical => 25,
                ExtensionRisk::High => 15,
                ExtensionRisk::Medium => 5,
                ExtensionRisk::Low => 1,
                ExtensionRisk::None => 0,
            })
            .sum::<u8>()
            .min(50);

        let hijack_risk: u8 = (hijack_count as u8 * 10).min(50);
        let risk_score = (ext_risk + hijack_risk).min(100);

        Ok(BrowserScanResult {
            extensions,
            hijacks,
            suspicious_extensions,
            hijack_count,
            risk_score,
        })
    }

    /// Scan only for suspicious items.
    pub fn scan_suspicious(&self) -> Result<BrowserScanResult> {
        let mut result = self.scan_all()?;

        // Filter to only suspicious extensions
        result.extensions.retain(|e| {
            e.risk == ExtensionRisk::High
                || e.risk == ExtensionRisk::Critical
                || e.risk == ExtensionRisk::Medium
        });

        Ok(result)
    }

    /// Scan a specific browser.
    pub fn scan_browser(&self, browser: BrowserType) -> Result<BrowserScanResult> {
        let extensions = self.extension_scanner.scan_browser(browser)?;
        let hijacks = self.hijack_scanner.scan_browser(browser)?;

        let suspicious_extensions = extensions
            .iter()
            .filter(|e| e.risk == ExtensionRisk::High || e.risk == ExtensionRisk::Critical)
            .count();

        let hijack_count = hijacks.len();
        let risk_score = ((suspicious_extensions as u8 * 15) + (hijack_count as u8 * 10)).min(100);

        Ok(BrowserScanResult {
            extensions,
            hijacks,
            suspicious_extensions,
            hijack_count,
            risk_score,
        })
    }
}

impl Default for BrowserScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_browser_scanner_creation() {
        let scanner = BrowserScanner::new();
        // Should not panic
        let _ = scanner;
    }

    #[test]
    fn test_scan_all() {
        let scanner = BrowserScanner::new();
        // Should not panic even if no browsers installed
        let result = scanner.scan_all();
        assert!(result.is_ok());
    }

    #[test]
    fn test_browser_scan_result() {
        let result = BrowserScanResult {
            extensions: Vec::new(),
            hijacks: Vec::new(),
            suspicious_extensions: 0,
            hijack_count: 0,
            risk_score: 0,
        };
        assert_eq!(result.risk_score, 0);
    }
}
