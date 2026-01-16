//! Report generation for scan results.
//!
//! This module provides export functionality in multiple formats:
//! - HTML reports
//! - CSV spreadsheets
//! - PDF documents
//! - JSON export

pub mod csv;
pub mod html;
pub mod pdf;

use crate::core::error::{Error, Result};
use crate::core::types::ScanSummary;
use std::path::Path;

pub use csv::CsvExporter;
pub use html::HtmlReporter;
pub use pdf::PdfReporter;

/// Report format enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Html,
    Csv,
    Pdf,
    Json,
}

/// Generate a report from scan results.
pub fn generate_report(
    summary: &ScanSummary,
    format: ReportFormat,
    output_path: &Path,
) -> Result<()> {
    match format {
        ReportFormat::Html => {
            let reporter = HtmlReporter::new();
            reporter.generate(summary, output_path)
        }
        ReportFormat::Csv => {
            let exporter = CsvExporter::new();
            exporter.export(summary, output_path)
        }
        ReportFormat::Pdf => {
            let reporter = PdfReporter::new();
            reporter.generate(summary, output_path)
        }
        ReportFormat::Json => {
            let json = serde_json::to_string_pretty(summary)?;
            std::fs::write(output_path, json).map_err(|e| Error::Io(e.to_string()))?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_format() {
        assert_ne!(ReportFormat::Html, ReportFormat::Csv);
        assert_ne!(ReportFormat::Pdf, ReportFormat::Json);
    }
}
