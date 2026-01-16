//! CSV export functionality.
//!
//! Exports scan results to CSV format for spreadsheet analysis.

use crate::core::error::Result;
use crate::core::types::ScanSummary;
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// CSV exporter for scan results.
pub struct CsvExporter {
    /// Delimiter character
    delimiter: char,
    /// Include header row
    include_header: bool,
}

impl CsvExporter {
    /// Create a new CSV exporter.
    pub fn new() -> Self {
        Self {
            delimiter: ',',
            include_header: true,
        }
    }

    /// Set the delimiter character.
    pub fn with_delimiter(mut self, delimiter: char) -> Self {
        self.delimiter = delimiter;
        self
    }

    /// Set whether to include headers.
    pub fn with_header(mut self, include: bool) -> Self {
        self.include_header = include;
        self
    }

    /// Export scan results to CSV.
    pub fn export(&self, summary: &ScanSummary, output_path: &Path) -> Result<()> {
        let mut file = File::create(output_path)?;

        // Write summary section
        writeln!(file, "# PC-Peroxide Scan Report")?;
        writeln!(file, "# Scan ID: {}", summary.scan_id)?;
        writeln!(file, "# Scan Type: {}", summary.scan_type)?;
        writeln!(file, "# Status: {:?}", summary.status)?;
        writeln!(file, "# Start Time: {}", summary.start_time)?;
        if let Some(end_time) = summary.end_time {
            writeln!(file, "# End Time: {}", end_time)?;
        }
        writeln!(file, "# Files Scanned: {}", summary.files_scanned)?;
        writeln!(file, "# Bytes Scanned: {}", summary.bytes_scanned)?;
        writeln!(file, "# Threats Found: {}", summary.threats_found)?;
        writeln!(file, "# Errors: {}", summary.errors)?;
        writeln!(file)?;

        // Write detections
        if self.include_header {
            writeln!(
                file,
                "Severity{}Threat Name{}Category{}Path{}Description{}SHA256{}Detection Method{}Score",
                self.delimiter,
                self.delimiter,
                self.delimiter,
                self.delimiter,
                self.delimiter,
                self.delimiter,
                self.delimiter,
            )?;
        }

        for det in &summary.detections {
            let sha256 = det.sha256.as_deref().unwrap_or("");
            writeln!(
                file,
                "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}",
                Self::escape_csv(&format!("{:?}", det.severity)),
                self.delimiter,
                Self::escape_csv(&det.threat_name),
                self.delimiter,
                Self::escape_csv(&format!("{:?}", det.category)),
                self.delimiter,
                Self::escape_csv(&det.path.display().to_string()),
                self.delimiter,
                Self::escape_csv(&det.description),
                self.delimiter,
                Self::escape_csv(sha256),
                self.delimiter,
                Self::escape_csv(&format!("{:?}", det.method)),
                self.delimiter,
                det.score,
            )?;
        }

        Ok(())
    }

    /// Export multiple scan summaries to CSV.
    pub fn export_multiple(&self, summaries: &[ScanSummary], output_path: &Path) -> Result<()> {
        let mut file = File::create(output_path)?;

        // Write header for summary data
        if self.include_header {
            writeln!(
                file,
                "Scan ID{}Scan Type{}Status{}Start Time{}End Time{}Files Scanned{}Bytes Scanned{}Threats Found{}Errors",
                self.delimiter,
                self.delimiter,
                self.delimiter,
                self.delimiter,
                self.delimiter,
                self.delimiter,
                self.delimiter,
                self.delimiter,
            )?;
        }

        for summary in summaries {
            let end_time = summary
                .end_time
                .map(|t| t.to_string())
                .unwrap_or_default();
            writeln!(
                file,
                "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}",
                Self::escape_csv(&summary.scan_id),
                self.delimiter,
                Self::escape_csv(&summary.scan_type.to_string()),
                self.delimiter,
                Self::escape_csv(&format!("{:?}", summary.status)),
                self.delimiter,
                Self::escape_csv(&summary.start_time.to_string()),
                self.delimiter,
                Self::escape_csv(&end_time),
                self.delimiter,
                summary.files_scanned,
                self.delimiter,
                summary.bytes_scanned,
                self.delimiter,
                summary.threats_found,
                self.delimiter,
                summary.errors,
            )?;
        }

        Ok(())
    }

    /// Escape a CSV field.
    fn escape_csv(field: &str) -> String {
        if field.contains(',') || field.contains('"') || field.contains('\n') || field.contains('\r')
        {
            format!("\"{}\"", field.replace('"', "\"\""))
        } else {
            field.to_string()
        }
    }
}

impl Default for CsvExporter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_csv() {
        assert_eq!(CsvExporter::escape_csv("simple"), "simple");
        assert_eq!(CsvExporter::escape_csv("with,comma"), "\"with,comma\"");
        assert_eq!(
            CsvExporter::escape_csv("with\"quote"),
            "\"with\"\"quote\""
        );
        assert_eq!(CsvExporter::escape_csv("with\nnewline"), "\"with\nnewline\"");
    }

    #[test]
    fn test_exporter_creation() {
        let exporter = CsvExporter::new();
        assert_eq!(exporter.delimiter, ',');
        assert!(exporter.include_header);
    }

    #[test]
    fn test_exporter_with_options() {
        let exporter = CsvExporter::new().with_delimiter(';').with_header(false);
        assert_eq!(exporter.delimiter, ';');
        assert!(!exporter.include_header);
    }
}
