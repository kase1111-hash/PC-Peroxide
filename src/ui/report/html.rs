//! HTML report generator.
//!
//! Generates styled HTML reports for scan results.

use crate::core::error::{Error, Result};
use crate::core::types::{ScanStatus, ScanSummary};
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// HTML report generator.
pub struct HtmlReporter {
    /// Include CSS inline
    inline_css: bool,
}

impl HtmlReporter {
    /// Create a new HTML reporter.
    pub fn new() -> Self {
        Self { inline_css: true }
    }

    /// Generate an HTML report.
    pub fn generate(&self, summary: &ScanSummary, output_path: &Path) -> Result<()> {
        let html = self.render(summary);
        let mut file = File::create(output_path).map_err(|e| Error::Io(e.to_string()))?;
        file.write_all(html.as_bytes())
            .map_err(|e| Error::Io(e.to_string()))?;
        Ok(())
    }

    /// Render the HTML content.
    fn render(&self, summary: &ScanSummary) -> String {
        let css = if self.inline_css {
            self.default_css()
        } else {
            ""
        };

        let status_class = match summary.status {
            ScanStatus::Completed if summary.threats_found == 0 => "status-clean",
            ScanStatus::Completed => "status-threats",
            ScanStatus::Failed => "status-error",
            _ => "status-unknown",
        };

        let detections_html = if summary.detections.is_empty() {
            "<p class=\"no-threats\">No threats detected.</p>".to_string()
        } else {
            let mut html = String::from("<table class=\"detections\">\n");
            html.push_str("<thead><tr><th>Severity</th><th>Threat Name</th><th>Path</th><th>Category</th></tr></thead>\n");
            html.push_str("<tbody>\n");
            for det in &summary.detections {
                let severity_class = match det.severity {
                    crate::core::types::Severity::Critical => "severity-critical",
                    crate::core::types::Severity::High => "severity-high",
                    crate::core::types::Severity::Medium => "severity-medium",
                    crate::core::types::Severity::Low => "severity-low",
                };
                html.push_str(&format!(
                    "<tr class=\"{}\"><td>{:?}</td><td>{}</td><td><code>{}</code></td><td>{:?}</td></tr>\n",
                    severity_class,
                    det.severity,
                    Self::escape_html(&det.threat_name),
                    Self::escape_html(&det.path.display().to_string()),
                    det.category
                ));
            }
            html.push_str("</tbody>\n</table>");
            html
        };

        let duration = summary.duration_secs().unwrap_or(0);
        let scan_rate = if summary.files_scanned > 0 && duration > 0 {
            format!(
                "{:.1} files/sec",
                summary.files_scanned as f64 / duration as f64
            )
        } else {
            "N/A".to_string()
        };

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PC-Peroxide Scan Report - {scan_id}</title>
    <style>{css}</style>
</head>
<body>
    <div class="container">
        <header>
            <h1>PC-Peroxide Scan Report</h1>
            <p class="subtitle">Malware Detection and Removal Utility</p>
        </header>

        <section class="summary">
            <h2>Scan Summary</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <span class="label">Scan ID</span>
                    <span class="value">{scan_id}</span>
                </div>
                <div class="summary-card">
                    <span class="label">Scan Type</span>
                    <span class="value">{scan_type}</span>
                </div>
                <div class="summary-card {status_class}">
                    <span class="label">Status</span>
                    <span class="value">{status:?}</span>
                </div>
                <div class="summary-card">
                    <span class="label">Start Time</span>
                    <span class="value">{start_time}</span>
                </div>
            </div>
        </section>

        <section class="statistics">
            <h2>Statistics</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <span class="stat-value">{files_scanned}</span>
                    <span class="stat-label">Files Scanned</span>
                </div>
                <div class="stat-card">
                    <span class="stat-value">{bytes_scanned}</span>
                    <span class="stat-label">Data Scanned</span>
                </div>
                <div class="stat-card threats">
                    <span class="stat-value">{threats_found}</span>
                    <span class="stat-label">Threats Found</span>
                </div>
                <div class="stat-card">
                    <span class="stat-value">{errors}</span>
                    <span class="stat-label">Errors</span>
                </div>
                <div class="stat-card">
                    <span class="stat-value">{duration}s</span>
                    <span class="stat-label">Duration</span>
                </div>
                <div class="stat-card">
                    <span class="stat-value">{scan_rate}</span>
                    <span class="stat-label">Scan Rate</span>
                </div>
            </div>
        </section>

        <section class="detections">
            <h2>Detections</h2>
            {detections_html}
        </section>

        <footer>
            <p>Generated by PC-Peroxide v{version}</p>
            <p>Report generated at {generated_at}</p>
        </footer>
    </div>
</body>
</html>"#,
            scan_id = summary.scan_id,
            css = css,
            status_class = status_class,
            scan_type = summary.scan_type,
            status = summary.status,
            start_time = summary.start_time.format("%Y-%m-%d %H:%M:%S"),
            files_scanned = summary.files_scanned,
            bytes_scanned = Self::format_bytes(summary.bytes_scanned),
            threats_found = summary.threats_found,
            errors = summary.errors,
            duration = duration,
            scan_rate = scan_rate,
            detections_html = detections_html,
            version = env!("CARGO_PKG_VERSION"),
            generated_at = chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        )
    }

    /// Default CSS styles.
    fn default_css(&self) -> &'static str {
        r#"
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            text-align: center;
            padding: 40px 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 8px;
            margin-bottom: 30px;
        }
        header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .subtitle {
            opacity: 0.9;
            font-size: 1.1em;
        }
        section {
            background: white;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h2 {
            color: #4a5568;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e2e8f0;
        }
        .summary-grid, .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }
        .summary-card, .stat-card {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 6px;
            text-align: center;
        }
        .summary-card .label, .stat-label {
            display: block;
            color: #718096;
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .summary-card .value, .stat-value {
            display: block;
            font-size: 1.2em;
            font-weight: 600;
            margin-top: 5px;
        }
        .stat-value {
            font-size: 2em;
            color: #4a5568;
        }
        .stat-card.threats .stat-value {
            color: #e53e3e;
        }
        .status-clean { background: #c6f6d5; }
        .status-threats { background: #fed7d7; }
        .status-error { background: #feebc8; }
        .no-threats {
            text-align: center;
            padding: 40px;
            color: #38a169;
            font-size: 1.2em;
        }
        table.detections {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        table.detections th, table.detections td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }
        table.detections th {
            background: #f7fafc;
            font-weight: 600;
            color: #4a5568;
        }
        table.detections tbody tr:hover {
            background: #f7fafc;
        }
        .severity-critical { background: #fed7d7 !important; }
        .severity-high { background: #feebc8 !important; }
        .severity-medium { background: #fefcbf !important; }
        .severity-low { background: #f0fff4 !important; }
        code {
            background: #edf2f7;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 0.9em;
            word-break: break-all;
        }
        footer {
            text-align: center;
            padding: 30px;
            color: #718096;
            font-size: 0.9em;
        }
        @media (max-width: 768px) {
            .container { padding: 10px; }
            header h1 { font-size: 1.8em; }
            table.detections { font-size: 0.85em; }
            table.detections th, table.detections td { padding: 8px; }
        }
        "#
    }

    /// Escape HTML special characters.
    fn escape_html(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;")
    }

    /// Format bytes for display.
    fn format_bytes(bytes: u64) -> String {
        const KB: u64 = 1024;
        const MB: u64 = KB * 1024;
        const GB: u64 = MB * 1024;

        if bytes >= GB {
            format!("{:.2} GB", bytes as f64 / GB as f64)
        } else if bytes >= MB {
            format!("{:.2} MB", bytes as f64 / MB as f64)
        } else if bytes >= KB {
            format!("{:.2} KB", bytes as f64 / KB as f64)
        } else {
            format!("{} bytes", bytes)
        }
    }
}

impl Default for HtmlReporter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_html() {
        assert_eq!(HtmlReporter::escape_html("<script>"), "&lt;script&gt;");
        assert_eq!(HtmlReporter::escape_html("A & B"), "A &amp; B");
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(HtmlReporter::format_bytes(500), "500 bytes");
        assert_eq!(HtmlReporter::format_bytes(1024), "1.00 KB");
        assert_eq!(HtmlReporter::format_bytes(1024 * 1024), "1.00 MB");
    }

    #[test]
    fn test_reporter_creation() {
        let reporter = HtmlReporter::new();
        assert!(reporter.inline_css);
    }
}
