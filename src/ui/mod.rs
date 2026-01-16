//! User interface components.
//!
//! This module provides:
//! - CLI interface (Phase 9)
//! - Report generation (HTML, CSV, PDF)
//! - GUI application (Phase 10)
//! - Progress reporting
//! - User prompts

pub mod cli;
#[cfg(feature = "gui")]
pub mod gui;
pub mod report;

pub use cli::Cli;
#[cfg(feature = "gui")]
pub use gui::{PeroxideApp, SignatureUpdater, Theme, View};
pub use report::{generate_report, CsvExporter, HtmlReporter, PdfReporter, ReportFormat};
