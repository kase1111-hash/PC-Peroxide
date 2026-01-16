//! Core module containing fundamental types, configuration, and error handling.

pub mod config;
pub mod error;
pub mod reporting;
pub mod types;

pub use config::Config;
pub use error::{Error, ErrorCategory, Result};
pub use reporting::{
    create_cli_error_report, error_to_exit_code, format_error_for_log, format_error_for_user,
    CliErrorReport, ErrorMetrics,
};
