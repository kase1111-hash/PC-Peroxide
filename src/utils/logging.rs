//! Logging infrastructure for PC-Peroxide.

use crate::core::config::Config;
use crate::core::error::Result;
use chrono::Local;
use env_logger::Builder;
use log::LevelFilter;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

/// Logging configuration.
pub struct LogConfig {
    /// Log level
    pub level: LevelFilter,
    /// Enable console output
    pub console: bool,
    /// Enable file output
    pub file: bool,
    /// Log file path
    pub file_path: Option<PathBuf>,
    /// Show timestamps
    pub timestamps: bool,
    /// Show module path
    pub module_path: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: LevelFilter::Info,
            console: true,
            file: false,
            file_path: None,
            timestamps: true,
            module_path: false,
        }
    }
}

impl LogConfig {
    /// Create a log config from application config.
    pub fn from_config(config: &Config) -> Self {
        let level = match config.logging.log_level.to_lowercase().as_str() {
            "trace" => LevelFilter::Trace,
            "debug" => LevelFilter::Debug,
            "info" => LevelFilter::Info,
            "warn" | "warning" => LevelFilter::Warn,
            "error" => LevelFilter::Error,
            _ => LevelFilter::Info,
        };

        Self {
            level,
            console: true,
            file: true,
            file_path: Some(config.logging.log_dir().join("pc-peroxide.log")),
            timestamps: true,
            module_path: level == LevelFilter::Debug || level == LevelFilter::Trace,
        }
    }

    /// Create a verbose log config for CLI.
    pub fn verbose() -> Self {
        Self {
            level: LevelFilter::Debug,
            console: true,
            file: false,
            file_path: None,
            timestamps: true,
            module_path: true,
        }
    }

    /// Create a quiet log config (errors only).
    pub fn quiet() -> Self {
        Self {
            level: LevelFilter::Error,
            console: true,
            file: false,
            file_path: None,
            timestamps: false,
            module_path: false,
        }
    }
}

/// Initialize the logging system.
pub fn init_logging(config: LogConfig) -> Result<()> {
    // Set up file logging first (if requested) so we can capture the writer
    let file_writer: Option<std::sync::Mutex<File>> = if config.file {
        if let Some(ref path) = config.file_path {
            setup_file_logging(path)?;
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| {
                    crate::core::error::Error::ConfigSave(format!(
                        "Failed to open log file: {}",
                        e
                    ))
                })?;
            Some(std::sync::Mutex::new(file))
        } else {
            None
        }
    } else {
        None
    };

    let file_writer = std::sync::Arc::new(file_writer);

    let mut builder = Builder::new();

    // Set the log level
    builder.filter_level(config.level);

    // Configure log format
    let file_writer_clone = file_writer.clone();
    builder.format(move |buf, record| {
        let mut output = String::new();

        // Timestamp
        if config.timestamps {
            output.push_str(&format!("{} ", Local::now().format("%Y-%m-%d %H:%M:%S")));
        }

        // Level with color for console
        let level = record.level();
        let level_str = match level {
            log::Level::Error => "\x1b[31mERROR\x1b[0m",
            log::Level::Warn => "\x1b[33mWARN\x1b[0m ",
            log::Level::Info => "\x1b[32mINFO\x1b[0m ",
            log::Level::Debug => "\x1b[34mDEBUG\x1b[0m",
            log::Level::Trace => "\x1b[35mTRACE\x1b[0m",
        };
        output.push_str(&format!("[{}] ", level_str));

        // Module path
        if config.module_path {
            if let Some(path) = record.module_path() {
                output.push_str(&format!("{}: ", path));
            }
        }

        // Message
        output.push_str(&format!("{}", record.args()));

        // Also write to file if configured (without ANSI colors)
        if let Some(ref file_mutex) = *file_writer_clone {
            let level_plain = match level {
                log::Level::Error => "ERROR",
                log::Level::Warn => "WARN ",
                log::Level::Info => "INFO ",
                log::Level::Debug => "DEBUG",
                log::Level::Trace => "TRACE",
            };
            let mut file_output = String::new();
            if config.timestamps {
                file_output
                    .push_str(&format!("{} ", Local::now().format("%Y-%m-%d %H:%M:%S")));
            }
            file_output.push_str(&format!("[{}] ", level_plain));
            if config.module_path {
                if let Some(path) = record.module_path() {
                    file_output.push_str(&format!("{}: ", path));
                }
            }
            file_output.push_str(&format!("{}", record.args()));
            if let Ok(mut f) = file_mutex.lock() {
                let _ = writeln!(f, "{}", file_output);
            }
        }

        writeln!(buf, "{}", output)
    });

    // Initialize the logger
    builder.init();

    log::debug!("Logging initialized with level: {:?}", config.level);
    Ok(())
}

/// Set up file logging by writing log entries to the specified file.
fn setup_file_logging(path: &PathBuf) -> Result<()> {
    // Ensure directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            crate::core::error::Error::ConfigSave(format!("Failed to create log directory: {}", e))
        })?;
    }

    // Validate the path is writable by opening in append mode
    let _file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| {
            crate::core::error::Error::ConfigSave(format!(
                "Failed to open log file {:?}: {}",
                path, e
            ))
        })?;

    log::info!("File logging enabled: {:?}", path);
    Ok(())
}

/// Clean up old log files.
pub fn cleanup_old_logs(log_dir: &PathBuf, keep_days: u32) -> Result<u32> {
    use std::time::{Duration, SystemTime};

    let cutoff = SystemTime::now() - Duration::from_secs(keep_days as u64 * 24 * 60 * 60);
    let mut deleted = 0u32;

    if !log_dir.exists() {
        return Ok(0);
    }

    let entries =
        fs::read_dir(log_dir).map_err(|e| crate::core::error::Error::DirectoryAccess {
            path: log_dir.clone(),
            source: e,
        })?;

    for entry in entries.flatten() {
        let path = entry.path();

        if path.extension().is_some_and(|ext| ext == "log") {
            if let Ok(metadata) = entry.metadata() {
                if let Ok(modified) = metadata.modified() {
                    if modified < cutoff && fs::remove_file(&path).is_ok() {
                        log::debug!("Deleted old log file: {:?}", path);
                        deleted += 1;
                    }
                }
            }
        }
    }

    if deleted > 0 {
        log::info!("Cleaned up {} old log file(s)", deleted);
    }

    Ok(deleted)
}

/// A simple log writer for file output.
pub struct FileLogger {
    file: File,
}

impl FileLogger {
    /// Create a new file logger.
    pub fn new(path: &PathBuf) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| crate::core::error::Error::file_write(path, e))?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| crate::core::error::Error::file_write(path, e))?;

        Ok(Self { file })
    }

    /// Write a log entry.
    pub fn log(&mut self, level: &str, message: &str) -> Result<()> {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
        writeln!(self.file, "{} [{}] {}", timestamp, level, message)
            .map_err(|e| crate::core::error::Error::Internal(format!("Failed to write log: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_config_default() {
        let config = LogConfig::default();
        assert_eq!(config.level, LevelFilter::Info);
        assert!(config.console);
        assert!(!config.file);
    }

    #[test]
    fn test_log_config_verbose() {
        let config = LogConfig::verbose();
        assert_eq!(config.level, LevelFilter::Debug);
        assert!(config.module_path);
    }

    #[test]
    fn test_log_config_quiet() {
        let config = LogConfig::quiet();
        assert_eq!(config.level, LevelFilter::Error);
        assert!(!config.timestamps);
    }
}
