//! Command-line interface definition.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// PC-Peroxide: Lightweight malware detection and removal utility
#[derive(Parser, Debug)]
#[command(name = "pc-peroxide")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Output format (text, json)
    #[arg(long, default_value = "text", global = true)]
    pub format: OutputFormat,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

/// Output format for results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    /// Human-readable text output
    Text,
    /// JSON output for machine processing
    Json,
}

/// Available commands.
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run a malware scan
    Scan {
        /// Perform a quick scan (common locations only)
        #[arg(short, long, conflicts_with_all = ["full", "path"])]
        quick: bool,

        /// Perform a full system scan
        #[arg(short, long, conflicts_with_all = ["quick", "path"])]
        full: bool,

        /// Scan specific path(s)
        #[arg(short, long, conflicts_with_all = ["quick", "full"])]
        path: Option<Vec<PathBuf>>,

        /// Export results to file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Scan only, don't take any action
        #[arg(long)]
        no_action: bool,

        /// Use custom YARA rules file
        #[arg(long)]
        yara: Option<PathBuf>,
    },

    /// Manage quarantined items
    Quarantine {
        #[command(subcommand)]
        action: QuarantineAction,
    },

    /// Update signature database
    Update {
        /// Force update even if up to date
        #[arg(short, long)]
        force: bool,

        /// Import signatures from local file
        #[arg(long)]
        import: Option<PathBuf>,
    },

    /// Configure settings
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// View scan history and statistics
    History {
        #[command(subcommand)]
        action: HistoryAction,
    },

    /// Scan for persistence mechanisms (autorun entries, services, scheduled tasks)
    Persistence {
        /// Show all entries, not just suspicious ones
        #[arg(short, long)]
        all: bool,

        /// Scan specific type only (registry, startup, tasks)
        #[arg(short, long)]
        r#type: Option<PersistenceTypeFilter>,
    },

    /// Scan running processes for suspicious activity
    Processes {
        /// Show all processes, not just suspicious ones
        #[arg(short, long)]
        all: bool,

        /// Scan a specific process by PID
        #[arg(short, long)]
        pid: Option<u32>,

        /// Enable memory scanning (requires elevated privileges)
        #[arg(short, long)]
        memory: bool,

        /// Minimum suspicion score to report (0-100)
        #[arg(long, default_value = "30")]
        threshold: u8,
    },

    /// Manage file whitelist (exclude from detection)
    Whitelist {
        #[command(subcommand)]
        action: WhitelistAction,
    },

    /// Show application information
    Info,
}

/// Persistence scan type filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum PersistenceTypeFilter {
    /// Registry autorun locations
    Registry,
    /// Startup folders
    Startup,
    /// Scheduled tasks
    Tasks,
}

/// Quarantine subcommands.
#[derive(Subcommand, Debug)]
pub enum QuarantineAction {
    /// List quarantined items
    List,

    /// Restore a quarantined item
    Restore {
        /// ID of item to restore
        id: String,

        /// Restore to a different path
        #[arg(short, long)]
        path: Option<PathBuf>,
    },

    /// Delete a quarantined item permanently
    Delete {
        /// ID of item to delete
        id: String,
    },

    /// Delete all quarantined items
    Clear {
        /// Skip confirmation prompt
        #[arg(short, long)]
        yes: bool,
    },

    /// Show quarantine statistics
    Stats,
}

/// Whitelist subcommands.
#[derive(Subcommand, Debug)]
pub enum WhitelistAction {
    /// List whitelist entries
    List,

    /// Add a file hash to whitelist
    AddHash {
        /// SHA-256 hash of file to whitelist
        hash: String,

        /// Reason for whitelisting
        #[arg(short, long, default_value = "User whitelist")]
        reason: String,
    },

    /// Add a path pattern to whitelist
    AddPath {
        /// Path pattern (supports * and ? wildcards)
        pattern: String,

        /// Reason for whitelisting
        #[arg(short, long, default_value = "User whitelist")]
        reason: String,
    },

    /// Add a detection name pattern to whitelist
    AddDetection {
        /// Detection name pattern (supports * and ? wildcards)
        pattern: String,

        /// Reason for whitelisting
        #[arg(short, long, default_value = "User whitelist")]
        reason: String,
    },

    /// Remove a whitelist entry
    Remove {
        /// ID of whitelist entry to remove
        id: String,
    },

    /// Disable a whitelist entry
    Disable {
        /// ID of whitelist entry to disable
        id: String,
    },

    /// Enable a whitelist entry
    Enable {
        /// ID of whitelist entry to enable
        id: String,
    },
}

/// Configuration subcommands.
#[derive(Subcommand, Debug)]
pub enum ConfigAction {
    /// Show current configuration
    Show,

    /// Set a configuration value
    Set {
        /// Configuration key (e.g., scan.skip_large_files_mb)
        key: String,
        /// Value to set
        value: String,
    },

    /// Reset configuration to defaults
    Reset {
        /// Skip confirmation prompt
        #[arg(short, long)]
        yes: bool,
    },

    /// Open configuration file location
    Path,
}

/// History subcommands.
#[derive(Subcommand, Debug)]
pub enum HistoryAction {
    /// Show recent scan history
    List {
        /// Number of recent scans to show
        #[arg(short, long, default_value = "10")]
        limit: usize,
    },

    /// Show details of a specific scan
    Show {
        /// Scan ID to show details for
        id: String,
    },

    /// Show aggregate statistics
    Stats,

    /// Clear old scan history
    Clear {
        /// Days of history to keep
        #[arg(short, long, default_value = "30")]
        days: u32,

        /// Skip confirmation prompt
        #[arg(short, long)]
        yes: bool,
    },
}

impl Cli {
    /// Parse command-line arguments.
    pub fn parse_args() -> Self {
        Self::parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parse() {
        // Test that CLI can be constructed
        let cli = Cli {
            verbose: false,
            format: OutputFormat::Text,
            command: None,
        };
        assert!(!cli.verbose);
    }
}
