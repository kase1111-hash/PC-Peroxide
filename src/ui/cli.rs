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

    /// Show application information
    Info,
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
