//! PC-Peroxide: A lightweight, portable malware detection and removal utility.
//!
//! This is the main entry point for the CLI application.

use pc_peroxide::core::config::Config;
use pc_peroxide::core::error::Result;
use pc_peroxide::scanner::FileScanner;
use pc_peroxide::ui::cli::{Cli, Commands, ConfigAction, OutputFormat, QuarantineAction};
use pc_peroxide::utils::logging::{init_logging, LogConfig};
use std::process::ExitCode;
use std::sync::Arc;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {}", e);
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    // Parse command-line arguments
    let cli = Cli::parse_args();

    // Initialize logging based on verbosity
    let log_config = if cli.verbose {
        LogConfig::verbose()
    } else {
        LogConfig::default()
    };
    init_logging(log_config)?;

    log::info!("PC-Peroxide v{}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let config = Arc::new(Config::load_or_default());
    log::debug!("Configuration loaded");

    // Handle commands
    match cli.command {
        Some(Commands::Scan {
            quick,
            full,
            path,
            output,
            no_action,
            yara,
        }) => {
            run_scan(config, quick, full, path, output, no_action, yara, cli.format).await
        }
        Some(Commands::Quarantine { action }) => run_quarantine(action, cli.format).await,
        Some(Commands::Update { force, import }) => run_update(force, import).await,
        Some(Commands::Config { action }) => run_config(action, &config),
        Some(Commands::Info) => run_info(&config),
        None => {
            // No command specified, show help
            println!("PC-Peroxide - Malware Detection and Removal Utility");
            println!();
            println!("Use --help for usage information");
            println!();
            println!("Quick start:");
            println!("  pc-peroxide scan --quick     Run a quick scan");
            println!("  pc-peroxide scan --full      Run a full system scan");
            println!("  pc-peroxide quarantine list  View quarantined items");
            println!("  pc-peroxide update           Update signatures");
            Ok(())
        }
    }
}

/// Run a malware scan.
async fn run_scan(
    config: Arc<Config>,
    quick: bool,
    full: bool,
    path: Option<Vec<std::path::PathBuf>>,
    _output: Option<std::path::PathBuf>,
    _no_action: bool,
    _yara: Option<std::path::PathBuf>,
    format: OutputFormat,
) -> Result<()> {
    let scanner = FileScanner::new(config);

    let summary = if quick {
        log::info!("Starting quick scan...");
        scanner.quick_scan().await?
    } else if full {
        log::info!("Starting full system scan...");
        scanner.full_scan().await?
    } else if let Some(paths) = path {
        log::info!("Starting custom scan of {} path(s)...", paths.len());
        scanner.custom_scan(paths).await?
    } else {
        // Default to quick scan
        log::info!("Starting quick scan (default)...");
        scanner.quick_scan().await?
    };

    // Output results
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        OutputFormat::Text => {
            println!();
            println!("=== Scan Complete ===");
            println!("Scan ID:         {}", summary.scan_id);
            println!("Scan Type:       {}", summary.scan_type);
            println!("Status:          {:?}", summary.status);
            println!("Files Scanned:   {}", summary.files_scanned);
            println!("Threats Found:   {}", summary.threats_found);
            if let Some(duration) = summary.duration_secs() {
                println!("Duration:        {} seconds", duration);
            }
        }
    }

    Ok(())
}

/// Manage quarantine.
async fn run_quarantine(action: QuarantineAction, _format: OutputFormat) -> Result<()> {
    match action {
        QuarantineAction::List => {
            log::info!("Listing quarantined items...");
            // TODO: Implement in Phase 7
            println!("Quarantine is empty.");
        }
        QuarantineAction::Restore { id } => {
            log::info!("Restoring item: {}", id);
            // TODO: Implement in Phase 7
            println!("Restore functionality not yet implemented.");
        }
        QuarantineAction::Delete { id } => {
            log::info!("Deleting item: {}", id);
            // TODO: Implement in Phase 7
            println!("Delete functionality not yet implemented.");
        }
        QuarantineAction::Clear { yes: _ } => {
            log::info!("Clearing quarantine...");
            // TODO: Implement in Phase 7
            println!("Clear functionality not yet implemented.");
        }
    }
    Ok(())
}

/// Update signatures.
async fn run_update(force: bool, import: Option<std::path::PathBuf>) -> Result<()> {
    if let Some(path) = import {
        log::info!("Importing signatures from: {:?}", path);
        // TODO: Implement in Phase 2
        println!("Import functionality not yet implemented.");
    } else {
        log::info!("Checking for signature updates...");
        if force {
            log::info!("Forcing update...");
        }
        // TODO: Implement in Phase 10
        println!("Update functionality not yet implemented.");
    }
    Ok(())
}

/// Handle configuration commands.
fn run_config(action: ConfigAction, config: &Config) -> Result<()> {
    match action {
        ConfigAction::Show => {
            println!("{}", serde_json::to_string_pretty(config)?);
        }
        ConfigAction::Set { key, value } => {
            log::info!("Setting {} = {}", key, value);
            // TODO: Implement config modification
            println!("Config modification not yet implemented.");
            println!("Edit the config file directly: {:?}", Config::default_config_path());
        }
        ConfigAction::Reset { yes: _ } => {
            log::info!("Resetting configuration to defaults...");
            let default_config = Config::default();
            default_config.save(&Config::default_config_path())?;
            println!("Configuration reset to defaults.");
        }
        ConfigAction::Path => {
            println!("{}", Config::default_config_path().display());
        }
    }
    Ok(())
}

/// Show application information.
fn run_info(config: &Config) -> Result<()> {
    println!("PC-Peroxide - Malware Detection and Removal Utility");
    println!();
    println!("Version:          {}", env!("CARGO_PKG_VERSION"));
    println!("Config Path:      {}", Config::default_config_path().display());
    println!("Data Directory:   {}", Config::data_dir().display());
    println!("Log Directory:    {}", config.logging.log_dir().display());
    println!("Quarantine Path:  {}", config.quarantine.quarantine_dir().display());
    println!();
    println!("Detection Settings:");
    println!("  Heuristic:      {:?}", config.detection.heuristic_sensitivity);
    println!("  YARA Enabled:   {}", config.detection.enable_yara);
    println!("  PUP Detection:  {}", config.detection.pup_detection);
    println!();
    println!("Scan Settings:");
    println!("  Max File Size:  {} MB", config.scan.skip_large_files_mb);
    println!("  Scan Archives:  {}", config.scan.scan_archives);
    println!("  Threads:        {}", config.scan.scan_threads);
    Ok(())
}
