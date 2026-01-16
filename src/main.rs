//! PC-Peroxide: A lightweight, portable malware detection and removal utility.
//!
//! This is the main entry point for the CLI application.

use pc_peroxide::core::config::Config;
use pc_peroxide::core::error::Result;
use pc_peroxide::scanner::{FileScanner, PersistenceScanner, ScanResultStore};
use pc_peroxide::ui::cli::{Cli, Commands, ConfigAction, HistoryAction, OutputFormat, PersistenceTypeFilter, QuarantineAction};
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
        Some(Commands::History { action }) => run_history(action, cli.format),
        Some(Commands::Persistence { all, r#type }) => run_persistence(all, r#type, cli.format),
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

    // Save scan results to database
    if let Ok(store) = ScanResultStore::open_default() {
        if let Err(e) = store.save_scan(&summary) {
            log::warn!("Failed to save scan results: {}", e);
        } else {
            log::debug!("Scan results saved to database");
        }
    }

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
            println!("Bytes Scanned:   {}", format_bytes(summary.bytes_scanned));
            println!("Threats Found:   {}", summary.threats_found);
            println!("Errors:          {}", summary.errors);
            if let Some(duration) = summary.duration_secs() {
                println!("Duration:        {}", format_duration(duration));
                if summary.files_scanned > 0 && duration > 0 {
                    let rate = summary.files_scanned as f64 / duration as f64;
                    println!("Scan Rate:       {:.1} files/sec", rate);
                }
            }

            // Show detections if any
            if !summary.detections.is_empty() {
                println!();
                println!("=== Detections ===");
                for det in &summary.detections {
                    println!("  [{}] {} - {}", det.severity, det.threat_name, det.path.display());
                }
            }
        }
    }

    Ok(())
}

/// Format bytes for human-readable display.
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

/// Format duration for human-readable display.
fn format_duration(seconds: i64) -> String {
    if seconds >= 3600 {
        let hours = seconds / 3600;
        let minutes = (seconds % 3600) / 60;
        let secs = seconds % 60;
        format!("{}h {}m {}s", hours, minutes, secs)
    } else if seconds >= 60 {
        let minutes = seconds / 60;
        let secs = seconds % 60;
        format!("{}m {}s", minutes, secs)
    } else {
        format!("{}s", seconds)
    }
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

/// Handle history commands.
fn run_history(action: HistoryAction, format: OutputFormat) -> Result<()> {
    let store = ScanResultStore::open_default()?;

    match action {
        HistoryAction::List { limit } => {
            let scans = store.get_recent_scans(limit)?;

            if scans.is_empty() {
                println!("No scan history found.");
                return Ok(());
            }

            match format {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&scans)?);
                }
                OutputFormat::Text => {
                    println!("=== Recent Scans ===");
                    println!("{:<36} {:>10} {:>8} {:>8} {:>8}", "Scan ID", "Type", "Files", "Threats", "Status");
                    println!("{}", "-".repeat(80));
                    for scan in scans {
                        println!(
                            "{:<36} {:>10} {:>8} {:>8} {:>8?}",
                            scan.scan_id,
                            format!("{}", scan.scan_type),
                            scan.files_scanned,
                            scan.threats_found,
                            scan.status
                        );
                    }
                }
            }
        }

        HistoryAction::Show { id } => {
            match store.load_scan(&id)? {
                Some(scan) => {
                    match format {
                        OutputFormat::Json => {
                            println!("{}", serde_json::to_string_pretty(&scan)?);
                        }
                        OutputFormat::Text => {
                            println!("=== Scan Details ===");
                            println!("Scan ID:         {}", scan.scan_id);
                            println!("Type:            {}", scan.scan_type);
                            println!("Status:          {:?}", scan.status);
                            println!("Start Time:      {}", scan.start_time);
                            if let Some(end) = scan.end_time {
                                println!("End Time:        {}", end);
                            }
                            println!("Files Scanned:   {}", scan.files_scanned);
                            println!("Bytes Scanned:   {}", format_bytes(scan.bytes_scanned));
                            println!("Threats Found:   {}", scan.threats_found);
                            println!("Errors:          {}", scan.errors);

                            if !scan.detections.is_empty() {
                                println!();
                                println!("=== Detections ===");
                                for det in &scan.detections {
                                    println!("  [{}] {} - {}", det.severity, det.threat_name, det.path.display());
                                    if !det.description.is_empty() {
                                        println!("      {}", det.description);
                                    }
                                }
                            }
                        }
                    }
                }
                None => {
                    println!("Scan not found: {}", id);
                }
            }
        }

        HistoryAction::Stats => {
            let stats = store.get_statistics()?;

            match format {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                        "total_scans": stats.total_scans,
                        "total_files_scanned": stats.total_files_scanned,
                        "total_bytes_scanned": stats.total_bytes_scanned,
                        "total_threats_found": stats.total_threats_found,
                        "last_scan_time": stats.last_scan_time.map(|t| t.to_rfc3339()),
                    }))?);
                }
                OutputFormat::Text => {
                    println!("=== Scan Statistics ===");
                    println!("Total Scans:         {}", stats.total_scans);
                    println!("Total Files Scanned: {}", stats.total_files_scanned);
                    println!("Total Data Scanned:  {}", format_bytes(stats.total_bytes_scanned));
                    println!("Total Threats Found: {}", stats.total_threats_found);
                    if let Some(last) = stats.last_scan_time {
                        println!("Last Scan:           {}", last);
                    }
                }
            }
        }

        HistoryAction::Clear { days, yes } => {
            if !yes {
                println!("This will delete scan history older than {} days.", days);
                println!("Use --yes to confirm.");
                return Ok(());
            }

            let deleted = store.cleanup_old_scans(days)?;
            println!("Deleted {} old scan record(s).", deleted);
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

/// Scan for persistence mechanisms.
fn run_persistence(
    show_all: bool,
    type_filter: Option<PersistenceTypeFilter>,
    format: OutputFormat,
) -> Result<()> {
    log::info!("Scanning for persistence mechanisms...");
    let scanner = PersistenceScanner::new();

    let entries = if show_all {
        scanner.scan_all()?
    } else {
        scanner.scan_suspicious()?
    };

    // Filter by type if specified
    let entries: Vec<_> = match type_filter {
        Some(PersistenceTypeFilter::Registry) => entries
            .into_iter()
            .filter(|e| matches!(
                e.persistence_type,
                pc_peroxide::scanner::PersistenceType::RegistryRun
                    | pc_peroxide::scanner::PersistenceType::Service
                    | pc_peroxide::scanner::PersistenceType::Ifeo
                    | pc_peroxide::scanner::PersistenceType::AppInitDll
                    | pc_peroxide::scanner::PersistenceType::ShellExtension
                    | pc_peroxide::scanner::PersistenceType::Winlogon
                    | pc_peroxide::scanner::PersistenceType::LsaPackage
            ))
            .collect(),
        Some(PersistenceTypeFilter::Startup) => entries
            .into_iter()
            .filter(|e| e.persistence_type == pc_peroxide::scanner::PersistenceType::StartupFolder)
            .collect(),
        Some(PersistenceTypeFilter::Tasks) => entries
            .into_iter()
            .filter(|e| e.persistence_type == pc_peroxide::scanner::PersistenceType::ScheduledTask)
            .collect(),
        None => entries,
    };

    match format {
        OutputFormat::Json => {
            let json_entries: Vec<_> = entries
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "type": format!("{}", e.persistence_type),
                        "name": e.name,
                        "location": e.location,
                        "path": e.path.as_ref().map(|p| p.display().to_string()),
                        "arguments": e.arguments,
                        "file_exists": e.file_exists,
                        "suspicious": e.suspicious,
                        "suspicion_reason": e.suspicion_reason,
                        "severity_score": e.severity_score,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json_entries)?);
        }
        OutputFormat::Text => {
            if entries.is_empty() {
                if show_all {
                    println!("No persistence entries found.");
                } else {
                    println!("No suspicious persistence entries found.");
                    println!();
                    println!("Use --all to show all entries.");
                }
                return Ok(());
            }

            let suspicious_count = entries.iter().filter(|e| e.suspicious).count();
            let title = if show_all {
                "=== All Persistence Entries ==="
            } else {
                "=== Suspicious Persistence Entries ==="
            };

            println!();
            println!("{}", title);
            println!("Total: {} ({} suspicious)", entries.len(), suspicious_count);
            println!();

            for entry in &entries {
                let status = if entry.suspicious {
                    format!("[SUSPICIOUS - Score: {}]", entry.severity_score)
                } else {
                    "[OK]".to_string()
                };

                println!("{} {} - {}", status, entry.persistence_type, entry.name);
                println!("  Location: {}", entry.location);

                if let Some(ref path) = entry.path {
                    let exists = if entry.file_exists { "exists" } else { "MISSING" };
                    println!("  Path: {} ({})", path.display(), exists);
                }

                if let Some(ref args) = entry.arguments {
                    println!("  Arguments: {}", args);
                }

                if let Some(ref reason) = entry.suspicion_reason {
                    println!("  Reason: {}", reason);
                }

                println!();
            }

            if suspicious_count > 0 {
                println!("Warning: {} suspicious persistence mechanism(s) found!", suspicious_count);
                println!("Review each entry carefully before taking action.");
            }
        }
    }

    Ok(())
}
