//! PC-Peroxide: A lightweight, portable malware detection and removal utility.
//!
//! This is the main entry point for the CLI application.

use pc_peroxide::core::config::Config;
use pc_peroxide::core::error::Result;
use pc_peroxide::core::reporting::{create_cli_error_report, error_to_exit_code};
use pc_peroxide::detection::SignatureDatabase;
use pc_peroxide::quarantine::{get_quarantine_path, QuarantineVault, WhitelistEntry, WhitelistManager, WhitelistType};
use pc_peroxide::scanner::{
    BrowserScanner, BrowserType, ConsoleProgressReporter, FileScanner, NetworkScanner,
    PersistenceScanner, ProcessScanner, ScanResultStore,
};
use pc_peroxide::ui::cli::{
    BrowserFilter, Cli, Commands, ConfigAction, ExportFormat, HistoryAction, OutputFormat,
    PersistenceTypeFilter, QuarantineAction, WhitelistAction,
};
use pc_peroxide::ui::report::{generate_report, ReportFormat};
use pc_peroxide::utils::logging::{init_logging, LogConfig};
use std::process::ExitCode;
use std::sync::Arc;
use uuid::Uuid;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let report = create_cli_error_report(&e);
            eprintln!("{}", report);

            // Log full error details for debugging
            log::error!("Fatal error: {:?}", e);

            // Use category-specific exit code
            ExitCode::from(error_to_exit_code(&e) as u8)
        }
    }
}

async fn run() -> Result<()> {
    // Parse command-line arguments
    let cli = Cli::parse_args();

    // Initialize logging based on verbosity (skip if silent)
    if !cli.silent {
        let log_config = if cli.verbose {
            LogConfig::verbose()
        } else {
            LogConfig::default()
        };
        init_logging(log_config)?;
        log::info!("PC-Peroxide v{}", env!("CARGO_PKG_VERSION"));
    }

    // Load configuration
    let config = Arc::new(Config::load_or_default());
    if !cli.silent {
        log::debug!("Configuration loaded");
    }

    // Handle commands
    match cli.command {
        Some(Commands::Scan {
            quick,
            full,
            path,
            output,
            export_format,
            no_action,
            yara,
        }) => {
            run_scan(config, quick, full, path, output, export_format, no_action, yara, cli.format, cli.silent).await
        }
        Some(Commands::Quarantine { action }) => run_quarantine(action, cli.format).await,
        Some(Commands::Update { force, import }) => run_update(force, import).await,
        Some(Commands::Config { action }) => run_config(action, &config),
        Some(Commands::History { action }) => run_history(action, cli.format),
        Some(Commands::Persistence { all, r#type }) => run_persistence(all, r#type, cli.format),
        Some(Commands::Processes { all, pid, memory, threshold }) => {
            run_processes(all, pid, memory, threshold, cli.format)
        }
        Some(Commands::Whitelist { action }) => run_whitelist(action, cli.format),
        Some(Commands::Network { all, listening, pid }) => {
            run_network(all, listening, pid, cli.format)
        }
        Some(Commands::Browser { all, browser, hijacks_only }) => {
            run_browser(all, browser, hijacks_only, cli.format)
        }
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
#[allow(clippy::too_many_arguments)]
async fn run_scan(
    config: Arc<Config>,
    quick: bool,
    full: bool,
    path: Option<Vec<std::path::PathBuf>>,
    output: Option<std::path::PathBuf>,
    export_format: ExportFormat,
    no_action: bool,
    yara: Option<std::path::PathBuf>,
    format: OutputFormat,
    silent: bool,
) -> Result<()> {
    let mut scanner = FileScanner::new(config);

    // Load custom YARA rules if provided
    if let Some(ref yara_path) = yara {
        scanner.load_yara_rules(yara_path)?;
    }

    if no_action {
        log::info!("No-action mode: auto-remediation suppressed");
    }

    // Set up progress reporting for non-silent mode
    if !silent {
        let reporter = Arc::new(ConsoleProgressReporter::new());
        let reporter_clone = reporter.clone();
        scanner.set_progress_callback(move |progress| {
            reporter_clone.report(&progress);
        });
    }

    let summary = if quick {
        if !silent {
            eprintln!("Starting quick scan...");
        }
        scanner.quick_scan().await?
    } else if full {
        if !silent {
            eprintln!("Starting full system scan...");
        }
        scanner.full_scan().await?
    } else if let Some(paths) = path {
        if !silent {
            eprintln!("Starting custom scan of {} path(s)...", paths.len());
        }
        scanner.custom_scan(paths).await?
    } else {
        // Default to quick scan
        if !silent {
            eprintln!("Starting quick scan (default)...");
        }
        scanner.quick_scan().await?
    };

    // Save scan results to database
    if let Ok(store) = ScanResultStore::open_default() {
        if let Err(e) = store.save_scan(&summary) {
            if !silent {
                log::warn!("Failed to save scan results: {}", e);
            }
        } else if !silent {
            log::debug!("Scan results saved to database");
        }
    }

    // Export to file if requested
    if let Some(output_path) = output {
        let report_format = match export_format {
            ExportFormat::Json => ReportFormat::Json,
            ExportFormat::Html => ReportFormat::Html,
            ExportFormat::Csv => ReportFormat::Csv,
            ExportFormat::Pdf => ReportFormat::Pdf,
        };
        generate_report(&summary, report_format, &output_path)?;
        if !silent {
            println!("Report exported to: {}", output_path.display());
        }
    }

    // Output results (unless silent)
    if silent {
        // In silent mode, return based on threats found
        // Exit code is handled by caller based on Result
        return if summary.threats_found > 0 {
            Err(pc_peroxide::core::error::Error::Custom(format!(
                "Threats found: {}",
                summary.threats_found
            )))
        } else {
            Ok(())
        };
    }

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
async fn run_quarantine(action: QuarantineAction, format: OutputFormat) -> Result<()> {
    let vault = QuarantineVault::open_default()?;

    match action {
        QuarantineAction::List => {
            log::info!("Listing quarantined items...");
            let items = vault.list()?;

            if items.is_empty() {
                println!("Quarantine is empty.");
                return Ok(());
            }

            match format {
                OutputFormat::Json => {
                    let json_items: Vec<_> = items
                        .iter()
                        .map(|item| {
                            serde_json::json!({
                                "id": item.id,
                                "original_path": item.original_path.display().to_string(),
                                "detection_name": item.detection_name,
                                "category": item.category,
                                "severity": item.severity,
                                "quarantine_time": item.quarantine_time.to_rfc3339(),
                                "original_size": item.original_size,
                                "hash": item.hash_sha256,
                                "restorable": item.restorable,
                            })
                        })
                        .collect();
                    println!("{}", serde_json::to_string_pretty(&json_items)?);
                }
                OutputFormat::Text => {
                    println!("=== Quarantined Items ===");
                    println!("Total: {}", items.len());
                    println!();

                    for item in &items {
                        let status = if item.restorable { "" } else { " [DELETED]" };
                        println!("[{}]{}", item.severity, status);
                        println!("  ID:        {}", item.id);
                        println!("  Name:      {}", item.detection_name);
                        println!("  Category:  {}", item.category);
                        println!("  Path:      {}", item.original_path.display());
                        println!("  Size:      {}", format_bytes(item.original_size));
                        println!("  Time:      {}", item.quarantine_time.format("%Y-%m-%d %H:%M:%S"));
                        println!();
                    }
                }
            }
        }

        QuarantineAction::Restore { id, path } => {
            log::info!("Restoring item: {}", id);

            let result = if let Some(restore_path) = path {
                vault.restore_to(&id, Some(&restore_path))
            } else {
                vault.restore(&id)
            };

            if result.success {
                println!("Successfully restored: {}", result.restored_path.display());
            } else {
                let error_msg = result.error.unwrap_or_else(|| "Unknown error".to_string());
                eprintln!("Failed to restore: {}", error_msg);
            }
        }

        QuarantineAction::Delete { id } => {
            log::info!("Deleting item: {}", id);
            vault.delete(&id)?;
            println!("Deleted item: {}", id);
        }

        QuarantineAction::Clear { yes } => {
            if !yes {
                let count = vault.count()?;
                if count == 0 {
                    println!("Quarantine is already empty.");
                    return Ok(());
                }
                println!("This will permanently delete {} quarantined item(s).", count);
                println!("Use --yes to confirm.");
                return Ok(());
            }

            log::info!("Clearing quarantine...");
            let items = vault.list()?;
            let mut deleted = 0;
            for item in items {
                if vault.delete(&item.id).is_ok() {
                    deleted += 1;
                }
            }
            println!("Deleted {} item(s) from quarantine.", deleted);
        }

        QuarantineAction::Stats => {
            let stats = vault.stats()?;

            match format {
                OutputFormat::Json => {
                    let json_stats = serde_json::json!({
                        "total_count": stats.total_count,
                        "total_original_size": stats.total_original_size,
                        "vault_size": stats.vault_size,
                        "categories": stats.categories,
                    });
                    println!("{}", serde_json::to_string_pretty(&json_stats)?);
                }
                OutputFormat::Text => {
                    println!("=== Quarantine Statistics ===");
                    println!("Items:            {}", stats.total_count);
                    println!("Original Size:    {}", format_bytes(stats.total_original_size));
                    println!("Vault Size:       {}", format_bytes(stats.vault_size));
                    println!("Vault Location:   {}", get_quarantine_path().display());

                    if !stats.categories.is_empty() {
                        println!();
                        println!("By Category:");
                        for (category, count) in &stats.categories {
                            println!("  {}: {}", category, count);
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Update signatures.
async fn run_update(force: bool, import: Option<std::path::PathBuf>) -> Result<()> {
    if let Some(path) = import {
        log::info!("Importing signatures from: {}", path.display());
        let db = SignatureDatabase::open_default()?;
        let result = db.import_file(&path)?;
        println!("{}", result);
        return Ok(());
    }

    log::info!("Checking for signature updates...");
    if force {
        log::info!("Forcing update...");
    }
    // TODO: Implement online update in a future phase
    println!("Online update not yet implemented. Use --import <file> to import signatures from a file.");
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

            let config_path = Config::default_config_path();
            let mut config = Config::load_or_default();

            // Serialize to JSON, navigate dotted path, set value
            let json_str = serde_json::to_string(&config)?;
            let mut json: serde_json::Value = serde_json::from_str(&json_str)?;

            let parts: Vec<&str> = key.split('.').collect();
            let mut target = &mut json;
            for part in &parts[..parts.len() - 1] {
                target = target.get_mut(*part).ok_or_else(|| {
                    pc_peroxide::core::error::Error::ConfigInvalid {
                        field: key.clone(),
                        message: format!("Unknown config section: {}", part),
                    }
                })?;
            }
            let field = parts.last().unwrap();

            if target.get(*field).is_none() {
                return Err(pc_peroxide::core::error::Error::ConfigInvalid {
                    field: key.clone(),
                    message: format!("Unknown config key: {}", field),
                });
            }

            // Parse value as JSON literal, fall back to string
            let parsed: serde_json::Value = serde_json::from_str(&value)
                .unwrap_or(serde_json::Value::String(value.clone()));
            target[*field] = parsed;

            // Deserialize back, validate, and save
            config = serde_json::from_value(json)?;
            config.validate()?;
            config.save(&config_path)?;
            println!("Set {} = {}", key, value);
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

        HistoryAction::Export { id, output, format: export_fmt } => {
            // Get the scan to export
            let scan = if id == "latest" {
                // Get the most recent scan
                let scans = store.get_recent_scans(1)?;
                scans.into_iter().next()
            } else {
                store.load_scan(&id)?
            };

            match scan {
                Some(summary) => {
                    let report_format = match export_fmt {
                        ExportFormat::Json => ReportFormat::Json,
                        ExportFormat::Html => ReportFormat::Html,
                        ExportFormat::Csv => ReportFormat::Csv,
                        ExportFormat::Pdf => ReportFormat::Pdf,
                    };
                    generate_report(&summary, report_format, &output)?;
                    println!("Report exported to: {}", output.display());
                }
                None => {
                    if id == "latest" {
                        println!("No scan history found.");
                    } else {
                        println!("Scan not found: {}", id);
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

/// Scan running processes for suspicious activity.
fn run_processes(
    show_all: bool,
    specific_pid: Option<u32>,
    scan_memory: bool,
    threshold: u8,
    format: OutputFormat,
) -> Result<()> {
    log::info!("Scanning processes...");

    let scanner = ProcessScanner::new()
        .with_memory_scan(scan_memory)
        .with_threshold(threshold);

    let results = if let Some(pid) = specific_pid {
        // Scan specific process
        match scanner.scan_pid(pid)? {
            Some(result) => vec![result],
            None => {
                println!("Process not found: PID {}", pid);
                return Ok(());
            }
        }
    } else if show_all {
        scanner.scan_all()?
    } else {
        scanner.scan_suspicious()?
    };

    match format {
        OutputFormat::Json => {
            let json_results: Vec<_> = results
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "pid": r.pid,
                        "name": r.name,
                        "path": r.path.as_ref().map(|p| p.display().to_string()),
                        "suspicious": r.suspicious,
                        "score": r.score,
                        "indicators": r.indicators.iter().map(|i| {
                            serde_json::json!({
                                "name": i.name,
                                "description": i.description,
                                "severity": i.severity,
                            })
                        }).collect::<Vec<_>>(),
                        "pattern_matches": r.pattern_matches.iter().map(|m| {
                            serde_json::json!({
                                "pattern": m.pattern_name,
                                "address": format!("0x{:x}", m.address),
                                "description": m.description,
                                "severity": m.severity,
                            })
                        }).collect::<Vec<_>>(),
                        "memory_stats": {
                            "virtual_size": r.memory_stats.virtual_size,
                            "executable_regions": r.memory_stats.executable_regions,
                            "rwx_regions": r.memory_stats.rwx_regions,
                        }
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json_results)?);
        }
        OutputFormat::Text => {
            if results.is_empty() {
                if show_all {
                    println!("No processes found.");
                } else {
                    println!("No suspicious processes found (threshold: {}).", threshold);
                    println!();
                    println!("Use --all to show all processes, or --threshold to adjust sensitivity.");
                }
                return Ok(());
            }

            let suspicious_count = results.iter().filter(|r| r.suspicious).count();
            let title = if show_all {
                "=== All Processes ==="
            } else {
                "=== Suspicious Processes ==="
            };

            println!();
            println!("{}", title);
            println!("Total: {} ({} suspicious)", results.len(), suspicious_count);
            println!();

            for result in &results {
                let status = if result.suspicious {
                    format!("[SUSPICIOUS - Score: {}]", result.score)
                } else {
                    format!("[OK - Score: {}]", result.score)
                };

                println!("{} PID {} - {}", status, result.pid, result.name);

                if let Some(ref path) = result.path {
                    println!("  Path: {}", path.display());
                }

                if !result.indicators.is_empty() {
                    println!("  Indicators:");
                    for indicator in &result.indicators {
                        println!("    - {} (severity: {})", indicator.name, indicator.severity);
                        if !indicator.description.is_empty() {
                            println!("      {}", indicator.description);
                        }
                    }
                }

                if !result.pattern_matches.is_empty() {
                    println!("  Memory Pattern Matches:");
                    for m in &result.pattern_matches {
                        println!("    - {} at 0x{:x} (severity: {})", m.pattern_name, m.address, m.severity);
                    }
                }

                if result.memory_stats.region_count > 0 {
                    println!("  Memory: {} regions, {} executable, {} RWX",
                        result.memory_stats.region_count,
                        result.memory_stats.executable_regions,
                        result.memory_stats.rwx_regions
                    );
                }

                println!();
            }

            if suspicious_count > 0 {
                println!("Warning: {} suspicious process(es) found!", suspicious_count);
                println!("Review each process carefully before taking action.");
            }
        }
    }

    Ok(())
}

/// Manage whitelist entries.
fn run_whitelist(action: WhitelistAction, format: OutputFormat) -> Result<()> {
    let whitelist_path = get_quarantine_path().join("whitelist.db");
    let manager = WhitelistManager::open(&whitelist_path)?;

    match action {
        WhitelistAction::List => {
            let entries = manager.list()?;

            if entries.is_empty() {
                println!("Whitelist is empty.");
                return Ok(());
            }

            match format {
                OutputFormat::Json => {
                    let json_entries: Vec<_> = entries
                        .iter()
                        .map(|e| {
                            serde_json::json!({
                                "id": e.id,
                                "type": format!("{:?}", e.whitelist_type).to_lowercase(),
                                "pattern": e.pattern,
                                "reason": e.reason,
                                "created_at": e.created_at.to_rfc3339(),
                                "active": e.active,
                            })
                        })
                        .collect();
                    println!("{}", serde_json::to_string_pretty(&json_entries)?);
                }
                OutputFormat::Text => {
                    println!("=== Whitelist Entries ===");
                    println!("Total: {} ({} active)", entries.len(),
                        entries.iter().filter(|e| e.active).count());
                    println!();

                    for entry in &entries {
                        let status = if entry.active { "" } else { " [DISABLED]" };
                        let type_str = match entry.whitelist_type {
                            WhitelistType::Hash => "Hash",
                            WhitelistType::Path => "Path",
                            WhitelistType::Detection => "Detection",
                        };
                        println!("[{}]{}", type_str, status);
                        println!("  ID:      {}", entry.id);
                        println!("  Pattern: {}", entry.pattern);
                        println!("  Reason:  {}", entry.reason);
                        println!("  Created: {}", entry.created_at.format("%Y-%m-%d %H:%M:%S"));
                        println!();
                    }
                }
            }
        }

        WhitelistAction::AddHash { hash, reason } => {
            let id = Uuid::new_v4().to_string();
            let entry = WhitelistEntry::by_hash(id.clone(), hash.clone(), reason);
            manager.add(&entry)?;
            println!("Added hash to whitelist: {}", hash);
            println!("Entry ID: {}", id);
        }

        WhitelistAction::AddPath { pattern, reason } => {
            let id = Uuid::new_v4().to_string();
            let entry = WhitelistEntry::by_path(id.clone(), pattern.clone(), reason);
            manager.add(&entry)?;
            println!("Added path pattern to whitelist: {}", pattern);
            println!("Entry ID: {}", id);
        }

        WhitelistAction::AddDetection { pattern, reason } => {
            let id = Uuid::new_v4().to_string();
            let entry = WhitelistEntry::by_detection(id.clone(), pattern.clone(), reason);
            manager.add(&entry)?;
            println!("Added detection pattern to whitelist: {}", pattern);
            println!("Entry ID: {}", id);
        }

        WhitelistAction::Remove { id } => {
            if manager.remove(&id)? {
                println!("Removed whitelist entry: {}", id);
            } else {
                println!("Entry not found: {}", id);
            }
        }

        WhitelistAction::Disable { id } => {
            if manager.disable(&id)? {
                println!("Disabled whitelist entry: {}", id);
            } else {
                println!("Entry not found: {}", id);
            }
        }

        WhitelistAction::Enable { id } => {
            if manager.enable(&id)? {
                println!("Enabled whitelist entry: {}", id);
            } else {
                println!("Entry not found: {}", id);
            }
        }
    }

    Ok(())
}

/// Scan network connections for suspicious activity.
fn run_network(
    show_all: bool,
    include_listening: bool,
    specific_pid: Option<u32>,
    format: OutputFormat,
) -> Result<()> {
    log::info!("Scanning network connections...");

    let scanner = NetworkScanner::new()
        .with_listening(include_listening)
        .with_established(true);

    let results = if let Some(pid) = specific_pid {
        scanner.scan_pid(pid)?
    } else if show_all {
        scanner.scan_all()?
    } else {
        scanner.scan_suspicious()?
    };

    let suspicious_count = results.iter().filter(|r| r.suspicious).count();

    match format {
        OutputFormat::Json => {
            let json_result = serde_json::json!({
                "total_connections": results.len(),
                "suspicious_count": suspicious_count,
                "connections": results.iter().map(|r| {
                    serde_json::json!({
                        "type": format!("{}", r.connection.conn_type),
                        "local_address": r.connection.local_addr.to_string(),
                        "local_port": r.connection.local_port,
                        "remote_address": r.connection.remote_addr.map(|a| a.to_string()),
                        "remote_port": r.connection.remote_port,
                        "state": format!("{}", r.connection.state),
                        "pid": r.connection.pid,
                        "process_name": r.connection.process_name.clone(),
                        "suspicious": r.suspicious,
                        "severity": r.severity,
                        "local_port_category": format!("{:?}", r.local_port_info.category),
                    })
                }).collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&json_result)?);
        }
        OutputFormat::Text => {
            if results.is_empty() {
                if show_all {
                    println!("No network connections found.");
                } else {
                    println!("No suspicious network connections found.");
                    println!();
                    println!("Use --all to show all connections.");
                }
                return Ok(());
            }

            let title = if show_all {
                "=== All Network Connections ==="
            } else {
                "=== Suspicious Network Connections ==="
            };

            println!();
            println!("{}", title);
            println!("Total: {} ({} suspicious)", results.len(), suspicious_count);
            println!();

            println!("{:<6} {:<22} {:<22} {:>12} {:>8}",
                "Proto", "Local Address", "Remote Address", "State", "PID");
            println!("{}", "-".repeat(78));

            for r in &results {
                let conn = &r.connection;
                let local = format!("{}:{}", conn.local_addr, conn.local_port);
                let remote = match (conn.remote_addr, conn.remote_port) {
                    (Some(addr), Some(port)) => format!("{}:{}", addr, port),
                    _ => "*:*".to_string(),
                };
                let proto = format!("{}", conn.conn_type);
                let state = format!("{}", conn.state);
                let pid_str = conn.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".to_string());

                let suspicious_marker = if r.suspicious { "[!]" } else { "" };
                println!("{:<6} {:<22} {:<22} {:>12} {:>8} {}",
                    proto, local, remote, state, pid_str, suspicious_marker);

                if let Some(ref name) = conn.process_name {
                    println!("       Process: {}", name);
                }

                if r.suspicious {
                    println!("       Port Category: {:?} (severity: {})",
                        r.local_port_info.category, r.severity);
                }
            }

            if suspicious_count > 0 {
                println!();
                println!("Warning: {} suspicious connection(s) detected!", suspicious_count);
                println!("Review connections on these ports carefully.");
            }
        }
    }

    Ok(())
}

/// Scan browser extensions and detect hijacks.
fn run_browser(
    show_all: bool,
    browser_filter: Option<BrowserFilter>,
    hijacks_only: bool,
    format: OutputFormat,
) -> Result<()> {
    log::info!("Scanning browser extensions and settings...");

    let scanner = BrowserScanner::new();

    // Convert CLI filter to scanner BrowserType filter and scan
    let result = match browser_filter {
        Some(BrowserFilter::Chrome) => scanner.scan_browser(BrowserType::Chrome)?,
        Some(BrowserFilter::Edge) => scanner.scan_browser(BrowserType::Edge)?,
        Some(BrowserFilter::Firefox) => scanner.scan_browser(BrowserType::Firefox)?,
        Some(BrowserFilter::Brave) => scanner.scan_browser(BrowserType::Brave)?,
        Some(BrowserFilter::Opera) => scanner.scan_browser(BrowserType::Opera)?,
        None => if show_all {
            scanner.scan_all()?
        } else {
            scanner.scan_suspicious()?
        },
    };

    match format {
        OutputFormat::Json => {
            let json_result = serde_json::json!({
                "risk_score": result.risk_score,
                "suspicious_extensions": result.suspicious_extensions,
                "hijack_count": result.hijack_count,
                "extensions": result.extensions.iter().map(|ext| {
                    serde_json::json!({
                        "id": ext.id,
                        "name": ext.name,
                        "version": ext.version,
                        "description": ext.description,
                        "browser": format!("{}", ext.browser),
                        "enabled": ext.enabled,
                        "risk": format!("{}", ext.risk),
                        "risk_reasons": ext.risk_reasons,
                        "permissions": ext.permissions.iter().map(|p| format!("{:?}", p)).collect::<Vec<_>>(),
                    })
                }).collect::<Vec<_>>(),
                "hijacks": result.hijacks.iter().map(|h| {
                    serde_json::json!({
                        "browser": format!("{}", h.browser),
                        "hijack_type": format!("{:?}", h.hijack_type),
                        "current_value": h.current_value,
                        "description": h.description,
                        "severity": h.severity,
                    })
                }).collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&json_result)?);
        }
        OutputFormat::Text => {
            // Show hijacks
            if !result.hijacks.is_empty() {
                println!();
                println!("=== Browser Hijacks Detected ===");
                println!("Total: {}", result.hijacks.len());
                println!();

                for hijack in &result.hijacks {
                    println!("[{:?}] {:?} - Severity: {}",
                        hijack.browser, hijack.hijack_type, hijack.severity);
                    println!("  Value: {}", hijack.current_value);
                    println!("  {}", hijack.description);
                    println!();
                }
            }

            if hijacks_only {
                if result.hijacks.is_empty() {
                    println!("No browser hijacks detected.");
                }
                return Ok(());
            }

            // Filter extensions
            let extensions: Vec<_> = if show_all {
                result.extensions
            } else {
                result
                    .extensions
                    .into_iter()
                    .filter(|ext| {
                        !matches!(ext.risk, pc_peroxide::scanner::ExtensionRisk::None)
                    })
                    .collect()
            };

            if extensions.is_empty() {
                if show_all {
                    println!("No browser extensions found.");
                } else {
                    println!("No suspicious browser extensions found.");
                    println!();
                    println!("Use --all to show all extensions.");
                }
            } else {
                let title = if show_all {
                    "=== All Browser Extensions ==="
                } else {
                    "=== Suspicious Browser Extensions ==="
                };

                println!();
                println!("{}", title);
                println!("Total: {} ({} suspicious)", extensions.len(), result.suspicious_extensions);
                println!();

                for ext in &extensions {
                    let risk_str = match ext.risk {
                        pc_peroxide::scanner::ExtensionRisk::None => "[OK]",
                        pc_peroxide::scanner::ExtensionRisk::Low => "[LOW]",
                        pc_peroxide::scanner::ExtensionRisk::Medium => "[MEDIUM]",
                        pc_peroxide::scanner::ExtensionRisk::High => "[HIGH]",
                        pc_peroxide::scanner::ExtensionRisk::Critical => "[CRITICAL]",
                    };

                    let status = if ext.enabled { "" } else { " (disabled)" };
                    println!("{} {:?} - {}{}", risk_str, ext.browser, ext.name, status);
                    println!("  ID:      {}", ext.id);
                    println!("  Version: {}", ext.version);

                    if let Some(ref desc_text) = ext.description {
                        // Truncate long descriptions
                        let desc = if desc_text.len() > 60 {
                            format!("{}...", &desc_text[..60])
                        } else {
                            desc_text.clone()
                        };
                        println!("  Desc:    {}", desc);
                    }

                    if !ext.risk_reasons.is_empty() {
                        for reason in &ext.risk_reasons {
                            println!("  Risk:    {}", reason);
                        }
                    }

                    if !ext.permissions.is_empty() {
                        let perms: Vec<String> = ext.permissions.iter().take(5).map(|p| format!("{:?}", p)).collect();
                        let more = if ext.permissions.len() > 5 {
                            format!(" (+{} more)", ext.permissions.len() - 5)
                        } else {
                            String::new()
                        };
                        println!("  Perms:   {}{}", perms.join(", "), more);
                    }

                    println!();
                }
            }

            // Summary
            if result.hijack_count > 0 || result.suspicious_extensions > 0 {
                println!("=== Summary ===");
                println!("Risk Score:            {}/100", result.risk_score);
                println!("Suspicious Extensions: {}", result.suspicious_extensions);
                println!("Browser Hijacks:       {}", result.hijack_count);
                println!();
                println!("Warning: Review suspicious items carefully before taking action.");
            }
        }
    }

    Ok(())
}
