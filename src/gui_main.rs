//! GUI entry point for PC-Peroxide.
//!
//! This binary provides a graphical user interface for the malware scanner.
//! Compile with `cargo build --features gui --bin pc-peroxide-gui`

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(feature = "gui")]
fn main() -> Result<(), eframe::Error> {
    use pc_peroxide::core::config::Config;

    // Log to the console and to a file at the configured level; release
    // builds on Windows have no console, so the file is the only record.
    let config_path = Config::default_config_path();
    let config_error = config_path
        .exists()
        .then(|| Config::load(&config_path).err())
        .flatten();
    let config = Config::load_or_default();
    let log_config = pc_peroxide::utils::logging::LogConfig::from_config(&config);
    let log_file = log_config.file_path.clone();
    if let Err(e) = pc_peroxide::utils::logging::init_logging(log_config) {
        eprintln!("Failed to set up logging: {}", e);
    }
    if let Some(e) = config_error {
        log::warn!(
            "Config file {} could not be read ({}); using defaults",
            config_path.display(),
            e
        );
    }

    // Record panics in the log file too; without a console they would
    // otherwise leave no trace.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        log::error!("Panic: {}", info);
        default_hook(info);
    }));

    log::info!("Starting PC-Peroxide GUI v{}", env!("CARGO_PKG_VERSION"));

    // Configure window options
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("PC-Peroxide - Malware Scanner")
            .with_inner_size([1200.0, 800.0])
            .with_min_inner_size([800.0, 600.0])
            .with_drag_and_drop(true),
        default_theme: eframe::Theme::Dark,
        follow_system_theme: false,
        centered: true,
        ..Default::default()
    };

    // Run the application. Start-up failures (e.g. no OpenGL 2 in a VM or
    // remote session) can be errors or panics; either way say so, as there
    // is no console to show it.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        eframe::run_native(
            "PC-Peroxide",
            options,
            Box::new(|cc| Box::new(pc_peroxide::ui::gui::PeroxideApp::new(cc))),
        )
    }));

    let failure = match result {
        Ok(Ok(())) => return Ok(()),
        Ok(Err(ref e)) => e.to_string(),
        Err(_) => "the program stopped unexpectedly".to_string(),
    };
    log::error!("Failed to run the GUI: {}", failure);
    // Release builds on Windows have no console, so show a message box.
    // (Elsewhere the error is on stderr; a GTK dialog without a display
    // would hang.)
    #[cfg(windows)]
    {
        let log_hint = log_file
            .map(|p| format!("\n\nDetails are in the log file: {}", p.display()))
            .unwrap_or_default();
        rfd::MessageDialog::new()
            .set_level(rfd::MessageLevel::Error)
            .set_title("PC-Peroxide")
            .set_description(format!(
                "PC-Peroxide could not run: {}.{}\n\nThe command-line scanner (pc-peroxide) still works.",
                failure, log_hint
            ))
            .show();
    }
    #[cfg(not(windows))]
    let _ = log_file;

    match result {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[cfg(not(feature = "gui"))]
fn main() {
    eprintln!("Error: GUI feature not enabled.");
    eprintln!("Rebuild with: cargo build --features gui --bin pc-peroxide-gui");
    std::process::exit(1);
}
