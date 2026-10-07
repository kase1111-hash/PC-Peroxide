//! GUI entry point for PC-Peroxide.
//!
//! This binary provides a graphical user interface for the malware scanner.
//! Compile with `cargo build --features gui --bin pc-peroxide-gui`

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(feature = "gui")]
fn main() -> Result<(), eframe::Error> {
    // Log to the console and to a file at the configured level; release
    // builds on Windows have no console, so the file is the only record.
    let config = pc_peroxide::core::config::Config::load_or_default();
    let log_config = pc_peroxide::utils::logging::LogConfig::from_config(&config);
    if let Err(e) = pc_peroxide::utils::logging::init_logging(log_config) {
        eprintln!("Failed to set up logging: {}", e);
    }

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

    // Run the application
    eframe::run_native(
        "PC-Peroxide",
        options,
        Box::new(|cc| Box::new(pc_peroxide::ui::gui::PeroxideApp::new(cc))),
    )
}

#[cfg(not(feature = "gui"))]
fn main() {
    eprintln!("Error: GUI feature not enabled.");
    eprintln!("Rebuild with: cargo build --features gui --bin pc-peroxide-gui");
    std::process::exit(1);
}
