//! GUI entry point for PC-Peroxide.
//!
//! This binary provides a graphical user interface for the malware scanner.
//! Compile with `cargo build --features gui --bin pc-peroxide-gui`

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(feature = "gui")]
fn main() -> Result<(), eframe::Error> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp(Some(env_logger::fmt::TimestampPrecision::Millis))
        .init();

    log::info!("Starting PC-Peroxide GUI v{}", env!("CARGO_PKG_VERSION"));

    // Configure window options
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
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
        Box::new(|cc| Ok(Box::new(pc_peroxide::ui::gui::PeroxideApp::new(cc)))),
    )
}

#[cfg(not(feature = "gui"))]
fn main() {
    eprintln!("Error: GUI feature not enabled.");
    eprintln!("Rebuild with: cargo build --features gui --bin pc-peroxide-gui");
    std::process::exit(1);
}
