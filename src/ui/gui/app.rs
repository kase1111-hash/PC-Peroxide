//! Main application struct for the GUI.

#[cfg(feature = "gui")]
use eframe::egui::{self, CentralPanel, Context, SidePanel, TopBottomPanel};

use super::dashboard::DashboardView;
use super::quarantine_view::QuarantineView;
use super::results_view::ResultsView;
use super::scan_view::ScanView;
use super::settings_view::SettingsView;
use super::theme::Theme;
use super::updates::{SignatureUpdater, UpdateStatus};
use super::View;
use crate::config::Config;
use crate::core::types::{Detection, ScanSummary, ScanType};
use crate::quarantine::QuarantineVault;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Scan state for async scanning.
#[derive(Clone)]
pub struct ScanState {
    /// Whether a scan is in progress
    pub is_scanning: bool,
    /// Current scan progress (0.0 - 1.0)
    pub progress: f32,
    /// Files scanned so far
    pub files_scanned: u64,
    /// Current file being scanned
    pub current_file: String,
    /// Scan type
    pub scan_type: ScanType,
    /// Status message
    pub status: String,
    /// Threats found during scan
    pub threats_found: Vec<Detection>,
    /// Completed scan summary
    pub last_scan: Option<ScanSummary>,
}

impl Default for ScanState {
    fn default() -> Self {
        Self {
            is_scanning: false,
            progress: 0.0,
            files_scanned: 0,
            current_file: String::new(),
            scan_type: ScanType::Quick,
            status: "Ready".to_string(),
            threats_found: Vec::new(),
            last_scan: None,
        }
    }
}

/// Main application struct.
pub struct PeroxideApp {
    /// Current view
    view: View,
    /// Application theme
    theme: Theme,
    /// Use dark mode
    dark_mode: bool,
    /// Configuration
    config: Arc<Config>,
    /// Scan state
    scan_state: Arc<Mutex<ScanState>>,
    /// Quarantine vault
    quarantine: Option<QuarantineVault>,
    /// Signature updater
    updater: SignatureUpdater,
    /// Dashboard view state
    dashboard: DashboardView,
    /// Scan view state
    scan_view: ScanView,
    /// Results view state
    results_view: ResultsView,
    /// Quarantine view state
    quarantine_view: QuarantineView,
    /// Settings view state
    settings_view: SettingsView,
    /// Show about dialog
    show_about: bool,
    /// Custom scan paths (for drag & drop)
    custom_scan_paths: Vec<PathBuf>,
}

impl PeroxideApp {
    /// Create a new application instance.
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let config = Arc::new(Config::load_or_default());
        let scan_state = Arc::new(Mutex::new(ScanState::default()));
        let quarantine = QuarantineVault::new(None).ok();
        let theme = Theme::default();

        // Apply theme
        theme.apply(&cc.egui_ctx);

        Self {
            view: View::Dashboard,
            theme: theme.clone(),
            dark_mode: true,
            config: config.clone(),
            scan_state: scan_state.clone(),
            quarantine,
            updater: SignatureUpdater::new(),
            dashboard: DashboardView::new(theme.clone()),
            scan_view: ScanView::new(scan_state, theme.clone()),
            results_view: ResultsView::new(theme.clone()),
            quarantine_view: QuarantineView::new(theme.clone()),
            settings_view: SettingsView::new(config, theme.clone()),
            show_about: false,
            custom_scan_paths: Vec::new(),
        }
    }

    /// Render the navigation sidebar.
    fn render_sidebar(&mut self, ctx: &Context) {
        SidePanel::left("nav_panel")
            .resizable(false)
            .default_width(200.0)
            .show(ctx, |ui| {
                ui.add_space(20.0);

                // Logo/Title
                ui.vertical_centered(|ui| {
                    ui.label(self.theme.heading("PC-Peroxide"));
                    ui.label(self.theme.subheading("Malware Scanner"));
                });

                ui.add_space(30.0);
                ui.separator();
                ui.add_space(10.0);

                // Navigation buttons
                let nav_items = [
                    (View::Dashboard, "Dashboard", "Home view"),
                    (View::Scan, "Scan", "Start a scan"),
                    (View::Results, "Results", "View scan results"),
                    (View::Quarantine, "Quarantine", "Manage quarantined items"),
                    (View::Settings, "Settings", "Configure application"),
                    (View::Updates, "Updates", "Check for updates"),
                ];

                for (view, label, tooltip) in nav_items {
                    let is_selected = self.view == view;
                    let button = egui::Button::new(
                        egui::RichText::new(label)
                            .size(15.0)
                            .color(if is_selected {
                                self.theme.primary
                            } else {
                                self.theme.text_primary
                            }),
                    )
                    .fill(if is_selected {
                        self.theme.primary.linear_multiply(0.15)
                    } else {
                        egui::Color32::TRANSPARENT
                    })
                    .min_size(egui::vec2(180.0, 36.0));

                    if ui.add(button).on_hover_text(tooltip).clicked() {
                        self.view = view;
                    }
                    ui.add_space(4.0);
                }

                // Bottom section
                ui.with_layout(egui::Layout::bottom_up(egui::Align::Center), |ui| {
                    ui.add_space(10.0);

                    // Version info
                    ui.label(
                        self.theme
                            .label(&format!("v{}", env!("CARGO_PKG_VERSION"))),
                    );

                    ui.add_space(5.0);

                    // Theme toggle
                    if ui
                        .selectable_label(
                            !self.dark_mode,
                            egui::RichText::new(if self.dark_mode {
                                "Switch to Light"
                            } else {
                                "Switch to Dark"
                            })
                            .size(12.0),
                        )
                        .clicked()
                    {
                        self.dark_mode = !self.dark_mode;
                        self.theme = if self.dark_mode {
                            Theme::default()
                        } else {
                            Theme::light()
                        };
                        self.theme.apply(ctx);
                    }

                    ui.add_space(10.0);
                    ui.separator();
                });
            });
    }

    /// Render the top bar with status.
    fn render_top_bar(&mut self, ctx: &Context) {
        TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.add_space(10.0);

                // Scan status indicator - use unwrap_or_else to recover from poisoned mutex
                let scan_state = self.scan_state.lock().unwrap_or_else(|e| e.into_inner());
                let status_color = if scan_state.is_scanning {
                    self.theme.warning
                } else if scan_state
                    .last_scan
                    .as_ref()
                    .map(|s| s.threats_found > 0)
                    .unwrap_or(false)
                {
                    self.theme.danger
                } else {
                    self.theme.success
                };

                ui.colored_label(status_color, "●");
                ui.label(&scan_state.status);

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // About button
                    if ui.small_button("About").clicked() {
                        self.show_about = true;
                    }

                    ui.separator();

                    // Update status
                    match self.updater.status() {
                        UpdateStatus::Checking => {
                            ui.spinner();
                            ui.label("Checking updates...");
                        }
                        UpdateStatus::Available { version } => {
                            ui.colored_label(
                                self.theme.warning,
                                format!("Update available: {}", version),
                            );
                        }
                        UpdateStatus::UpToDate => {
                            ui.colored_label(self.theme.success, "Up to date");
                        }
                        UpdateStatus::Error(msg) => {
                            ui.colored_label(self.theme.danger, format!("Update error: {}", msg));
                        }
                        UpdateStatus::Idle => {}
                    }
                });
            });
        });
    }

    /// Render the main content area.
    fn render_content(&mut self, ctx: &Context) {
        CentralPanel::default().show(ctx, |ui| {
            // Handle file drops
            self.handle_file_drop(ctx);

            match self.view {
                View::Dashboard => {
                    let scan_state = self.scan_state.lock().unwrap_or_else(|e| e.into_inner()).clone();
                    let quarantine_count = self
                        .quarantine
                        .as_ref()
                        .and_then(|q| q.list().ok())
                        .map(|l| l.len())
                        .unwrap_or(0);

                    if let Some(action) = self.dashboard.render(ui, &scan_state, quarantine_count) {
                        match action {
                            DashboardAction::StartQuickScan => {
                                self.start_scan(ScanType::Quick, Vec::new());
                                self.view = View::Scan;
                            }
                            DashboardAction::StartFullScan => {
                                self.start_scan(ScanType::Full, Vec::new());
                                self.view = View::Scan;
                            }
                            DashboardAction::ViewResults => {
                                self.view = View::Results;
                            }
                            DashboardAction::ViewQuarantine => {
                                self.view = View::Quarantine;
                            }
                        }
                    }
                }
                View::Scan => {
                    if let Some(action) = self.scan_view.render(ui) {
                        match action {
                            ScanAction::Cancel => {
                                self.cancel_scan();
                            }
                            ScanAction::ViewResults => {
                                self.view = View::Results;
                            }
                            ScanAction::StartScan(scan_type, paths) => {
                                self.start_scan(scan_type, paths);
                            }
                        }
                    }
                }
                View::Results => {
                    let scan_state = self.scan_state.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(action) =
                        self.results_view
                            .render(ui, scan_state.last_scan.as_ref(), &scan_state.threats_found)
                    {
                        drop(scan_state);
                        match action {
                            ResultsAction::Quarantine(path) => {
                                self.quarantine_file(&path);
                            }
                            ResultsAction::Export(format) => {
                                self.export_results(format);
                            }
                        }
                    }
                }
                View::Quarantine => {
                    let items = self
                        .quarantine
                        .as_ref()
                        .and_then(|q| q.list().ok())
                        .unwrap_or_default();

                    if let Some(action) = self.quarantine_view.render(ui, &items) {
                        match action {
                            QuarantineAction::Restore(id) => {
                                self.restore_quarantined(&id);
                            }
                            QuarantineAction::Delete(id) => {
                                self.delete_quarantined(&id);
                            }
                            QuarantineAction::DeleteAll => {
                                self.clear_quarantine();
                            }
                        }
                    }
                }
                View::Settings => {
                    if self.settings_view.render(ui) {
                        // Settings were saved - reload config
                        self.config = Arc::new(Config::load_or_default());
                    }
                }
                View::Updates => {
                    self.render_updates_view(ui);
                }
            }
        });
    }

    /// Handle file drag and drop.
    fn handle_file_drop(&mut self, ctx: &Context) {
        // Check for dropped files
        ctx.input(|i| {
            if !i.raw.dropped_files.is_empty() {
                self.custom_scan_paths.clear();
                for file in &i.raw.dropped_files {
                    if let Some(path) = &file.path {
                        self.custom_scan_paths.push(path.clone());
                    }
                }

                if !self.custom_scan_paths.is_empty() {
                    self.start_scan(ScanType::Custom, self.custom_scan_paths.clone());
                    self.view = View::Scan;
                }
            }
        });
    }

    /// Render updates view.
    fn render_updates_view(&mut self, ui: &mut egui::Ui) {
        ui.heading("Signature Updates");
        ui.add_space(20.0);

        ui.horizontal(|ui| {
            if ui.button("Check for Updates").clicked() {
                self.updater.check_for_updates();
            }

            ui.add_space(10.0);

            match self.updater.status() {
                UpdateStatus::Available { version } => {
                    if ui.button(format!("Download {}", version)).clicked() {
                        self.updater.download_update();
                    }
                }
                _ => {}
            }
        });

        ui.add_space(20.0);

        // Show current signature info
        ui.group(|ui| {
            ui.label(self.theme.subheading("Current Signatures"));
            ui.add_space(10.0);

            ui.horizontal(|ui| {
                ui.label("Version:");
                ui.label(self.updater.current_version());
            });

            ui.horizontal(|ui| {
                ui.label("Last Updated:");
                ui.label(self.updater.last_updated());
            });

            ui.horizontal(|ui| {
                ui.label("Signature Count:");
                ui.label(format!("{}", self.updater.signature_count()));
            });
        });

        // Update progress
        if let UpdateStatus::Downloading { progress } = self.updater.status() {
            ui.add_space(20.0);
            ui.add(egui::ProgressBar::new(progress).text("Downloading..."));
        }
    }

    /// Render about dialog.
    fn render_about(&mut self, ctx: &Context) {
        if self.show_about {
            egui::Window::new("About PC-Peroxide")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(10.0);
                        ui.label(self.theme.heading("PC-Peroxide"));
                        ui.label(
                            self.theme
                                .subheading("Lightweight Malware Detection & Removal"),
                        );
                        ui.add_space(10.0);

                        ui.label(format!("Version: {}", env!("CARGO_PKG_VERSION")));
                        ui.add_space(5.0);

                        ui.label("A fast, portable malware scanner for Windows systems.");
                        ui.add_space(10.0);

                        ui.hyperlink_to("GitHub Repository", env!("CARGO_PKG_REPOSITORY"));
                        ui.add_space(10.0);

                        if ui.button("Close").clicked() {
                            self.show_about = false;
                        }
                    });
                });
        }
    }

    /// Start a scan with the given type and paths.
    fn start_scan(&self, scan_type: ScanType, paths: Vec<PathBuf>) {
        let mut state = self.scan_state.lock().unwrap_or_else(|e| e.into_inner());
        state.is_scanning = true;
        state.progress = 0.0;
        state.files_scanned = 0;
        state.current_file = String::new();
        state.scan_type = scan_type;
        state.status = format!("Starting {:?} scan...", scan_type);
        state.threats_found.clear();

        // Note: Actual scanning would be done in a background thread
        // This is a placeholder for the UI state management
        drop(state);

        // TODO: Spawn actual scan task
        log::info!("Starting {:?} scan with {} custom paths", scan_type, paths.len());
    }

    /// Cancel the current scan.
    fn cancel_scan(&self) {
        let mut state = self.scan_state.lock().unwrap_or_else(|e| e.into_inner());
        state.is_scanning = false;
        state.status = "Scan cancelled".to_string();
    }

    /// Quarantine a file.
    fn quarantine_file(&mut self, path: &PathBuf) {
        if let Some(ref mut vault) = self.quarantine {
            match vault.quarantine_file(path, "GUI quarantine action", None) {
                Ok(_) => {
                    log::info!("Quarantined file: {:?}", path);
                }
                Err(e) => {
                    log::error!("Failed to quarantine file: {}", e);
                }
            }
        }
    }

    /// Restore a quarantined file.
    fn restore_quarantined(&mut self, id: &str) {
        if let Some(ref mut vault) = self.quarantine {
            match vault.restore(id, None) {
                Ok(path) => {
                    log::info!("Restored file to: {:?}", path);
                }
                Err(e) => {
                    log::error!("Failed to restore file: {}", e);
                }
            }
        }
    }

    /// Delete a quarantined file.
    fn delete_quarantined(&mut self, id: &str) {
        if let Some(ref mut vault) = self.quarantine {
            match vault.delete(id) {
                Ok(_) => {
                    log::info!("Deleted quarantined file: {}", id);
                }
                Err(e) => {
                    log::error!("Failed to delete file: {}", e);
                }
            }
        }
    }

    /// Clear all quarantined files.
    fn clear_quarantine(&mut self) {
        if let Some(ref mut vault) = self.quarantine {
            match vault.clear() {
                Ok(count) => {
                    log::info!("Cleared {} quarantined files", count);
                }
                Err(e) => {
                    log::error!("Failed to clear quarantine: {}", e);
                }
            }
        }
    }

    /// Export scan results.
    fn export_results(&self, format: ExportFormat) {
        let state = self.scan_state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ref summary) = state.last_scan {
            // Open file dialog
            if let Some(path) = rfd::FileDialog::new()
                .set_title("Export Scan Results")
                .add_filter(
                    format.extension(),
                    &[format.extension()],
                )
                .save_file()
            {
                let report_format = match format {
                    ExportFormat::Html => crate::ui::report::ReportFormat::Html,
                    ExportFormat::Csv => crate::ui::report::ReportFormat::Csv,
                    ExportFormat::Pdf => crate::ui::report::ReportFormat::Pdf,
                    ExportFormat::Json => crate::ui::report::ReportFormat::Json,
                };

                if let Err(e) = crate::ui::report::generate_report(summary, report_format, &path) {
                    log::error!("Failed to export report: {}", e);
                } else {
                    log::info!("Exported report to: {:?}", path);
                }
            }
        }
    }
}

impl eframe::App for PeroxideApp {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        self.render_sidebar(ctx);
        self.render_top_bar(ctx);
        self.render_content(ctx);
        self.render_about(ctx);

        // Request repaint if scanning - use unwrap_or_else to recover from poisoned mutex
        if self.scan_state.lock().unwrap_or_else(|e| e.into_inner()).is_scanning {
            ctx.request_repaint();
        }
    }
}

/// Actions from dashboard.
pub enum DashboardAction {
    StartQuickScan,
    StartFullScan,
    ViewResults,
    ViewQuarantine,
}

/// Actions from scan view.
pub enum ScanAction {
    Cancel,
    ViewResults,
    StartScan(ScanType, Vec<PathBuf>),
}

/// Actions from results view.
pub enum ResultsAction {
    Quarantine(PathBuf),
    Export(ExportFormat),
}

/// Actions from quarantine view.
pub enum QuarantineAction {
    Restore(String),
    Delete(String),
    DeleteAll,
}

/// Export formats.
#[derive(Clone, Copy)]
pub enum ExportFormat {
    Html,
    Csv,
    Pdf,
    Json,
}

impl ExportFormat {
    /// Get file extension.
    pub fn extension(&self) -> &'static str {
        match self {
            Self::Html => "html",
            Self::Csv => "csv",
            Self::Pdf => "pdf",
            Self::Json => "json",
        }
    }
}
