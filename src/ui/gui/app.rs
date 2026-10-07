//! Main application struct for the GUI.

use eframe::egui::{self, CentralPanel, Context, SidePanel, TopBottomPanel};

use super::dashboard::DashboardView;
use super::quarantine_view::QuarantineView;
use super::results_view::ResultsView;
use super::scan_view::ScanView;
use super::settings_view::SettingsView;
use super::theme::Theme;
use super::updates::SignatureUpdater;
use super::View;
use crate::core::config::Config;
use crate::core::error::Error;
use crate::core::types::{Detection, DetectionMethod, ScanStatus, ScanSummary, ScanType, Severity};
use crate::quarantine::{QuarantineItem, QuarantineVault, WhitelistEntry, WhitelistManager};
use crate::scanner::{BackgroundScan, FileScanner, ScanRequest, ScanResultStore};
use crate::utils::hash::HashCalculator;
use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::Arc;
use std::time::Duration;

/// How often the UI refreshes while background work is running.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Scan state shown by the views.
#[derive(Clone)]
pub struct ScanState {
    /// Whether a scan is in progress
    pub is_scanning: bool,
    /// Whether cancellation has been requested for the running scan
    pub cancelling: bool,
    /// Scan progress (0.0 - 1.0), known once file discovery has finished
    pub progress: f32,
    /// Files scanned so far
    pub files_scanned: u64,
    /// Files to scan, once discovery has finished
    pub total_files: Option<u64>,
    /// Folders discovered so far
    pub directories_found: u64,
    /// File or folder currently being processed
    pub current_file: String,
    /// Scan type
    pub scan_type: ScanType,
    /// Status message
    pub status: String,
    /// Threats found so far by the running scan
    pub live_threats: Vec<Detection>,
    /// Threats found by the last completed scan (`last_scan`)
    pub threats_found: Vec<Detection>,
    /// Completed scan summary
    pub last_scan: Option<ScanSummary>,
}

impl Default for ScanState {
    fn default() -> Self {
        Self {
            is_scanning: false,
            cancelling: false,
            progress: 0.0,
            files_scanned: 0,
            total_files: None,
            directories_found: 0,
            current_file: String::new(),
            scan_type: ScanType::Quick,
            status: "Ready".to_string(),
            live_threats: Vec::new(),
            threats_found: Vec::new(),
            last_scan: None,
        }
    }
}

/// A message shown in the top bar.
struct Notice {
    text: String,
    is_error: bool,
}

/// A quarantine vault operation, run off the UI thread because encryption
/// and secure deletion can take seconds.
enum VaultOp {
    Quarantine(Detection),
    /// Whitelist a detected file (a false positive) without touching it
    Allow(Detection),
    /// Critical detections quarantined automatically after a scan
    AutoQuarantine(Vec<Detection>),
    /// Restore an item; `allow` also whitelists its hash so it is not
    /// flagged again
    Restore {
        id: String,
        allow: bool,
    },
    Delete(String),
    /// Delete these items (the ones the user confirmed)
    DeleteAll(Vec<String>),
}

/// Result of a [`VaultOp`].
struct VaultOpOutcome {
    message: String,
    is_error: bool,
    /// Paths that were moved into quarantine.
    quarantined: Vec<PathBuf>,
    /// Path that was whitelisted, if any.
    allowed: Option<PathBuf>,
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
    /// Scan state shown by the views
    scan_state: ScanState,
    /// Running scan, if any
    scan: Option<BackgroundScan>,
    /// Quarantined items, refreshed after every vault operation
    quarantine_items: Vec<QuarantineItem>,
    /// Error from the last attempt to read the quarantine vault
    quarantine_error: Option<String>,
    /// Running quarantine vault operation, if any
    vault_task: Option<Receiver<VaultOpOutcome>>,
    /// The window was asked to close while vault operations were pending
    close_when_idle: bool,
    /// Vault operations waiting for the running one to finish
    queued_vault_ops: VecDeque<VaultOp>,
    /// Detected files that are now in the vault (derived from the vault, so
    /// it survives restarts)
    quarantined_paths: HashSet<PathBuf>,
    /// Detected files whitelisted from the current results
    allowed_paths: HashSet<PathBuf>,
    /// Message shown in the top bar
    notice: Option<Notice>,
    /// Signature database status and import
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
}

impl PeroxideApp {
    /// Create a new application instance.
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let config = Arc::new(Config::load_or_default());
        let theme = Theme::default();

        // Apply theme
        theme.apply(&cc.egui_ctx);

        let last_scan = load_last_scan();
        let threats_found = last_scan
            .as_ref()
            .map(|s| s.detections.clone())
            .unwrap_or_default();

        let mut app = Self {
            view: View::Dashboard,
            theme: theme.clone(),
            dark_mode: true,
            config: config.clone(),
            scan_state: ScanState {
                threats_found,
                last_scan,
                ..ScanState::default()
            },
            scan: None,
            quarantine_items: Vec::new(),
            quarantine_error: None,
            vault_task: None,
            close_when_idle: false,
            queued_vault_ops: VecDeque::new(),
            quarantined_paths: HashSet::new(),
            allowed_paths: HashSet::new(),
            notice: None,
            updater: SignatureUpdater::new(),
            dashboard: DashboardView::new(theme.clone()),
            scan_view: ScanView::new(theme.clone()),
            results_view: ResultsView::new(theme.clone()),
            quarantine_view: QuarantineView::new(theme.clone()),
            settings_view: SettingsView::new(config, theme),
            show_about: false,
        };
        app.refresh_quarantine();
        app
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
                    (View::Updates, "Signatures", "Signature database"),
                ];

                for (view, label, tooltip) in nav_items {
                    let is_selected = self.view == view;
                    let button = egui::Button::new(egui::RichText::new(label).size(15.0).color(
                        if is_selected {
                            self.theme.primary
                        } else {
                            self.theme.text_primary
                        },
                    ))
                    .fill(if is_selected {
                        self.theme.primary.linear_multiply(0.15)
                    } else {
                        egui::Color32::TRANSPARENT
                    })
                    .min_size(egui::vec2(180.0, 36.0));

                    if ui.add(button).on_hover_text(tooltip).clicked() {
                        self.navigate(view);
                    }
                    ui.add_space(4.0);
                }

                // Bottom section
                ui.with_layout(egui::Layout::bottom_up(egui::Align::Center), |ui| {
                    ui.add_space(10.0);

                    // Version info
                    ui.label(self.theme.label(&format!("v{}", env!("CARGO_PKG_VERSION"))));

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
                        let theme = if self.dark_mode {
                            Theme::default()
                        } else {
                            Theme::light()
                        };
                        self.set_theme(ctx, theme);
                    }

                    ui.add_space(10.0);
                    ui.separator();
                });
            });
    }

    /// Apply a theme to the context and every view.
    fn set_theme(&mut self, ctx: &Context, theme: Theme) {
        theme.apply(ctx);
        self.dashboard.set_theme(theme.clone());
        self.scan_view.set_theme(theme.clone());
        self.results_view.set_theme(theme.clone());
        self.quarantine_view.set_theme(theme.clone());
        self.settings_view.set_theme(theme.clone());
        self.theme = theme;
    }

    /// Switch views, refreshing data the new view shows.
    fn navigate(&mut self, view: View) {
        if view != self.view {
            match view {
                View::Quarantine | View::Dashboard => self.refresh_quarantine(),
                View::Updates => self.updater.refresh(),
                _ => {}
            }
        }
        self.view = view;
    }

    /// Render the top bar with status.
    fn render_top_bar(&mut self, ctx: &Context) {
        TopBottomPanel::top("top_panel").show(ctx, |ui| {
            // Buttons are laid out first (right to left) so the status text
            // gets the remaining width and is elided instead of overlapping.
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button("About").clicked() {
                    self.show_about = true;
                }
                if self.notice.is_some() && ui.small_button("Dismiss").clicked() {
                    self.notice = None;
                }

                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    ui.add_space(10.0);

                    let status_color = match self.scan_state.last_scan {
                        _ if self.scan_state.is_scanning => self.theme.warning,
                        Some(ref s) if s.threats_found > 0 => self.theme.danger,
                        Some(ref s) if s.status == ScanStatus::Cancelled => self.theme.warning,
                        Some(_) => self.theme.success,
                        None => self.theme.text_secondary,
                    };

                    // Painted, because the default font has no "●" glyph
                    let (rect, _) =
                        ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
                    ui.painter().circle_filled(rect.center(), 5.0, status_color);
                    ui.label(&self.scan_state.status);

                    if self.vault_task.is_some() {
                        ui.separator();
                        ui.spinner();
                        ui.label("Working...");
                    }

                    if let Some(ref notice) = self.notice {
                        ui.separator();
                        let color = if notice.is_error {
                            self.theme.danger
                        } else {
                            self.theme.success
                        };
                        ui.add(
                            egui::Label::new(egui::RichText::new(&notice.text).color(color))
                                .truncate(true),
                        )
                        .on_hover_text(&notice.text);
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
                    if let Some(action) =
                        self.dashboard
                            .render(ui, &self.scan_state, self.quarantine_items.len())
                    {
                        match action {
                            DashboardAction::StartQuickScan => {
                                self.start_scan(ScanRequest::Quick);
                            }
                            DashboardAction::StartFullScan => {
                                self.start_scan(ScanRequest::Full);
                            }
                            DashboardAction::ViewResults => {
                                self.navigate(View::Results);
                            }
                            DashboardAction::ViewQuarantine => {
                                self.navigate(View::Quarantine);
                            }
                        }
                    }
                }
                View::Scan => {
                    if let Some(action) = self.scan_view.render(ui, &self.scan_state) {
                        match action {
                            ScanAction::Cancel => {
                                self.cancel_scan();
                            }
                            ScanAction::ViewResults => {
                                self.navigate(View::Results);
                            }
                            ScanAction::StartScan(request) => {
                                self.start_scan(request);
                            }
                        }
                    }
                }
                View::Results => {
                    if let Some(action) = self.results_view.render(
                        ui,
                        self.scan_state.last_scan.as_ref(),
                        &self.scan_state.threats_found,
                        &self.quarantined_paths,
                        &self.allowed_paths,
                        self.vault_task.is_some(),
                    ) {
                        match action {
                            ResultsAction::Quarantine(detection) => {
                                self.run_vault_op(VaultOp::Quarantine(detection));
                            }
                            ResultsAction::Allow(detection) => {
                                self.run_vault_op(VaultOp::Allow(detection));
                            }
                            ResultsAction::Export(format) => {
                                self.export_results(format);
                            }
                        }
                    }
                }
                View::Quarantine => {
                    if let Some(action) = self.quarantine_view.render(
                        ui,
                        &self.quarantine_items,
                        self.quarantine_error.as_deref(),
                        self.vault_task.is_some(),
                    ) {
                        match action {
                            QuarantineAction::Restore { id, allow } => {
                                self.run_vault_op(VaultOp::Restore { id, allow });
                            }
                            QuarantineAction::Delete(id) => {
                                self.run_vault_op(VaultOp::Delete(id));
                            }
                            QuarantineAction::DeleteAll(ids) => {
                                self.run_vault_op(VaultOp::DeleteAll(ids));
                            }
                            QuarantineAction::Refresh => {
                                self.refresh_quarantine();
                            }
                        }
                    }
                }
                View::Settings => {
                    if self.settings_view.render(ui) {
                        // Settings were saved - reload config for the next scan
                        self.config = Arc::new(Config::load_or_default());
                    }
                }
                View::Updates => {
                    self.updater.render(ui, &self.theme);
                }
            }
        });
    }

    /// Handle file drag and drop.
    fn handle_file_drop(&mut self, ctx: &Context) {
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .filter_map(|file| file.path.clone())
                .collect()
        });

        if !dropped.is_empty() {
            self.start_scan(ScanRequest::Custom(dropped));
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

    /// Start a scan in the background.
    fn start_scan(&mut self, request: ScanRequest) {
        if self.scan.is_some() {
            self.set_notice("A scan is already running", true);
            return;
        }
        if let ScanRequest::Custom(ref paths) = request {
            if paths.is_empty() {
                self.set_notice("Choose at least one file or folder to scan", true);
                return;
            }
        }

        let scan_type = request.scan_type();
        let config = Arc::clone(&self.config);
        self.scan = Some(BackgroundScan::spawn(
            request,
            move || FileScanner::new(config),
            |summary| match ScanResultStore::open_default() {
                Ok(store) => {
                    if let Err(e) = store.save_scan(summary) {
                        log::warn!("Failed to save scan results: {}", e);
                    }
                }
                Err(e) => log::warn!("Failed to open scan history: {}", e),
            },
        ));

        self.notice = None;
        // The previous results stay in place until the new scan succeeds.
        self.scan_state = ScanState {
            is_scanning: true,
            scan_type,
            status: format!("Starting {}...", scan_type),
            threats_found: std::mem::take(&mut self.scan_state.threats_found),
            last_scan: self.scan_state.last_scan.take(),
            ..ScanState::default()
        };
        self.view = View::Scan;
        log::info!("Started {}", scan_type);
    }

    /// Ask the running scan to stop.
    fn cancel_scan(&mut self) {
        if let Some(ref scan) = self.scan {
            scan.cancel();
            self.scan_state.cancelling = true;
            self.scan_state.status = "Cancelling scan...".to_string();
        }
    }

    /// Copy progress from the running scan and handle its completion.
    fn poll_scan(&mut self) {
        let Some(scan) = self.scan.as_mut() else {
            return;
        };

        let state = &mut self.scan_state;
        if let Some(progress) = scan.progress() {
            state.files_scanned = progress.files_scanned;
            state.total_files = progress.total_files;
            state.directories_found = progress.directories_scanned;
            state.current_file = progress
                .current_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            state.progress = progress
                .percentage()
                .map_or(0.0, |pct| (pct / 100.0) as f32);
            if !state.cancelling {
                state.status = match progress.total_files {
                    None => format!(
                        "Discovering files ({} folders)...",
                        progress.directories_scanned
                    ),
                    Some(total) => {
                        format!(
                            "Scanning {} of {} files...",
                            progress.files_processed(),
                            total
                        )
                    }
                };
            }
            if progress.threats_found as usize != state.live_threats.len() {
                state.live_threats = scan.detections();
            }
        }

        let Some(outcome) = scan.take_outcome() else {
            return;
        };
        self.scan = None;
        state.is_scanning = false;
        state.cancelling = false;
        state.current_file.clear();
        state.live_threats.clear();

        match outcome {
            Ok(summary) => {
                state.status = match summary.status {
                    ScanStatus::Cancelled => format!(
                        "Scan cancelled after {} ({} found)",
                        super::count(summary.files_scanned, "file", "files"),
                        super::count(summary.threats_found.into(), "threat", "threats")
                    ),
                    _ => format!(
                        "Scan complete: {} scanned, {} found",
                        super::count(summary.files_scanned, "file", "files"),
                        super::count(summary.threats_found.into(), "threat", "threats")
                    ),
                };
                log::info!("{}", state.status);
                state.threats_found = summary.detections.clone();
                self.allowed_paths.clear();
                self.quarantined_paths =
                    quarantined_among(&state.threats_found, &self.quarantine_items);
                // Only exact signature matches are certain enough to act on
                // unattended; pattern and heuristic matches are left for the
                // user. Skip files already quarantined during the scan.
                let critical: Vec<Detection> = summary
                    .detections
                    .iter()
                    .filter(|d| {
                        d.severity == Severity::Critical
                            && d.method == DetectionMethod::Signature
                            && !self.quarantined_paths.contains(&d.path)
                    })
                    .cloned()
                    .collect();
                state.last_scan = Some(summary);
                if !state.threats_found.is_empty() {
                    self.view = View::Results;
                }
                if self.config.actions.auto_quarantine_critical && !critical.is_empty() {
                    self.run_vault_op(VaultOp::AutoQuarantine(critical));
                }
            }
            Err(Error::ScanCancelled) => {
                state.status = "Scan cancelled".to_string();
            }
            Err(e) => {
                state.status = "Scan failed".to_string();
                log::error!("Scan failed: {}", e);
                self.set_notice(&format!("Scan failed: {}", e), true);
            }
        }
    }

    /// Run a quarantine vault operation on a worker thread, after any
    /// operation already running.
    fn run_vault_op(&mut self, op: VaultOp) {
        if self.vault_task.is_some() {
            self.queued_vault_ops.push_back(op);
            return;
        }

        let config = Arc::clone(&self.config);
        let (tx, rx) = mpsc::channel();
        let spawned = std::thread::Builder::new()
            .name("quarantine-op".to_string())
            .spawn(move || {
                let _ = tx.send(perform_vault_op(config, op));
            });
        match spawned {
            Ok(_) => self.vault_task = Some(rx),
            Err(e) => self.set_notice(&format!("Failed to start operation: {}", e), true),
        }
    }

    /// Handle completion of the running vault operation.
    fn poll_vault_task(&mut self) {
        let Some(ref rx) = self.vault_task else {
            return;
        };
        let outcome = match rx.try_recv() {
            Ok(outcome) => outcome,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => VaultOpOutcome {
                message: "Quarantine operation failed unexpectedly".to_string(),
                is_error: true,
                quarantined: Vec::new(),
                allowed: None,
            },
        };
        self.vault_task = None;

        self.quarantined_paths.extend(outcome.quarantined);
        self.allowed_paths.extend(outcome.allowed);
        if outcome.is_error {
            log::error!("{}", outcome.message);
        } else {
            log::info!("{}", outcome.message);
        }
        self.set_notice(&outcome.message, outcome.is_error);
        self.refresh_quarantine();

        if let Some(next) = self.queued_vault_ops.pop_front() {
            self.run_vault_op(next);
        }
    }

    /// Reload the list of quarantined items.
    fn refresh_quarantine(&mut self) {
        let vault_dir = self.config.quarantine.quarantine_dir();
        match QuarantineVault::open(&vault_dir).and_then(|vault| vault.list()) {
            Ok(items) => {
                self.quarantined_paths = quarantined_among(&self.scan_state.threats_found, &items);
                self.quarantine_items = items;
                self.quarantine_error = None;
            }
            Err(e) => {
                self.quarantine_items.clear();
                self.quarantine_error = Some(format!("Cannot open quarantine vault: {}", e));
            }
        }
    }

    /// Export scan results.
    fn export_results(&mut self, format: ExportFormat) {
        let Some(ref summary) = self.scan_state.last_scan else {
            return;
        };

        // Native save dialog (modal)
        let Some(path) = rfd::FileDialog::new()
            .set_title("Export Scan Results")
            .set_file_name(format!("pc-peroxide-scan.{}", format.extension()))
            .add_filter(format.extension(), &[format.extension()])
            .save_file()
        else {
            return;
        };

        let report_format = match format {
            ExportFormat::Html => crate::ui::report::ReportFormat::Html,
            ExportFormat::Csv => crate::ui::report::ReportFormat::Csv,
            ExportFormat::Pdf => crate::ui::report::ReportFormat::Pdf,
            ExportFormat::Json => crate::ui::report::ReportFormat::Json,
        };

        match crate::ui::report::generate_report(summary, report_format, &path) {
            Ok(()) => {
                log::info!("Exported report to: {:?}", path);
                self.set_notice(&format!("Report saved to {}", path.display()), false);
            }
            Err(e) => {
                log::error!("Failed to export report: {}", e);
                self.set_notice(&format!("Failed to export report: {}", e), true);
            }
        }
    }

    fn set_notice(&mut self, text: &str, is_error: bool) {
        self.notice = Some(Notice {
            text: text.to_string(),
            is_error,
        });
    }
}

impl eframe::App for PeroxideApp {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        self.poll_scan();
        self.poll_vault_task();
        self.updater.poll();

        self.render_sidebar(ctx);
        self.render_top_bar(ctx);
        self.render_content(ctx);
        self.render_about(ctx);

        // Don't let closing the window kill a quarantine, restore or delete
        // half-way; close once the queue has drained.
        let vault_busy = self.vault_task.is_some() || !self.queued_vault_ops.is_empty();
        if ctx.input(|i| i.viewport().close_requested()) && vault_busy {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.close_when_idle = true;
            self.set_notice("Finishing quarantine operations before closing...", false);
        }
        if self.close_when_idle && !vault_busy {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }

        // Keep polling background work without spinning the CPU
        if self.scan.is_some() || vault_busy || self.updater.is_busy() {
            ctx.request_repaint_after(POLL_INTERVAL);
        }
    }
}

/// Detected files that have been dealt with: the vault holds a file from
/// that path and it is gone from disk (a new file there is not handled).
/// Only the shown detections are checked, so the UI thread never probes
/// every vault item's path (a disconnected network drive would block).
fn quarantined_among(detections: &[Detection], items: &[QuarantineItem]) -> HashSet<PathBuf> {
    let vault_paths: HashSet<&PathBuf> = items.iter().map(|item| &item.original_path).collect();
    detections
        .iter()
        .map(|d| &d.path)
        .filter(|path| vault_paths.contains(path) && !path.exists())
        .cloned()
        .collect()
}

/// Load the most recent scan from history, with its detections.
fn load_last_scan() -> Option<ScanSummary> {
    let store = ScanResultStore::open_default().ok()?;
    let latest = store.get_recent_scans(1).ok()?.into_iter().next()?;
    store.load_scan(&latest.scan_id).ok().flatten()
}

/// Re-checks detections before anything is quarantined, so a file that was
/// replaced or whitelisted since the scan is never moved by mistake.
struct Rechecker {
    scanner: FileScanner,
    runtime: tokio::runtime::Runtime,
}

impl Rechecker {
    fn new(config: Arc<Config>) -> Result<Self, String> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .map_err(|e| format!("Cannot start re-check: {}", e))?;
        Ok(Self {
            scanner: FileScanner::new(config),
            runtime,
        })
    }

    /// Ok if the file still triggers the same detection.
    fn check(&self, detection: &Detection) -> Result<(), String> {
        match self
            .runtime
            .block_on(self.scanner.scan_file(&detection.path))
        {
            Ok(Some(current)) if current.threat_name == detection.threat_name => Ok(()),
            Ok(_) => Err(format!(
                "{} no longer matches {} (changed or whitelisted since the scan); not quarantined",
                detection.path.display(),
                detection.threat_name
            )),
            Err(e) => Err(format!(
                "Cannot re-check {}: {}",
                detection.path.display(),
                e
            )),
        }
    }
}

/// Move a detected file into the vault after re-checking it. A file that
/// was copied into the vault but could not be removed (e.g. locked by a
/// running process) counts as a failure: the threat is still on disk.
fn quarantine_detection(
    vault: &QuarantineVault,
    rechecker: &Rechecker,
    detection: &Detection,
) -> Result<(), String> {
    rechecker.check(detection)?;
    let result = vault.quarantine(
        &detection.path,
        &detection.threat_name,
        &detection.category.to_string(),
        detection.severity.score(),
        true,
    );
    if !result.success {
        return Err(format!(
            "Failed to quarantine {}: {}",
            detection.path.display(),
            result.error.unwrap_or_else(|| "unknown error".to_string())
        ));
    }
    match result.warning {
        Some(warning) => Err(format!(
            "{} was copied to quarantine but is still on disk: {}",
            detection.path.display(),
            warning
        )),
        None => Ok(()),
    }
}

/// Run a vault operation against the configured vault.
fn perform_vault_op(config: Arc<Config>, op: VaultOp) -> VaultOpOutcome {
    let fail = |message: String| VaultOpOutcome {
        message,
        is_error: true,
        quarantined: Vec::new(),
        allowed: None,
    };
    let done = |message: String| VaultOpOutcome {
        message,
        is_error: false,
        quarantined: Vec::new(),
        allowed: None,
    };

    // Whitelisting does not need the vault
    let op = match op {
        VaultOp::Allow(detection) => {
            return match HashCalculator::sha256_file(&detection.path)
                .and_then(|hash| allow_hash(&hash, "Allowed from scan results"))
            {
                Ok(()) => VaultOpOutcome {
                    message: format!(
                        "Allowed {}; it will not be reported again",
                        detection.path.display()
                    ),
                    is_error: false,
                    quarantined: Vec::new(),
                    allowed: Some(detection.path),
                },
                Err(e) => fail(format!(
                    "Failed to allow {}: {}",
                    detection.path.display(),
                    e
                )),
            };
        }
        other => other,
    };

    let vault = match QuarantineVault::open(&config.quarantine.quarantine_dir()) {
        Ok(vault) => vault,
        Err(e) => return fail(format!("Cannot open quarantine vault: {}", e)),
    };

    match op {
        VaultOp::Allow(_) => unreachable!("whitelisting is handled before the vault is opened"),
        VaultOp::Quarantine(detection) => {
            let rechecker = match Rechecker::new(Arc::clone(&config)) {
                Ok(rechecker) => rechecker,
                Err(message) => return fail(message),
            };
            match quarantine_detection(&vault, &rechecker, &detection) {
                Ok(()) => VaultOpOutcome {
                    message: format!("Quarantined {}", detection.path.display()),
                    is_error: false,
                    quarantined: vec![detection.path],
                    allowed: None,
                },
                Err(message) => fail(message),
            }
        }
        VaultOp::AutoQuarantine(detections) => {
            let rechecker = match Rechecker::new(Arc::clone(&config)) {
                Ok(rechecker) => rechecker,
                Err(message) => return fail(message),
            };
            let total = detections.len();
            let mut quarantined = Vec::new();
            let mut errors = Vec::new();
            for detection in detections {
                // Already moved (e.g. quarantined by hand meanwhile)
                if !detection.path.exists() {
                    continue;
                }
                match quarantine_detection(&vault, &rechecker, &detection) {
                    Ok(()) => quarantined.push(detection.path),
                    Err(message) => {
                        log::error!("{}", message);
                        errors.push(message);
                    }
                }
            }
            VaultOpOutcome {
                message: if errors.is_empty() {
                    format!(
                        "Automatically quarantined {} critical threat(s)",
                        quarantined.len()
                    )
                } else {
                    format!(
                        "Automatically quarantined {} of {} critical threat(s); {}",
                        quarantined.len(),
                        total,
                        errors.join("; ")
                    )
                },
                is_error: !errors.is_empty(),
                quarantined,
                allowed: None,
            }
        }
        VaultOp::Restore { id, allow } => {
            let hash = vault.get(&id).ok().flatten().map(|item| item.hash_sha256);
            let result = vault.restore(&id);
            if result.success {
                let restored = result.restored_path.display().to_string();
                match (allow, hash) {
                    (false, _) => done(format!("Restored {}", restored)),
                    (true, Some(hash)) => match allow_hash(&hash, "Restored from quarantine") {
                        Ok(()) => done(format!(
                            "Restored {} and added it to the whitelist",
                            restored
                        )),
                        Err(e) => fail(format!(
                            "Restored {} but could not whitelist it: {}",
                            restored, e
                        )),
                    },
                    (true, None) => fail(format!(
                        "Restored {} but could not whitelist it: hash unknown",
                        restored
                    )),
                }
            } else {
                fail(format!(
                    "Failed to restore: {}",
                    result.error.unwrap_or_else(|| "unknown error".to_string())
                ))
            }
        }
        VaultOp::Delete(id) => match vault.delete(&id) {
            Ok(()) => done("Deleted quarantined item".to_string()),
            Err(e) => fail(format!("Failed to delete quarantined item: {}", e)),
        },
        VaultOp::DeleteAll(ids) => {
            let total = ids.len();
            let failed = ids
                .iter()
                .filter(|id| match vault.delete(id) {
                    // Already gone, e.g. restored or deleted meanwhile
                    Ok(()) | Err(Error::QuarantineItemNotFound(_)) => false,
                    Err(e) => {
                        log::error!("Failed to delete quarantine item {}: {}", id, e);
                        true
                    }
                })
                .count();
            if failed == 0 {
                done(format!(
                    "Deleted {}",
                    super::count(total as u64, "quarantined item", "quarantined items")
                ))
            } else {
                fail(format!(
                    "Deleted {} of {} quarantined items; {} failed",
                    total - failed,
                    total,
                    failed
                ))
            }
        }
    }
}

/// Whitelist a file hash so the file is not flagged again.
fn allow_hash(hash: &str, reason: &str) -> crate::core::error::Result<()> {
    let whitelist = WhitelistManager::open(&WhitelistManager::default_path())?;
    if whitelist.is_hash_whitelisted(hash)? {
        return Ok(());
    }
    whitelist.add(&WhitelistEntry::by_hash(
        uuid::Uuid::new_v4().to_string(),
        hash.to_string(),
        reason.to_string(),
    ))
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
    StartScan(ScanRequest),
}

/// Actions from results view.
pub enum ResultsAction {
    Quarantine(Detection),
    Allow(Detection),
    Export(ExportFormat),
}

/// Actions from quarantine view.
pub enum QuarantineAction {
    Restore { id: String, allow: bool },
    Delete(String),
    DeleteAll(Vec<String>),
    Refresh,
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
