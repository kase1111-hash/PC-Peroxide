//! Theme and styling for the GUI.

#[cfg(feature = "gui")]
use eframe::egui::{self, Color32, FontFamily, FontId, RichText, Rounding, Stroke, TextStyle};

/// Application theme colors and settings.
#[derive(Clone)]
pub struct Theme {
    /// Primary brand color
    pub primary: Color32,
    /// Success/clean color
    pub success: Color32,
    /// Warning color
    pub warning: Color32,
    /// Danger/error color
    pub danger: Color32,
    /// Background color
    pub background: Color32,
    /// Surface/card color
    pub surface: Color32,
    /// Text primary color
    pub text_primary: Color32,
    /// Text secondary color
    pub text_secondary: Color32,
    /// Border color
    pub border: Color32,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            primary: Color32::from_rgb(102, 126, 234),     // Purple-blue
            success: Color32::from_rgb(72, 187, 120),      // Green
            warning: Color32::from_rgb(237, 137, 54),      // Orange
            danger: Color32::from_rgb(245, 101, 101),      // Red
            background: Color32::from_rgb(26, 32, 44),     // Dark blue-gray
            surface: Color32::from_rgb(45, 55, 72),        // Lighter dark
            text_primary: Color32::from_rgb(237, 242, 247), // Almost white
            text_secondary: Color32::from_rgb(160, 174, 192), // Gray
            border: Color32::from_rgb(74, 85, 104),        // Border gray
        }
    }
}

impl Theme {
    /// Create a light theme.
    pub fn light() -> Self {
        Self {
            primary: Color32::from_rgb(102, 126, 234),
            success: Color32::from_rgb(56, 161, 105),
            warning: Color32::from_rgb(221, 107, 32),
            danger: Color32::from_rgb(229, 62, 62),
            background: Color32::from_rgb(247, 250, 252),
            surface: Color32::WHITE,
            text_primary: Color32::from_rgb(26, 32, 44),
            text_secondary: Color32::from_rgb(113, 128, 150),
            border: Color32::from_rgb(226, 232, 240),
        }
    }

    /// Apply theme to egui context.
    pub fn apply(&self, ctx: &egui::Context) {
        let mut style = (*ctx.style()).clone();

        // Set visuals
        let visuals = &mut style.visuals;
        visuals.dark_mode = self.background.r() < 128;
        visuals.override_text_color = Some(self.text_primary);
        visuals.widgets.noninteractive.bg_fill = self.surface;
        visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, self.border);
        visuals.widgets.inactive.bg_fill = self.surface;
        visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, self.border);
        visuals.widgets.hovered.bg_fill = self.primary.linear_multiply(0.2);
        visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, self.primary);
        visuals.widgets.active.bg_fill = self.primary;
        visuals.widgets.active.bg_stroke = Stroke::new(1.0, self.primary);
        visuals.selection.bg_fill = self.primary.linear_multiply(0.4);
        visuals.selection.stroke = Stroke::new(1.0, self.primary);
        visuals.window_fill = self.surface;
        visuals.window_stroke = Stroke::new(1.0, self.border);
        visuals.panel_fill = self.background;
        visuals.window_rounding = Rounding::same(8.0);
        visuals.menu_rounding = Rounding::same(4.0);

        // Set text styles
        style.text_styles = [
            (TextStyle::Small, FontId::new(12.0, FontFamily::Proportional)),
            (TextStyle::Body, FontId::new(14.0, FontFamily::Proportional)),
            (TextStyle::Button, FontId::new(14.0, FontFamily::Proportional)),
            (TextStyle::Heading, FontId::new(20.0, FontFamily::Proportional)),
            (TextStyle::Monospace, FontId::new(13.0, FontFamily::Monospace)),
        ]
        .into();

        ctx.set_style(style);
    }

    /// Create styled heading text.
    pub fn heading(&self, text: &str) -> RichText {
        RichText::new(text)
            .size(24.0)
            .color(self.text_primary)
            .strong()
    }

    /// Create styled subheading text.
    pub fn subheading(&self, text: &str) -> RichText {
        RichText::new(text)
            .size(16.0)
            .color(self.text_secondary)
    }

    /// Create styled label text.
    pub fn label(&self, text: &str) -> RichText {
        RichText::new(text)
            .size(12.0)
            .color(self.text_secondary)
    }

    /// Create styled value text.
    pub fn value(&self, text: &str) -> RichText {
        RichText::new(text)
            .size(18.0)
            .color(self.text_primary)
            .strong()
    }

    /// Create styled large value text.
    pub fn large_value(&self, text: &str) -> RichText {
        RichText::new(text)
            .size(32.0)
            .color(self.text_primary)
            .strong()
    }

    /// Create status text with appropriate color.
    pub fn status_text(&self, text: &str, is_clean: bool) -> RichText {
        let color = if is_clean { self.success } else { self.danger };
        RichText::new(text).size(16.0).color(color).strong()
    }

    /// Get severity color.
    pub fn severity_color(&self, severity: &str) -> Color32 {
        match severity.to_lowercase().as_str() {
            "critical" => self.danger,
            "high" => Color32::from_rgb(237, 137, 54), // Orange
            "medium" => Color32::from_rgb(236, 201, 75), // Yellow
            "low" => self.success,
            _ => self.text_secondary,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_theme_creation() {
        let theme = Theme::default();
        assert!(theme.background.r() < 128); // Dark theme
    }

    #[test]
    fn test_light_theme() {
        let theme = Theme::light();
        assert!(theme.background.r() >= 128); // Light theme
    }

    #[test]
    fn test_severity_colors() {
        let theme = Theme::default();
        assert_eq!(theme.severity_color("critical"), theme.danger);
        assert_eq!(theme.severity_color("low"), theme.success);
    }
}
