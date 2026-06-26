//! Semantic color palettes that adapt to the detected [`ColorDepth`].
//!
//! The palette maps *roles* (accent, success, error, …) to concrete
//! `crossterm::style::Color` values appropriate for each tier.  The caller
//! never hardcodes ANSI escape sequences; it just asks for a role color and
//! lets the palette decide the best representation.

use crossterm::style::Color;
use super::capability::ColorDepth;
use crate::persistence::{ChatTheme, ThemeColor};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Semantic color roles used throughout the UI.
#[derive(Debug, Clone)]
pub struct ColorPalette {
    pub background:  Color,
    pub foreground:  Color,
    pub accent:      Color,
    pub success:     Color,
    pub warning:     Color,
    pub error:       Color,
    pub dim:         Color,
    pub highlight:   Color,
    pub border:      Color,
    /// Rotating per-peer attribution colors — index with `peer_color(n)`.
    pub peer_colors: Vec<Color>,
    // Chat message colors — overridden by ChatTheme when one is active.
    pub chat_timestamp:  Color,
    pub chat_own_id:     Color,
    pub chat_own_text:   Color,
    /// Fixed color for peer sender labels, or `Color::Reset` to use rotation.
    pub chat_peer_id:    Color,
    pub chat_peer_text:  Color,
    /// Background behind message rows; `Color::Reset` = terminal default.
    pub chat_background: Color,
    /// Color for system / status lines.
    pub chat_system:     Color,
}

impl ColorPalette {
    /// Select the richest palette that fits `depth`.
    pub fn for_depth(depth: ColorDepth) -> Self {
        match depth {
            ColorDepth::Monochrome => Self::monochrome(),
            ColorDepth::Ansi16    => Self::ansi16(),
            ColorDepth::Ansi256   => Self::ansi256(),
            ColorDepth::TrueColor => Self::truecolor(),
        }
    }

    /// Return a peer color, wrapping around if `index` exceeds the list.
    pub fn peer_color(&self, index: usize) -> Color {
        self.peer_colors[index % self.peer_colors.len()]
    }

    // -----------------------------------------------------------------------
    // Tier implementations
    // -----------------------------------------------------------------------

    /// Override chat colors and optionally border from a persisted `ChatTheme`.
    pub fn apply_chat_theme(&mut self, theme: &ChatTheme, depth: ColorDepth) {
        self.chat_timestamp  = tc_to_color(theme.timestamp,  depth);
        self.chat_own_id     = tc_to_color(theme.own_id,     depth);
        self.chat_own_text   = tc_to_color(theme.own_text,   depth);
        self.chat_peer_id    = tc_to_color(theme.peer_id,    depth); // Reset = use rotation
        self.chat_peer_text  = tc_to_color(theme.peer_text,   depth);
        self.chat_background = tc_to_color(theme.background,  depth); // Reset = transparent
        self.chat_system     = tc_to_color(theme.system_text, depth);
        if theme.border != ThemeColor::Default {
            self.border = tc_to_color(theme.border, depth);
        }
    }

    fn monochrome() -> Self {
        // No ANSI colors — use Color::Reset everywhere.
        // The renderer uses Attribute::Bold / Underlined for emphasis.
        Self {
            background:  Color::Reset,
            foreground:  Color::Reset,
            accent:      Color::Reset,
            success:     Color::Reset,
            warning:     Color::Reset,
            error:       Color::Reset,
            dim:         Color::Reset,
            highlight:   Color::Reset,
            border:      Color::Reset,
            peer_colors:     vec![Color::Reset],
            chat_timestamp:  Color::Reset,
            chat_own_id:     Color::Reset,
            chat_own_text:   Color::Reset,
            chat_peer_id:    Color::Reset,
            chat_peer_text:  Color::Reset,
            chat_background: Color::Reset,
            chat_system:     Color::Reset,
        }
    }

    fn ansi16() -> Self {
        Self {
            background:  Color::Reset,
            foreground:  Color::White,
            accent:      Color::Cyan,
            success:     Color::Green,
            warning:     Color::Yellow,
            error:       Color::Red,
            dim:         Color::DarkGrey,
            highlight:   Color::White,
            border:      Color::DarkCyan,
            peer_colors: vec![
                Color::Green, Color::Yellow, Color::Cyan,
                Color::Magenta, Color::Blue, Color::Red,
                Color::White, Color::DarkGreen,
            ],
            chat_timestamp:  Color::White,
            chat_own_id:     Color::Cyan,
            chat_own_text:   Color::White,
            chat_peer_id:    Color::Reset,
            chat_peer_text:  Color::White,
            chat_background: Color::Reset,
            chat_system:     Color::DarkGrey,
        }
    }

    fn ansi256() -> Self {
        // Use the 256-color palette for richer but still universally
        // supported values.  Index 0-15 are the same as the 16-color names;
        // 16-231 are the 6×6×6 color cube; 232-255 are the greyscale ramp.
        Self {
            background:  Color::AnsiValue(235), // dark grey
            foreground:  Color::AnsiValue(252), // near-white
            accent:      Color::AnsiValue(51),  // bright cyan
            success:     Color::AnsiValue(82),  // bright green
            warning:     Color::AnsiValue(220), // amber
            error:       Color::AnsiValue(196), // bright red
            dim:         Color::AnsiValue(240), // mid-grey
            highlight:   Color::AnsiValue(255), // white
            border:      Color::AnsiValue(24),  // teal
            peer_colors: vec![
                Color::AnsiValue(82),  // green
                Color::AnsiValue(214), // orange
                Color::AnsiValue(51),  // cyan
                Color::AnsiValue(207), // pink
                Color::AnsiValue(99),  // purple
                Color::AnsiValue(226), // yellow
                Color::AnsiValue(39),  // sky blue
                Color::AnsiValue(196), // red
            ],
            chat_timestamp:  Color::AnsiValue(255), // white
            chat_own_id:     Color::AnsiValue(51),  // bright cyan
            chat_own_text:   Color::AnsiValue(255), // white
            chat_peer_id:    Color::Reset,           // use rotation
            chat_peer_text:  Color::AnsiValue(255), // white
            chat_background: Color::Reset,           // transparent
            chat_system:     Color::AnsiValue(240), // mid-grey
        }
    }

    fn truecolor() -> Self {
        // Full 24-bit RGB.
        Self {
            background:  Color::Rgb { r: 18,  g: 18,  b: 24  }, // near-black
            foreground:  Color::Rgb { r: 220, g: 220, b: 230 }, // off-white
            accent:      Color::Rgb { r: 64,  g: 196, b: 196 }, // teal
            success:     Color::Rgb { r: 80,  g: 200, b: 100 }, // soft green
            warning:     Color::Rgb { r: 240, g: 180, b: 40  }, // amber
            error:       Color::Rgb { r: 220, g: 50,  b: 60  }, // crimson
            dim:         Color::Rgb { r: 100, g: 100, b: 110 }, // muted grey
            highlight:   Color::Rgb { r: 255, g: 255, b: 255 }, // white
            border:      Color::Rgb { r: 40,  g: 120, b: 140 }, // dark teal
            peer_colors: vec![
                Color::Rgb { r: 80,  g: 200, b: 100 }, // mint
                Color::Rgb { r: 240, g: 180, b: 40  }, // amber
                Color::Rgb { r: 64,  g: 196, b: 196 }, // teal
                Color::Rgb { r: 220, g: 120, b: 220 }, // lavender
                Color::Rgb { r: 120, g: 140, b: 220 }, // periwinkle
                Color::Rgb { r: 240, g: 120, b: 80  }, // coral
                Color::Rgb { r: 180, g: 240, b: 80  }, // lime
                Color::Rgb { r: 80,  g: 160, b: 240 }, // sky blue
            ],
            chat_timestamp:  Color::Rgb { r: 255, g: 255, b: 255 }, // white
            chat_own_id:     Color::Rgb { r: 64,  g: 220, b: 230 }, // bright cyan
            chat_own_text:   Color::Rgb { r: 255, g: 255, b: 255 }, // white
            chat_peer_id:    Color::Reset,                           // use rotation
            chat_peer_text:  Color::Rgb { r: 255, g: 255, b: 255 }, // white
            chat_background: Color::Reset,                           // transparent
            chat_system:     Color::Rgb { r: 130, g: 130, b: 140 }, // muted grey
        }
    }
}

// ---------------------------------------------------------------------------
// ThemeColor → crossterm Color
// ---------------------------------------------------------------------------

/// Convert a `ThemeColor` to a `crossterm::Color` for the given depth.
pub fn tc_to_color(tc: ThemeColor, depth: ColorDepth) -> Color {
    if depth == ColorDepth::Monochrome {
        return Color::Reset;
    }
    match tc {
        ThemeColor::Default  => Color::Reset,
        ThemeColor::White    => Color::White,
        ThemeColor::Grey     => Color::Grey,
        ThemeColor::DarkGrey => Color::DarkGrey,
        ThemeColor::Black    => Color::Black,
        ThemeColor::Cyan     => Color::Cyan,
        ThemeColor::Green    => Color::Green,
        ThemeColor::Yellow   => Color::Yellow,
        ThemeColor::Magenta  => Color::Magenta,
        ThemeColor::Blue     => Color::Blue,
        ThemeColor::Red      => Color::Red,
    }
}
