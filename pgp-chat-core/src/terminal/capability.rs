//! Terminal capability detection.
//!
//! Supports every OS tier that Rust targets: Windows, Linux, macOS, FreeBSD,
//! NetBSD, OpenBSD, Solaris/illumos, Haiku, Redox, WASI, and more.
//!
//! Detection uses only environment variables and `crossterm::terminal::size()`
//! — no system calls beyond what `std` and `crossterm` already abstract.
//! This means the code compiles and runs on every `std`-capable Rust target.

use std::env;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// How many colours the terminal can display.
///
/// Ordered so that `a > b` means "richer capabilities than b".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ColorDepth {
    /// No colour support — VT-100 / `dumb` / `NO_COLOR` set.
    Monochrome,
    /// 16 basic ANSI named colours (8 standard + 8 bright).
    Ansi16,
    /// 256-colour xterm/vte palette.
    Ansi256,
    /// 24-bit true colour (16.7 M colours).
    TrueColor,
}

/// Detected capabilities of the running terminal.
#[derive(Debug, Clone)]
pub struct TerminalCapability {
    /// Maximum colour depth we can rely on.
    pub color_depth: ColorDepth,
    /// Whether box-drawing / Unicode characters are safe to emit.
    pub unicode: bool,
    /// Terminal width in columns.
    pub width: u16,
    /// Terminal height in rows.
    pub height: u16,
    /// Value of `$TERM` (or `"unknown"` if absent).
    pub term_name: String,
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

impl TerminalCapability {
    /// Auto-detect the capability of the connected terminal.
    ///
    /// Reads `NO_COLOR`, `COLORTERM`, `TERM_PROGRAM`, `TERM`, `LANG`,
    /// `LC_ALL`, `LC_CTYPE`, and (on Windows) `WT_SESSION`.  Falls back
    /// safely when variables are absent.
    pub fn detect() -> Self {
        let term_name = env::var("TERM").unwrap_or_else(|_| "unknown".to_string());
        let colorterm = env::var("COLORTERM").unwrap_or_default();
        let term_program = env::var("TERM_PROGRAM").unwrap_or_default();

        let color_depth = detect_color_depth(&term_name, &colorterm, &term_program);
        let unicode = detect_unicode();

        let (width, height) = crossterm::terminal::size().unwrap_or((80, 24));

        Self { color_depth, unicode, width, height, term_name }
    }

    /// Human-readable summary, e.g. `"xterm-256color (256 colours, Unicode)"`.
    pub fn summary(&self) -> String {
        let color_label = match self.color_depth {
            ColorDepth::Monochrome => "monochrome",
            ColorDepth::Ansi16    => "16 colours",
            ColorDepth::Ansi256   => "256 colours",
            ColorDepth::TrueColor => "24-bit true colour",
        };
        let uni_label = if self.unicode { "Unicode" } else { "ASCII" };
        format!("{} ({}, {})", self.term_name, color_label, uni_label)
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn detect_color_depth(term: &str, colorterm: &str, term_program: &str) -> ColorDepth {
    // 1. NO_COLOR → honour it unconditionally (https://no-color.org)
    if env::var_os("NO_COLOR").is_some() {
        return ColorDepth::Monochrome;
    }

    // 2. COLORTERM=truecolor|24bit → explicit true-colour opt-in
    let ct = colorterm.to_ascii_lowercase();
    if ct == "truecolor" || ct == "24bit" {
        return ColorDepth::TrueColor;
    }

    // 3. Known true-colour terminal programs
    match term_program {
        "iTerm.app" | "WezTerm" | "Hyper" | "alacritty" | "vscode" => {
            return ColorDepth::TrueColor;
        }
        _ => {}
    }

    // 4. Windows Terminal sets WT_SESSION (any OS the binary might run on)
    if env::var_os("WT_SESSION").is_some() {
        return ColorDepth::TrueColor;
    }

    // 5. TERM suffix / prefix heuristics
    if term.contains("256color") || term.contains("256") {
        return ColorDepth::Ansi256;
    }
    if term.starts_with("xterm")
        || term.starts_with("screen")
        || term.starts_with("tmux")
        || term.contains("color")
    {
        return ColorDepth::Ansi16;
    }

    // 6. Explicit monochrome terminals
    if term.starts_with("vt")
        || term == "dumb"
        || term == "unknown"
        || term.is_empty()
    {
        return ColorDepth::Monochrome;
    }

    // 7. Unknown — assume 16 colours (conservative)
    ColorDepth::Ansi16
}

fn detect_unicode() -> bool {
    // Windows Terminal and known GUI terminals always support Unicode
    if env::var_os("WT_SESSION").is_some() {
        return true;
    }
    if let Ok(tp) = env::var("TERM_PROGRAM") {
        if matches!(
            tp.as_str(),
            "iTerm.app" | "WezTerm" | "Hyper" | "alacritty" | "vscode"
        ) {
            return true;
        }
    }

    // Unix: locale declares UTF-8
    for var in &["LANG", "LC_ALL", "LC_CTYPE"] {
        if let Ok(v) = env::var(var) {
            let u = v.to_ascii_uppercase();
            if u.contains("UTF-8") || u.contains("UTF8") {
                return true;
            }
        }
    }

    // On systems where none of the above apply, default to safe ASCII
    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truecolor_from_colorterm() {
        // Temporarily shadow via direct call (env is process-wide so just
        // test the helper function directly)
        assert_eq!(
            detect_color_depth("xterm", "truecolor", ""),
            ColorDepth::TrueColor
        );
        assert_eq!(
            detect_color_depth("xterm", "24bit", ""),
            ColorDepth::TrueColor
        );
    }

    #[test]
    fn ansi256_from_term() {
        assert_eq!(
            detect_color_depth("xterm-256color", "", ""),
            ColorDepth::Ansi256
        );
    }

    #[test]
    fn monochrome_vt100() {
        assert_eq!(
            detect_color_depth("vt100", "", ""),
            ColorDepth::Monochrome
        );
    }

    #[test]
    fn monochrome_dumb() {
        assert_eq!(
            detect_color_depth("dumb", "", ""),
            ColorDepth::Monochrome
        );
    }

    #[test]
    fn ordering() {
        assert!(ColorDepth::TrueColor > ColorDepth::Ansi256);
        assert!(ColorDepth::Ansi256  > ColorDepth::Ansi16);
        assert!(ColorDepth::Ansi16   > ColorDepth::Monochrome);
    }
}
