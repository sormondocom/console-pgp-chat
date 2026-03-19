//! Adaptive terminal renderer.
//!
//! Selects box-drawing characters (Unicode or ASCII) and colour attributes
//! based on the detected [`TerminalCapability`].  All output goes through
//! `crossterm` so the same code path works on every supported OS / terminal.

use crossterm::{
    cursor,
    queue,
    style::{
        Attribute, Color, Print, ResetColor, SetAttribute, SetForegroundColor,
    },
    terminal::{Clear, ClearType},
};
use std::io::{self, stdout, Write};

use super::{
    capability::{ColorDepth, TerminalCapability},
    color::ColorPalette,
};

// ---------------------------------------------------------------------------
// Border sets
// ---------------------------------------------------------------------------

/// A complete set of box-drawing characters.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BorderSet {
    pub(crate) tl: &'static str, // top-left corner
    pub(crate) tr: &'static str, // top-right corner
    pub(crate) bl: &'static str, // bottom-left corner
    pub(crate) br: &'static str, // bottom-right corner
    pub(crate) h:  &'static str, // horizontal line
    pub(crate) v:  &'static str, // vertical line
    pub(crate) ml: &'static str, // mid-left T
    pub(crate) mr: &'static str, // mid-right T
}

/// Double-line Unicode box (requires a Unicode-capable terminal).
pub(crate) const UNICODE: BorderSet = BorderSet {
    tl: "╔", tr: "╗", bl: "╚", br: "╝",
    h:  "═", v:  "║", ml: "╠", mr: "╣",
};

/// Plain ASCII box (works on every terminal including VT-100).
pub(crate) const ASCII: BorderSet = BorderSet {
    tl: "+", tr: "+", bl: "+", br: "+",
    h:  "-", v:  "|", ml: "+", mr: "+",
};

// ---------------------------------------------------------------------------
// Renderer
// ---------------------------------------------------------------------------

/// Owns the detected capability, the colour palette, and the border set.
pub struct Renderer {
    cap:     TerminalCapability,
    palette: ColorPalette,
    borders: BorderSet,
}

impl Renderer {
    pub fn new(cap: TerminalCapability) -> Self {
        let palette = ColorPalette::for_depth(cap.color_depth);
        let borders = if cap.unicode { UNICODE } else { ASCII };
        Self { cap, palette, borders }
    }

    pub fn cap(&self)     -> &TerminalCapability { &self.cap }
    pub fn palette(&self) -> &ColorPalette       { &self.palette }

    // -----------------------------------------------------------------------
    // Box drawing helpers
    // -----------------------------------------------------------------------

    fn width(&self) -> usize { self.cap.width as usize }

    /// Print a horizontal line of `ch` padded to terminal width - 2.
    fn hline(&self, ch: &str) -> String {
        ch.repeat(self.width().saturating_sub(2))
    }

    // -----------------------------------------------------------------------
    // Public draw methods
    // -----------------------------------------------------------------------

    pub fn clear(&self) -> io::Result<()> {
        let mut out = stdout();
        queue!(out, Clear(ClearType::All), cursor::MoveTo(0, 0))?;
        out.flush()
    }

    /// Top border with centred title.
    pub fn draw_box_top(&self, title: &str) -> io::Result<()> {
        let mut out = stdout();
        let inner_width = self.width().saturating_sub(2);
        let padded = format!(" {} ", title);
        let left_pad  = inner_width.saturating_sub(padded.len()) / 2;
        let right_pad = inner_width.saturating_sub(padded.len() + left_pad);
        let line = format!(
            "{}{}{}{}{}",
            self.borders.h.repeat(left_pad),
            padded,
            self.borders.h.repeat(right_pad),
            self.borders.tr,
            "\r\n"
        );
        queue!(
            out,
            SetForegroundColor(self.palette.border),
            Print(self.borders.tl),
            Print(&line),
            ResetColor
        )?;
        out.flush()
    }

    /// Mid separator line.
    pub fn draw_box_separator(&self) -> io::Result<()> {
        let mut out = stdout();
        queue!(
            out,
            SetForegroundColor(self.palette.border),
            Print(self.borders.ml),
            Print(self.hline(self.borders.h)),
            Print(self.borders.mr),
            Print("\r\n"),
            ResetColor
        )?;
        out.flush()
    }

    /// Bottom border.
    pub fn draw_box_bottom(&self) -> io::Result<()> {
        let mut out = stdout();
        queue!(
            out,
            SetForegroundColor(self.palette.border),
            Print(self.borders.bl),
            Print(self.hline(self.borders.h)),
            Print(self.borders.br),
            Print("\r\n"),
            ResetColor
        )?;
        out.flush()
    }

    /// A single menu item row: `  [k] Label`.
    ///
    /// `selected` highlights the row in the accent colour.
    pub fn draw_menu_item(&self, key: char, label: &str, selected: bool) -> io::Result<()> {
        let mut out = stdout();
        let color = if selected { self.palette.accent } else { self.palette.foreground };
        queue!(
            out,
            SetForegroundColor(self.palette.border),
            Print(self.borders.v),
            ResetColor,
            SetForegroundColor(color),
        )?;
        if selected {
            queue!(out, SetAttribute(Attribute::Bold))?;
        }
        queue!(
            out,
            Print(format!("  [{}] {:<width$}  ", key, label,
                          width = self.width().saturating_sub(10))),
        )?;
        if selected {
            queue!(out, SetAttribute(Attribute::Reset))?;
        }
        queue!(
            out,
            ResetColor,
            SetForegroundColor(self.palette.border),
            Print(self.borders.v),
            Print("\r\n"),
            ResetColor
        )?;
        out.flush()
    }

    /// A chat message row.
    ///
    /// - `timestamp`  — short time string, e.g. `"14:32"`
    /// - `sender`     — nickname
    /// - `content`    — message body
    /// - `verified`   — whether the PGP signature checked out
    /// - `peer_index` — stable index for per-peer colour
    pub fn draw_message(
        &self,
        timestamp: &str,
        sender: &str,
        content: &str,
        verified: bool,
        peer_index: usize,
    ) -> io::Result<()> {
        let mut out = stdout();
        let peer_color = self.palette.peer_color(peer_index);
        let sig_mark = if verified { "✓" } else { "?" };
        // Fall back to ASCII on non-Unicode terminals
        let sig_mark = if self.cap.unicode { sig_mark } else { if verified { "V" } else { "?" } };

        queue!(
            out,
            SetForegroundColor(self.palette.dim),
            Print(format!(" {} ", timestamp)),
            ResetColor,
            SetForegroundColor(peer_color),
            SetAttribute(Attribute::Bold),
            Print(format!("<{}>", sender)),
            SetAttribute(Attribute::Reset),
            ResetColor,
            Print(" "),
            SetForegroundColor(self.palette.foreground),
            Print(content),
            Print("  "),
            SetForegroundColor(if verified { self.palette.success } else { self.palette.warning }),
            Print(sig_mark),
            ResetColor,
            Print("\r\n"),
        )?;
        out.flush()
    }

    /// Status bar at the bottom of the screen.
    pub fn draw_status_bar(&self, text: &str) -> io::Result<()> {
        let mut out = stdout();
        let bar = format!(" {} ", text);
        queue!(
            out,
            SetForegroundColor(self.palette.accent),
            SetAttribute(Attribute::Reverse),
            Print(format!("{:<width$}", bar, width = self.width())),
            SetAttribute(Attribute::Reset),
            ResetColor,
            Print("\r\n"),
        )?;
        out.flush()
    }

    /// Demonstrate colour capabilities: adapt output to detected depth.
    pub fn draw_color_test(&self) -> io::Result<()> {
        let mut out = stdout();
        let w = self.width();

        queue!(out, Print("\r\n"))?;
        self.draw_box_top("Colour Capability Test")?;

        match self.cap.color_depth {
            // ----------------------------------------------------------------
            ColorDepth::Monochrome => {
                queue!(
                    out,
                    SetForegroundColor(self.palette.border), Print(self.borders.v), ResetColor,
                    Print("  Monochrome terminal — no colour support."),
                    Print("\r\n"),
                    SetForegroundColor(self.palette.border), Print(self.borders.v), ResetColor,
                    Print("  Bold and underline are available for emphasis:"),
                    Print("\r\n"),
                    SetForegroundColor(self.palette.border), Print(self.borders.v), ResetColor,
                    Print("  "),
                    SetAttribute(Attribute::Bold), Print("bold text"), SetAttribute(Attribute::Reset),
                    Print("  "),
                    SetAttribute(Attribute::Underlined), Print("underlined"), SetAttribute(Attribute::Reset),
                    Print("\r\n"),
                )?;
            }

            // ----------------------------------------------------------------
            ColorDepth::Ansi16 => {
                queue!(
                    out,
                    SetForegroundColor(self.palette.border), Print(self.borders.v), ResetColor,
                    Print("  16 ANSI colours:\r\n"),
                    SetForegroundColor(self.palette.border), Print(self.borders.v), ResetColor,
                    Print("  "),
                )?;
                for code in 0u8..16 {
                    let color = ansi16_color(code);
                    queue!(
                        out,
                        SetForegroundColor(color),
                        Print(format!("{:>3}", code)),
                        ResetColor,
                        Print(" "),
                    )?;
                }
                queue!(out, Print("\r\n"))?;
            }

            // ----------------------------------------------------------------
            ColorDepth::Ansi256 => {
                queue!(
                    out,
                    SetForegroundColor(self.palette.border), Print(self.borders.v), ResetColor,
                    Print("  256-colour palette (6×6×6 cube + greyscale ramp):\r\n"),
                    SetForegroundColor(self.palette.border), Print(self.borders.v), ResetColor,
                    Print("  "),
                )?;
                // Show 16 per row
                for i in 0u16..=255 {
                    if i > 0 && i % 16 == 0 {
                        queue!(
                            out,
                            Print("\r\n"),
                            SetForegroundColor(self.palette.border), Print(self.borders.v), ResetColor,
                            Print("  "),
                        )?;
                    }
                    queue!(
                        out,
                        SetForegroundColor(Color::AnsiValue(i as u8)),
                        Print("█"),
                        ResetColor,
                    )?;
                }
                queue!(out, Print("\r\n"))?;
            }

            // ----------------------------------------------------------------
            ColorDepth::TrueColor => {
                // Smooth horizontal RGB gradient
                queue!(
                    out,
                    SetForegroundColor(self.palette.border), Print(self.borders.v), ResetColor,
                    Print("  24-bit true colour gradient:\r\n"),
                    SetForegroundColor(self.palette.border), Print(self.borders.v), ResetColor,
                    Print("  "),
                )?;
                let usable = w.saturating_sub(4) as u32;
                for col in 0..usable {
                    let t = col as f32 / usable as f32;
                    // Rotate through hue: R → G → B → R
                    let (r, g, b) = hue_rgb(t);
                    queue!(
                        out,
                        SetForegroundColor(Color::Rgb { r, g, b }),
                        Print("█"),
                        ResetColor,
                    )?;
                }
                queue!(out, Print("\r\n"))?;

                // Also show a brightness ramp (white → black)
                queue!(
                    out,
                    SetForegroundColor(self.palette.border), Print(self.borders.v), ResetColor,
                    Print("  Greyscale ramp:\r\n"),
                    SetForegroundColor(self.palette.border), Print(self.borders.v), ResetColor,
                    Print("  "),
                )?;
                for col in 0..usable {
                    let v = ((col * 255) / usable) as u8;
                    queue!(
                        out,
                        SetForegroundColor(Color::Rgb { r: v, g: v, b: v }),
                        Print("█"),
                        ResetColor,
                    )?;
                }
                queue!(out, Print("\r\n"))?;
            }
        }

        self.draw_box_bottom()?;
        out.flush()
    }
}

// ---------------------------------------------------------------------------
// Colour helpers
// ---------------------------------------------------------------------------

/// Map an index 0-15 to the corresponding basic ANSI colour.
fn ansi16_color(code: u8) -> Color {
    match code {
        0  => Color::Black,
        1  => Color::DarkRed,
        2  => Color::DarkGreen,
        3  => Color::DarkYellow,
        4  => Color::DarkBlue,
        5  => Color::DarkMagenta,
        6  => Color::DarkCyan,
        7  => Color::Grey,
        8  => Color::DarkGrey,
        9  => Color::Red,
        10 => Color::Green,
        11 => Color::Yellow,
        12 => Color::Blue,
        13 => Color::Magenta,
        14 => Color::Cyan,
        _  => Color::White,
    }
}

/// Simple HSV-style hue rotation: `t` in [0,1] → RGB.
fn hue_rgb(t: f32) -> (u8, u8, u8) {
    let h = t * 6.0;
    let f = h - h.floor();
    let (r, g, b) = match h as u8 % 6 {
        0 => (1.0_f32, f,   0.0),
        1 => (1.0 - f, 1.0, 0.0),
        2 => (0.0,     1.0, f  ),
        3 => (0.0, 1.0 - f, 1.0),
        4 => (f,       0.0, 1.0),
        _ => (1.0,     0.0, 1.0 - f),
    };
    ((r * 255.0) as u8, (g * 255.0) as u8, (b * 255.0) as u8)
}
