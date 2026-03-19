//! Shared UI utilities for the demo binary.
//!
//! Thin wrappers around `crossterm` and the `pgp_chat_core::terminal`
//! renderer that handle raw-mode input, prompts, and common layout pieces.

use crossterm::{
    cursor, execute, queue,
    style::{Attribute, Print, ResetColor, SetAttribute, SetForegroundColor},
    terminal::{Clear, ClearType},
};
use pgp_chat_core::terminal::{
    capability::TerminalCapability, renderer::Renderer,
};
use std::io::{self, stdout, Write};

// ---------------------------------------------------------------------------
// Ui
// ---------------------------------------------------------------------------

/// Owns the [`Renderer`] and provides convenience methods for the demo menu.
pub struct Ui {
    pub renderer: Renderer,
}

impl Ui {
    /// Detect the current terminal and build a `Ui`.
    pub fn new() -> Self {
        let cap = TerminalCapability::detect();
        Self { renderer: Renderer::new(cap) }
    }

    // -----------------------------------------------------------------------
    // Layout
    // -----------------------------------------------------------------------

    /// Clear the screen and move the cursor to (0, 0).
    pub fn clear(&self) -> io::Result<()> {
        execute!(stdout(), Clear(ClearType::All), cursor::MoveTo(0, 0))
    }

    /// Print the application banner with capability info in the header.
    ///
    /// Example (true-colour Unicode terminal):
    /// ```text
    /// ╔══ Console PGP Chat ══╗
    /// ║  P2P Encrypted Chat  ║
    /// ╠══════════════════════╣
    /// ║  xterm-256color (256 colours, Unicode) │ 220×50  ║
    /// ╚══════════════════════╝
    /// ```
    pub fn print_banner(&self) -> io::Result<()> {
        let mut out = stdout();
        let cap = self.renderer.cap();
        let pal = self.renderer.palette();

        self.renderer.draw_box_top("Console PGP Chat")?;

        // Subtitle row
        queue!(
            out,
            SetForegroundColor(pal.border),
            Print(self.renderer_border_v()),
            ResetColor,
            SetForegroundColor(pal.accent),
            SetAttribute(Attribute::Bold),
            Print(format!(
                "  {:<width$}",
                "P2P · End-to-End Encrypted · PGP Authenticated",
                width = cap.width.saturating_sub(4) as usize
            )),
            SetAttribute(Attribute::Reset),
            ResetColor,
            SetForegroundColor(pal.border),
            Print(self.renderer_border_v()),
            Print("\r\n"),
            ResetColor,
        )?;

        self.renderer.draw_box_separator()?;

        // Capability info row
        queue!(
            out,
            SetForegroundColor(pal.border),
            Print(self.renderer_border_v()),
            ResetColor,
            SetForegroundColor(pal.dim),
            Print(format!(
                "  {}  │  {}×{}",
                cap.summary(),
                cap.width,
                cap.height
            )),
            ResetColor,
        )?;
        // Pad to width
        let info_len = cap.summary().len() + format!("  │  {}×{}", cap.width, cap.height).len() + 4;
        let pad = cap.width.saturating_sub(info_len as u16 + 2) as usize;
        queue!(
            out,
            Print(" ".repeat(pad)),
            SetForegroundColor(pal.border),
            Print(self.renderer_border_v()),
            Print("\r\n"),
            ResetColor,
        )?;

        self.renderer.draw_box_separator()?;
        out.flush()
    }

    // -----------------------------------------------------------------------
    // Input
    // -----------------------------------------------------------------------

    /// Show a prompt and read a line of text in raw mode.
    pub fn prompt(&self, msg: &str) -> io::Result<String> {
        use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};

        let mut out = stdout();
        let pal = self.renderer.palette();

        queue!(
            out,
            SetForegroundColor(pal.accent),
            Print(format!("  {} ", msg)),
            ResetColor,
            SetForegroundColor(pal.foreground),
        )?;
        out.flush()?;

        let mut line = String::new();

        loop {
            if let Event::Key(KeyEvent { code, modifiers, kind: KeyEventKind::Press, .. }) = event::read()? {
                // Ctrl-C / Ctrl-D abort
                if modifiers.contains(crossterm::event::KeyModifiers::CONTROL) {
                    if matches!(code, KeyCode::Char('c') | KeyCode::Char('d')) {
                        queue!(out, ResetColor, Print("\r\n"))?;
                        out.flush()?;
                        return Ok(String::new());
                    }
                }
                match code {
                    KeyCode::Enter => break,
                    KeyCode::Char(c) => {
                        line.push(c);
                        queue!(out, Print(c))?;
                        out.flush()?;
                    }
                    KeyCode::Backspace if !line.is_empty() => {
                        line.pop();
                        queue!(
                            out,
                            cursor::MoveLeft(1),
                            Print(' '),
                            cursor::MoveLeft(1),
                        )?;
                        out.flush()?;
                    }
                    _ => {}
                }
            }
        }

        queue!(out, ResetColor, Print("\r\n"))?;
        out.flush()?;
        Ok(line)
    }

    /// Show a prompt and read a passphrase without echoing characters.
    ///
    /// Each keystroke prints `*` instead of the actual character so the
    /// length is visible but the content is not.  Returns a `Zeroizing<String>`
    /// so the passphrase is wiped from memory when it is dropped.
    pub fn prompt_password(&self, msg: &str) -> io::Result<zeroize::Zeroizing<String>> {
        use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};

        let mut out = stdout();
        let pal = self.renderer.palette();

        queue!(
            out,
            SetForegroundColor(pal.accent),
            Print(format!("  {} ", msg)),
            ResetColor,
            SetForegroundColor(pal.dim),
        )?;
        out.flush()?;

        let mut line = zeroize::Zeroizing::new(String::new());

        loop {
            if let Event::Key(KeyEvent { code, modifiers, kind: KeyEventKind::Press, .. }) = event::read()? {
                if modifiers.contains(crossterm::event::KeyModifiers::CONTROL) {
                    if matches!(code, KeyCode::Char('c') | KeyCode::Char('d')) {
                        queue!(out, ResetColor, Print("\r\n"))?;
                        out.flush()?;
                        return Ok(zeroize::Zeroizing::new(String::new()));
                    }
                }
                match code {
                    KeyCode::Enter => break,
                    KeyCode::Char(c) => {
                        line.push(c);
                        queue!(out, Print('*'))?;
                        out.flush()?;
                    }
                    KeyCode::Backspace if !line.is_empty() => {
                        line.pop();
                        queue!(
                            out,
                            cursor::MoveLeft(1),
                            Print(' '),
                            cursor::MoveLeft(1),
                        )?;
                        out.flush()?;
                    }
                    _ => {}
                }
            }
        }

        queue!(out, ResetColor, Print("\r\n"))?;
        out.flush()?;
        Ok(line)
    }

    /// Print a message and wait for any key before returning.
    pub fn wait_for_key(&self, msg: &str) -> io::Result<()> {
        use crossterm::event::{self, Event, KeyEvent, KeyEventKind};
        let mut out = stdout();
        let pal = self.renderer.palette();

        queue!(
            out,
            SetForegroundColor(pal.dim),
            Print(format!("\r\n  {}", msg)),
            ResetColor,
        )?;
        out.flush()?;

        loop {
            if let Event::Key(KeyEvent { kind: KeyEventKind::Press, .. }) = event::read()? {
                break;
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Status / messaging
    // -----------------------------------------------------------------------

    /// Print a success line.
    pub fn success(&self, text: &str) -> io::Result<()> {
        let mut out = stdout();
        let pal = self.renderer.palette();
        let mark = if self.renderer.cap().unicode { "✓" } else { "OK" };
        queue!(
            out,
            SetForegroundColor(pal.success),
            Print(format!("  {} {}\r\n", mark, text)),
            ResetColor,
        )?;
        out.flush()
    }

    /// Print an error line.
    pub fn error(&self, text: &str) -> io::Result<()> {
        let mut out = stdout();
        let pal = self.renderer.palette();
        let mark = if self.renderer.cap().unicode { "✗" } else { "ERR" };
        queue!(
            out,
            SetForegroundColor(pal.error),
            Print(format!("  {} {}\r\n", mark, text)),
            ResetColor,
        )?;
        out.flush()
    }

    /// Print a plain info line.
    pub fn info(&self, label: &str, value: &str) -> io::Result<()> {
        let mut out = stdout();
        let pal = self.renderer.palette();
        queue!(
            out,
            SetForegroundColor(pal.dim),
            Print(format!("  {:>16} : ", label)),
            ResetColor,
            SetForegroundColor(pal.foreground),
            Print(format!("{}\r\n", value)),
            ResetColor,
        )?;
        out.flush()
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn renderer_border_v(&self) -> &'static str {
        if self.renderer.cap().unicode { "║" } else { "|" }
    }
}
