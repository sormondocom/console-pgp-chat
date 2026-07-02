//! Shared UI utilities for the demo binary.
//!
//! Thin wrappers around `crossterm` and the `pgp_chat_core::terminal`
//! renderer that handle raw-mode input, prompts, and common layout pieces.

use crossterm::{
    cursor, execute, queue,
    style::{Attribute, Print, ResetColor, SetAttribute, SetForegroundColor},
    terminal::{Clear, ClearType},
};
use pgp_chat_core::{
    persistence::{AppConfig, ChatTheme},
    terminal::{capability::TerminalCapability, renderer::Renderer},
};
use std::io::{self, stdout, Write};

// ---------------------------------------------------------------------------
// Display sanitization
// ---------------------------------------------------------------------------

/// Strip control characters from a peer-supplied string before printing to the
/// terminal. Bytes below 0x20 (except tab) and DEL (0x7F) can carry ANSI/VT100
/// escape sequences that manipulate terminal state, inject fake UI content, or
/// on some terminals read/write the system clipboard via OSC 52.
pub fn sanitize_display(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() && c != '\t' { '?' } else { c })
        .collect()
}

// ---------------------------------------------------------------------------
// Ui
// ---------------------------------------------------------------------------

/// Owns the [`Renderer`] and provides convenience methods for the demo menu.
pub struct Ui {
    pub renderer: Renderer,
}

impl Ui {
    /// Build a `Ui` with chat colors driven by the active theme in `config`.
    #[allow(dead_code)]
    pub fn from_config(config: &AppConfig) -> Self {
        let cap = TerminalCapability::detect();
        Self { renderer: Renderer::with_theme(cap, &config.chat_theme) }
    }

    /// Like `from_config` but overrides the detected terminal width.
    /// Used to reserve the right columns for the sidebar.
    pub fn from_config_at_width(config: &AppConfig, width: u16) -> Self {
        let mut cap = TerminalCapability::detect();
        cap.width = width;
        Self { renderer: Renderer::with_theme(cap, &config.chat_theme) }
    }

    /// Build a `Ui` from an explicit theme + width (used after identity prefs are loaded).
    pub fn from_theme_at_width(theme: &ChatTheme, width: u16) -> Self {
        let mut cap = TerminalCapability::detect();
        cap.width = width;
        Self { renderer: Renderer::with_theme(cap, theme) }
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
    /// Example (true-color Unicode terminal):
    /// ```text
    /// ╔══ Console PGP Chat ══╗
    /// ║  P2P Encrypted Chat  ║
    /// ╠══════════════════════╣
    /// ║  xterm-256color (256 colors, Unicode) │ 220×50  ║
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
                "PGP Chat · End-to-End Encrypted · PGP Authenticated",
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

        // Capability info row — measure by char count (not bytes) so that
        // multi-byte Unicode chars like │ (3 bytes) and × (2 bytes) are each
        // counted as the 1 terminal column they actually occupy.
        let info_str = format!("  {}  │  {}×{}", cap.summary(), cap.width, cap.height);
        let info_cols = info_str.chars().count();
        let inner_width = cap.width.saturating_sub(2) as usize; // minus left and right border
        let pad = inner_width.saturating_sub(info_cols);
        queue!(
            out,
            SetForegroundColor(pal.border),
            Print(self.renderer_border_v()),
            ResetColor,
            SetForegroundColor(pal.dim),
            Print(&info_str),
            Print(" ".repeat(pad)),
            ResetColor,
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

    /// Print the prompt label in accent color without reading input.
    ///
    /// Use this on menus that read a single keypress through a separate handler
    /// so that the visual style matches `prompt()` on all other screens.
    pub fn print_prompt_label(&self, msg: &str) -> io::Result<()> {
        let mut out = stdout();
        let pal = self.renderer.palette();
        queue!(
            out,
            SetForegroundColor(pal.accent),
            Print(format!("  {} ", msg)),
            ResetColor,
        )?;
        out.flush()
    }

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
                    KeyCode::Esc => {
                        queue!(out, ResetColor, Print("\r\n"))?;
                        out.flush()?;
                        return Ok(String::new());
                    }
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
                    KeyCode::Esc => {
                        queue!(out, ResetColor, Print("\r\n"))?;
                        out.flush()?;
                        return Ok(zeroize::Zeroizing::new(String::new()));
                    }
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

    /// Render the lock mascot as content rows inside the currently-open box.
    ///
    /// All mascot lines are pre-padded to the same width so they centre
    /// at a consistent horizontal offset regardless of terminal width.
    /// The shackle legs (col 2 & 8) align with the body connectors (+) on
    /// the top row of the body.
    pub fn print_mascot(&self) -> io::Result<()> {
        let mut out = stdout();
        let pal = self.renderer.palette();
        let inner = self.renderer.cap().width.saturating_sub(2) as usize;

        // Scene: two CRT desktops flanking a bidirectional encrypted channel.
        //
        // Each computer column is 11 chars wide.  Between them: 4-char gap,
        // 15-char arrow region, 4-char gap.  Total per row: 45 chars.
        //
        // Computers (11 chars each):
        //   .---------.   monitor top / bottom corners
        //   | .-----. |   CRT bezel
        //   | |     | |   screen inner
        //   '---------'   monitor base edge
        //       |   |     stand legs (cols 4 & 8 of the 11-char block)
        //    .-------.    desk base
        //    |_______|
        //
        // Left screen shows padlock (local identity locked).
        // Right screen shows data lines (peer terminal activity).
        // A padlock hangs in the centre column below the arrow:
        //
        //   centre col (15 chars), rows 4-8:
        //     row 4 — shackle top :  "     .---.     "  (legs at cols 5 & 9)
        //     row 5 — shackle legs:  "     |   |     "  (legs at cols 5 & 9)
        //     row 6 — body top    :  "   .-------.   "  (corners at cols 3 & 11)
        //     row 7 — keyhole     :  "   |  (o)  |   "
        //     row 8 — body bottom :  "   |_______|   "
        //
        //   Shackle legs (5, 9) fall inside the body span (3–11), so the shackle
        //   appears to insert through the top face of the body — correct padlock form.
        let blank    = "               ";  // 15 spaces
        let gap      = "    ";             // 4-space gap on each side of the centre
        let arrow    = "<~~~~~~~~~~~~~>"; // 15 chars, bidirectional channel
        let lk_sh_t  = "     .---.     ";  // 15: shackle top  (.---. at cols 5-9)
        let lk_sh_s  = "     |   |     ";  // 15: shackle sides
        let lk_bd_t  = "   .-------.   ";  // 15: body top     (.-------.at cols 3-11)
        let lk_bd_m  = "   |  (o)  |   ";  // 15: body keyhole
        let lk_bd_b  = "   |_______|   ";  // 15: body bottom

        let rows: Vec<String> = vec![
            String::new(),
            format!(".---------.{gap}{blank}{gap}.---------."),
            format!("| .-----. |{gap}{blank}{gap}| .-----. |"),
            format!("| | (o) | |{gap}{arrow}{gap}| | === | |"),
            format!("| |  |  | |{gap}{lk_sh_t}{gap}| | --- | |"),
            format!("| '-----' |{gap}{lk_sh_s}{gap}| '-----' |"),
            format!("'---------'{gap}{lk_bd_t}{gap}'---------'"),
            format!("    |   |  {gap}{lk_bd_m}{gap}    |   |  "),
            format!(" .-------. {gap}{lk_bd_b}{gap} .-------. "),
            format!(" |_______| {gap}{blank}{gap} |_______| "),
            String::new(),
        ];

        for row in &rows {
            let len = row.chars().count();
            let pad_left  = inner.saturating_sub(len) / 2;
            let pad_right = inner.saturating_sub(len + pad_left);
            queue!(
                out,
                SetForegroundColor(pal.border),
                Print(self.renderer_border_v()),
                ResetColor,
                SetForegroundColor(pal.accent),
                Print(" ".repeat(pad_left)),
                Print(row.as_str()),
                Print(" ".repeat(pad_right)),
                ResetColor,
                SetForegroundColor(pal.border),
                Print(self.renderer_border_v()),
                Print("\r\n"),
                ResetColor,
            )?;
        }
        out.flush()
    }

    /// Print a labelled passphrase box for easy copying / sharing.
    ///
    /// The box is sized to whichever is wider: the label row or the passphrase
    /// row.  Both label and passphrase should be ASCII so `.len()` equals the
    /// display column count.
    pub fn show_passphrase_box(&self, label: &str, passphrase: &str) {
        let inner_w = std::cmp::max(
            label.len() + 6,
            passphrase.len() + 4,
        );
        let top_prefix = format!("══ {} ", label);
        let top_fill   = "═".repeat(inner_w - top_prefix.chars().count());
        println!("  ╔{}{}╗\r", top_prefix, top_fill);
        let mid     = format!("  {}  ", passphrase);
        let mid_pad = " ".repeat(inner_w - mid.len());
        println!("  ║{}{}║\r", mid, mid_pad);
        println!("  ╚{}╝\r", "═".repeat(inner_w));
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
