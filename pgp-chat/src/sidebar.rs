use std::io::{stdout, Write};
use std::path::Path;

use crossterm::{cursor, execute, queue, style::{Color, Print, ResetColor, SetBackgroundColor, SetForegroundColor}};
use pgp_chat_core::persistence;

use crate::ui::Ui;

pub const SIDEBAR_W: u16 = 22;
const INNER: usize = (SIDEBAR_W - 2) as usize; // 20 inner columns
const MIN_TERM_W: u16 = 90;

/// Width the main content renderer should use when a sidebar is shown.
pub fn main_width(term_w: u16) -> u16 {
    if term_w >= MIN_TERM_W { term_w - SIDEBAR_W } else { term_w }
}

pub fn has_sidebar(term_w: u16) -> bool {
    term_w >= MIN_TERM_W
}

/// Draw sidebar or badge. Saves and restores cursor position.
pub fn draw(storage_dir: &Path, term_w: u16, unicode: bool) -> std::io::Result<()> {
    draw_with_selection(storage_dir, term_w, unicode, None)
}

/// Draw sidebar with one contact row optionally highlighted (Tab navigation).
pub fn draw_with_selection(
    storage_dir: &Path,
    term_w:      u16,
    unicode:     bool,
    selected:    Option<usize>,
) -> std::io::Result<()> {
    let (_, term_h) = crossterm::terminal::size().unwrap_or((80, 24));
    if has_sidebar(term_w) {
        draw_full(storage_dir, term_w, term_h, unicode, selected)
    } else {
        draw_badge(storage_dir, term_w, unicode)
    }
}

/// Convenience wrapper: reads terminal size and unicode flag from the Ui.
pub fn draw_auto(storage_dir: &Path, ui: &Ui) {
    if let Ok((w, _)) = crossterm::terminal::size() {
        let _ = draw(storage_dir, w, ui.renderer.cap().unicode);
    }
}

fn draw_full(
    storage_dir: &Path,
    term_w:      u16,
    term_h:      u16,
    unicode:     bool,
    selected:    Option<usize>,
) -> std::io::Result<()> {
    let store     = persistence::load_contacts(storage_dir);
    let pending   = persistence::load_pending_trust_requests(storage_dir);
    let pending_n = pending.len();
    let x         = term_w - SIDEBAR_W;

    let (tl, tr, bl, br, h_ch, v_ch, ml, mr) = if unicode {
        ("┌", "┐", "└", "┘", "─", "│", "├", "┤")
    } else {
        ("+", "+", "+", "+", "-", "|", "+", "+")
    };
    let star = if unicode { "★" } else { "*" };

    let mut out = stdout();
    queue!(out, cursor::SavePosition)?;

    let mut row: u16 = 0;

    // Title row
    let title  = " Friends ";
    let fill_l = (INNER.saturating_sub(title.len())) / 2;
    let fill_r = INNER.saturating_sub(title.len() + fill_l);
    queue!(out,
        cursor::MoveTo(x, row),
        SetForegroundColor(Color::Cyan),
        Print(format!("{}{}{}{}{}", tl, h_ch.repeat(fill_l), title, h_ch.repeat(fill_r), tr)),
        ResetColor,
    )?;
    row += 1;
    if row >= term_h { return flush_restore(&mut out); }

    // Pending notice
    if pending_n > 0 {
        let text   = format!(" {} {} pending ", star, pending_n);
        let padded = format!("{:<width$}", text, width = INNER);
        queue!(out,
            cursor::MoveTo(x, row),
            SetForegroundColor(Color::Yellow),
            Print(format!("{}{}{}", v_ch, padded, v_ch)),
            ResetColor,
        )?;
        row += 1;
        if row >= term_h { return flush_restore(&mut out); }

        queue!(out,
            cursor::MoveTo(x, row),
            SetForegroundColor(Color::Cyan),
            Print(format!("{}{}{}", ml, h_ch.repeat(INNER), mr)),
            ResetColor,
        )?;
        row += 1;
        if row >= term_h { return flush_restore(&mut out); }
    }

    // Contact rows
    if store.contacts.is_empty() {
        let padded = format!("{:<width$}", " (no contacts)", width = INNER);
        queue!(out,
            cursor::MoveTo(x, row),
            SetForegroundColor(Color::DarkGrey),
            Print(format!("{}{}{}", v_ch, padded, v_ch)),
            ResetColor,
        )?;
        row += 1;
    } else {
        for (i, c) in store.contacts.iter().enumerate() {
            if row >= term_h { break; }
            let entry = if c.nickname.len() + 2 <= INNER {
                format!(" {}", c.nickname)
            } else {
                format!(" {}…", &c.nickname[..INNER.saturating_sub(4)])
            };
            let padded = format!("{:<width$}", entry, width = INNER);
            if selected == Some(i) {
                // Highlighted row: inverted cyan for Tab focus
                queue!(out,
                    cursor::MoveTo(x, row),
                    SetForegroundColor(Color::Black),
                    SetBackgroundColor(Color::Cyan),
                    Print(format!("{}{}{}", v_ch, padded, v_ch)),
                    ResetColor,
                )?;
            } else {
                queue!(out,
                    cursor::MoveTo(x, row),
                    SetForegroundColor(Color::Cyan),
                    Print(v_ch),
                    ResetColor,
                    Print(&padded),
                    SetForegroundColor(Color::Cyan),
                    Print(v_ch),
                    ResetColor,
                )?;
            }
            row += 1;
        }
    }

    // Bottom border
    if row < term_h {
        queue!(out,
            cursor::MoveTo(x, row),
            SetForegroundColor(Color::Cyan),
            Print(format!("{}{}{}", bl, h_ch.repeat(INNER), br)),
            ResetColor,
        )?;
    }

    flush_restore(&mut out)
}

fn flush_restore(out: &mut std::io::Stdout) -> std::io::Result<()> {
    execute!(out, cursor::RestorePosition)?;
    out.flush()
}

fn draw_badge(storage_dir: &Path, term_w: u16, unicode: bool) -> std::io::Result<()> {
    let pending_n  = persistence::load_pending_trust_requests(storage_dir).len();
    let contacts_n = persistence::load_contacts(storage_dir).contacts.len();
    let star       = if unicode { "★" } else { "*" };

    let badge = if pending_n > 0 {
        format!("[{}+{}{}]", contacts_n, star, pending_n)
    } else {
        format!("[{} contacts]", contacts_n)
    };

    let x     = term_w.saturating_sub(badge.chars().count() as u16 + 1);
    let color = if pending_n > 0 { Color::Yellow } else { Color::DarkGrey };

    execute!(stdout(),
        cursor::SavePosition,
        cursor::MoveTo(x, 0),
        SetForegroundColor(color),
        Print(&badge),
        ResetColor,
        cursor::RestorePosition,
    )?;
    Ok(())
}
