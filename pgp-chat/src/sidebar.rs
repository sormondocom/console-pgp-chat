use std::io::{stdout, Write};
use std::path::Path;

use crossterm::{cursor, execute, queue, style::{Color, Print, ResetColor, SetBackgroundColor, SetForegroundColor}};
use pgp_chat_core::persistence::{self, PendingTrustRequest, PersistedTrustStore};

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

fn active_identity_name(storage_dir: &Path) -> String {
    persistence::load_config(storage_dir)
        .active_identity
        .unwrap_or_default()
}

/// Total navigable items in the combined pending-then-contacts list.
/// The index space matches the `selected` parameter of `draw_with_selection`.
pub fn item_count(storage_dir: &Path) -> usize {
    let name = active_identity_name(storage_dir);
    persistence::load_pending_trust_requests(storage_dir, &name).len()
        + persistence::load_contacts(storage_dir, &name).contacts.len()
}

/// Number of pending trust requests.
pub fn pending_count(storage_dir: &Path) -> usize {
    let name = active_identity_name(storage_dir);
    persistence::load_pending_trust_requests(storage_dir, &name).len()
}

/// Draw sidebar or compact badge. Saves and restores cursor position.
pub fn draw(storage_dir: &Path, term_w: u16, unicode: bool) -> std::io::Result<()> {
    draw_with_selection(storage_dir, term_w, unicode, None)
}

/// Draw sidebar with one item optionally highlighted (Tab navigation).
///
/// `selected` indexes the combined pending-then-contacts list:
///   0 .. pending.len()   → pending trust requests
///   pending.len() ..     → trusted contacts
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
    let name   = active_identity_name(storage_dir);
    let store  = persistence::load_contacts(storage_dir, &name);
    let pend   = persistence::load_pending_trust_requests(storage_dir, &name);
    let n_pend = pend.len();
    let x      = term_w - SIDEBAR_W;

    let (tl, tr, bl, br, h_ch, v_ch, ml, mr) = if unicode {
        ("┌", "┐", "└", "┘", "─", "│", "├", "┤")
    } else {
        ("+", "+", "+", "+", "-", "|", "+", "+")
    };
    let star_pfx  = if unicode { "★" } else { "*" };
    let check_pfx = if unicode { "✓" } else { "+" };
    let ellipsis  = if unicode { "…" } else { "." };

    let mut out = stdout();
    queue!(out, cursor::SavePosition)?;

    let mut row: u16 = 0;

    // ── Title ───────────────────────────────────────────────────────────────
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

    // ── Pending trust request rows ──────────────────────────────────────────
    for (i, req) in pend.iter().enumerate() {
        if row >= term_h { break; }
        let nick   = crate::ui::sanitize_display(&req.from_nickname);
        let entry  = sidebar_entry(star_pfx, &nick, ellipsis);
        let padded = format!("{:<w$}", entry, w = INNER);

        if selected == Some(i) {
            queue!(out,
                cursor::MoveTo(x, row),
                SetForegroundColor(Color::Black),
                SetBackgroundColor(Color::Yellow),
                Print(format!("{}{}{}", v_ch, padded, v_ch)),
                ResetColor,
            )?;
        } else {
            queue!(out,
                cursor::MoveTo(x, row),
                SetForegroundColor(Color::Yellow),
                Print(v_ch),
                ResetColor,
                Print(&padded),
                SetForegroundColor(Color::Yellow),
                Print(v_ch),
                ResetColor,
            )?;
        }
        row += 1;
    }

    // Separator between pending and contacts (only when both are present)
    if !pend.is_empty() && !store.contacts.is_empty() && row < term_h {
        queue!(out,
            cursor::MoveTo(x, row),
            SetForegroundColor(Color::Cyan),
            Print(format!("{}{}{}", ml, h_ch.repeat(INNER), mr)),
            ResetColor,
        )?;
        row += 1;
    }

    // ── Trusted contact rows ────────────────────────────────────────────────
    if store.contacts.is_empty() && pend.is_empty() {
        if row < term_h {
            let padded = format!("{:<w$}", " (no contacts)", w = INNER);
            queue!(out,
                cursor::MoveTo(x, row),
                SetForegroundColor(Color::DarkGrey),
                Print(format!("{}{}{}", v_ch, padded, v_ch)),
                ResetColor,
            )?;
            row += 1;
        }
    } else {
        for (i, c) in store.contacts.iter().enumerate() {
            if row >= term_h { break; }
            let nick   = crate::ui::sanitize_display(&c.nickname);
            let entry  = sidebar_entry(check_pfx, &nick, ellipsis);
            let padded = format!("{:<w$}", entry, w = INNER);

            if selected == Some(n_pend + i) {
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

    // ── Bottom border (or T-junction into detail strip) ─────────────────────
    if row < term_h {
        if selected.is_some() {
            queue!(out,
                cursor::MoveTo(x, row),
                SetForegroundColor(Color::Cyan),
                Print(format!("{}{}{}", ml, h_ch.repeat(INNER), mr)),
                ResetColor,
            )?;
        } else {
            queue!(out,
                cursor::MoveTo(x, row),
                SetForegroundColor(Color::Cyan),
                Print(format!("{}{}{}", bl, h_ch.repeat(INNER), br)),
                ResetColor,
            )?;
        }
        row += 1;
    }

    // ── Detail strip (when an item is selected) ─────────────────────────────
    if let Some(sel) = selected {
        row = draw_detail_strip(&mut out, x, row, term_h, unicode, sel, &pend, &store)?;
    }

    // Clear any stale sidebar-column rows below what we just drew
    while row < term_h {
        queue!(out,
            cursor::MoveTo(x, row),
            Print(" ".repeat(SIDEBAR_W as usize)),
        )?;
        row += 1;
    }

    flush_restore(&mut out)
}

/// Format a sidebar entry: `"PREFIX NICKNAME"` truncated to `INNER` columns.
fn sidebar_entry(prefix: &str, nick: &str, ellipsis: &str) -> String {
    // overhead = prefix chars + 1 space
    let overhead  = prefix.chars().count() + 1;
    let max_nick  = INNER.saturating_sub(overhead);
    let nick_chars: Vec<char> = nick.chars().collect();
    let display = if nick_chars.len() <= max_nick {
        nick.to_string()
    } else {
        let ell_len = ellipsis.chars().count();
        let take    = max_nick.saturating_sub(ell_len);
        format!("{}{}", nick_chars[..take].iter().collect::<String>(), ellipsis)
    };
    format!("{} {}", prefix, display)
}

fn draw_detail_strip(
    out:     &mut std::io::Stdout,
    x:       u16,
    mut row: u16,
    term_h:  u16,
    unicode: bool,
    sel:     usize,
    pend:    &[PendingTrustRequest],
    store:   &PersistedTrustStore,
) -> std::io::Result<u16> {
    let n_pend = pend.len();

    let (bl, br, h_ch, v_ch) = if unicode {
        ("└", "┘", "─", "│")
    } else {
        ("+", "+", "-", "|")
    };

    if sel < n_pend {
        // ── Pending trust request detail ─────────────────────────────────
        let req    = &pend[sel];
        let nick   = crate::ui::sanitize_display(&req.from_nickname);
        let fp     = &req.from_fingerprint;
        let fp_disp = if fp.len() >= 14 { &fp[..14] } else { fp };

        let now     = chrono::Utc::now();
        let age_min = (now - req.received_at).num_minutes();
        let age_str = match age_min {
            0        => "just now".to_string(),
            1        => "1 min ago".to_string(),
            n @ 2..=59 => format!("{} min ago", n),
            n          => format!("{} hr ago", n / 60),
        };

        drow(out, x, &mut row, term_h, v_ch,
             &dline(&nick, INNER),          Color::Yellow)?;
        drow(out, x, &mut row, term_h, v_ch,
             &dline(&format!("fp:{}", fp_disp), INNER), Color::DarkGrey)?;
        drow(out, x, &mut row, term_h, v_ch,
             &dline(&age_str, INNER),        Color::DarkGrey)?;
        drow(out, x, &mut row, term_h, v_ch,
             &dline("[5] Contacts menu", INNER), Color::Cyan)?;

        if row < term_h {
            queue!(out,
                cursor::MoveTo(x, row),
                SetForegroundColor(Color::Yellow),
                Print(format!("{}{}{}", bl, h_ch.repeat(INNER), br)),
                ResetColor,
            )?;
            row += 1;
        }
    } else {
        // ── Trusted contact detail ────────────────────────────────────────
        let ci = sel - n_pend;
        if ci >= store.contacts.len() { return Ok(row); }
        let c      = &store.contacts[ci];
        let nick   = crate::ui::sanitize_display(&c.nickname);
        let fp     = &c.fingerprint;
        let fp_disp = if fp.len() >= 14 { &fp[..14] } else { fp };

        drow(out, x, &mut row, term_h, v_ch,
             &dline(&nick, INNER),           Color::Cyan)?;
        drow(out, x, &mut row, term_h, v_ch,
             &dline(&format!("fp:{}", fp_disp), INNER), Color::DarkGrey)?;
        drow(out, x, &mut row, term_h, v_ch,
             &dline("[↵] start chat", INNER), Color::DarkGrey)?;

        if row < term_h {
            queue!(out,
                cursor::MoveTo(x, row),
                SetForegroundColor(Color::Cyan),
                Print(format!("{}{}{}", bl, h_ch.repeat(INNER), br)),
                ResetColor,
            )?;
            row += 1;
        }
    }

    Ok(row)
}

/// Draw one detail-strip content row.
fn drow(
    out:    &mut std::io::Stdout,
    x:      u16,
    row:    &mut u16,
    term_h: u16,
    v_ch:   &str,
    text:   &str,
    color:  Color,
) -> std::io::Result<()> {
    if *row >= term_h { return Ok(()); }
    queue!(out,
        cursor::MoveTo(x, *row),
        SetForegroundColor(color),
        Print(format!("{}{}{}", v_ch, text, v_ch)),
        ResetColor,
    )?;
    *row += 1;
    Ok(())
}

/// Pad `" {text}"` left-justified to `width` characters.
fn dline(text: &str, width: usize) -> String {
    format!("{:<w$}", format!(" {}", text), w = width)
}

fn flush_restore(out: &mut std::io::Stdout) -> std::io::Result<()> {
    execute!(out, cursor::RestorePosition)?;
    out.flush()
}

fn draw_badge(storage_dir: &Path, term_w: u16, unicode: bool) -> std::io::Result<()> {
    let name       = active_identity_name(storage_dir);
    let pending_n  = persistence::load_pending_trust_requests(storage_dir, &name).len();
    let contacts_n = persistence::load_contacts(storage_dir, &name).contacts.len();
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
