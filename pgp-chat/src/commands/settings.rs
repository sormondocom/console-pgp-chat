//! Application settings: configure identities directory, downloads directory,
//! and chat color theme.

use anyhow::{Context, Result};
use crossterm::{queue, style::{Color, Print, ResetColor, SetBackgroundColor, SetForegroundColor}};
use pgp_chat_core::persistence::{self, AppConfig, ChatTheme, ThemeColor};
use pgp_chat_core::terminal::color::tc_to_color;
use pgp_chat_core::terminal::capability::ColorDepth;
use std::io::{stdout, Write};
use std::path::Path;
use crate::ui::Ui;

pub fn run(ui: &Ui, storage_dir: &Path, config: &mut AppConfig) -> Result<()> {
    loop {
        ui.clear()?;
        ui.renderer.draw_box_top("Settings")?;

        println!("  [1] Identities directory\r");
        println!("      {}\r", config.identities_dir.display());
        println!("\r");
        println!("  [2] Downloads directory  (default save path for received files)\r");
        println!("      {}\r", config.downloads_dir.display());
        println!("\r");
        println!("  [3] Chat Theme  (active: {})\r", config.chat_theme.name);
        println!("\r");

        ui.renderer.draw_box_separator()?;
        println!("  [0] Back\r");
        ui.renderer.draw_box_bottom()?;
        stdout().flush()?;
        crate::sidebar::draw_auto(storage_dir, ui);

        let choice = ui.prompt("Choice:")?;
        match choice.trim() {
            "0" | "" => return Ok(()),

            "1" => {
                println!("  Current: {}\r", config.identities_dir.display());
                println!("  NOTE: changing this path will not move existing identity files.\r");
                println!("  Press Enter to keep the current value.\r");
                let new_val = ui.prompt("New identities directory:")?;
                let new_val = new_val.trim().to_string();
                if !new_val.is_empty() {
                    let new_path = Path::new(&new_val).to_path_buf();
                    if ensure_directory(ui, &new_path)? {
                        config.identities_dir = new_path;
                        persistence::save_config(storage_dir, config)
                            .with_context(|| "Failed to save config")?;
                        ui.success("Identities directory updated.")?;
                    }
                    ui.wait_for_key("Press any key...")?;
                }
            }

            "2" => {
                println!("  Current: {}\r", config.downloads_dir.display());
                println!("  Press Enter to keep the current value.\r");
                let new_val = ui.prompt("New downloads directory:")?;
                let new_val = new_val.trim().to_string();
                if !new_val.is_empty() {
                    let new_path = Path::new(&new_val).to_path_buf();
                    if ensure_directory(ui, &new_path)? {
                        config.downloads_dir = new_path;
                        persistence::save_config(storage_dir, config)
                            .with_context(|| "Failed to save config")?;
                        ui.success("Downloads directory updated.")?;
                    }
                    ui.wait_for_key("Press any key...")?;
                }
            }

            "3" => theme_editor(ui, storage_dir, config)?,

            _ => {
                ui.error("Unknown choice.")?;
                ui.wait_for_key("Press any key...")?;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Theme editor
// ---------------------------------------------------------------------------

fn theme_editor(ui: &Ui, storage_dir: &Path, config: &mut AppConfig) -> Result<()> {
    let depth = ui.renderer.cap().color_depth;
    loop {
        ui.clear()?;
        ui.renderer.draw_box_top("Chat Theme")?;

        println!("  Active theme: {}\r", config.chat_theme.name);
        println!("\r");
        println!("  Enter the number of an element to open its color picker.\r");
        println!("\r");

        let t = &config.chat_theme;
        print_theme_row(depth, "  [1] Timestamp ", t.timestamp, false);
        print_theme_row(depth, "  [2] Your ID   ", t.own_id,    false);
        print_theme_row(depth, "  [3] Your Text ", t.own_text,  false);
        print_theme_row(depth, "  [4] Peer Name ", t.peer_id,   true);
        print_theme_row(depth, "  [5] Peer Text ", t.peer_text, false);
        print_theme_row(depth, "  [6] Background", t.background, true);
        print_theme_row(depth, "  [7] Border    ", t.border,      false);
        print_theme_row(depth, "  [8] System Msgs", t.system_text, false);

        println!("\r");
        println!("  Preview:\r");
        print_preview(depth, &config.chat_theme);

        ui.renderer.draw_box_separator()?;
        println!("  [s] Save theme as…\r");
        if !config.saved_themes.is_empty() {
            println!("  [l] Load saved theme\r");
            println!("  [x] Delete saved theme\r");
        }
        println!("  [r] Reset to defaults\r");
        println!("  [0] Back\r");
        ui.renderer.draw_box_bottom()?;
        stdout().flush()?;

        let choice = ui.prompt("Choice:")?;
        match choice.trim() {
            "0" | "" => return Ok(()),

            "1" => pick_and_save(ui, storage_dir, config, depth, "Timestamp color",
                                 |t| &mut t.timestamp)?,
            "2" => pick_and_save(ui, storage_dir, config, depth, "Your ID color",
                                 |t| &mut t.own_id)?,
            "3" => pick_and_save(ui, storage_dir, config, depth, "Your text color",
                                 |t| &mut t.own_text)?,
            "4" => pick_and_save(ui, storage_dir, config, depth, "Peer name color",
                                 |t| &mut t.peer_id)?,
            "5" => pick_and_save(ui, storage_dir, config, depth, "Peer text color",
                                 |t| &mut t.peer_text)?,
            "6" => pick_and_save(ui, storage_dir, config, depth, "Background color",
                                 |t| &mut t.background)?,
            "7" => pick_and_save(ui, storage_dir, config, depth, "Border color",
                                 |t| &mut t.border)?,
            "8" => pick_and_save(ui, storage_dir, config, depth, "System message color",
                                 |t| &mut t.system_text)?,

            "s" => save_theme(ui, storage_dir, config)?,
            "l" if !config.saved_themes.is_empty() => load_theme(ui, storage_dir, config)?,
            "x" if !config.saved_themes.is_empty() => delete_theme(ui, storage_dir, config)?,
            "r" => {
                config.chat_theme = ChatTheme::default();
                persistence::save_config(storage_dir, config)
                    .with_context(|| "Failed to save config")?;
                ui.success("Theme reset to defaults.")?;
                ui.wait_for_key("Press any key...")?;
            }

            _ => {
                ui.error("Unknown choice.")?;
                ui.wait_for_key("Press any key...")?;
            }
        }
    }
}

/// Open the color picker for one theme field, save on change.
fn pick_and_save(
    ui:          &Ui,
    storage_dir: &Path,
    config:      &mut AppConfig,
    depth:       ColorDepth,
    label:       &str,
    field:       impl Fn(&mut ChatTheme) -> &mut ThemeColor,
) -> Result<()> {
    let current = *field(&mut config.chat_theme);
    let chosen  = pick_color(ui, label, current, depth)?;
    *field(&mut config.chat_theme) = chosen;
    persistence::save_config(storage_dir, config)
        .with_context(|| "Failed to save config")
}

// ---------------------------------------------------------------------------
// Color picker
// ---------------------------------------------------------------------------

fn pick_color(ui: &Ui, label: &str, current: ThemeColor, depth: ColorDepth) -> Result<ThemeColor> {
    let colors = ThemeColor::all();
    let mut out = stdout();

    println!("\r");
    println!("  {} — current: {}\r", label, current.display_name());
    println!("\r");

    for (i, &c) in colors.iter().enumerate() {
        let marker = if c == current { " ◀" } else { "" };
        let col    = tc_to_color(c, depth);
        queue!(out, Print(format!("  [{:>2}] ", i + 1)))?;
        // Black needs a white background so the swatch blocks are visible.
        if c == ThemeColor::Black {
            queue!(
                out,
                SetBackgroundColor(Color::White),
                SetForegroundColor(Color::Black),
                Print("██"),
                ResetColor,
                Print(" "),
            )?;
        } else {
            queue!(out, SetForegroundColor(col), Print("██ "), ResetColor)?;
        }
        queue!(out, Print(format!("{}{}\r\n", c.display_name(), marker)))?;
    }
    println!("\r");
    println!("  [ 0] Cancel\r");
    out.flush()?;

    let choice = ui.prompt("Color number:")?;
    let choice = choice.trim();

    if choice == "0" || choice.is_empty() {
        return Ok(current);
    }
    if let Ok(n) = choice.parse::<usize>() {
        if n >= 1 && n <= colors.len() {
            return Ok(colors[n - 1]);
        }
    }
    ui.error("Invalid choice — keeping current color.")?;
    Ok(current)
}

// ---------------------------------------------------------------------------
// Save / load / delete named themes
// ---------------------------------------------------------------------------

fn save_theme(ui: &Ui, storage_dir: &Path, config: &mut AppConfig) -> Result<()> {
    let name = ui.prompt("Theme name (Enter to cancel):")?;
    let name = name.trim().to_string();
    if name.is_empty() {
        return Ok(());
    }
    config.chat_theme.name = name.clone();
    if let Some(pos) = config.saved_themes.iter().position(|t| t.name == name) {
        config.saved_themes[pos] = config.chat_theme.clone();
        ui.success(&format!("Theme '{}' updated.", name))?;
    } else {
        config.saved_themes.push(config.chat_theme.clone());
        ui.success(&format!("Theme '{}' saved.", name))?;
    }
    persistence::save_config(storage_dir, config)
        .with_context(|| "Failed to save config")?;
    ui.wait_for_key("Press any key...")?;
    Ok(())
}

fn load_theme(ui: &Ui, storage_dir: &Path, config: &mut AppConfig) -> Result<()> {
    println!("\r");
    for (i, t) in config.saved_themes.iter().enumerate() {
        println!("  [{}] {}\r", i + 1, t.name);
    }
    println!("  [0] Cancel\r");
    stdout().flush()?;

    let choice = ui.prompt("Load theme:")?;
    let choice = choice.trim().to_string();
    if choice == "0" || choice.is_empty() {
        return Ok(());
    }
    if let Ok(n) = choice.parse::<usize>() {
        if n >= 1 && n <= config.saved_themes.len() {
            config.chat_theme = config.saved_themes[n - 1].clone();
            persistence::save_config(storage_dir, config)
                .with_context(|| "Failed to save config")?;
            ui.success(&format!("Loaded theme '{}'.", config.chat_theme.name))?;
            ui.wait_for_key("Press any key...")?;
            return Ok(());
        }
    }
    ui.error("Invalid choice.")?;
    ui.wait_for_key("Press any key...")?;
    Ok(())
}

fn delete_theme(ui: &Ui, storage_dir: &Path, config: &mut AppConfig) -> Result<()> {
    println!("\r");
    for (i, t) in config.saved_themes.iter().enumerate() {
        println!("  [{}] {}\r", i + 1, t.name);
    }
    println!("  [0] Cancel\r");
    stdout().flush()?;

    let choice = ui.prompt("Delete theme:")?;
    let choice = choice.trim().to_string();
    if choice == "0" || choice.is_empty() {
        return Ok(());
    }
    if let Ok(n) = choice.parse::<usize>() {
        if n >= 1 && n <= config.saved_themes.len() {
            let name = config.saved_themes.remove(n - 1).name;
            persistence::save_config(storage_dir, config)
                .with_context(|| "Failed to save config")?;
            ui.success(&format!("Deleted theme '{}'.", name))?;
            ui.wait_for_key("Press any key...")?;
            return Ok(());
        }
    }
    ui.error("Invalid choice.")?;
    ui.wait_for_key("Press any key...")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

/// Print one theme element row with a color swatch.
/// `note_default` appends "(rotating colors)" or "(transparent)" for Default-special fields.
fn print_theme_row(depth: ColorDepth, label: &str, color: ThemeColor, note_default: bool) {
    let mut out = stdout();
    let col  = tc_to_color(color, depth);
    let note = if note_default && color == ThemeColor::Default {
        "  (uses rotating peer colors)"
    } else {
        ""
    };
    let _ = queue!(out, Print(format!("{}:  ", label)));
    // Black swatch needs a white background to be visible against dark terminals.
    if color == ThemeColor::Black {
        let _ = queue!(
            out,
            SetBackgroundColor(Color::White),
            SetForegroundColor(Color::Black),
            Print("██"),
            ResetColor,
            Print(" "),
        );
    } else {
        let _ = queue!(out, SetForegroundColor(col), Print("██ "), ResetColor);
    }
    let _ = queue!(out, Print(format!("{}{}\r\n", color.display_name(), note)));
    let _ = out.flush();
}

/// Render a two-line sample showing what chat messages look like with this theme.
fn print_preview(depth: ColorDepth, theme: &ChatTheme) {
    let mut out = stdout();
    let ts_col   = tc_to_color(theme.timestamp,  depth);
    let own_id   = tc_to_color(theme.own_id,     depth);
    let own_txt  = tc_to_color(theme.own_text,   depth);
    let peer_id  = if theme.peer_id == ThemeColor::Default {
        Color::Green // show one representative rotation color
    } else {
        tc_to_color(theme.peer_id, depth)
    };
    let peer_txt = tc_to_color(theme.peer_text,  depth);
    let sys_col  = tc_to_color(theme.system_text, depth);
    let bg       = tc_to_color(theme.background, depth);

    let set_bg = bg != Color::Reset;

    // Sent message row
    if set_bg { let _ = queue!(out, SetBackgroundColor(bg)); }
    let _ = queue!(
        out,
        Print("  "),
        SetForegroundColor(ts_col),  Print("2026-01-01 12:00:00 "),
        SetForegroundColor(own_id),  Print("[You]"),
        ResetColor,
        if set_bg { SetBackgroundColor(bg) } else { SetBackgroundColor(Color::Reset) },
        Print(" "),
        SetForegroundColor(own_txt), Print("Hello, this is your message."),
        ResetColor,                  Print("\r\n"),
    );

    // Received message row
    if set_bg { let _ = queue!(out, SetBackgroundColor(bg)); }
    let _ = queue!(
        out,
        Print("  "),
        SetForegroundColor(ts_col),   Print("2026-01-01 12:00:01 "),
        SetForegroundColor(peer_id),  Print("<Alice>"),
        ResetColor,
        if set_bg { SetBackgroundColor(bg) } else { SetBackgroundColor(Color::Reset) },
        Print(" "),
        SetForegroundColor(peer_txt), Print("And this is a reply from a peer."),
        ResetColor,                   Print("\r\n"),
    );

    // System message row
    let _ = queue!(
        out,
        SetForegroundColor(sys_col),
        Print("  2026-01-01 12:00:02 [*] Alice has joined the room."),
        ResetColor,
        Print("\r\n"),
    );
    let _ = out.flush();
}

// ---------------------------------------------------------------------------
// Directory helper
// ---------------------------------------------------------------------------

fn ensure_directory(ui: &Ui, path: &Path) -> Result<bool> {
    if path.exists() {
        return Ok(true);
    }
    println!("  Directory does not exist: {}\r", path.display());
    let answer = ui.prompt("Create it now? [y/n]:")?;
    if !answer.trim().eq_ignore_ascii_case("y") {
        println!("  Directory not created — setting not saved.\r");
        return Ok(false);
    }
    std::fs::create_dir_all(path)
        .with_context(|| format!("Failed to create '{}'", path.display()))?;
    ui.success(&format!("Created: {}", path.display()))?;
    Ok(true)
}
