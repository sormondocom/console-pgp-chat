//! Top-level interactive menu for the demo binary.

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent};
use std::io::{stdout, Write};

use crate::{commands, ui::Ui};

// ---------------------------------------------------------------------------
// Menu items
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MenuItem {
    TerminalCapabilities,
    ColorTest,
    GenerateIdentity,
    ImportIdentity,
    CryptoDemo,
    NetworkDemo,
    Exit,
}

#[allow(dead_code)] // `item` is used in ENTRIES initialization for documentation clarity
struct MenuEntry {
    item:  MenuItem,
    key:   char,
    label: &'static str,
}

const ENTRIES: &[MenuEntry] = &[
    MenuEntry { item: MenuItem::TerminalCapabilities, key: '1', label: "Terminal Capabilities" },
    MenuEntry { item: MenuItem::ColorTest,            key: '2', label: "Colour Test" },
    MenuEntry { item: MenuItem::GenerateIdentity,     key: '3', label: "Generate PGP Identity" },
    MenuEntry { item: MenuItem::ImportIdentity,       key: '4', label: "Import Existing PGP Key" },
    MenuEntry { item: MenuItem::CryptoDemo,           key: '5', label: "Encrypt / Sign Demo" },
    MenuEntry { item: MenuItem::NetworkDemo,          key: '6', label: "P2P Network Demo" },
    MenuEntry { item: MenuItem::Exit,                 key: 'q', label: "Exit" },
];

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Run the interactive menu loop.  Returns when the user selects Exit.
pub async fn run() -> Result<()> {
    let ui = Ui::new();

    loop {
        render_menu(&ui)?;

        // Wait for a valid keypress
        let selected = wait_for_selection()?;

        ui.clear()?;
        let result = match selected {
            MenuItem::TerminalCapabilities => {
                commands::terminal_demo::show_capabilities(&ui)
                    .map_err(anyhow::Error::from)
            }
            MenuItem::ColorTest => {
                commands::terminal_demo::show_color_test(&ui)
                    .map_err(anyhow::Error::from)
            }
            MenuItem::GenerateIdentity => {
                commands::crypto_demo::generate_identity(&ui)
                    .map_err(anyhow::Error::from)
            }
            MenuItem::ImportIdentity => {
                commands::crypto_demo::import_identity(&ui)
                    .map_err(anyhow::Error::from)
            }
            MenuItem::CryptoDemo => {
                commands::crypto_demo::run_crypto_demo(&ui)
                    .map_err(anyhow::Error::from)
            }
            MenuItem::NetworkDemo => {
                commands::network_demo::run(&ui).await
            }
            MenuItem::Exit => return Ok(()),
        };

        if let Err(e) = result {
            ui.error(&format!("{:#}", e))?;
            ui.wait_for_key("Press any key to return to the menu...")?;
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn render_menu(ui: &Ui) -> Result<()> {
    ui.clear()?;
    ui.print_banner()?;

    for entry in ENTRIES {
        ui.renderer.draw_menu_item(entry.key, entry.label, false)?;
    }

    ui.renderer.draw_box_bottom()?;
    stdout().flush()?;
    Ok(())
}

fn wait_for_selection() -> Result<MenuItem> {
    loop {
        if let Event::Key(KeyEvent { code, .. }) = event::read()? {
            let selected = match code {
                KeyCode::Char('1') => Some(MenuItem::TerminalCapabilities),
                KeyCode::Char('2') => Some(MenuItem::ColorTest),
                KeyCode::Char('3') => Some(MenuItem::GenerateIdentity),
                KeyCode::Char('4') => Some(MenuItem::ImportIdentity),
                KeyCode::Char('5') => Some(MenuItem::CryptoDemo),
                KeyCode::Char('6') => Some(MenuItem::NetworkDemo),
                KeyCode::Char('q') | KeyCode::Esc => Some(MenuItem::Exit),
                _ => None,
            };
            if let Some(item) = selected {
                return Ok(item);
            }
        }
    }
}
