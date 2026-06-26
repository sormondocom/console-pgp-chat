//! Top-level interactive menu.

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};

use pgp_chat_core::persistence;
use crate::{commands, ui::Ui};

// ---------------------------------------------------------------------------
// Menu items
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MenuItem {
    StartChat,
    ManageIdentities,
    ManageRooms,
    ScanPeers,
    Settings,
    Exit,
}

struct MenuEntry {
    key:   char,
    label: &'static str,
    desc:  &'static str,
}

const ENTRIES: &[MenuEntry] = &[
    MenuEntry { key: '1', label: "Start Chat",         desc: "Connect to a room and exchange encrypted messages" },
    MenuEntry { key: '2', label: "Manage Identities",  desc: "Create, import, switch, or delete PGP identities" },
    MenuEntry { key: '3', label: "Manage Rooms",       desc: "Create rooms or join rooms shared by others" },
    MenuEntry { key: '4', label: "Scan for Peers",     desc: "Discover pgp-chat nodes on the network (no trust required)" },
    MenuEntry { key: '5', label: "Settings",           desc: "Configure file paths and chat color theme" },
    MenuEntry { key: 'q', label: "Quit",               desc: "" },
];

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub async fn run() -> Result<()> {
    let storage_dir = persistence::storage_dir();
    let mut config  = persistence::load_config(&storage_dir);

    loop {
        // Rebuild Ui each iteration so theme changes made in Settings are
        // reflected immediately without requiring a restart.
        let ui = Ui::from_config(&config);

        render_menu(&ui)?;
        let selected = wait_for_selection()?;
        ui.clear()?;

        let result = match selected {
            MenuItem::StartChat => {
                commands::chat::run(&ui, &storage_dir, &config, None).await
            }
            MenuItem::ManageIdentities => {
                commands::identity_manager::run(&ui, &storage_dir, &mut config)
            }
            MenuItem::ManageRooms => {
                commands::room_manager::run(&ui, &storage_dir)
            }
            MenuItem::ScanPeers => {
                commands::peer_scanner::run(&ui, &storage_dir, &config).await
            }
            MenuItem::Settings => {
                commands::settings::run(&ui, &storage_dir, &mut config)
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
// Rendering
// ---------------------------------------------------------------------------

fn render_menu(ui: &Ui) -> Result<()> {
    ui.clear()?;
    ui.print_banner()?;
    ui.print_mascot()?;
    ui.renderer.draw_box_separator()?;

    for entry in ENTRIES {
        let label = if entry.desc.is_empty() {
            entry.label.to_string()
        } else {
            format!("{:<22} {}", entry.label, entry.desc)
        };
        ui.renderer.draw_menu_item(entry.key, &label, false)?;
    }

    ui.renderer.draw_box_bottom()?;
    ui.print_prompt_label("Choice:")?;
    Ok(())
}

fn wait_for_selection() -> Result<MenuItem> {
    loop {
        if let Event::Key(KeyEvent { code, kind: KeyEventKind::Press, .. }) = event::read()? {
            let selected = match code {
                KeyCode::Char('1') => Some(MenuItem::StartChat),
                KeyCode::Char('2') => Some(MenuItem::ManageIdentities),
                KeyCode::Char('3') => Some(MenuItem::ManageRooms),
                KeyCode::Char('4') => Some(MenuItem::ScanPeers),
                KeyCode::Char('5') => Some(MenuItem::Settings),
                KeyCode::Char('q') | KeyCode::Esc => Some(MenuItem::Exit),
                _ => None,
            };
            if let Some(item) = selected {
                return Ok(item);
            }
        }
    }
}
