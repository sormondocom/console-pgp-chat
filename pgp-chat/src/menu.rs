use std::io::{stdout, Write};
use std::time::Duration;

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind},
    style::{Print, ResetColor, SetForegroundColor, Color},
    terminal,
    queue,
};
use pgp_chat_core::persistence::{self, PersistedRoom};
use zeroize::Zeroizing;

use crate::{background, commands, sidebar, ui::Ui};

// ---------------------------------------------------------------------------
// Menu items
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum MenuItem {
    StartChat,
    ManageIdentities,
    ManageRooms,
    ScanPeers,
    TrustRequests,
    Settings,
    StartChatWithContact(usize),
    Exit,
}

struct MenuEntry {
    key:   char,
    label: &'static str,
    desc:  &'static str,
}

const ENTRIES: &[MenuEntry] = &[
    MenuEntry { key: '1', label: "Start Chat",        desc: "Connect to a room and exchange encrypted messages" },
    MenuEntry { key: '2', label: "Manage Identities", desc: "Create, import, switch, or delete PGP identities" },
    MenuEntry { key: '3', label: "Manage Rooms",      desc: "Create rooms or join rooms shared by others" },
    MenuEntry { key: '4', label: "Scan for Peers",    desc: "Discover pgp-chat nodes on the network" },
    MenuEntry { key: '5', label: "Contacts & Trust",  desc: "View trusted contacts and pending trust requests" },
    MenuEntry { key: '6', label: "Settings",          desc: "Configure file paths and chat color theme" },
    MenuEntry { key: 'q', label: "Quit",              desc: "" },
];

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub async fn run() -> Result<()> {
    let storage_dir = persistence::storage_dir();
    let mut config  = persistence::load_config(&storage_dir);

    tokio::spawn(background::run(storage_dir.clone()));

    loop {
        let (term_w, _) = terminal::size().unwrap_or((80, 24));
        let main_w      = sidebar::main_width(term_w);
        let ui          = Ui::from_config_at_width(&config, main_w);

        render_menu(&ui)?;
        sidebar::draw(&storage_dir, term_w, ui.renderer.cap().unicode)?;

        let selected = wait_for_selection(&storage_dir, &config, term_w, ui.renderer.cap().unicode)?;
        ui.clear()?;

        let result = match selected {
            MenuItem::StartChat => {
                commands::chat::run(&ui, &storage_dir, &config, None).await
            }
            MenuItem::ManageIdentities => {
                commands::identity_manager::run(&ui, &storage_dir, &mut config)
            }
            MenuItem::ManageRooms => {
                commands::room_manager::run(&ui, &storage_dir, &config)
            }
            MenuItem::ScanPeers => {
                commands::peer_scanner::run(&ui, &storage_dir, &config).await
            }
            MenuItem::TrustRequests => {
                commands::trust_manager::run(&ui, &storage_dir, &config)
            }
            MenuItem::Settings => {
                commands::settings::run(&ui, &storage_dir, &mut config)
            }
            MenuItem::StartChatWithContact(idx) => {
                start_chat_with_contact(&ui, &storage_dir, &config, idx).await
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
// Start-chat-with-contact flow
// ---------------------------------------------------------------------------

async fn start_chat_with_contact(
    ui:          &Ui,
    storage_dir: &std::path::Path,
    config:      &pgp_chat_core::persistence::AppConfig,
    contact_idx: usize,
) -> Result<()> {
    let store = persistence::load_contacts(storage_dir);
    if contact_idx >= store.contacts.len() {
        ui.error("Contact no longer exists.")?;
        return Ok(());
    }
    let contact = &store.contacts[contact_idx];

    ui.renderer.draw_box_top("Chat with Contact")?;
    ui.info("Contact", &contact.nickname)?;
    ui.info("Fingerprint", &contact.fingerprint[..contact.fingerprint.len().min(32)])?;
    println!("\r");

    // Suggest a room name based on the contact's nickname
    let default_name = contact.nickname
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect::<String>()
        .to_lowercase();
    let default_name = if default_name.is_empty() { "chat".to_string() } else { default_name };

    let raw = ui.prompt(&format!("Room name [{}]:", default_name))?;
    let raw = raw.trim().to_string();
    let room_name = if raw.is_empty() { default_name } else { raw };

    // Generate a random passphrase; wrap in Zeroizing so it's wiped on drop.
    let mut bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    let passphrase = Zeroizing::new(hex::encode(bytes));

    // Show the passphrase prominently for out-of-band delivery
    println!("\r");
    ui.show_passphrase_box(
        &format!("Room passphrase for '{}' — share with {}", room_name, contact.nickname),
        &passphrase,
    );
    println!("  Share this passphrase with {} before they join.\r", contact.nickname);
    println!("  Press Enter to open the room...\r");
    ui.renderer.draw_box_bottom()?;
    stdout().flush()?;

    // Wait for Enter
    loop {
        if let Event::Key(KeyEvent { code: KeyCode::Enter, kind: KeyEventKind::Press, .. }) = event::read()? {
            break;
        }
    }

    let room = PersistedRoom {
        name:       room_name,
        passphrase: passphrase.as_str().to_owned(),
        is_owner:   true,
    };

    commands::chat::run(ui, storage_dir, config, Some((room, None))).await
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
    ui.print_prompt_label("Choice [Tab=contacts]:")?;
    Ok(())
}

// Poll with a 500 ms timeout so the sidebar refreshes live while the menu idles.
// Tab key puts focus into the sidebar contact list; arrows navigate; Enter selects.
// Terminal resize is handled inline: clear + full redraw at the new dimensions.
fn wait_for_selection(
    storage_dir: &std::path::Path,
    config:      &pgp_chat_core::persistence::AppConfig,
    term_w:      u16,
    unicode:     bool,
) -> Result<MenuItem> {
    let mut term_w         = term_w;
    let mut unicode        = unicode;
    let mut sidebar_focused = false;
    let mut sidebar_idx: usize = 0;

    loop {
        if event::poll(Duration::from_millis(500))? {
            match event::read()? {
                Event::Resize(new_w, _) => {
                    term_w  = new_w;
                    let main_w  = sidebar::main_width(new_w);
                    let new_ui  = Ui::from_config_at_width(config, main_w);
                    unicode = new_ui.renderer.cap().unicode;
                    new_ui.clear()?;
                    render_menu(&new_ui)?;
                    let sel = if sidebar_focused { Some(sidebar_idx) } else { None };
                    let _ = sidebar::draw_with_selection(storage_dir, new_w, unicode, sel);
                }

                Event::Key(KeyEvent { code, kind: KeyEventKind::Press, .. }) => {
                    if sidebar_focused {
                        let contacts = persistence::load_contacts(storage_dir).contacts;
                        match code {
                            KeyCode::Tab | KeyCode::Down => {
                                if !contacts.is_empty() {
                                    sidebar_idx = (sidebar_idx + 1) % contacts.len();
                                    let _ = sidebar::draw_with_selection(storage_dir, term_w, unicode, Some(sidebar_idx));
                                }
                            }
                            KeyCode::BackTab | KeyCode::Up => {
                                if !contacts.is_empty() {
                                    sidebar_idx = if sidebar_idx == 0 {
                                        contacts.len() - 1
                                    } else {
                                        sidebar_idx - 1
                                    };
                                    let _ = sidebar::draw_with_selection(storage_dir, term_w, unicode, Some(sidebar_idx));
                                }
                            }
                            KeyCode::Enter => {
                                return Ok(MenuItem::StartChatWithContact(sidebar_idx));
                            }
                            KeyCode::Esc => {
                                sidebar_focused = false;
                                let _ = sidebar::draw_with_selection(storage_dir, term_w, unicode, None);
                            }
                            _ => {}
                        }
                    } else {
                        match code {
                            KeyCode::Tab => {
                                let contacts = persistence::load_contacts(storage_dir).contacts;
                                if !contacts.is_empty() {
                                    sidebar_focused = true;
                                    sidebar_idx = 0;
                                    let _ = sidebar::draw_with_selection(storage_dir, term_w, unicode, Some(0));
                                    let mut out = stdout();
                                    let _ = queue!(out,
                                        SetForegroundColor(Color::DarkGrey),
                                        Print("  [Tab/↑↓ navigate · Enter select · Esc cancel]"),
                                        ResetColor,
                                    );
                                    let _ = out.flush();
                                }
                            }
                            KeyCode::Char('1') => return Ok(MenuItem::StartChat),
                            KeyCode::Char('2') => return Ok(MenuItem::ManageIdentities),
                            KeyCode::Char('3') => return Ok(MenuItem::ManageRooms),
                            KeyCode::Char('4') => return Ok(MenuItem::ScanPeers),
                            KeyCode::Char('5') => return Ok(MenuItem::TrustRequests),
                            KeyCode::Char('6') => return Ok(MenuItem::Settings),
                            KeyCode::Char('q') | KeyCode::Esc => return Ok(MenuItem::Exit),
                            _ => {}
                        }
                    }
                }

                _ => {}
            }
        } else {
            // Timeout — refresh the sidebar in case pending count changed.
            let sel = if sidebar_focused { Some(sidebar_idx) } else { None };
            let _ = sidebar::draw_with_selection(storage_dir, term_w, unicode, sel);
        }
    }
}
