use std::io::Write;
use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use chrono::Utc;
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind},
    terminal,
};
use pgp_chat_core::{
    crypto::identity::PgpIdentity,
    persistence::{
        self, IdentityPrefs, PendingTrustRequest, PersistedContact, PersistedTrustStore,
    },
};

use crate::{background, commands, sidebar, ui::Ui};

// ---------------------------------------------------------------------------
// Menu items
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum MenuItem {
    ManageIdentities,
    ManageRooms,
    ScanPeers,
    TrustRequests,
    FriendsView,
    Settings,
    Exit,
}

struct MenuEntry {
    key:   char,
    label: &'static str,
    desc:  &'static str,
}

const ENTRIES: &[MenuEntry] = &[
    MenuEntry { key: '1', label: "Manage Identities", desc: "Create, import, switch, or delete PGP identities" },
    MenuEntry { key: '2', label: "Manage Rooms",      desc: "Create and manage your chat rooms" },
    MenuEntry { key: '3', label: "Scan for Peers",    desc: "Discover pgp-chat nodes on the network" },
    MenuEntry { key: '4', label: "Friends",           desc: "View contacts, start chat, handle trust requests" },
    MenuEntry { key: '5', label: "Settings",          desc: "Configure file paths and chat color theme" },
    MenuEntry { key: 'q', label: "Quit",              desc: "" },
];

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub async fn run() -> Result<()> {
    let storage_dir = persistence::storage_dir();
    let mut config  = persistence::load_config(&storage_dir);

    let identity = match startup_identity_gate(&storage_dir, &mut config)? {
        Some(id) => id,
        None     => return Ok(()),
    };

    let identity_name = config.active_identity.clone().unwrap_or_default();
    let mut prefs = persistence::load_identity_prefs(&storage_dir, &identity_name, &identity);

    tokio::spawn(background::run(storage_dir.clone(), identity.clone(), identity_name.clone()));

    loop {
        let (term_w, _) = terminal::size().unwrap_or((80, 24));
        let main_w      = sidebar::main_width(term_w);
        let ui          = Ui::from_theme_at_width(&prefs.chat_theme, main_w);

        render_menu(&ui)?;
        sidebar::draw(&storage_dir, term_w, ui.renderer.cap().unicode, &identity)?;

        let selected = wait_for_selection(&storage_dir, &config, &prefs, term_w, ui.renderer.cap().unicode, &identity)?;
        ui.clear()?;

        let result = match selected {
            MenuItem::ManageIdentities => {
                commands::identity_manager::run(&ui, &storage_dir, &mut config, Some(&identity)).map(|_| ())
            }
            MenuItem::ManageRooms => {
                commands::room_manager::run(&ui, &storage_dir, &config, &identity)
            }
            MenuItem::ScanPeers => {
                match commands::peer_scanner::run(&ui, &storage_dir, &config, &identity).await {
                    Ok(Some((room, bootstrap, port_pref))) => {
                        commands::chat::run(&ui, &storage_dir, &config, Some((room, bootstrap, port_pref)), &identity).await
                    }
                    Ok(None) => Ok(()),
                    Err(e)   => Err(e),
                }
            }
            MenuItem::TrustRequests | MenuItem::FriendsView => {
                match commands::friends::run(&ui, &storage_dir, &config, &identity).await {
                    Ok(Some((room, bootstrap, port_pref))) => {
                        commands::chat::run(&ui, &storage_dir, &config, Some((room, bootstrap, port_pref)), &identity).await
                    }
                    Ok(None) => Ok(()),
                    Err(e)   => Err(e),
                }
            }
            MenuItem::Settings => {
                commands::settings::run(&ui, &storage_dir, &mut config, &mut prefs, &identity_name, &identity)
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
// Startup identity gate
// ---------------------------------------------------------------------------

fn startup_identity_gate(
    storage_dir: &Path,
    config:      &mut pgp_chat_core::persistence::AppConfig,
) -> Result<Option<PgpIdentity>> {
    loop {
        let (term_w, _) = terminal::size().unwrap_or((80, 24));
        let ui = Ui::from_config_at_width(config, sidebar::main_width(term_w));

        let entries = persistence::load_identity_entries(&config.identities_dir);

        if entries.is_empty() || config.active_identity.is_none() {
            ui.clear()?;
            ui.renderer.draw_box_top("pgp-chat")?;
            if entries.is_empty() {
                println!("  Welcome!  No PGP identity found.\r");
                println!("  You need to create or import one to use pgp-chat.\r");
            } else {
                println!("  No active identity is set.\r");
                println!("  Select or create one in Manage Identities.\r");
            }
            ui.renderer.draw_box_bottom()?;
            ui.wait_for_key("Press any key to open Identity Manager...")?;

            if let Some(new_identity) = commands::identity_manager::run(&ui, storage_dir, config, None)? {
                return Ok(Some(new_identity));
            }

            let after = persistence::load_identity_entries(&config.identities_dir);
            if after.is_empty() || config.active_identity.is_none() {
                return Ok(None);
            }
            continue;
        }

        let name = config.active_identity.as_ref().unwrap().clone();
        let entry = match entries.iter().find(|e| e.name == name) {
            Some(e) => e.clone(),
            None => {
                config.active_identity = None;
                let _ = persistence::save_config(storage_dir, config);
                continue;
            }
        };

        let armored = match persistence::load_named_identity(&config.identities_dir, &name)? {
            Some(a) => a,
            None => {
                ui.clear()?;
                ui.error(&format!("Key file for identity '{}' is missing.", name))?;
                println!("  Use Manage Identities to re-import the key or delete the entry.\r");
                ui.wait_for_key("Press any key to open Identity Manager...")?;
                if let Some(new_identity) = commands::identity_manager::run(&ui, storage_dir, config, None)? {
                    return Ok(Some(new_identity));
                }
                continue;
            }
        };

        ui.clear()?;
        ui.renderer.draw_box_top("pgp-chat — Unlock Identity")?;
        println!("\r");
        ui.info("Identity",    &format!("{} ({})", entry.name, entry.nickname))?;
        ui.info("Fingerprint", &entry.fingerprint)?;
        println!("\r");
        ui.renderer.draw_box_bottom()?;

        loop {
            let passphrase = ui.prompt_password("Passphrase [Enter to quit]:")?;
            if passphrase.is_empty() {
                return Ok(None);
            }
            match PgpIdentity::from_armored_secret_key(&entry.nickname, &armored, passphrase) {
                Ok(id) => return Ok(Some(id)),
                Err(_) => ui.error("Incorrect passphrase — try again.")?,
            }
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
    ui.print_prompt_label("Choice [Tab = Friends view]:")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Input loop
// ---------------------------------------------------------------------------

fn wait_for_selection(
    storage_dir: &Path,
    config:      &pgp_chat_core::persistence::AppConfig,
    prefs:       &IdentityPrefs,
    term_w:      u16,
    unicode:     bool,
    identity:    &PgpIdentity,
) -> Result<MenuItem> {
    let id_name = config.active_identity.as_deref().unwrap_or("");

    let mut term_w  = term_w;
    let mut unicode = unicode;

    let mut trust_alert: Option<PendingTrustRequest> = None;
    let mut last_pending_count = sidebar::pending_count(storage_dir, identity);

    loop {
        if event::poll(Duration::from_millis(500))? {
            match event::read()? {
                Event::Resize(new_w, _) => {
                    term_w  = new_w;
                    let main_w = sidebar::main_width(new_w);
                    let new_ui = Ui::from_theme_at_width(&prefs.chat_theme, main_w);
                    unicode    = new_ui.renderer.cap().unicode;
                    new_ui.clear()?;
                    render_menu(&new_ui)?;
                    let _ = sidebar::draw(storage_dir, new_w, unicode, identity);
                    if let Some(ref alert) = trust_alert {
                        draw_trust_banner(alert)?;
                    }
                }

                Event::Key(KeyEvent { code, kind: KeyEventKind::Press, .. }) => {
                    // Trust banner takes priority: T/D/R handle the incoming request.
                    if trust_alert.is_some() {
                        match code {
                            KeyCode::Char('t') | KeyCode::Char('T') => {
                                if let Some(req) = trust_alert.take() {
                                    menu_accept_trust(storage_dir, identity, id_name, &req);
                                }
                                clear_trust_banner()?;
                                last_pending_count = sidebar::pending_count(storage_dir, identity);
                                let _ = sidebar::draw(storage_dir, term_w, unicode, identity);
                                continue;
                            }
                            KeyCode::Char('d') | KeyCode::Char('D') => {
                                trust_alert = None;
                                clear_trust_banner()?;
                                continue;
                            }
                            KeyCode::Char('r') | KeyCode::Char('R') => {
                                if let Some(req) = trust_alert.take() {
                                    menu_reject_trust(storage_dir, identity, id_name, &req);
                                }
                                clear_trust_banner()?;
                                last_pending_count = sidebar::pending_count(storage_dir, identity);
                                let _ = sidebar::draw(storage_dir, term_w, unicode, identity);
                                continue;
                            }
                            _ => {}
                        }
                    }

                    match code {
                        KeyCode::Tab => return Ok(MenuItem::FriendsView),
                        KeyCode::Char('1') => return Ok(MenuItem::ManageIdentities),
                        KeyCode::Char('2') => return Ok(MenuItem::ManageRooms),
                        KeyCode::Char('3') => return Ok(MenuItem::ScanPeers),
                        KeyCode::Char('4') => return Ok(MenuItem::TrustRequests),
                        KeyCode::Char('5') => return Ok(MenuItem::Settings),
                        KeyCode::Char('q') | KeyCode::Esc => return Ok(MenuItem::Exit),
                        _ => {}
                    }
                }

                _ => {}
            }
        } else {
            // 500 ms tick — refresh sidebar, surface new trust requests.
            let current_pending = sidebar::pending_count(storage_dir, identity);
            if current_pending > last_pending_count && trust_alert.is_none() {
                let reqs = persistence::load_pending_trust_requests(storage_dir, id_name, identity);
                if let Some(newest) = reqs.last().cloned() {
                    trust_alert = Some(newest);
                    draw_trust_banner(trust_alert.as_ref().unwrap())?;
                }
            }
            last_pending_count = current_pending;
            let _ = sidebar::draw(storage_dir, term_w, unicode, identity);
        }
    }
}

// ---------------------------------------------------------------------------
// Trust banner — shown at the bottom of the terminal when a new trust request
// arrives while the user is on the main menu screen.
// ---------------------------------------------------------------------------

fn draw_trust_banner(req: &PendingTrustRequest) -> Result<()> {
    use crossterm::{cursor, style::{Color, Print, ResetColor, SetForegroundColor}, terminal};
    let (_, h) = terminal::size().unwrap_or((80, 24));
    let fp = &req.from_fingerprint;
    let fp_short = &fp[..fp.len().min(20)];
    let mut out = std::io::stdout();
    crossterm::queue!(out,
        cursor::SavePosition,
        cursor::MoveTo(0, h.saturating_sub(3)),
        terminal::Clear(terminal::ClearType::CurrentLine),
        SetForegroundColor(Color::Yellow),
        Print(format!("  ! Trust request from \"{}\"  fp: {}…",
            crate::ui::sanitize_display(&req.from_nickname), fp_short)),
        ResetColor,
        cursor::MoveTo(0, h.saturating_sub(2)),
        terminal::Clear(terminal::ClearType::CurrentLine),
        SetForegroundColor(Color::DarkGrey),
        Print("    [T] Trust   [D] Defer (handle later)   [R] Reject"),
        ResetColor,
        cursor::RestorePosition,
    )?;
    out.flush()?;
    Ok(())
}

fn clear_trust_banner() -> Result<()> {
    use crossterm::{cursor, terminal};
    let (_, h) = terminal::size().unwrap_or((80, 24));
    let mut out = std::io::stdout();
    crossterm::queue!(out,
        cursor::SavePosition,
        cursor::MoveTo(0, h.saturating_sub(3)),
        terminal::Clear(terminal::ClearType::CurrentLine),
        cursor::MoveTo(0, h.saturating_sub(2)),
        terminal::Clear(terminal::ClearType::CurrentLine),
        cursor::RestorePosition,
    )?;
    out.flush()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Trust request accept/reject used by the main menu trust banner
// ---------------------------------------------------------------------------

fn menu_accept_trust(
    storage_dir:   &Path,
    identity:      &PgpIdentity,
    identity_name: &str,
    req:           &PendingTrustRequest,
) {
    let tmp = PersistedContact {
        fingerprint:        req.from_fingerprint.clone(),
        nickname:           req.from_nickname.clone(),
        armored_public_key: req.from_public_key_armored.clone(),
        last_seen:          None,
    };
    if persistence::parse_contact(&tmp).is_err() {
        let mut pending = persistence::load_pending_trust_requests(storage_dir, identity_name, identity);
        pending.retain(|r| r.from_fingerprint != req.from_fingerprint);
        let _ = persistence::save_pending_trust_requests(storage_dir, identity_name, &pending, identity);
        return;
    }
    let mut store = persistence::load_contacts(storage_dir, identity_name, identity);
    if !store.contacts.iter().any(|c| c.fingerprint == req.from_fingerprint) {
        store.contacts.push(PersistedContact {
            fingerprint:        req.from_fingerprint.clone(),
            nickname:           req.from_nickname.clone(),
            armored_public_key: req.from_public_key_armored.clone(),
            last_seen:          Some(Utc::now()),
        });
        let _ = persistence::save_contacts(storage_dir, identity_name, &store, identity);
    }
    let mut pending = persistence::load_pending_trust_requests(storage_dir, identity_name, identity);
    pending.retain(|r| r.from_fingerprint != req.from_fingerprint);
    let _ = persistence::save_pending_trust_requests(storage_dir, identity_name, &pending, identity);
}

fn menu_reject_trust(
    storage_dir:   &Path,
    identity:      &PgpIdentity,
    identity_name: &str,
    req:           &PendingTrustRequest,
) {
    let mut pending = persistence::load_pending_trust_requests(storage_dir, identity_name, identity);
    pending.retain(|r| r.from_fingerprint != req.from_fingerprint);
    let _ = persistence::save_pending_trust_requests(storage_dir, identity_name, &pending, identity);

    let mut store: PersistedTrustStore = persistence::load_contacts(storage_dir, identity_name, identity);
    if !store.rejected.contains(&req.from_fingerprint) {
        store.rejected.push(req.from_fingerprint.clone());
        let _ = persistence::save_contacts(storage_dir, identity_name, &store, identity);
    }
}
