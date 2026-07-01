use std::io::{stdout, Write};
use std::path::Path;

use anyhow::Result;
use chrono::Utc;
use pgp_chat_core::persistence::{
    self, AppConfig, PersistedContact, PersistedTrustStore,
};

use crate::ui::Ui;

pub fn run(ui: &Ui, storage_dir: &Path, config: &AppConfig) -> Result<()> {
    let identity_name = config.active_identity.as_deref().unwrap_or("");
    loop {
        let store    = persistence::load_contacts(storage_dir, identity_name);
        let mut pending = persistence::load_pending_trust_requests(storage_dir, identity_name);

        ui.clear()?;
        ui.renderer.draw_box_top("Contacts & Trust")?;

        println!("  Trusted contacts ({}):\r", store.contacts.len());
        if store.contacts.is_empty() {
            println!("    (none yet)\r");
        } else {
            for c in &store.contacts {
                let fp = &c.fingerprint[..c.fingerprint.len().min(16)];
                println!("    {} — {}…\r", c.nickname, fp);
            }
        }

        println!("\r");

        if pending.is_empty() {
            println!("  No pending trust requests.\r");
        } else {
            println!("  Pending trust requests:\r");
            ui.renderer.draw_box_separator()?;
            let now = Utc::now();
            for (i, req) in pending.iter().enumerate() {
                let mins = (now - req.received_at).num_minutes();
                let fp   = &req.from_fingerprint[..req.from_fingerprint.len().min(8)];
                let age  = if mins < 1 {
                    "just now".to_string()
                } else if mins == 1 {
                    "1 min ago".to_string()
                } else {
                    format!("{} min ago", mins)
                };
                println!(
                    "  [{}] {} — fp: {}… — {}\r",
                    i + 1, crate::ui::sanitize_display(&req.from_nickname), fp, age
                );
            }
        }

        println!("\r");
        ui.renderer.draw_box_separator()?;
        if !pending.is_empty() {
            println!("  Enter a number to view details, then [a]ccept or [r]eject.\r");
        }
        println!("  [0] Back\r");
        ui.renderer.draw_box_bottom()?;
        stdout().flush()?;
        crate::sidebar::draw_auto(storage_dir, ui);

        let choice = ui.prompt("Choice:")?;
        let choice = choice.trim().to_string();

        if choice == "0" || choice.is_empty() {
            return Ok(());
        }

        if !pending.is_empty() {
            if let Ok(n) = choice.parse::<usize>() {
                if n >= 1 && n <= pending.len() {
                    let idx = n - 1;
                    let req = pending[idx].clone();

                    ui.clear()?;
                    ui.renderer.draw_box_top("Trust Request Detail")?;
                    println!("  Nickname    : {}\r", crate::ui::sanitize_display(&req.from_nickname));
                    println!("  Fingerprint : {}\r", req.from_fingerprint);
                    println!("  Received    : {}\r", req.received_at.format("%Y-%m-%d %H:%M UTC"));
                    println!("\r");
                    println!("  [a] Accept — add to trusted contacts\r");
                    println!("  [r] Reject — add fingerprint to rejected list\r");
                    println!("  [0] Cancel\r");
                    ui.renderer.draw_box_bottom()?;
                    stdout().flush()?;

                    let action = ui.prompt("Action:")?;
                    let action = action.trim().to_lowercase();

                    match action.as_str() {
                        "a" => {
                            let tmp = PersistedContact {
                                fingerprint:        req.from_fingerprint.clone(),
                                nickname:           req.from_nickname.clone(),
                                armored_public_key: req.from_public_key_armored.clone(),
                                last_seen:          None,
                            };
                            if let Err(e) = persistence::parse_contact(&tmp) {
                                ui.error(&format!("Key fingerprint mismatch — request is invalid: {e}"))?;
                                pending.remove(idx);
                                persistence::save_pending_trust_requests(storage_dir, identity_name, &pending)?;
                                ui.wait_for_key("Press any key...")?;
                                continue;
                            }

                            let mut store = persistence::load_contacts(storage_dir, identity_name);
                            let already = store.contacts.iter()
                                .any(|c| c.fingerprint == req.from_fingerprint);
                            if !already {
                                store.contacts.push(PersistedContact {
                                    fingerprint:        req.from_fingerprint.clone(),
                                    nickname:           req.from_nickname.clone(),
                                    armored_public_key: req.from_public_key_armored.clone(),
                                    last_seen:          Some(Utc::now()),
                                });
                                persistence::save_contacts(storage_dir, identity_name, &store)?;
                            }
                            pending.remove(idx);
                            persistence::save_pending_trust_requests(storage_dir, identity_name, &pending)?;
                            ui.success(&format!("Accepted trust from {}.", req.from_nickname))?;
                            println!("  Note: they won't have you as a contact yet.\r");
                            println!("  Open Scan for Peers (menu 4) and press [T] to\r");
                            println!("  broadcast your identity so they can add you back.\r");
                            ui.wait_for_key("Press any key...")?;
                        }
                        "r" => {
                            let mut store: PersistedTrustStore = persistence::load_contacts(storage_dir, identity_name);
                            if !store.rejected.contains(&req.from_fingerprint) {
                                store.rejected.push(req.from_fingerprint.clone());
                                persistence::save_contacts(storage_dir, identity_name, &store)?;
                            }
                            pending.remove(idx);
                            persistence::save_pending_trust_requests(storage_dir, identity_name, &pending)?;
                            ui.error(&format!("Rejected trust from {}.", req.from_nickname))?;
                            ui.wait_for_key("Press any key...")?;
                        }
                        _ => {}
                    }
                    continue;
                }
            }
        }

        ui.error("Invalid choice.")?;
        ui.wait_for_key("Press any key...")?;
    }
}
