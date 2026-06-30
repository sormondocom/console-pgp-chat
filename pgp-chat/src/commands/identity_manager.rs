//! Manage multiple stored PGP identities: list, create, import, view, delete.

use anyhow::{Context, Result};
use chrono::Utc;
use pgp_chat_core::{
    crypto::identity::PgpIdentity,
    persistence::{self, AppConfig, IdentityEntry},
};
use std::io::{stdout, Write};
use std::path::Path;
use crate::ui::Ui;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn run(ui: &Ui, storage_dir: &Path, config: &mut AppConfig) -> Result<()> {
    loop {
        let entries = persistence::load_identity_entries(&config.identities_dir);

        ui.clear()?;
        ui.renderer.draw_box_top("Manage Identities")?;

        if entries.is_empty() {
            println!("  No identities stored.  Use [n] to create your first identity.\r");
        } else {
            println!(
                "  {:<3}  {:<20}  {:<18}  {}\r",
                "#", "Name", "Nickname", "Fingerprint (first 16 chars)"
            );
            ui.renderer.draw_box_separator()?;
            for (i, e) in entries.iter().enumerate() {
                let fp_short = format!("{}…", &e.fingerprint[..16.min(e.fingerprint.len())]);
                let active   = if config.active_identity.as_deref() == Some(&e.name) {
                    "  ◀ active"
                } else {
                    ""
                };
                println!(
                    "  [{:<2}]  {:<20}  {:<18}  {}{}\r",
                    i + 1, e.name, e.nickname, fp_short, active
                );
            }
            println!("\r");
            println!("  Enter a number to view details / set as active\r");
        }

        ui.renderer.draw_box_separator()?;
        println!("  [n] New identity\r");
        println!("  [i] Import existing PGP secret key\r");
        if !entries.is_empty() {
            println!("  [d] Delete an identity\r");
        }
        println!("  [0] Back\r");
        ui.renderer.draw_box_bottom()?;
        stdout().flush()?;
        crate::sidebar::draw_auto(storage_dir, ui);

        let choice = ui.prompt("Choice:")?;
        let choice = choice.trim().to_lowercase();

        match choice.as_str() {
            "0" | "" => return Ok(()),
            "n"      => create_identity(ui, config, storage_dir)?,
            "i"      => import_identity(ui, config, storage_dir)?,
            "d" if !entries.is_empty() => delete_identity(ui, config, &entries, storage_dir)?,
            _ => {
                if let Ok(idx) = choice.parse::<usize>() {
                    if idx >= 1 && idx <= entries.len() {
                        identity_detail(ui, config, &entries[idx - 1], storage_dir)?;
                    } else {
                        ui.error("Invalid number.")?;
                        ui.wait_for_key("Press any key...")?;
                    }
                } else {
                    ui.error("Unknown choice.")?;
                    ui.wait_for_key("Press any key...")?;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Create a new identity
// ---------------------------------------------------------------------------

fn create_identity(ui: &Ui, config: &mut AppConfig, storage_dir: &Path) -> Result<()> {
    ui.renderer.draw_box_top("New Identity")?;
    println!("  Generates a fresh PGP keypair:\r");
    println!("    Primary key: EdDSA (sign + certify)\r");
    println!("    Subkey:      ECDH Curve25519 (encrypt)\r");
    println!("\r");

    let entries = persistence::load_identity_entries(&config.identities_dir);

    // Unique name slug
    let name = prompt_unique_name(ui, &entries, "Identity name (unique label e.g. \"work\", \"personal\"):")?;
    if name.is_empty() {
        return Ok(());
    }

    let nickname = ui.prompt("Display nickname (shown to peers in chat):")?;
    let nickname = if nickname.trim().is_empty() { name.clone() } else { nickname.trim().to_string() };

    println!("\r");
    println!("  A passphrase encrypts your secret key on disk.\r");
    println!("  Leave blank for no protection (not recommended).\r");
    let passphrase = ui.prompt_password("Passphrase (blank = none):")?;
    if !passphrase.is_empty() {
        let confirm = ui.prompt_password("Confirm passphrase:")?;
        if *passphrase != *confirm {
            ui.error("Passphrases do not match — cancelled.")?;
            ui.wait_for_key("Press any key...")?;
            return Ok(());
        }
    }

    println!("  Generating EdDSA + ECDH keypair for \"{}\"…\r", nickname);

    let identity = PgpIdentity::generate(&nickname, passphrase)
        .map_err(|e| anyhow::anyhow!("Key generation failed: {e}"))?;

    persist_identity(ui, config, storage_dir, &name, &nickname, &identity, &entries)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Import an existing PGP secret key
// ---------------------------------------------------------------------------

fn import_identity(ui: &Ui, config: &mut AppConfig, storage_dir: &Path) -> Result<()> {
    ui.renderer.draw_box_top("Import PGP Secret Key")?;
    println!("  Provide your SECRET key file.\r");
    println!("  The file must begin with:  -----BEGIN PGP PRIVATE KEY BLOCK-----\r");
    println!("  Export from GnuPG:  gpg --export-secret-keys --armor you@email > key.asc\r");
    println!("\r");

    let entries = persistence::load_identity_entries(&config.identities_dir);

    let name = prompt_unique_name(ui, &entries, "Identity name (unique label):")?;
    if name.is_empty() {
        return Ok(());
    }

    let nickname = ui.prompt("Display nickname:")?;
    let nickname = if nickname.trim().is_empty() { name.clone() } else { nickname.trim().to_string() };

    let path = ui.prompt("Path to secret key file (.asc):")?;
    let path = path.trim().to_string();
    if path.is_empty() {
        println!("  Cancelled.\r");
        ui.wait_for_key("Press any key...")?;
        return Ok(());
    }

    let armored = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read '{path}'"))?;

    let identity = loop {
        let passphrase = ui.prompt_password("Key passphrase:")?;
        match PgpIdentity::from_armored_secret_key(&nickname, &armored, passphrase) {
            Ok(id) => break id,
            Err(_) => {
                ui.error("Incorrect passphrase — could not unlock key.")?;
                let retry = ui.prompt("Try again? [y/n]:")?;
                if !retry.trim().eq_ignore_ascii_case("y") {
                    println!("  Import cancelled.\r");
                    return Ok(());
                }
            }
        }
    };

    // Store the imported armored key (the key file the user gave us, not a re-exported copy)
    persistence::save_named_identity(&config.identities_dir, &name, &armored)
        .with_context(|| "Failed to save key to identities directory")?;

    let mut updated = entries;
    updated.push(IdentityEntry {
        name:        name.clone(),
        nickname:    nickname.clone(),
        fingerprint: identity.fingerprint(),
        created_at:  Utc::now(),
    });
    persistence::save_identity_entries(&config.identities_dir, &updated)
        .with_context(|| "Failed to update identity index")?;

    let key_path = persistence::identity_file_path(&config.identities_dir, &name);
    ui.success(&format!("Identity '{}' imported.", name))?;
    ui.info("Fingerprint", &identity.fingerprint())?;
    ui.info("Key file",    &key_path.display().to_string())?;

    maybe_set_active(ui, config, storage_dir, &name, &updated)?;
    ui.wait_for_key("Press any key to continue...")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// View identity details / set as active
// ---------------------------------------------------------------------------

fn identity_detail(ui: &Ui, config: &mut AppConfig, entry: &IdentityEntry, storage_dir: &Path) -> Result<()> {
    ui.renderer.draw_box_top("Identity Details")?;
    ui.info("Name",        &entry.name)?;
    ui.info("Nickname",    &entry.nickname)?;
    ui.info("Fingerprint", &entry.fingerprint)?;
    ui.info("Created",     &entry.created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string())?;
    let status = if config.active_identity.as_deref() == Some(&entry.name) {
        "active"
    } else {
        "not active"
    };
    ui.info("Status", status)?;
    ui.renderer.draw_box_bottom()?;

    if config.active_identity.as_deref() != Some(&entry.name) {
        let answer = ui.prompt("Set as active identity? [y/n]:")?;
        if answer.trim().eq_ignore_ascii_case("y") {
            config.active_identity = Some(entry.name.clone());
            persistence::save_config(storage_dir, config)
                .with_context(|| "Failed to save config")?;
            ui.success(&format!("'{}' is now the active identity.", entry.name))?;
        }
    }

    ui.wait_for_key("Press any key to continue...")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Delete an identity
// ---------------------------------------------------------------------------

fn delete_identity(
    ui:          &Ui,
    config:      &mut AppConfig,
    entries:     &[IdentityEntry],
    storage_dir: &Path,
) -> Result<()> {
    ui.renderer.draw_box_top("Delete Identity")?;
    for (i, e) in entries.iter().enumerate() {
        let active = if config.active_identity.as_deref() == Some(&e.name) { "  [active]" } else { "" };
        println!("  [{}] {}  ({})  fp: {}…{}\r", i + 1, e.name, e.nickname, &e.fingerprint[..8], active);
    }
    ui.renderer.draw_box_bottom()?;

    let choice = ui.prompt("Number to delete [0 to cancel]:")?;
    let choice = choice.trim().to_string();
    if choice == "0" || choice.is_empty() {
        return Ok(());
    }

    let idx = match choice.parse::<usize>() {
        Ok(i) if i >= 1 && i <= entries.len() => i - 1,
        _ => {
            ui.error("Invalid number.")?;
            ui.wait_for_key("Press any key...")?;
            return Ok(());
        }
    };

    let entry = &entries[idx];
    let confirm = ui.prompt(&format!(
        "Permanently delete '{}' ({})? Type YES to confirm:", entry.name, entry.nickname
    ))?;
    if !confirm.trim().eq_ignore_ascii_case("yes") {
        println!("  Cancelled.\r");
        ui.wait_for_key("Press any key...")?;
        return Ok(());
    }

    // Remove key file
    let key_path = persistence::identity_file_path(&config.identities_dir, &entry.name);
    if key_path.exists() {
        std::fs::remove_file(&key_path)
            .with_context(|| "Failed to delete key file")?;
    }

    // Update index
    let remaining: Vec<_> = entries.iter()
        .filter(|e| e.name != entry.name)
        .cloned()
        .collect();
    persistence::save_identity_entries(&config.identities_dir, &remaining)
        .with_context(|| "Failed to update index")?;

    // Clear or reassign the active pointer
    if config.active_identity.as_deref() == Some(&entry.name) {
        config.active_identity = remaining.first().map(|e| e.name.clone());
        persistence::save_config(storage_dir, config)
            .with_context(|| "Failed to save config")?;
        match &config.active_identity {
            Some(n) => ui.success(&format!("Active identity changed to '{}'.", n))?,
            None    => println!("  No identities remaining.  Create one before starting chat.\r"),
        }
    }

    ui.success(&format!("Identity '{}' deleted.", entry.name))?;
    ui.wait_for_key("Press any key...")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Prompt for a name slug that is unique within the existing entries.
///
/// Returns an empty string if the user cancels (enters nothing after being
/// told the name is taken).
fn prompt_unique_name(ui: &Ui, entries: &[IdentityEntry], prompt: &str) -> Result<String> {
    loop {
        let n = ui.prompt(prompt)?;
        let n = n.trim().to_string();
        if n.is_empty() {
            println!("  Cancelled.\r");
            return Ok(String::new());
        }
        if !n.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            ui.error("Name may only contain letters, digits, hyphens, and underscores.")?;
            continue;
        }
        if entries.iter().any(|e| e.name == n) {
            ui.error(&format!("Name '{}' is already taken — choose another.", n))?;
            continue;
        }
        return Ok(n);
    }
}

/// Save a freshly generated identity, update the index, offer to set active.
fn persist_identity(
    ui:          &Ui,
    config:      &mut AppConfig,
    storage_dir: &Path,
    name:        &str,
    nickname:    &str,
    identity:    &PgpIdentity,
    existing:    &[IdentityEntry],
) -> Result<()> {
    let armored_sk = identity.secret_key_armored()
        .map_err(|e| anyhow::anyhow!("Failed to export key: {e}"))?;

    persistence::save_named_identity(&config.identities_dir, name, &armored_sk)
        .with_context(|| "Failed to save key file")?;

    let mut updated = existing.to_vec();
    updated.push(IdentityEntry {
        name:        name.to_owned(),
        nickname:    nickname.to_owned(),
        fingerprint: identity.fingerprint(),
        created_at:  Utc::now(),
    });
    persistence::save_identity_entries(&config.identities_dir, &updated)
        .with_context(|| "Failed to update identity index")?;

    let key_path = persistence::identity_file_path(&config.identities_dir, name);
    ui.success(&format!("Identity '{}' created.", name))?;
    ui.info("Nickname",    nickname)?;
    ui.info("Fingerprint", &identity.fingerprint())?;
    ui.info("Key file",    &key_path.display().to_string())?;

    maybe_set_active(ui, config, storage_dir, name, &updated)?;
    ui.wait_for_key("Press any key to continue...")?;
    Ok(())
}

/// If no active identity is set, set this one automatically.
/// Otherwise, offer the user the choice.
fn maybe_set_active(
    ui:          &Ui,
    config:      &mut AppConfig,
    storage_dir: &Path,
    name:        &str,
    entries:     &[IdentityEntry],
) -> Result<()> {
    let should_set = if config.active_identity.is_none() {
        true
    } else {
        let answer = ui.prompt(&format!("Set '{}' as the active identity? [y/n]:", name))?;
        answer.trim().eq_ignore_ascii_case("y")
    };

    if should_set {
        config.active_identity = Some(name.to_owned());
        persistence::save_config(storage_dir, config)
            .with_context(|| "Failed to save config")?;
        ui.success(&format!("'{}' is now the active identity.", name))?;
    }
    let _ = entries; // suppress unused-var warning
    Ok(())
}
