//! Manage persisted rooms: list, add, view details, rename, update passphrase, forget.

use anyhow::{Context, Result};
use pgp_chat_core::persistence::{self, PersistedRoom};
use std::io::{stdout, Write};
use std::path::Path;
use crate::ui::Ui;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn run(ui: &Ui, storage_dir: &Path) -> Result<()> {
    loop {
        let rooms = persistence::load_rooms(storage_dir);

        ui.clear()?;
        ui.renderer.draw_box_top("Manage Rooms")?;

        if rooms.is_empty() {
            println!("  No rooms saved yet.  Use [n] to add one.\r");
        } else {
            println!("  {:<3}  {:<26}  {}\r", "#", "Room Name", "Role");
            ui.renderer.draw_box_separator()?;
            for (i, r) in rooms.iter().enumerate() {
                let role = if r.is_owner { "owner" } else { "member" };
                println!("  [{:<2}]  {:<26}  {}\r", i + 1, r.name, role);
            }
        }

        ui.renderer.draw_box_separator()?;
        println!("  [c] Create Room   (set or generate a passphrase — you become the owner)\r");
        println!("  [j] Join Room     (enter a passphrase someone shared with you)\r");
        if !rooms.is_empty() {
            println!("  Enter a number to view / edit details\r");
            println!("  [f] Forget a room\r");
        }
        println!("  [0] Back\r");
        ui.renderer.draw_box_bottom()?;
        stdout().flush()?;

        let choice = ui.prompt("Choice:")?;
        let choice = choice.trim().to_lowercase();

        match choice.as_str() {
            "0" | "" => return Ok(()),
            "c"      => create_room(ui, storage_dir, &rooms)?,
            "j"      => join_room(ui, storage_dir, &rooms)?,
            "f" if !rooms.is_empty() => forget_room(ui, storage_dir, &rooms)?,
            _ => {
                if let Ok(idx) = choice.parse::<usize>() {
                    if idx >= 1 && idx <= rooms.len() {
                        room_detail(ui, storage_dir, idx - 1)?;
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
// Create a new room (owner sets or generates the passphrase)
// ---------------------------------------------------------------------------

fn create_room(ui: &Ui, storage_dir: &Path, existing: &[PersistedRoom]) -> Result<()> {
    ui.renderer.draw_box_top("Create Room")?;
    println!("  You can choose your own passphrase or let the app generate one.\r");
    println!("  Share it out-of-band with peers before they try to join.\r");
    println!("\r");

    let name = prompt_unique_room_name(ui, existing)?;
    if name.is_empty() {
        return Ok(());
    }

    println!("\r");
    let input = ui.prompt_password("Room passphrase [blank = generate one]:")?;
    let passphrase = if input.is_empty() {
        let mut raw = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut raw);
        hex::encode(raw)
    } else {
        input.as_str().to_owned()
    };

    println!("\r");
    ui.show_passphrase_box("Room Passphrase — share this with your peers", &passphrase);
    println!("  Anyone without this passphrase cannot read room traffic.\r");

    let mut rooms = persistence::load_rooms(storage_dir);
    rooms.push(PersistedRoom { name: name.clone(), passphrase, is_owner: true });
    persistence::save_rooms(storage_dir, &rooms)
        .with_context(|| "Failed to save rooms")?;

    ui.success(&format!("Room '{}' created — you are the owner.", name))?;
    ui.wait_for_key("Press any key to continue...")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Join an existing room (member enters the owner's passphrase)
// ---------------------------------------------------------------------------

fn join_room(ui: &Ui, storage_dir: &Path, existing: &[PersistedRoom]) -> Result<()> {
    ui.renderer.draw_box_top("Join Room")?;
    println!("  Enter the room name and passphrase that the room owner shared with you.\r");
    println!("\r");

    let name = prompt_unique_room_name(ui, existing)?;
    if name.is_empty() {
        return Ok(());
    }

    let input = ui.prompt_password("Room passphrase:")?;
    if input.is_empty() {
        ui.error("A passphrase is required to join a room. Use [c] to create a new room instead.")?;
        ui.wait_for_key("Press any key...")?;
        return Ok(());
    }

    let mut rooms = persistence::load_rooms(storage_dir);
    rooms.push(PersistedRoom {
        name:       name.clone(),
        passphrase: input.as_str().to_owned(),
        is_owner:   false,
    });
    persistence::save_rooms(storage_dir, &rooms)
        .with_context(|| "Failed to save rooms")?;

    ui.success(&format!("Room '{}' saved — you are a member.", name))?;
    ui.wait_for_key("Press any key to continue...")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Shared helper — prompt for a room name that doesn't already exist
// ---------------------------------------------------------------------------

fn prompt_unique_room_name(ui: &Ui, existing: &[PersistedRoom]) -> Result<String> {
    let name = ui.prompt("Room name [blank to cancel]:")?;
    let name = name.trim().to_string();
    if name.is_empty() {
        println!("  Cancelled.\r");
        ui.wait_for_key("Press any key...")?;
        return Ok(String::new());
    }
    if existing.iter().any(|r| r.name == name) {
        ui.error(&format!("'{}' is already in your room list.", name))?;
        ui.wait_for_key("Press any key...")?;
        return Ok(String::new());
    }
    Ok(name)
}

// ---------------------------------------------------------------------------
// Room detail / edit
// ---------------------------------------------------------------------------

fn room_detail(ui: &Ui, storage_dir: &Path, idx: usize) -> Result<()> {
    loop {
        let rooms = persistence::load_rooms(storage_dir);
        if idx >= rooms.len() {
            return Ok(());
        }
        let r = &rooms[idx];

        ui.clear()?;
        ui.renderer.draw_box_top("Room Details")?;
        ui.info("Name",       &r.name)?;
        ui.info("Role",       if r.is_owner { "owner" } else { "member" })?;
        ui.info("Passphrase", &"*".repeat(r.passphrase.len().min(32)))?;
        ui.renderer.draw_box_separator()?;
        println!("  [s] Show passphrase\r");
        println!("  [n] Rename room\r");
        println!("  [p] Update passphrase\r");
        println!("  [0] Back\r");
        ui.renderer.draw_box_bottom()?;
        stdout().flush()?;

        let choice = ui.prompt("Choice:")?;
        match choice.trim().to_lowercase().as_str() {
            "0" | "" => return Ok(()),
            "s"      => show_passphrase(ui, storage_dir, idx)?,
            "n"      => { rename_room(ui, storage_dir, idx)?; }
            "p"      => { update_passphrase(ui, storage_dir, idx)?; }
            _        => {
                ui.error("Unknown choice.")?;
                ui.wait_for_key("Press any key...")?;
            }
        }
    }
}

fn show_passphrase(ui: &Ui, storage_dir: &Path, idx: usize) -> Result<()> {
    let rooms = persistence::load_rooms(storage_dir);
    if idx >= rooms.len() {
        return Ok(());
    }
    let r = &rooms[idx];
    println!("\r");
    ui.show_passphrase_box(&format!("Passphrase for '{}'", r.name), &r.passphrase);
    println!("  Share this out-of-band with peers who need to join the room.\r");
    ui.wait_for_key("Press any key to continue...")?;
    Ok(())
}

fn rename_room(ui: &Ui, storage_dir: &Path, idx: usize) -> Result<()> {
    let mut rooms = persistence::load_rooms(storage_dir);
    if idx >= rooms.len() {
        return Ok(());
    }
    let old_name = rooms[idx].name.clone();

    let new_name = ui.prompt(&format!("New name for '{}' [blank to cancel]:", old_name))?;
    let new_name = new_name.trim().to_string();
    if new_name.is_empty() {
        println!("  Cancelled.\r");
        ui.wait_for_key("Press any key...")?;
        return Ok(());
    }
    if rooms.iter().any(|r| r.name == new_name) {
        ui.error(&format!("A room named '{}' already exists.", new_name))?;
        ui.wait_for_key("Press any key...")?;
        return Ok(());
    }

    rooms[idx].name = new_name.clone();
    persistence::save_rooms(storage_dir, &rooms)
        .with_context(|| "Failed to save rooms")?;
    ui.success(&format!("Room renamed from '{}' to '{}'.", old_name, new_name))?;
    ui.wait_for_key("Press any key...")?;
    Ok(())
}

fn update_passphrase(ui: &Ui, storage_dir: &Path, idx: usize) -> Result<()> {
    let mut rooms = persistence::load_rooms(storage_dir);
    if idx >= rooms.len() {
        return Ok(());
    }
    let room_name = rooms[idx].name.clone();

    println!("\r");
    println!("  Enter the NEW passphrase for '{}'.\r", room_name);
    println!("  Leave blank to generate a new one (you become the owner).\r");

    let input = ui.prompt_password("New passphrase [blank = generate]:")?;
    let (passphrase, is_owner) = if input.is_empty() {
        let mut raw = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut raw);
        let generated = hex::encode(raw);
        println!("\r");
        ui.show_passphrase_box("New Room Passphrase", &generated);
        println!("  Share this with all peers before they reconnect.\r");
        (generated, true)
    } else {
        (input.as_str().to_owned(), false)
    };

    rooms[idx].passphrase = passphrase;
    rooms[idx].is_owner   = is_owner;
    persistence::save_rooms(storage_dir, &rooms)
        .with_context(|| "Failed to save rooms")?;
    let role = if is_owner { "owner" } else { "member" };
    ui.success(&format!("Passphrase updated for '{}' ({}).", room_name, role))?;
    ui.wait_for_key("Press any key...")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Forget a room
// ---------------------------------------------------------------------------

fn forget_room(ui: &Ui, storage_dir: &Path, rooms: &[PersistedRoom]) -> Result<()> {
    ui.renderer.draw_box_top("Forget Room")?;
    for (i, r) in rooms.iter().enumerate() {
        let role = if r.is_owner { "owner" } else { "member" };
        println!("  [{}] {}  ({})\r", i + 1, r.name, role);
    }
    ui.renderer.draw_box_bottom()?;
    stdout().flush()?;

    let choice = ui.prompt("Number to forget [0 to cancel]:")?;
    let choice = choice.trim().to_string();
    if choice == "0" || choice.is_empty() {
        return Ok(());
    }

    let idx = match choice.parse::<usize>() {
        Ok(i) if i >= 1 && i <= rooms.len() => i - 1,
        _ => {
            ui.error("Invalid number.")?;
            ui.wait_for_key("Press any key...")?;
            return Ok(());
        }
    };

    let room = &rooms[idx];

    if room.is_owner {
        // Owners confirm with passphrase before removing.
        println!("\r");
        println!("  You are the owner of '{}'.  Confirm with your room passphrase.\r", room.name);
        let entered = ui.prompt_password("Room passphrase:")?;
        if entered.as_str() != room.passphrase {
            ui.error("Incorrect passphrase — cancelled.")?;
            ui.wait_for_key("Press any key...")?;
            return Ok(());
        }
    } else {
        let confirm = ui.prompt(&format!(
            "Remove '{}' from your list? [y/n]:", room.name
        ))?;
        if !confirm.trim().eq_ignore_ascii_case("y") {
            println!("  Cancelled.\r");
            ui.wait_for_key("Press any key...")?;
            return Ok(());
        }
    }

    let room_name = room.name.clone();
    let mut updated = persistence::load_rooms(storage_dir);
    updated.retain(|r| r.name != room_name);
    persistence::save_rooms(storage_dir, &updated)
        .with_context(|| "Failed to save rooms")?;

    ui.success(&format!("Room '{}' removed from your list.", room_name))?;
    ui.wait_for_key("Press any key...")?;
    Ok(())
}
