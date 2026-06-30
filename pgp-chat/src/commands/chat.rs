//! Secure P2P chat session: start a node, join a room, exchange encrypted messages.
//!
//! Uses `tokio::select!` to poll both:
//!   - `crossterm::event::EventStream` (keyboard input)
//!   - `ChatRoomHandle::event_rx` (gossipsub messages, peer events)
//!
//! ## Chat commands
//!
//! Type a message and press Enter to send.  To run a command, start the line
//! with `/`.  Type `/help` at any time for the full list.
//!
//! | Command              | Action                                          |
//! |----------------------|-------------------------------------------------|
//! | /help                | List available commands                         |
//! | /quit                | Disconnect and return to the main menu          |
//! | /peers               | Show connected peer list                        |
//! | /rooms               | Manage rooms (switch / join / leave / delete)   |
//! | /join <room>         | Switch to a room by name                        |
//! | /trust [fp]          | Approve last pending key, or a fingerprint      |
//! | /deny [fp]           | Deny last pending key, or a fingerprint         |
//! | /trustall            | Approve all pending keys at once                |
//! | /defer               | Toggle key deferral mode on/off                 |
//! | /send                | Send a file to a peer (prompts interactively)   |
//! | /accept [path]       | Accept an incoming file offer                   |
//! | /decline             | Decline an incoming file offer                  |
//! | /admit [fp]          | Vote YES on a pending room join request         |
//! | /veto [fp]           | Vote NO on a pending room join request          |
//! | /nuke                | Wipe identity and broadcast revocation          |
//! | Ctrl-C / Ctrl-D      | Quit                                            |

use anyhow::{Context, Result};
use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::style::Color;
use futures::StreamExt;
use libp2p::identity::Keypair;
use std::collections::{HashMap, HashSet};
use std::io::{stdout, Write};
use std::path::Path;
use std::sync::Mutex;
use crossterm::{cursor, execute, queue, style::{Print, ResetColor, SetForegroundColor}};
use zeroize::Zeroizing;

// Mutable system-message color set once per chat session from the active theme.
static SYSTEM_COLOR: Mutex<Color> = Mutex::new(Color::DarkGrey);

fn set_system_color(c: Color) {
    if let Ok(mut g) = SYSTEM_COLOR.lock() { *g = c; }
}
use pgp_chat_core::{
    chat::{
        keystore::PeerKeyStore,
        message::{MessageKind, SignedChatMessage},
        room::{ChatRoom, RoomCommand},
    },
    crypto::identity::PgpIdentity,
    network::transport,
    persistence::{self, AppConfig, PersistedRoom, PersistedTrustStore},
};
use crate::ui::Ui;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Launch a chat session.
///
/// `direct` is `Some((room, bootstrap_addr))` when called from the peer
/// scanner — the room and the peer's address are already known, so the
/// interactive room-selection and bootstrap-address prompts are skipped.
/// Pass `None` for the normal menu flow.
pub async fn run(
    ui:          &Ui,
    storage_dir: &Path,
    config:      &AppConfig,
    direct:      Option<(PersistedRoom, Option<libp2p::Multiaddr>)>,
) -> Result<()> {
    // Apply the active theme's system-message color for this session.
    set_system_color(ui.renderer.palette().chat_system);

    ui.renderer.draw_box_top("Secure Chat")?;

    // ── PGP identity ───────────────────────────────────────────────────────
    let pgp_identity = match load_startup_identity(ui, config)? {
        Some(id) => id,
        None     => return Ok(()),
    };
    ui.info("PGP Fingerprint", &pgp_identity.fingerprint())?;

    // ── Load persisted contacts ────────────────────────────────────────────
    let persisted_contacts = persistence::load_contacts(&storage_dir);
    let (initial_keystore, loaded_count, failed_count) = build_keystore(&persisted_contacts);

    if loaded_count > 0 {
        ui.info(
            "Loaded contacts",
            &format!("{} trusted, {} rejected", loaded_count, persisted_contacts.rejected.len()),
        )?;
        if failed_count > 0 {
            println!("  [!] {} contact(s) could not be loaded (key parse error).\r", failed_count);
        }
        println!("  Previously-trusted peers will be recognised automatically when they reconnect.\r");
    }

    // ── Load known rooms ───────────────────────────────────────────────────
    let mut known_rooms: Vec<PersistedRoom> = persistence::load_rooms(&storage_dir, Some(&pgp_identity));
    // Re-save immediately so any rooms created before an identity was loaded
    // (e.g. from room_manager when no identity was entered) get encrypted now.
    let _ = persistence::save_rooms(&storage_dir, &known_rooms, Some(&pgp_identity));

    // ── One-time network config ────────────────────────────────────────────
    let port_str = ui.prompt("Listen port [0 = random]:")?;
    let port: u16 = port_str.trim().parse().unwrap_or(0);

    // ── Room + bootstrap — interactive prompts or pre-selected from scanner ─
    let (initial_room, initial_passphrase, initial_is_owner, bootstrap_addr) =
        if let Some((room, bootstrap)) = direct {
            // Peer scanner handed us the room and the peer's address.
            println!("  Room: {}  [{}]\r",
                room.name,
                if room.is_owner { "owner" } else { "member" });
            if let Some(ref addr) = bootstrap {
                println!("  Bootstrap: {} (from peer scanner)\r", addr);
            }
            (
                room.name.clone(),
                Zeroizing::new(persistence::decrypt_room_passphrase(&room.passphrase, &pgp_identity)),
                room.is_owner,
                bootstrap,
            )
        } else {
            // Normal menu flow: interactive room selection then bootstrap prompt.
            let (room_name, pass, is_owner) =
                match select_room_at_startup(ui, &known_rooms)? {
                    Some(r) => r,
                    None    => return Ok(()),
                };
            let bootstrap_input = ui.prompt("Bootstrap peer multiaddr [leave blank to skip]:")?;
            let addr = if bootstrap_input.trim().is_empty() {
                None
            } else {
                match bootstrap_input.trim().parse::<libp2p::Multiaddr>() {
                    Ok(a)  => { ui.success(&format!("Dialling {}", a))?; Some(a) }
                    Err(_) => { ui.error("Invalid multiaddr — skipping bootstrap")?; None }
                }
            };
            (room_name, pass, is_owner, addr)
        };

    // ── Room-switching outer loop ──────────────────────────────────────────
    let mut current_room = initial_room;
    let mut current_pass = initial_passphrase;
    let mut current_is_owner = initial_is_owner;
    let mut current_keystore = initial_keystore;

    'room_loop: loop {
        // Persist this room if we haven't seen it before
        if !known_rooms.iter().any(|r| r.name == current_room) {
            known_rooms.push(PersistedRoom {
                name:       current_room.clone(),
                passphrase: current_pass.as_str().to_owned(),
                is_owner:   current_is_owner,
            });
            let _ = persistence::save_rooms(&storage_dir, &known_rooms, Some(&pgp_identity));
        }

        // ── Build a fresh swarm for this session ───────────────────────────
        println!("  Generating ephemeral libp2p keypair...\r");
        let libp2p_keypair = Keypair::generate_ed25519();
        let local_peer_id = libp2p_keypair.public().to_peer_id();

        ui.info("Local Peer ID", &local_peer_id.to_string())?;

        println!("  Building swarm (TCP + QUIC)...\r");
        let mut swarm = transport::build_swarm(libp2p_keypair)
            .map_err(|e| anyhow::anyhow!("swarm build failed: {e}"))?;

        let tcp_addr = format!("/ip4/0.0.0.0/tcp/{}", port)
            .parse()
            .context("invalid TCP multiaddr")?;
        let quic_addr = format!("/ip4/0.0.0.0/udp/{}/quic-v1", port)
            .parse()
            .context("invalid QUIC multiaddr")?;

        swarm.listen_on(tcp_addr).context("failed to start TCP listener")?;
        swarm.listen_on(quic_addr).context("failed to start QUIC listener")?;

        if let Some(ref addr) = bootstrap_addr {
            match swarm.dial(addr.clone()) {
                Ok(()) => { let _ = ui.success(&format!("Dialling {}", addr)); }
                Err(e) => { let _ = ui.error(&format!("Dial failed: {e}")); }
            }
        }

        // ── Room header ────────────────────────────────────────────────────
        let role_tag = if current_is_owner { "owner" } else { "member" };
        ui.renderer.draw_box_separator()?;
        println!("  Room: {}  [{}]\r", current_room, role_tag);
        println!("  Type a message and Enter to send.  Start with / for commands (/help for list).\r");
        ui.renderer.draw_box_separator()?;
        stdout().flush()?;

        // ── Start the room ─────────────────────────────────────────────────
        let (room, mut handle) = ChatRoom::new(
            swarm,
            &current_room,
            pgp_identity.clone(),
            current_pass.clone(),
            current_keystore,
        );
        let room_task = tokio::spawn(room.run());
        tokio::pin!(room_task);

        // ── Per-session UI state ───────────────────────────────────────────
        let mut input_buf      = String::new();
        let mut cmd_mode       = false;
        let mut peer_index     = 0usize;
        let mut is_deferring   = false;
        let mut last_pending: Option<(String, String)> = None;
        let mut last_admission: Option<(String, String)> = None; // (fp, nickname) for /admit /veto
        let mut last_offer: Option<(uuid::Uuid, String)> = None; // (transfer_id, filename)
        let mut event_stream   = EventStream::new();
        let mut trust_snapshot: Option<PersistedTrustStore> = None;
        let mut pending_switch: Option<(String, Zeroizing<String>, bool)> = None;
        let mut nuked = false;
        // Maps raw nickname → set of fingerprints seen with that nick.
        // When two peers share the same nickname we append a fingerprint
        // suffix to disambiguate in the chat display.
        let mut nick_tracker: HashMap<String, HashSet<String>> = HashMap::new();

        // ── Inner event loop ───────────────────────────────────────────────
        loop {
            tokio::select! {
                // ── Room task exited ───────────────────────────────────────
                result = &mut room_task => {
                    match result {
                        Ok(snapshot) => { trust_snapshot = snapshot; }
                        Err(e) => print_system(&format!("Room task failed: {e}"))?,
                    }
                    break;
                }

                // ── Network / chat events ──────────────────────────────────
                net_evt = handle.event_rx.recv() => {
                    use pgp_chat_core::network::event::ChatNetEvent;
                    match net_evt {
                        Some(ChatNetEvent::ListeningOn(addr)) => {
                            let proto = if addr.to_string().contains("quic") { "QUIC/UDP" } else { "TCP" };
                            print_system(&format!("Listening on {} [{}]", addr, proto))?;
                        }

                        Some(ChatNetEvent::MessageReceived { payload, verified, .. }) => {
                            if let Ok(signed) = serde_json::from_slice::<SignedChatMessage>(&payload) {
                                let m = &signed.message;

                                // Convert the message's UTC timestamp to local wall-clock time.
                                let ts = m.timestamp
                                    .with_timezone(&chrono::Local)
                                    .format("%Y-%m-%d %H:%M:%S")
                                    .to_string();

                                // Track which fingerprints have been seen for this nickname
                                // so we can detect and disambiguate duplicates.
                                nick_tracker
                                    .entry(m.sender_nick.clone())
                                    .or_default()
                                    .insert(m.sender_fp.clone());

                                // Build the display name.
                                // Unverified senders get a [?] prefix.
                                // If two peers share a nickname, append the first 8 hex chars
                                // of the sender's fingerprint so the reader can tell them apart.
                                let has_dupe = nick_tracker
                                    .get(&m.sender_nick)
                                    .map(|fps| fps.len() > 1)
                                    .unwrap_or(false);
                                let fp_suffix = if has_dupe {
                                    format!(" [{}]", &m.sender_fp[..8.min(m.sender_fp.len())])
                                } else {
                                    String::new()
                                };
                                let safe_nick = crate::ui::sanitize_display(&m.sender_nick);
                                let display_nick = if verified {
                                    format!("{}{}", safe_nick, fp_suffix)
                                } else {
                                    format!("[?] {}{}", safe_nick, fp_suffix)
                                };

                                match &m.kind {
                                    MessageKind::Plaintext(text) => {
                                        ui.renderer.draw_message(
                                            &ts,
                                            &display_nick,
                                            text,
                                            verified,
                                            peer_index,
                                        )?;
                                        peer_index = peer_index.wrapping_add(1);
                                    }
                                    MessageKind::Encrypted { recipient_count, .. } => {
                                        print_system(&format!(
                                            "Encrypted message from {} ({} recipients) — decrypt with your key",
                                            display_nick, recipient_count
                                        ))?;
                                    }
                                    MessageKind::AnnounceKey { nickname, .. } => {
                                        let ann_nick = if verified {
                                            format!("{}{}", nickname, fp_suffix)
                                        } else {
                                            format!("[?] {}{}", nickname, fp_suffix)
                                        };
                                        print_system(&format!("{} is announcing their key", ann_nick))?;
                                    }
                                    MessageKind::StatusAnnounce { status } => {
                                        print_system(&format!(
                                            "{} status: {:?}", display_nick, status
                                        ))?;
                                    }
                                    MessageKind::Revoke { fingerprint } => {
                                        print_system(&format!(
                                            "REVOCATION: {} revoked fingerprint {}",
                                            display_nick, fingerprint
                                        ))?;
                                    }
                                    MessageKind::System(text) => {
                                        print_system(text)?;
                                    }
                                    MessageKind::FileOffer { .. }
                                    | MessageKind::FileAccept(_)
                                    | MessageKind::FileDecline(_)
                                    | MessageKind::FileChunk(_)
                                    | MessageKind::FileComplete(_)
                                    | MessageKind::JoinVote { .. } => {}
                                }
                            }
                        }

                        Some(ChatNetEvent::KeyApprovalRequired { fingerprint, nickname, .. }) => {
                            let safe_nick = crate::ui::sanitize_display(&nickname);
                            print_system(&format!(
                                "[?] New key from {} ({}) — /trust to approve, /deny to reject, /trustall for all",
                                safe_nick, fingerprint
                            ))?;
                            last_pending = Some((fingerprint, safe_nick));
                        }

                        Some(ChatNetEvent::JoinApprovalRequired { fingerprint, nickname, voter_count }) => {
                            let safe_nick = crate::ui::sanitize_display(&nickname);
                            print_system(&format!(
                                "[?] {} ({}) wants to join — {} member(s) must unanimously agree.",
                                safe_nick, &fingerprint[..fingerprint.len().min(16)], voter_count
                            ))?;
                            print_system("    Type /admit to approve or /veto to block.")?;
                            last_admission = Some((fingerprint, safe_nick));
                        }

                        Some(ChatNetEvent::JoinDecided { nickname, approved, vetoed_by_nick, .. }) => {
                            let safe_nick = crate::ui::sanitize_display(&nickname);
                            if approved {
                                print_system(&format!("[+] {} has been admitted to the room.", safe_nick))?;
                            } else {
                                let by = vetoed_by_nick
                                    .map(|n| format!(" (vetoed by {})", crate::ui::sanitize_display(&n)))
                                    .unwrap_or_default();
                                print_system(&format!("[-] {} was denied entry{}.", safe_nick, by))?;
                            }
                            if last_admission.as_ref().map(|(_, n)| n == &safe_nick).unwrap_or(false) {
                                last_admission = None;
                            }
                        }

                        Some(ChatNetEvent::DeferredKeysAvailable(n)) => {
                            print_system(&format!(
                                "[d] Deferring mode OFF — {} deferred key(s) pending.  Type /trustall to approve all.",
                                n
                            ))?;
                        }

                        Some(ChatNetEvent::NodeMapSnapshot(nodes)) => {
                            print_system("── Node Map ──────────────────────────────────")?;
                            if nodes.is_empty() {
                                print_system("  (no peers known yet)")?;
                            }
                            for node in &nodes {
                                let trust_s  = format!("{:?}", node.trust);
                                let status_s = format!("{:?}", node.status);
                                let fp_short = &node.fingerprint[..16.min(node.fingerprint.len())];
                                print_system(&format!(
                                    "  {:>9}  {:>10}  {}  {}",
                                    trust_s, status_s, fp_short,
                                    crate::ui::sanitize_display(&node.nickname),
                                ))?;
                            }
                            print_system("──────────────────────────────────────────────")?;
                        }

                        Some(ChatNetEvent::InboundFileOffer {
                            transfer_id, filename, size_bytes, description,
                            sender_fp, sender_nick, sender_addrs,
                        }) => {
                            let safe_nick = crate::ui::sanitize_display(&sender_nick);
                            let safe_filename = crate::ui::sanitize_display(&filename);
                            let safe_desc = crate::ui::sanitize_display(&description);
                            print_system("── Incoming File Transfer ─────────────────────")?;
                            print_system(&format!("  From:        {} ({})", safe_nick, sender_fp))?;
                            print_system(&format!("  File:        {}", safe_filename))?;
                            print_system(&format!("  Size:        {} bytes", size_bytes))?;
                            if !description.is_empty() {
                                print_system(&format!("  Description: {}", safe_desc))?;
                            }
                            if !sender_addrs.is_empty() {
                                print_system(&format!("  Network:     {}", sender_addrs.join(", ")))?;
                            }
                            print_system("  Type /accept to accept (prompts for save path), /decline to reject.")?;
                            print_system("──────────────────────────────────────────────")?;
                            last_offer = Some((transfer_id, safe_filename));
                        }

                        Some(ChatNetEvent::FileReceived { transfer_id: _, filename, save_path }) => {
                            print_system(&format!("[+] File '{}' saved to: {}", filename, save_path))?;
                        }

                        Some(ChatNetEvent::FileDeclined { transfer_id }) => {
                            print_system(&format!(
                                "[-] File offer {} was declined by recipient.", transfer_id
                            ))?;
                        }

                        Some(ChatNetEvent::FileSendProgress { transfer_id, sent_chunks, total_chunks }) => {
                            print_system(&format!(
                                "[~] Sending {} chunk {}/{}", transfer_id, sent_chunks, total_chunks
                            ))?;
                        }

                        Some(ChatNetEvent::FileTransferError { transfer_id, reason }) => {
                            print_system(&format!(
                                "[!] File transfer {} error: {}", transfer_id, reason
                            ))?;
                        }

                        Some(ChatNetEvent::PeerRevoked { fingerprint, nickname }) => {
                            print_system(&format!(
                                "[!] REVOKED: {} ({}) has wiped their identity.", nickname, fingerprint
                            ))?;
                        }

                        Some(ChatNetEvent::NukeComplete) => {
                            nuked = true;
                            print_system(
                                "[!] NUKE complete — all identity material wiped, contacts NOT saved.",
                            )?;
                        }

                        Some(ChatNetEvent::ConnectionEstablished { peer_id, addr }) => {
                            print_system(&format!("+ Peer connected: {} via {}", peer_id, addr))?;
                        }
                        Some(ChatNetEvent::ConnectionClosed(id)) => {
                            print_system(&format!("- Peer disconnected: {}", id))?;
                        }
                        Some(ChatNetEvent::Warning(w)) => {
                            print_system(&format!("[!] {}", w))?;
                        }
                        Some(ChatNetEvent::PeerDiscovered(id)) => {
                            print_system(&format!("~ Discovered peer: {}", id))?;
                        }
                        _ => {}
                    }
                }

                // ── Keyboard input ─────────────────────────────────────────
                term_evt = event_stream.next() => {
                    match term_evt {
                        // On resize, clear stale layout and reprint the room banner
                        // so content doesn't overlap across the old and new widths.
                        Some(Ok(Event::Resize(new_w, _))) => {
                            let main_w = crate::sidebar::main_width(new_w);
                            ui.renderer.set_width(main_w);
                            execute!(stdout(), crossterm::terminal::Clear(crossterm::terminal::ClearType::All), cursor::MoveTo(0, 0))?;
                            let role_tag = if current_is_owner { "owner" } else { "member" };
                            ui.renderer.draw_box_separator()?;
                            println!("  Room: {}  [{}]  — type /help for commands\r", current_room, role_tag);
                            ui.renderer.draw_box_separator()?;
                            stdout().flush()?;
                        }

                        Some(Ok(Event::Key(KeyEvent {
                            code, modifiers, kind: KeyEventKind::Press, ..
                        }))) => {
                            // Ctrl-C / Ctrl-D: always quit regardless of what is typed.
                            if modifiers.contains(KeyModifiers::CONTROL)
                                && matches!(code, KeyCode::Char('c') | KeyCode::Char('d'))
                            {
                                let _ = handle.cmd_tx.send(RoomCommand::Disconnect).await;
                                continue;
                            }

                            match code {
                                // Leading '/' on an empty buffer: enter command mode.
                                KeyCode::Char('/') if input_buf.is_empty() => {
                                    input_buf.push('/');
                                    let pal = ui.renderer.palette();
                                    queue!(
                                        stdout(),
                                        SetForegroundColor(pal.accent),
                                        Print("[CMD] /"),
                                        ResetColor,
                                    )?;
                                    stdout().flush()?;
                                    cmd_mode = true;
                                }

                                // Accumulate typed characters and echo them.
                                KeyCode::Char(c) => {
                                    input_buf.push(c);
                                    queue!(stdout(), Print(c))?;
                                    stdout().flush()?;
                                }

                                // Esc cancels command mode and clears the input line.
                                KeyCode::Esc if cmd_mode => {
                                    let total = 6 + input_buf.len(); // "[CMD] " + buffer
                                    execute!(
                                        stdout(),
                                        cursor::MoveLeft(total as u16),
                                        Print(" ".repeat(total)),
                                        cursor::MoveLeft(total as u16),
                                    )?;
                                    input_buf.clear();
                                    cmd_mode = false;
                                }

                                KeyCode::Backspace if !input_buf.is_empty() => {
                                    input_buf.pop();
                                    if cmd_mode && input_buf.is_empty() {
                                        // Erase "[CMD] /" — 7 visible chars.
                                        execute!(
                                            stdout(),
                                            cursor::MoveLeft(7),
                                            Print("       "),
                                            cursor::MoveLeft(7),
                                        )?;
                                        cmd_mode = false;
                                    } else {
                                        execute!(
                                            stdout(),
                                            cursor::MoveLeft(1),
                                            Print(' '),
                                            cursor::MoveLeft(1),
                                        )?;
                                    }
                                }

                                KeyCode::Enter if !input_buf.is_empty() => {
                                    cmd_mode = false;
                                    let line = std::mem::take(&mut input_buf);
                                    execute!(stdout(), Print("\r\n"))?;

                                    if let Some(cmd_str) = line.strip_prefix('/') {
                                        // ── Slash-command dispatch ─────────────────
                                        let parts: Vec<&str> = cmd_str.splitn(3, ' ').collect();
                                        let verb = parts[0].to_lowercase();
                                        match verb.as_str() {

                                            "help" | "?" => {
                                                print_system("Commands:")?;
                                                print_system("  /quit            — disconnect and return to menu")?;
                                                print_system("  /peers           — list connected peers")?;
                                                print_system("  /rooms           — manage rooms (switch / join / leave / delete)")?;
                                                print_system("  /join <room>     — switch to a room by name")?;
                                                print_system("  /trust [fp]      — approve last pending key, or a specific fingerprint")?;
                                                print_system("  /deny [fp]       — deny last pending key, or a specific fingerprint")?;
                                                print_system("  /trustall        — approve all pending keys at once")?;
                                                print_system("  /defer           — toggle key deferral mode on/off")?;
                                                print_system("  /admit [fp]      — vote YES on pending room join request")?;
                                                print_system("  /veto [fp]       — vote NO on pending room join request")?;
                                                print_system("  /send            — send a file to a peer (prompts interactively)")?;
                                                print_system("  /accept [path]   — accept an incoming file offer")?;
                                                print_system("  /decline         — decline an incoming file offer")?;
                                                print_system("  /nuke            — wipe identity and broadcast revocation")?;
                                            }

                                            "quit" | "q" | "exit" => {
                                                let _ = handle.cmd_tx.send(RoomCommand::Disconnect).await;
                                            }

                                            "peers" | "nodes" | "who" => {
                                                let _ = handle.cmd_tx.send(RoomCommand::GetNodeMap).await;
                                            }

                                            "rooms" => {
                                                if pending_switch.is_some() {
                                                    print_system("Room switch already in progress.")?;
                                                } else {
                                                    match manage_rooms(ui, &mut known_rooms, &current_room)? {
                                                        RoomAction::Switch(name, pass, is_owner) => {
                                                            if !known_rooms.iter().any(|r| r.name == name) {
                                                                known_rooms.push(PersistedRoom {
                                                                    name:       name.clone(),
                                                                    passphrase: pass.as_str().to_owned(),
                                                                    is_owner,
                                                                });
                                                                let _ = persistence::save_rooms(&storage_dir, &known_rooms, Some(&pgp_identity));
                                                            }
                                                            print_system(&format!("Leaving {}...", current_room))?;
                                                            pending_switch = Some((name, pass, is_owner));
                                                            let _ = handle.cmd_tx.send(RoomCommand::Disconnect).await;
                                                        }
                                                        RoomAction::Deleted(name) => {
                                                            print_system(&format!("Room '{}' deleted.", name))?;
                                                            let _ = persistence::save_rooms(&storage_dir, &known_rooms, Some(&pgp_identity));
                                                        }
                                                        RoomAction::Left(name) => {
                                                            print_system(&format!("Left room '{}'.", name))?;
                                                            let _ = persistence::save_rooms(&storage_dir, &known_rooms, Some(&pgp_identity));
                                                        }
                                                        RoomAction::Cancel => {}
                                                    }
                                                }
                                            }

                                            "join" => {
                                                if pending_switch.is_some() {
                                                    print_system("Room switch already in progress.")?;
                                                } else {
                                                    let name = parts.get(1)
                                                        .map(|s| s.trim())
                                                        .filter(|s| !s.is_empty());
                                                    match name {
                                                        None => {
                                                            print_system("Usage: /join <room-name>")?;
                                                            print_system("Use /rooms to browse your room list.")?;
                                                        }
                                                        Some(raw_name) => {
                                                            let name = raw_name.to_string();
                                                            if let Some(r) = known_rooms.iter().find(|r| r.name == name) {
                                                                let stored   = r.passphrase.clone();
                                                                let is_owner = r.is_owner;
                                                                let entered  = ui.prompt_password("Room passphrase:")?;
                                                                if entered.as_str() != stored {
                                                                    print_system("Incorrect passphrase.")?;
                                                                } else {
                                                                    print_system(&format!("Leaving {}...", current_room))?;
                                                                    pending_switch = Some((name, Zeroizing::new(stored), is_owner));
                                                                    let _ = handle.cmd_tx.send(RoomCommand::Disconnect).await;
                                                                }
                                                            } else {
                                                                let (pass, is_owner) = generate_room_passphrase(ui, &name)?;
                                                                known_rooms.push(PersistedRoom {
                                                                    name:       name.clone(),
                                                                    passphrase: pass.as_str().to_owned(),
                                                                    is_owner,
                                                                });
                                                                let _ = persistence::save_rooms(&storage_dir, &known_rooms, Some(&pgp_identity));
                                                                print_system(&format!("Leaving {}...", current_room))?;
                                                                pending_switch = Some((name, pass, is_owner));
                                                                let _ = handle.cmd_tx.send(RoomCommand::Disconnect).await;
                                                            }
                                                        }
                                                    }
                                                }
                                            }

                                            "trust" | "approve" => {
                                                let fp_arg = parts.get(1)
                                                    .map(|s| s.trim())
                                                    .filter(|s| !s.is_empty());
                                                match fp_arg {
                                                    Some(fp) => {
                                                        print_system(&format!("Approving key {}...", fp))?;
                                                        let _ = handle.cmd_tx.send(RoomCommand::ApproveKey(fp.to_string())).await;
                                                    }
                                                    None => {
                                                        if let Some((fp, nick)) = last_pending.take() {
                                                            print_system(&format!("Approving key from {} [{}]...", nick, fp))?;
                                                            let _ = handle.cmd_tx.send(RoomCommand::ApproveKey(fp)).await;
                                                        } else {
                                                            print_system("No pending key to approve.")?;
                                                        }
                                                    }
                                                }
                                            }

                                            "deny" => {
                                                let fp_arg = parts.get(1)
                                                    .map(|s| s.trim())
                                                    .filter(|s| !s.is_empty());
                                                match fp_arg {
                                                    Some(fp) => {
                                                        print_system(&format!("Denying key {}.", fp))?;
                                                        let _ = handle.cmd_tx.send(RoomCommand::DenyKey(fp.to_string())).await;
                                                    }
                                                    None => {
                                                        if let Some((fp, nick)) = last_pending.take() {
                                                            print_system(&format!("Denying key from {} [{}].", nick, fp))?;
                                                            let _ = handle.cmd_tx.send(RoomCommand::DenyKey(fp)).await;
                                                        } else {
                                                            print_system("No pending key to deny.")?;
                                                        }
                                                    }
                                                }
                                            }

                                            "trustall" | "approveall" => {
                                                print_system("Approving all pending keys...")?;
                                                let _ = handle.cmd_tx.send(RoomCommand::ApproveAll).await;
                                                last_pending = None;
                                            }

                                            "defer" => {
                                                is_deferring = !is_deferring;
                                                print_system(&format!(
                                                    "Deferring mode: {}",
                                                    if is_deferring { "ON — new keys will be queued" } else { "OFF" }
                                                ))?;
                                                let _ = handle.cmd_tx.send(RoomCommand::SetDeferring(is_deferring)).await;
                                            }

                                            "admit" => {
                                                let fp_arg = parts.get(1).map(|s| s.trim()).filter(|s| !s.is_empty());
                                                match fp_arg {
                                                    Some(fp) => {
                                                        let _ = handle.cmd_tx.send(RoomCommand::CastVote {
                                                            candidate_fp: fp.to_string(),
                                                            approved: true,
                                                        }).await;
                                                    }
                                                    None => {
                                                        if let Some((fp, nick)) = last_admission.take() {
                                                            print_system(&format!("Voting to admit {}...", nick))?;
                                                            let _ = handle.cmd_tx.send(RoomCommand::CastVote {
                                                                candidate_fp: fp,
                                                                approved: true,
                                                            }).await;
                                                        } else {
                                                            print_system("No pending join request to admit.")?;
                                                        }
                                                    }
                                                }
                                            }

                                            "veto" => {
                                                let fp_arg = parts.get(1).map(|s| s.trim()).filter(|s| !s.is_empty());
                                                match fp_arg {
                                                    Some(fp) => {
                                                        let _ = handle.cmd_tx.send(RoomCommand::CastVote {
                                                            candidate_fp: fp.to_string(),
                                                            approved: false,
                                                        }).await;
                                                    }
                                                    None => {
                                                        if let Some((fp, nick)) = last_admission.take() {
                                                            print_system(&format!("Vetoing {}'s entry...", nick))?;
                                                            let _ = handle.cmd_tx.send(RoomCommand::CastVote {
                                                                candidate_fp: fp,
                                                                approved: false,
                                                            }).await;
                                                        } else {
                                                            print_system("No pending join request to veto.")?;
                                                        }
                                                    }
                                                }
                                            }

                                            "send" => {
                                                let recipient_fp = ui.prompt("Recipient fingerprint:")?;
                                                let recipient_fp = recipient_fp.trim().to_string();
                                                if recipient_fp.is_empty() {
                                                    print_system("Cancelled.")?;
                                                } else {
                                                    let path = ui.prompt("File path:")?;
                                                    let path = path.trim().to_string();
                                                    if path.is_empty() {
                                                        print_system("Cancelled.")?;
                                                    } else {
                                                        let desc = ui.prompt("Description (optional):")?;
                                                        let _ = handle.cmd_tx.send(RoomCommand::SendFile {
                                                            recipient_fp,
                                                            path,
                                                            description: desc.trim().to_string(),
                                                        }).await;
                                                    }
                                                }
                                            }

                                            "accept" => {
                                                if let Some((tid, filename)) = last_offer.take() {
                                                    let default_path = config.downloads_dir.join(&filename);
                                                    let save_path = match parts.get(1)
                                                        .map(|s| s.trim().to_string())
                                                        .filter(|s| !s.is_empty())
                                                    {
                                                        Some(p) => p,
                                                        None => {
                                                            let prompt = format!(
                                                                "Save path [Enter for {}]:",
                                                                default_path.display()
                                                            );
                                                            let p = ui.prompt(&prompt)?;
                                                            let p = p.trim().to_string();
                                                            if p.is_empty() {
                                                                default_path.to_string_lossy().to_string()
                                                            } else {
                                                                p
                                                            }
                                                        }
                                                    };
                                                    if save_path.is_empty() {
                                                        print_system("Accept cancelled — no path given.")?;
                                                        last_offer = Some((tid, filename));
                                                    } else {
                                                        let _ = handle.cmd_tx.send(RoomCommand::AcceptFile {
                                                            transfer_id: tid,
                                                            save_path,
                                                        }).await;
                                                        print_system("File transfer accepted — receiving...")?;
                                                    }
                                                } else {
                                                    print_system("No pending file offer to accept.")?;
                                                }
                                            }

                                            "decline" => {
                                                if let Some((tid, _)) = last_offer.take() {
                                                    let _ = handle.cmd_tx.send(RoomCommand::DeclineFile {
                                                        transfer_id: tid,
                                                    }).await;
                                                    print_system("File offer declined.")?;
                                                } else {
                                                    print_system("No pending file offer to decline.")?;
                                                }
                                            }

                                            "nuke" => {
                                                let confirm = ui.prompt("Type NUKE to confirm, or Enter to cancel:")?;
                                                if confirm.trim() == "NUKE" {
                                                    let _ = handle.cmd_tx.send(RoomCommand::Nuke).await;
                                                } else {
                                                    print_system("Nuke cancelled.")?;
                                                }
                                            }

                                            _ => {
                                                print_system(&format!("Unknown command: /{}", parts[0]))?;
                                                print_system("Type /help for available commands.")?;
                                            }
                                        }
                                    } else {
                                        // ── Regular chat message ───────────────────
                                        let ts = chrono::Local::now()
                                            .format("%Y-%m-%d %H:%M:%S")
                                            .to_string();
                                        ui.renderer.draw_own_message(&ts, &line)?;
                                        let _ = handle
                                            .cmd_tx
                                            .send(RoomCommand::SendEncrypted { body: line })
                                            .await;
                                    }
                                }

                                _ => {}
                            }
                        }
                        None => break,
                        _ => {}
                    }
                }
            }
        }

        // ── Post-room cleanup ──────────────────────────────────────────────
        if nuked {
            print_system("Disconnected.")?;
            ui.wait_for_key("Press any key to return to the menu...")?;
            return Ok(());
        }

        if let Some(ref snapshot) = trust_snapshot {
            match persistence::save_contacts(&storage_dir, snapshot) {
                Ok(()) => {
                    print_system(&format!(
                        "[+] Saved {} trusted contact(s) to: {}",
                        snapshot.contacts.len(),
                        persistence::contacts_path(&storage_dir).display()
                    ))?;
                }
                Err(e) => {
                    print_system(&format!("[!] Failed to save contacts: {e}"))?;
                }
            }
        }

        if let Some((new_room, new_pass, new_is_owner)) = pending_switch {
            current_keystore = if let Some(ref snapshot) = trust_snapshot {
                build_keystore(snapshot).0
            } else {
                PeerKeyStore::new()
            };
            current_room     = new_room;
            current_pass     = new_pass;
            current_is_owner = new_is_owner;
            print_system(&format!("Joining room {}...", current_room))?;
            continue 'room_loop;
        }

        break 'room_loop;
    }

    print_system("Disconnected.")?;
    ui.wait_for_key("Press any key to return to the menu...")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Identity loading
// ---------------------------------------------------------------------------

/// Resolve and load the PGP identity for this session.
///
/// - If `config.active_identity` is set → load that entry.
/// - If there is exactly one identity → use it automatically.
/// - If there are multiple with no active set → prompt the user to pick.
/// - If no identities exist → print guidance and return `None`.
fn load_startup_identity(ui: &Ui, config: &AppConfig) -> Result<Option<PgpIdentity>> {
    let entries = persistence::load_identity_entries(&config.identities_dir);

    if entries.is_empty() {
        ui.error("No identities found.")?;
        println!("  Go to Manage Identities from the main menu to create or import a key.\r");
        println!("  If you have a legacy identity.asc file, use the Import option there.\r");
        ui.wait_for_key("Press any key to return to the menu...")?;
        return Ok(None);
    }

    let entry = if let Some(active_name) = &config.active_identity {
        match entries.iter().find(|e| &e.name == active_name) {
            Some(e) => e.clone(),
            None => {
                ui.error(&format!("Active identity '{}' not found in index.", active_name))?;
                println!("  Go to Manage Identities and set a valid active identity.\r");
                ui.wait_for_key("Press any key...")?;
                return Ok(None);
            }
        }
    } else if entries.len() == 1 {
        entries[0].clone()
    } else {
        loop {
            println!("\r");
            println!("  Select an identity:\r");
            for (i, e) in entries.iter().enumerate() {
                println!(
                    "  [{}] {:<20}  {}  fp: {}…\r",
                    i + 1, e.name, e.nickname,
                    &e.fingerprint[..16.min(e.fingerprint.len())]
                );
            }
            let choice = ui.prompt("Choice:")?;
            if choice.trim().is_empty() {
                return Ok(None);
            }
            if let Ok(idx) = choice.trim().parse::<usize>() {
                if idx >= 1 && idx <= entries.len() {
                    break entries[idx - 1].clone();
                }
            }
            ui.error("Invalid choice — try again.")?;
        }
    };

    let armored = match persistence::load_named_identity(&config.identities_dir, &entry.name)? {
        Some(a) => a,
        None => {
            ui.error(&format!("Key file for '{}' not found.", entry.name))?;
            ui.wait_for_key("Press any key...")?;
            return Ok(None);
        }
    };

    println!("\r");
    println!("  Identity: {}  ({})\r", entry.name, entry.nickname);

    let identity = loop {
        let passphrase = ui.prompt_password("Key passphrase:")?;
        match PgpIdentity::from_armored_secret_key(&entry.nickname, &armored, passphrase) {
            Ok(id) => break id,
            Err(_) => {
                ui.error("Incorrect passphrase — could not unlock key.")?;
                let retry = ui.prompt("Try again? [y/n]:")?;
                if !retry.trim().eq_ignore_ascii_case("y") {
                    return Ok(None);
                }
            }
        }
    };

    Ok(Some(identity))
}

// ---------------------------------------------------------------------------
// Startup room selection
// ---------------------------------------------------------------------------

/// Show the list of known rooms at startup so the user can pick one directly,
/// rather than typing a room name from scratch.
///
/// Returns `None` if the user cancels (Esc / empty input).
/// Returns `Some((room_name, passphrase, is_owner))` on a valid selection.
fn select_room_at_startup(
    ui: &Ui,
    known_rooms: &[PersistedRoom],
) -> Result<Option<(String, Zeroizing<String>, bool)>> {
    if known_rooms.is_empty() {
        // No rooms saved yet — prompt to create or join one.
        println!("\r");
        println!("  No rooms saved yet.  Add them via [3] Manage Rooms, or set one up now:\r");
        println!("\r");
        print_system("  [c] Create room  (generates a passphrase — you become the owner)")?;
        print_system("  [j] Join room    (enter a passphrase the room owner shared with you)")?;
        print_system("  [0] Back to menu")?;
        let action = ui.prompt("Choice:")?;
        return match action.trim().to_lowercase().as_str() {
            "c" => {
                let room_input = ui.prompt("Room name:")?;
                let name = room_input.trim().to_string();
                if name.is_empty() { return Ok(None); }
                let (pass, is_owner) = generate_room_passphrase(ui, &name)?;
                Ok(Some((name, pass, is_owner)))
            }
            "j" => {
                let room_input = ui.prompt("Room name:")?;
                let name = room_input.trim().to_string();
                if name.is_empty() { return Ok(None); }
                let pass = ui.prompt_password("Room passphrase:")?;
                if pass.is_empty() {
                    print_system("A passphrase is required to join a room.")?;
                    return Ok(None);
                }
                Ok(Some((name, pass, false)))
            }
            _ => Ok(None),
        };
    }

    // Show existing rooms.
    loop {
        print_system("── Your Rooms ────────────────────────────────────────────")?;
        for (i, r) in known_rooms.iter().enumerate() {
            let role = if r.is_owner { "owner" } else { "member" };
            print_system(&format!("  [{}] {}  ({})", i + 1, r.name, role))?;
        }
        print_system("  [c] Create a new room")?;
        print_system("  [j] Join an existing room")?;
        print_system("─────────────────────────────────────────────────────────")?;

        let choice = ui.prompt("Choice:")?;
        let choice = choice.trim().to_string();

        if choice.is_empty() {
            return Ok(None);
        }

        if choice.eq_ignore_ascii_case("c") {
            let room_input = ui.prompt("Room name:")?;
            let name = room_input.trim().to_string();
            if name.is_empty() {
                print_system("No name entered — try again.")?;
                continue;
            }
            let (pass, is_owner) = generate_room_passphrase(ui, &name)?;
            return Ok(Some((name, pass, is_owner)));
        }

        if choice.eq_ignore_ascii_case("j") {
            let room_input = ui.prompt("Room name:")?;
            let name = room_input.trim().to_string();
            if name.is_empty() {
                print_system("No name entered — try again.")?;
                continue;
            }
            // If already saved, require stored passphrase (re-entering a known room).
            if let Some(r) = known_rooms.iter().find(|r| r.name == name) {
                let stored   = r.passphrase.clone();
                let is_owner = r.is_owner;
                let entered  = ui.prompt_password("Room passphrase:")?;
                if entered.as_str() != stored {
                    print_system("Incorrect passphrase — try again.")?;
                    continue;
                }
                return Ok(Some((name, Zeroizing::new(stored), is_owner)));
            }
            let pass = ui.prompt_password("Room passphrase (from room owner):")?;
            if pass.is_empty() {
                print_system("A passphrase is required to join a room.")?;
                continue;
            }
            return Ok(Some((name, pass, false)));
        }

        if let Ok(idx) = choice.parse::<usize>() {
            if idx >= 1 && idx <= known_rooms.len() {
                let r        = &known_rooms[idx - 1];
                let name     = r.name.clone();
                let stored   = r.passphrase.clone();
                let is_owner = r.is_owner;
                println!("\r");
                let entered = ui.prompt_password("Room passphrase:")?;
                if entered.as_str() != stored {
                    print_system("Incorrect passphrase — try again.")?;
                    continue;
                }
                let role = if is_owner { "owner" } else { "member" };
                println!("  Your role: {}\r", role);
                return Ok(Some((name, Zeroizing::new(stored), is_owner)));
            }
        }

        print_system("Invalid choice — try again.")?;
    }
}

// ---------------------------------------------------------------------------
// Room management
// ---------------------------------------------------------------------------

/// What the user asked to do from the [j] room manager.
enum RoomAction {
    /// Switch to this room (name, passphrase, is_owner).
    Switch(String, Zeroizing<String>, bool),
    /// Owner deleted this room from the local list; it has already been removed
    /// from `known_rooms` by the time this variant is returned.
    Deleted(String),
    /// Non-owner left this room; already removed from `known_rooms`.
    Left(String),
    /// User cancelled — stay in the current room.
    Cancel,
}

/// Interactive room manager shown when the user presses `[j]`.
///
/// Handles three sub-operations:
/// - **Switch**: pick a known room or enter a new one.
/// - **Delete** (owner only): confirm passphrase, then purge from `known_rooms`.
/// - **Leave** (non-owner): confirm intent, then remove from `known_rooms`.
///
/// Mutates `known_rooms` in-place for delete/leave so the caller can
/// immediately persist the updated list.
fn manage_rooms(
    ui: &Ui,
    known_rooms: &mut Vec<PersistedRoom>,
    current_room: &str,
) -> Result<RoomAction> {
    loop {
        print_system("── Manage Rooms ──────────────────────────────────────────")?;
        if known_rooms.is_empty() {
            print_system("  (no rooms in your list yet)")?;
        } else {
            for (i, r) in known_rooms.iter().enumerate() {
                let role   = if r.is_owner { "owner"  } else { "member" };
                let marker = if r.name == current_room { " ← current" } else { "" };
                print_system(&format!("  [{}] {}  ({}){}", i + 1, r.name, role, marker))?;
            }
        }
        print_system("  ─────────────────────────────────────────────────────────")?;
        print_system("  [n] Join / create a new room")?;
        print_system("  [r] Remove a room from your list (delete if owner, leave if member)")?;
        print_system("  [0] Cancel")?;
        print_system("─────────────────────────────────────────────────────────")?;

        let choice = ui.prompt("Choice:")?;
        let choice = choice.trim().to_string();

        if choice == "0" || choice.is_empty() {
            return Ok(RoomAction::Cancel);
        }

        if choice.eq_ignore_ascii_case("n") {
            // ── Join / create a new room ───────────────────────────────────
            let name = ui.prompt("Room name:")?;
            let name = name.trim().to_string();
            if name.is_empty() {
                print_system("No name entered — cancelled.")?;
                return Ok(RoomAction::Cancel);
            }

            // If the room is already known, require passphrase to re-enter.
            if let Some(r) = known_rooms.iter().find(|r| r.name == name) {
                let stored   = r.passphrase.clone();
                let is_owner = r.is_owner;
                println!("\r");
                let entered = ui.prompt_password("Room passphrase:")?;
                if entered.as_str() != stored {
                    print_system("Incorrect passphrase.")?;
                    return Ok(RoomAction::Cancel);
                }
                return Ok(RoomAction::Switch(name, Zeroizing::new(stored), is_owner));
            }

            // New room — ask whether they are creating or joining.
            println!("\r");
            println!("  Leave passphrase blank to GENERATE one (you become room owner).\r");
            println!("  Enter an EXISTING passphrase if someone else created this room.\r");
            let (pass, is_owner) = generate_room_passphrase(ui, &name)?;
            // Caller is responsible for pushing to known_rooms and saving.
            return Ok(RoomAction::Switch(name, pass, is_owner));
        }

        if choice.eq_ignore_ascii_case("r") {
            // ── Remove a room ──────────────────────────────────────────────
            if known_rooms.is_empty() {
                print_system("No rooms in your list.")?;
                return Ok(RoomAction::Cancel);
            }

            let idx_str = ui.prompt("Room number to remove [0 to cancel]:")?;
            let idx_str = idx_str.trim().to_string();
            if idx_str == "0" || idx_str.is_empty() {
                return Ok(RoomAction::Cancel);
            }
            let idx = match idx_str.parse::<usize>() {
                Ok(i) if i >= 1 && i <= known_rooms.len() => i - 1,
                _ => {
                    print_system("Invalid number.")?;
                    return Ok(RoomAction::Cancel);
                }
            };

            let room_name  = known_rooms[idx].name.clone();
            let is_owner   = known_rooms[idx].is_owner;
            let stored_pass = known_rooms[idx].passphrase.clone();

            if is_owner {
                // Owner must confirm with the stored passphrase before deleting.
                print_system(&format!(
                    "You are the owner of '{}'.  Enter the room passphrase to confirm deletion.",
                    room_name
                ))?;
                let confirm = ui.prompt_password("Room passphrase:")?;
                if confirm.as_str() != stored_pass {
                    print_system("Incorrect passphrase — deletion cancelled.")?;
                    return Ok(RoomAction::Cancel);
                }
                known_rooms.remove(idx);
                return Ok(RoomAction::Deleted(room_name));
            } else {
                // Non-owner just confirms intent.
                let confirm = ui.prompt(&format!(
                    "Leave room '{}' and remove it from your list? [y/n]:", room_name
                ))?;
                if confirm.trim().eq_ignore_ascii_case("y") {
                    known_rooms.remove(idx);
                    return Ok(RoomAction::Left(room_name));
                }
                print_system("Cancelled.")?;
                return Ok(RoomAction::Cancel);
            }
        }

        // Numeric choice — switch to that room.
        if let Ok(idx) = choice.parse::<usize>() {
            if idx == 0 || idx > known_rooms.len() {
                print_system("Invalid number.")?;
                continue;
            }
            let r        = &known_rooms[idx - 1];
            let name     = r.name.clone();
            let stored   = r.passphrase.clone();
            let is_owner = r.is_owner;

            println!("\r");
            let entered = ui.prompt_password("Room passphrase:")?;
            if entered.as_str() != stored {
                print_system("Incorrect passphrase — cancelled.")?;
                return Ok(RoomAction::Cancel);
            }
            let role = if is_owner { "owner" } else { "member" };
            println!("  Your role: {}\r", role);

            return Ok(RoomAction::Switch(name, Zeroizing::new(stored), is_owner));
        }

        print_system("Unknown choice — try again.")?;
        // loop back to re-show the menu
    }
}

// ---------------------------------------------------------------------------
// Passphrase helpers
// ---------------------------------------------------------------------------

/// Prompt for a passphrase on a room that does not yet exist locally.
///
/// Returns `(passphrase, is_owner)`.
///
/// Generate a random 128-bit room passphrase, display it, and return it.
/// The caller is always the room owner when this path is taken.
fn generate_room_passphrase(ui: &Ui, room_name: &str) -> Result<(Zeroizing<String>, bool)> {
    let mut raw = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut raw);
    let generated = hex::encode(raw);
    println!("\r");
    ui.show_passphrase_box(
        &format!("Passphrase for '{}' — share with peers before they join", room_name),
        &generated,
    );
    println!("  Anyone without this passphrase cannot read room traffic.\r");
    Ok((Zeroizing::new(generated), true))
}

// ---------------------------------------------------------------------------
// Keystore builder
// ---------------------------------------------------------------------------

fn build_keystore(store: &PersistedTrustStore) -> (PeerKeyStore, usize, usize) {
    let mut ks = PeerKeyStore::new();
    let mut loaded = 0;
    let mut failed = 0;
    for c in &store.contacts {
        match persistence::parse_contact(c) {
            Ok((fp, nick, key)) => {
                ks.import_trusted(fp, key, nick);
                loaded += 1;
            }
            Err(e) => {
                eprintln!("[!] Skipping corrupt contact {}: {e}", c.fingerprint);
                failed += 1;
            }
        }
    }
    for fp in &store.rejected {
        ks.reject(fp);
    }
    (ks, loaded, failed)
}

// ---------------------------------------------------------------------------
// Print helper
// ---------------------------------------------------------------------------

fn print_system(text: &str) -> std::io::Result<()> {
    let color = SYSTEM_COLOR.lock().map(|g| *g).unwrap_or(Color::DarkGrey);
    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    execute!(
        stdout(),
        crossterm::style::SetForegroundColor(color),
        Print(format!("\r  {} [*] {}\r\n", ts, text)),
        crossterm::style::ResetColor,
    )
}
