//! Live P2P network demo: start a node, join a room, chat in real time.
//!
//! Uses `tokio::select!` to poll both:
//!   - `crossterm::event::EventStream` (keyboard input)
//!   - `ChatRoomHandle::event_rx` (gossipsub messages, peer events)
//!
//! ## Key bindings (while in the chat room)
//!
//! | Key       | Action                                        |
//! |-----------|-----------------------------------------------|
//! | Enter     | Send typed message (encrypted if keys known)  |
//! | y         | Approve last pending peer key                 |
//! | x         | Deny last pending peer key                    |
//! | a         | Approve ALL pending / deferred keys           |
//! | d         | Toggle deferring mode                         |
//! | n         | Display peer node map                         |
//! | f         | Send a file (prompts for path + recipient)    |
//! | !         | NUKE — wipe all state & broadcast revocation  |
//! | q         | Quit (graceful disconnect)                    |
//! | Ctrl-C/D  | Quit                                          |

use anyhow::{Context, Result};
use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyModifiers};
use futures::StreamExt;
use libp2p::identity::Keypair;
use std::io::{stdout, Write};
use crossterm::{cursor, execute, queue, style::Print};
use zeroize::Zeroizing;
use pgp_chat_core::{
    chat::{
        message::{MessageKind, SignedChatMessage},
        room::{ChatRoom, RoomCommand},
    },
    crypto::identity::PgpIdentity,
    network::transport,
};
use crate::ui::Ui;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub async fn run(ui: &Ui) -> Result<()> {
    ui.renderer.draw_box_top("P2P Network Demo")?;

    // ── Gather config from the user ────────────────────────────────────────
    let nickname = ui.prompt("Your nickname:")?;
    let nickname = if nickname.trim().is_empty() { "anonymous".to_string() } else { nickname.trim().to_string() };

    let port_str  = ui.prompt("Listen port [0 = random]:")?;
    let port: u16 = port_str.trim().parse().unwrap_or(0);

    let room_input = ui.prompt("Room name [default: main]:")?;
    let room_name  = if room_input.trim().is_empty() { "main".to_string() } else { room_input.trim().to_string() };

    // ── Room passphrase ────────────────────────────────────────────────────
    //
    // All gossipsub traffic is PGP-symmetrically encrypted with this
    // passphrase.  Share it with your peers out-of-band (Signal, QR code,
    // in-person).  Leave blank to derive one from the room name (weaker but
    // convenient for public demos).
    println!("\r");
    println!("  Room passphrase — encrypts ALL traffic in this room.\r");
    println!("  Share this value out-of-band with everyone in the room.\r");
    println!("  Leave blank to derive from room name (demo only — not secure).\r");
    let passphrase_input = ui.prompt_password("Room passphrase [blank = derive from room name]:")?;
    let room_passphrase: Zeroizing<String> = if passphrase_input.is_empty() {
        Zeroizing::new(format!("pgp-chat:room:{}", room_name))
    } else {
        passphrase_input
    };

    // ── PGP identity — generate or import ─────────────────────────────────
    println!("\r");
    println!("  PGP identity options:\r");
    println!("    [g] Generate a new secret key (EdDSA + ECDH Curve25519)\r");
    println!("    [i] Import your existing SECRET key from a .asc file\r");
    println!("        (the PUBLIC key is derived and shared automatically)\r");
    println!("    [q] Cancel\r");
    println!("  Choice: ");
    stdout().flush()?;

    let pgp_identity = loop {
        if let crossterm::event::Event::Key(crossterm::event::KeyEvent { code, .. }) =
            crossterm::event::read()?
        {
            match code {
                KeyCode::Char('g') | KeyCode::Char('G') => {
                    println!("generate\r");
                    println!("  A passphrase protects your secret key if the file is\r");
                    println!("  ever obtained by someone else.  Leave blank for none.\r");
                    let passphrase = ui.prompt_password("Passphrase for secret key (blank = none):")?;
                    println!("  Generating PGP identity for {}...\r", nickname);
                    break PgpIdentity::generate(&nickname, passphrase)
                        .map_err(|e| anyhow::anyhow!("PGP key generation failed: {e}"))?;
                }
                KeyCode::Char('i') | KeyCode::Char('I') => {
                    println!("import\r");
                    println!("  Provide your SECRET key file — the one that begins with:\r");
                    println!("    -----BEGIN PGP PRIVATE KEY BLOCK-----\r");
                    println!("  NOT the public key (-----BEGIN PGP PUBLIC KEY BLOCK-----).\r");
                    let path = ui.prompt("Path to secret key file (.asc):")?;
                    println!("  Enter the passphrase used when the key was created/exported.\r");
                    println!("  Leave blank if the key has no passphrase protection.\r");
                    let passphrase = ui.prompt_password("Secret key passphrase (blank = none):")?;
                    let armored = std::fs::read_to_string(path.trim())
                        .context("failed to read key file")?;
                    break PgpIdentity::from_armored_secret_key(&nickname, &armored, passphrase)
                        .map_err(|e| anyhow::anyhow!("Key import failed: {e}"))?;
                }
                KeyCode::Esc | KeyCode::Char('q') => {
                    println!("\r");
                    return Ok(());
                }
                _ => {}
            }
        }
    };

    // ── Build libp2p swarm ─────────────────────────────────────────────────
    println!("  Generating ephemeral libp2p keypair...\r");
    let libp2p_keypair = Keypair::generate_ed25519();
    let local_peer_id  = libp2p_keypair.public().to_peer_id();

    ui.info("Local Peer ID",   &local_peer_id.to_string())?;
    ui.info("PGP Fingerprint", &pgp_identity.fingerprint())?;

    println!("  Building swarm (TCP + QUIC)...\r");
    let mut swarm = transport::build_swarm(libp2p_keypair)
        .map_err(|e| anyhow::anyhow!("swarm build failed: {e}"))?;

    // Listen on both TCP and QUIC (UDP)
    let tcp_addr = format!("/ip4/0.0.0.0/tcp/{}", port).parse()
        .context("invalid TCP multiaddr")?;
    let quic_addr = format!("/ip4/0.0.0.0/udp/{}/quic-v1", port).parse()
        .context("invalid QUIC multiaddr")?;

    swarm.listen_on(tcp_addr).context("failed to start TCP listener")?;
    swarm.listen_on(quic_addr).context("failed to start QUIC listener")?;

    // ── Optional bootstrap peer ────────────────────────────────────────────
    let bootstrap = ui.prompt("Bootstrap peer multiaddr [leave blank to skip]:")?;
    if !bootstrap.trim().is_empty() {
        match bootstrap.trim().parse::<libp2p::Multiaddr>() {
            Ok(addr) => {
                swarm.dial(addr.clone()).context("dial failed")?;
                ui.success(&format!("Dialling {}", addr))?;
            }
            Err(_) => {
                ui.error("Invalid multiaddr — skipping bootstrap")?;
            }
        }
    }

    // ── Start room ─────────────────────────────────────────────────────────
    ui.renderer.draw_box_separator()?;
    println!("  Room: {}  |  Keys: [y] approve  [x] deny  [a] approve-all\r", room_name);
    println!("  [d] deferring  [n] node map  [f] send file  [r] accept file  [z] decline\r");
    println!("  [!] NUKE  [q] quit\r");
    println!("  Type a message and press Enter to send.\r");
    ui.renderer.draw_box_separator()?;
    stdout().flush()?;

    let (room, mut handle) = ChatRoom::new(swarm, &room_name, pgp_identity, room_passphrase);

    // Store the JoinHandle — if the room task panics, select! will see it.
    let room_handle = tokio::spawn(room.run());
    tokio::pin!(room_handle);

    // ── UI state ───────────────────────────────────────────────────────────
    let mut input_buf      = String::new();
    let mut peer_index     = 0usize;
    let mut is_deferring   = false;
    // Last seen pending fingerprint (for y/x single-key approval)
    let mut last_pending: Option<(String, String)> = None; // (fp, nick)
    // Last inbound file offer awaiting user response
    let mut last_offer: Option<uuid::Uuid> = None;
    let mut event_stream = EventStream::new();

    loop {
        tokio::select! {
            // ── Room task exited (normally or panicked) ────────────────────
            result = &mut room_handle => {
                match result {
                    Err(e) => print_system(&format!("Room task failed: {e}"))?,
                    Ok(()) => print_system("Room shut down.")?,
                }
                break;
            }

            // ── Network / chat events ──────────────────────────────────────
            net_evt = handle.event_rx.recv() => {
                use pgp_chat_core::network::event::ChatNetEvent;
                match net_evt {
                    Some(ChatNetEvent::ListeningOn(addr)) => {
                        let proto = if addr.to_string().contains("quic") { "QUIC/UDP" } else { "TCP" };
                        print_system(&format!("Listening on {} [{}]", addr, proto))?;
                    }

                    Some(ChatNetEvent::MessageReceived { payload, .. }) => {
                        if let Ok(signed) = serde_json::from_slice::<SignedChatMessage>(&payload) {
                            let m = &signed.message;
                            let ts = m.timestamp.format("%H:%M").to_string();
                            match &m.kind {
                                MessageKind::Plaintext(text) => {
                                    ui.renderer.draw_message(
                                        &ts,
                                        &m.sender_nick,
                                        text,
                                        false,
                                        peer_index,
                                    )?;
                                    peer_index = peer_index.wrapping_add(1);
                                }
                                MessageKind::Encrypted { recipients, .. } => {
                                    print_system(&format!(
                                        "Encrypted message from {} ({} recipients)",
                                        m.sender_nick,
                                        recipients.len()
                                    ))?;
                                }
                                MessageKind::AnnounceKey { nickname, .. } => {
                                    print_system(&format!("{} is announcing their key", nickname))?;
                                }
                                MessageKind::StatusAnnounce { status } => {
                                    print_system(&format!(
                                        "{} status: {:?}", m.sender_nick, status
                                    ))?;
                                }
                                MessageKind::Revoke { fingerprint } => {
                                    print_system(&format!(
                                        "REVOCATION: {} revoked fingerprint {}", m.sender_nick, fingerprint
                                    ))?;
                                }
                                MessageKind::System(text) => {
                                    print_system(text)?;
                                }
                                // File transfer messages are handled by the room task;
                                // events bubble up via ChatNetEvent — nothing to display here.
                                MessageKind::FileOffer { .. }
                                | MessageKind::FileAccept(_)
                                | MessageKind::FileDecline(_)
                                | MessageKind::FileChunk(_)
                                | MessageKind::FileComplete(_) => {}
                            }
                        }
                    }

                    Some(ChatNetEvent::KeyApprovalRequired { fingerprint, nickname, .. }) => {
                        print_system(&format!(
                            "[?] New key from {} ({})\r  Press 'y' to approve, 'x' to deny, 'a' for all",
                            nickname, fingerprint
                        ))?;
                        last_pending = Some((fingerprint, nickname));
                    }

                    Some(ChatNetEvent::DeferredKeysAvailable(n)) => {
                        print_system(&format!(
                            "[d] Deferring mode OFF — {} deferred key(s) promoted to pending.  Press 'a' to approve all.",
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
                                trust_s, status_s, fp_short, node.nickname,
                            ))?;
                        }
                        print_system("──────────────────────────────────────────────")?;
                    }

                    Some(ChatNetEvent::InboundFileOffer {
                        transfer_id, filename, size_bytes, description,
                        sender_fp, sender_nick, sender_addrs,
                    }) => {
                        print_system("── Incoming File Transfer ─────────────────────")?;
                        print_system(&format!("  From:        {} ({})", sender_nick, sender_fp))?;
                        print_system(&format!("  File:        {}", filename))?;
                        print_system(&format!("  Size:        {} bytes", size_bytes))?;
                        if !description.is_empty() {
                            print_system(&format!("  Description: {}", description))?;
                        }
                        if !sender_addrs.is_empty() {
                            print_system(&format!("  Network:     {}", sender_addrs.join(", ")))?;
                        }
                        print_system("  Press 'r' to accept (will prompt save path), 'z' to decline.")?;
                        print_system("──────────────────────────────────────────────")?;
                        last_offer = Some(transfer_id);
                    }

                    Some(ChatNetEvent::FileReceived { transfer_id: _, filename, save_path }) => {
                        print_system(&format!("[+] File '{}' saved to: {}", filename, save_path))?;
                    }

                    Some(ChatNetEvent::FileDeclined { transfer_id }) => {
                        print_system(&format!("[-] File offer {} was declined by recipient.", transfer_id))?;
                    }

                    Some(ChatNetEvent::FileSendProgress { transfer_id, sent_chunks, total_chunks }) => {
                        print_system(&format!(
                            "[~] Sending {} chunk {}/{}", transfer_id, sent_chunks, total_chunks
                        ))?;
                    }

                    Some(ChatNetEvent::FileTransferError { transfer_id, reason }) => {
                        print_system(&format!("[!] File transfer {} error: {}", transfer_id, reason))?;
                    }

                    Some(ChatNetEvent::PeerRevoked { fingerprint, nickname }) => {
                        print_system(&format!(
                            "[!] REVOKED: {} ({}) has wiped their identity.",
                            nickname, fingerprint
                        ))?;
                    }

                    Some(ChatNetEvent::NukeComplete) => {
                        print_system("[!] NUKE complete — all identity material wiped.")?;
                        break;
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

            // ── Keyboard input ─────────────────────────────────────────────
            term_evt = event_stream.next() => {
                match term_evt {
                    Some(Ok(Event::Key(KeyEvent { code, modifiers, .. }))) => {
                        // Ctrl-C or Ctrl-D to leave
                        if modifiers.contains(KeyModifiers::CONTROL)
                            && matches!(code, KeyCode::Char('c') | KeyCode::Char('d'))
                        {
                            let _ = handle.cmd_tx.send(RoomCommand::Disconnect).await;
                            break;
                        }

                        match code {
                            // Quit
                            KeyCode::Char('q') if input_buf.is_empty() => {
                                let _ = handle.cmd_tx.send(RoomCommand::Disconnect).await;
                                break;
                            }

                            // Approve last pending key
                            KeyCode::Char('y') if input_buf.is_empty() => {
                                if let Some((fp, nick)) = last_pending.take() {
                                    print_system(&format!("Approving key from {}...", nick))?;
                                    let _ = handle.cmd_tx.send(RoomCommand::ApproveKey(fp)).await;
                                } else {
                                    print_system("No pending key to approve.")?;
                                }
                            }

                            // Deny last pending key
                            KeyCode::Char('x') if input_buf.is_empty() => {
                                if let Some((fp, nick)) = last_pending.take() {
                                    print_system(&format!("Denying key from {}.", nick))?;
                                    let _ = handle.cmd_tx.send(RoomCommand::DenyKey(fp)).await;
                                } else {
                                    print_system("No pending key to deny.")?;
                                }
                            }

                            // Approve all pending / deferred keys
                            KeyCode::Char('a') if input_buf.is_empty() => {
                                print_system("Approving all pending keys...")?;
                                let _ = handle.cmd_tx.send(RoomCommand::ApproveAll).await;
                                last_pending = None;
                            }

                            // Toggle deferring mode
                            KeyCode::Char('d') if input_buf.is_empty() => {
                                is_deferring = !is_deferring;
                                print_system(&format!(
                                    "Deferring mode: {}",
                                    if is_deferring { "ON — new keys will be queued" } else { "OFF" }
                                ))?;
                                let _ = handle.cmd_tx.send(RoomCommand::SetDeferring(is_deferring)).await;
                            }

                            // Show node map
                            KeyCode::Char('n') if input_buf.is_empty() => {
                                let _ = handle.cmd_tx.send(RoomCommand::GetNodeMap).await;
                            }

                            // Send file
                            KeyCode::Char('f') if input_buf.is_empty() => {
                                crossterm::terminal::disable_raw_mode()?;
                                println!();
                                print!("  Recipient PGP fingerprint: ");
                                std::io::stdout().flush()?;
                                let mut recipient_fp = String::new();
                                std::io::stdin().read_line(&mut recipient_fp)?;

                                print!("  File path: ");
                                std::io::stdout().flush()?;
                                let mut file_path = String::new();
                                std::io::stdin().read_line(&mut file_path)?;

                                print!("  Description (max 256 chars, blank to skip): ");
                                std::io::stdout().flush()?;
                                let mut description = String::new();
                                std::io::stdin().read_line(&mut description)?;

                                crossterm::terminal::enable_raw_mode()?;

                                let recipient_fp = recipient_fp.trim().to_string();
                                let file_path    = file_path.trim().to_string();
                                let description  = description.trim().to_string();

                                if !recipient_fp.is_empty() && !file_path.is_empty() {
                                    let _ = handle.cmd_tx.send(RoomCommand::SendFile {
                                        recipient_fp,
                                        path: file_path,
                                        description,
                                    }).await;
                                } else {
                                    print_system("File send cancelled.")?;
                                }
                            }

                            // Accept incoming file offer
                            KeyCode::Char('r') if input_buf.is_empty() => {
                                if let Some(tid) = last_offer.take() {
                                    crossterm::terminal::disable_raw_mode()?;
                                    println!();
                                    print!("  Save file to path: ");
                                    std::io::stdout().flush()?;
                                    let mut save_path = String::new();
                                    std::io::stdin().read_line(&mut save_path)?;
                                    crossterm::terminal::enable_raw_mode()?;

                                    let save_path = save_path.trim().to_string();
                                    if !save_path.is_empty() {
                                        let _ = handle.cmd_tx.send(RoomCommand::AcceptFile {
                                            transfer_id: tid,
                                            save_path,
                                        }).await;
                                        print_system("File transfer accepted — receiving...")?;
                                    } else {
                                        print_system("Accept cancelled — no save path given.")?;
                                        last_offer = Some(tid);
                                    }
                                } else {
                                    print_system("No pending file offer to accept.")?;
                                }
                            }

                            // Decline incoming file offer
                            KeyCode::Char('z') if input_buf.is_empty() => {
                                if let Some(tid) = last_offer.take() {
                                    let _ = handle.cmd_tx.send(RoomCommand::DeclineFile {
                                        transfer_id: tid,
                                    }).await;
                                    print_system("File offer declined.")?;
                                } else {
                                    print_system("No pending file offer to decline.")?;
                                }
                            }

                            // NUKE
                            KeyCode::Char('!') if input_buf.is_empty() => {
                                print_system("Type NUKE and press Enter to confirm, or press Esc to cancel.")?;
                                // Switch to a blocking confirmation sub-loop
                                let mut confirm_buf = String::new();
                                loop {
                                    if let crossterm::event::Event::Key(
                                        crossterm::event::KeyEvent { code: kc, .. }
                                    ) = crossterm::event::read()? {
                                        match kc {
                                            KeyCode::Esc => {
                                                print_system("Nuke cancelled.")?;
                                                break;
                                            }
                                            KeyCode::Enter => {
                                                if confirm_buf.trim() == "NUKE" {
                                                    let _ = handle.cmd_tx.send(RoomCommand::Nuke).await;
                                                } else {
                                                    print_system("Nuke cancelled (did not type NUKE).")?;
                                                }
                                                break;
                                            }
                                            KeyCode::Char(c) => {
                                                confirm_buf.push(c);
                                                queue!(stdout(), Print(c))?;
                                                stdout().flush()?;
                                            }
                                            KeyCode::Backspace => {
                                                confirm_buf.pop();
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }

                            // Regular text input
                            KeyCode::Char(c) => {
                                input_buf.push(c);
                                queue!(stdout(), Print(c))?;
                                stdout().flush()?;
                            }

                            KeyCode::Enter if !input_buf.is_empty() => {
                                let msg = std::mem::take(&mut input_buf);
                                execute!(stdout(), Print("\r\n"))?;
                                let _ = handle.cmd_tx.send(RoomCommand::SendEncrypted { body: msg }).await;
                            }

                            KeyCode::Backspace if !input_buf.is_empty() => {
                                input_buf.pop();
                                execute!(
                                    stdout(),
                                    cursor::MoveLeft(1),
                                    Print(' '),
                                    cursor::MoveLeft(1),
                                )?;
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

    print_system("Disconnected.")?;
    ui.wait_for_key("Press any key to return to the menu...")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn print_system(text: &str) -> std::io::Result<()> {
    execute!(
        stdout(),
        crossterm::style::SetForegroundColor(crossterm::style::Color::DarkGrey),
        Print(format!("\r  [*] {}\r\n", text)),
        crossterm::style::ResetColor,
    )
}
