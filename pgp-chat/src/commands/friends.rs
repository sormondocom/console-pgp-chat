use std::collections::{BTreeSet, HashMap};
use std::io::{stdout, Write};
use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use chrono::Utc;
use crossterm::{
    cursor, execute,
    event::{Event, EventStream, KeyCode, KeyEventKind},
    style::{Attribute, Color, Print, ResetColor, SetAttribute, SetForegroundColor},
    terminal,
};
use futures::StreamExt;
use libp2p::{
    gossipsub::{self, IdentTopic},
    identify,
    identity::Keypair,
    mdns,
    noise, tcp, yamux,
    swarm::{NetworkBehaviour, SwarmEvent},
    Multiaddr, PeerId,
    SwarmBuilder,
};

use pgp_chat_core::{
    crypto::identity::PgpIdentity,
    network::trust_message::{ANNOUNCE_TOPIC, TRUST_TOPIC, TrustRequestMessage},
    persistence::{
        self, AppConfig, PendingTrustRequest, PersistedContact, PersistedRoom,
        PersistedTrustStore, parse_contact, decrypt_room_passphrase,
    },
};
use crate::ui::Ui;

const IDENTIFY_PROTOCOL: &str = "/pgp-chat/1.0.0";
const SPIN: [char; 4] = ['|', '/', '-', '\\'];
const HEADER: u16 = 2;  // box top + blank line
const FOOTER: u16 = 3;  // separator + hint + spinner

fn max_visible(term_h: u16) -> usize {
    term_h.saturating_sub(HEADER + FOOTER) as usize
}
fn content_row(i: usize) -> u16 { HEADER + i as u16 }
fn sep_row(h: u16)  -> u16 { h - FOOTER }
fn hint_row(h: u16) -> u16 { h - 2 }
fn spin_row(h: u16) -> u16 { h - 1 }

// ---------------------------------------------------------------------------
// Swarm behaviour (mirrors scanner — separate type to avoid cross-module Event issues)
// ---------------------------------------------------------------------------

#[derive(NetworkBehaviour)]
struct FriendsBehaviour {
    gossipsub: gossipsub::Behaviour,
    identify:  identify::Behaviour,
    mdns:      mdns::tokio::Behaviour,
}

fn build_swarm(keypair: Keypair) -> Result<libp2p::Swarm<FriendsBehaviour>> {
    let peer_id    = keypair.public().to_peer_id();
    let public_key = keypair.public();

    let gs_cfg = gossipsub::ConfigBuilder::default()
        .validation_mode(gossipsub::ValidationMode::Permissive)
        .build()
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let mut gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(keypair.clone()), gs_cfg,
    ).map_err(|e| anyhow::anyhow!("{e}"))?;

    gossipsub.subscribe(&IdentTopic::new(TRUST_TOPIC))?;
    gossipsub.subscribe(&IdentTopic::new(ANNOUNCE_TOPIC))?;

    let identify = identify::Behaviour::new(
        identify::Config::new(IDENTIFY_PROTOCOL.to_string(), public_key)
            .with_agent_version(format!("pgp-chat/{}", env!("CARGO_PKG_VERSION"))),
    );
    let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    Ok(SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .with_quic()
        .with_behaviour(|_| FriendsBehaviour { gossipsub, identify, mdns })
        .unwrap()
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build())
}

async fn next_event(
    swarm: &mut Option<libp2p::Swarm<FriendsBehaviour>>,
) -> SwarmEvent<FriendsBehaviourEvent> {
    match swarm {
        Some(s) => s.select_next_some().await,
        None    => std::future::pending().await,
    }
}

// ---------------------------------------------------------------------------
// Per-peer live state
// ---------------------------------------------------------------------------

#[derive(Default)]
struct PeerData {
    addr:   Option<Multiaddr>,
    topics: BTreeSet<String>,
}

// ---------------------------------------------------------------------------
// Data row model  (flat list: contacts first, pending after)
// ---------------------------------------------------------------------------

#[derive(Clone)]
enum Row {
    Contact {
        nickname:    String,
        fingerprint: String,
        is_online:   bool,
    },
    Pending(PendingTrustRequest),
}

/// Build flat row list: trusted contacts at top, pending requests at bottom.
fn build_rows(
    contacts: &[PersistedContact],
    pending:  &[PendingTrustRequest],
    fp_peer:  &HashMap<String, PeerId>,
) -> Vec<Row> {
    let mut rows: Vec<Row> = contacts.iter().map(|c| Row::Contact {
        nickname:    c.nickname.clone(),
        fingerprint: c.fingerprint.clone(),
        is_online:   fp_peer.contains_key(&c.fingerprint),
    }).collect();
    for req in pending {
        rows.push(Row::Pending(req.clone()));
    }
    rows
}

// ---------------------------------------------------------------------------
// Visual display list — interleaves non-selectable section headers with items
// ---------------------------------------------------------------------------

#[derive(Clone)]
enum DisplayRow {
    SectionHeader { label: String, color: Color, count: usize },
    Empty          { text: String },
    Item           { row_idx: usize, display_num: usize },
}

fn build_display(rows: &[Row]) -> Vec<DisplayRow> {
    let contact_indices: Vec<usize> = rows.iter().enumerate()
        .filter_map(|(i, r)| if matches!(r, Row::Contact { .. }) { Some(i) } else { None })
        .collect();
    let pending_indices: Vec<usize> = rows.iter().enumerate()
        .filter_map(|(i, r)| if matches!(r, Row::Pending(_)) { Some(i) } else { None })
        .collect();

    let mut display = Vec::new();

    // ── Trusted Friends section ─────────────────────────────────────────────
    display.push(DisplayRow::SectionHeader {
        label: "Trusted Friends".to_string(),
        color: Color::Cyan,
        count: contact_indices.len(),
    });
    if contact_indices.is_empty() {
        display.push(DisplayRow::Empty {
            text: "(no trusted contacts yet — use Scan for Peers)".to_string(),
        });
    } else {
        for (num, &i) in contact_indices.iter().enumerate() {
            display.push(DisplayRow::Item { row_idx: i, display_num: num + 1 });
        }
    }

    // ── Pending Requests section (only when non-empty) ──────────────────────
    if !pending_indices.is_empty() {
        display.push(DisplayRow::SectionHeader {
            label: "Pending Requests".to_string(),
            color: Color::Yellow,
            count: pending_indices.len(),
        });
        for (num, &i) in pending_indices.iter().enumerate() {
            display.push(DisplayRow::Item { row_idx: i, display_num: num + 1 });
        }
    }

    display
}

/// Find the visual position of a selectable row within the display list.
fn find_display_idx(display: &[DisplayRow], row_idx: usize) -> Option<usize> {
    display.iter().position(|dr| {
        matches!(dr, DisplayRow::Item { row_idx: i, .. } if *i == row_idx)
    })
}

/// Scroll `display_scroll` to keep `sel_di` inside the visible window.
fn ensure_visible(display_scroll: &mut usize, sel_di: usize, max: usize) {
    if sel_di < *display_scroll {
        *display_scroll = sel_di;
    } else if sel_di >= *display_scroll + max {
        *display_scroll = sel_di - max + 1;
    }
}

// ---------------------------------------------------------------------------
// Drawing
// ---------------------------------------------------------------------------

fn draw_row(ui: &Ui, content_w: u16, abs_row: u16, num: usize, row: &Row, selected: bool) -> Result<()> {
    let pal = ui.renderer.palette();

    execute!(stdout(),
        cursor::MoveTo(0, abs_row),
        terminal::Clear(terminal::ClearType::CurrentLine),
    )?;

    let (nick_raw, fp_short, tag, tag_color) = match row {
        Row::Contact { nickname, fingerprint, is_online } => {
            let fp_s = if fingerprint.len() >= 12 {
                format!("{}…", &fingerprint[..12])
            } else {
                fingerprint.clone()
            };
            let (tag, color) = if *is_online {
                ("[online]  ", Color::Green)
            } else {
                ("[offline] ", Color::DarkGrey)
            };
            (crate::ui::sanitize_display(nickname), fp_s, tag, color)
        }
        Row::Pending(req) => {
            let fp = &req.from_fingerprint;
            let fp_s = if fp.len() >= 12 { format!("{}…", &fp[..12]) } else { fp.clone() };
            (crate::ui::sanitize_display(&req.from_nickname), fp_s, "[pending] ", Color::Yellow)
        }
    };

    // nick_w: leave room for "   [N]  " (8) + "  [status]" (12) + "  fp:XXXX…" (18) = 38 fixed chars
    let nick_w = (content_w.saturating_sub(38) as usize).clamp(8, 30);
    let nick_chars: Vec<char> = nick_raw.chars().collect();
    let nick_disp = if nick_chars.len() <= nick_w {
        format!("{:<nick_w$}", nick_raw)
    } else {
        format!("{}…", nick_chars[..nick_w.saturating_sub(1)].iter().collect::<String>())
    };

    if selected {
        execute!(stdout(),
            SetForegroundColor(pal.accent),
            SetAttribute(Attribute::Bold),
            Print(format!(" > [{}]  {}", num, nick_disp)),
            SetAttribute(Attribute::Reset),
            ResetColor,
        )?;
    } else {
        execute!(stdout(), Print(format!("   [{}]  {}", num, nick_disp)))?;
    }

    execute!(stdout(),
        SetForegroundColor(tag_color),
        Print(format!("  {}", tag)),
        ResetColor,
        SetForegroundColor(pal.dim),
        Print(format!("  fp:{}", fp_short)),
        ResetColor,
    )?;

    Ok(())
}

fn draw_all(
    ui:             &Ui,
    rows:           &[Row],
    display:        &[DisplayRow],
    selected_idx:   usize,
    display_scroll: usize,
    scanning:       bool,
    spin:           char,
    term_w:         u16,
    term_h:         u16,
    status_msg:     Option<&(String, bool)>,
) -> Result<()> {
    let pal       = ui.renderer.palette();
    let content_w = crate::sidebar::main_width(term_w);
    ui.clear()?;
    ui.renderer.draw_box_top("Friends")?;
    execute!(stdout(), Print("\r\n"))?;

    let max     = max_visible(term_h);
    let mut last_v = 0usize;

    for v in 0..max {
        let di = display_scroll + v;
        if di >= display.len() { break; }
        let abs = content_row(v);

        match &display[di] {
            DisplayRow::SectionHeader { label, color, count } => {
                execute!(stdout(),
                    cursor::MoveTo(0, abs),
                    terminal::Clear(terminal::ClearType::CurrentLine),
                    SetForegroundColor(*color),
                    SetAttribute(Attribute::Bold),
                    Print(format!("  {} ({})", label, count)),
                    SetAttribute(Attribute::Reset),
                    ResetColor,
                )?;
            }
            DisplayRow::Empty { text } => {
                execute!(stdout(),
                    cursor::MoveTo(0, abs),
                    terminal::Clear(terminal::ClearType::CurrentLine),
                    SetForegroundColor(pal.dim),
                    Print(format!("    {}", text)),
                    ResetColor,
                )?;
            }
            DisplayRow::Item { row_idx, display_num } => {
                draw_row(ui, content_w, abs, *display_num, &rows[*row_idx], selected_idx == *row_idx)?;
            }
        }
        last_v = v + 1;
    }

    // Erase any stale content rows below what was just drawn.
    for v in last_v..max {
        execute!(stdout(),
            cursor::MoveTo(0, content_row(v)),
            terminal::Clear(terminal::ClearType::CurrentLine),
        )?;
    }

    if let Some((msg, is_err)) = status_msg {
        execute!(stdout(),
            cursor::MoveTo(0, sep_row(term_h).saturating_sub(1)),
            terminal::Clear(terminal::ClearType::CurrentLine),
            SetForegroundColor(if *is_err { Color::Red } else { Color::Green }),
            Print(format!("  {}", msg)),
            ResetColor,
        )?;
    }

    execute!(stdout(),
        cursor::MoveTo(0, sep_row(term_h)),
        terminal::Clear(terminal::ClearType::CurrentLine),
    )?;
    ui.renderer.draw_box_separator()?;
    execute!(stdout(),
        cursor::MoveTo(0, hint_row(term_h)),
        terminal::Clear(terminal::ClearType::CurrentLine),
        SetForegroundColor(pal.dim),
        Print("  \u{2191}\u{2193} navigate   Enter select   Esc back"),
        ResetColor,
        cursor::MoveTo(0, spin_row(term_h)),
        terminal::Clear(terminal::ClearType::CurrentLine),
    )?;
    if scanning {
        execute!(stdout(),
            SetForegroundColor(pal.accent),
            Print(format!("  {} Scanning for friends\u{2026}", spin)),
            ResetColor,
        )?;
    } else {
        execute!(stdout(),
            SetForegroundColor(pal.dim),
            Print("  \u{25a0} Offline"),
            ResetColor,
        )?;
    }
    stdout().flush()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Start Chat helper — prompts for room name, passphrase, and port
// ---------------------------------------------------------------------------

fn start_chat_from_friends(
    ui:            &Ui,
    storage_dir:   &Path,
    identity:      &PgpIdentity,
    identity_name: &str,
) -> Result<Option<(PersistedRoom, Option<Multiaddr>, Option<u16>)>> {
    ui.clear()?;
    ui.renderer.draw_box_top("Start Chat")?;
    println!("\r");
    println!("  Create a room and share the passphrase with peers out of band.\r");
    println!("  Peers can also join using Scan for Peers once your room is live.\r");
    println!("\r");

    let room_input = ui.prompt("Room name [blank to cancel]:")?;
    let room_name = room_input.trim().to_string();
    if room_name.is_empty() {
        return Ok(None);
    }

    // If the room already exists in saved rooms, reuse it.
    let saved = persistence::load_rooms(storage_dir, identity_name, identity);
    let room = if let Some(r) = saved.iter().find(|r| r.name == room_name) {
        let plain = decrypt_room_passphrase(&r.passphrase, identity);
        println!("\r");
        println!("  Using saved room '{}'  [{}].\r",
            room_name, if r.is_owner { "owner" } else { "member" });
        ui.show_passphrase_box(&format!("Passphrase for '{}'", room_name), &plain);
        r.clone()
    } else {
        let pass_input = ui.prompt_password("Room passphrase [blank = auto-generate]:")?;
        let (passphrase, is_owner) = if pass_input.is_empty() {
            let mut raw = [0u8; 16];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut raw);
            let generated = hex::encode(raw);
            println!("\r");
            ui.show_passphrase_box(
                &format!("Passphrase for '{}' — share with peers before they join", room_name),
                &generated,
            );
            println!("  Anyone without this passphrase cannot read room traffic.\r");
            (generated, true)
        } else {
            (pass_input.as_str().to_owned(), false)
        };
        PersistedRoom { name: room_name.clone(), passphrase, is_owner }
    };

    let port_input = ui.prompt("Listen port [0 = random]:")?;
    let port: u16 = port_input.trim().parse().unwrap_or(0);

    Ok(Some((room, None, Some(port))))
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub async fn run(
    ui:          &Ui,
    storage_dir: &Path,
    config:      &AppConfig,
    identity:    &PgpIdentity,
) -> Result<Option<(PersistedRoom, Option<Multiaddr>, Option<u16>)>> {
    let _ = execute!(stdout(), cursor::Hide);
    let result = run_inner(ui, storage_dir, config, identity).await;
    let _ = execute!(stdout(), cursor::Show);
    result
}

async fn run_inner(
    ui:          &Ui,
    storage_dir: &Path,
    config:      &AppConfig,
    identity:    &PgpIdentity,
) -> Result<Option<(PersistedRoom, Option<Multiaddr>, Option<u16>)>> {
    let identity_name = config.active_identity.as_deref().unwrap_or("");
    let own_fp        = identity.fingerprint();

    // State init before any disk I/O so the screen can be drawn immediately.
    let mut contacts: Vec<PersistedContact>    = Vec::new();
    let mut pending:  Vec<PendingTrustRequest> = Vec::new();
    let mut peer_data: HashMap<PeerId, PeerData> = HashMap::new();
    let mut fp_peer:   HashMap<String, PeerId>   = HashMap::new();
    let mut peer_fp:   HashMap<PeerId, String>   = HashMap::new();

    let mut selected_idx:   usize = 0;
    let mut display_scroll: usize = 0;
    let mut si:             usize = 0;
    let scanning = true;
    let mut status_msg: Option<(String, bool)> = None;
    let (mut term_w, mut term_h) = terminal::size().unwrap_or((80, 24));

    // Draw before disk reads so the screen appears the moment the user selects this option.
    {
        let rows    = build_rows(&contacts, &pending, &fp_peer);
        let display = build_display(&rows);
        draw_all(ui, &rows, &display, selected_idx, display_scroll, scanning, SPIN[si], term_w, term_h, None)?;
    }

    // Load disk data after the initial draw.
    let saved_rooms = persistence::load_rooms(storage_dir, identity_name, identity);
    let room_by_hash: HashMap<String, String> = saved_rooms.iter()
        .map(|r| (IdentTopic::new(&r.name).hash().to_string(), r.name.clone()))
        .collect();
    let announce_hash = IdentTopic::new(ANNOUNCE_TOPIC).hash();
    contacts = persistence::load_contacts(storage_dir, identity_name, identity).contacts;
    pending  = persistence::load_pending_trust_requests(storage_dir, identity_name, identity);

    // Redraw now that contacts and pending data are loaded.
    {
        let rows    = build_rows(&contacts, &pending, &fp_peer);
        let display = build_display(&rows);
        draw_all(ui, &rows, &display, selected_idx, display_scroll, scanning, SPIN[si], term_w, term_h, None)?;
    }
    crate::sidebar::draw_auto(storage_dir, ui, Some(identity));

    // Build the swarm after the initial draw (OS socket allocation happens here).
    let keypair = Keypair::generate_ed25519();
    let mut swarm = Some(build_swarm(keypair)?);
    if let Some(s) = swarm.as_mut() {
        s.listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())?;
        s.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap())?;
    }

    let mut event_stream = EventStream::new();
    let mut tick = tokio::time::interval(Duration::from_millis(500));

    loop {
        tokio::select! {
            biased;

            // ── Keyboard ──────────────────────────────────────────────────
            kb = event_stream.next() => {
                let Some(Ok(ev)) = kb else { continue; };

                if let Event::Resize(w, h) = ev {
                    term_w = w;
                    term_h = h;
                    ui.renderer.set_width(crate::sidebar::main_width(w));
                    let rows    = build_rows(&contacts, &pending, &fp_peer);
                    let display = build_display(&rows);
                    selected_idx = selected_idx.min(rows.len().saturating_sub(1));
                    if let Some(di) = find_display_idx(&display, selected_idx) {
                        ensure_visible(&mut display_scroll, di, max_visible(term_h));
                    }
                    draw_all(ui, &rows, &display, selected_idx, display_scroll, scanning, SPIN[si], term_w, term_h, status_msg.as_ref())?;
                    crate::sidebar::draw(storage_dir, term_w, ui.renderer.cap().unicode, identity)?;
                    continue;
                }

                let Event::Key(k) = ev else { continue; };
                if k.kind != KeyEventKind::Press { continue; }
                status_msg = None;

                match k.code {
                    KeyCode::Esc => return Ok(None),

                    KeyCode::Down => {
                        let rows = build_rows(&contacts, &pending, &fp_peer);
                        if !rows.is_empty() && selected_idx + 1 < rows.len() {
                            selected_idx += 1;
                            let display = build_display(&rows);
                            if let Some(di) = find_display_idx(&display, selected_idx) {
                                ensure_visible(&mut display_scroll, di, max_visible(term_h));
                            }
                            draw_all(ui, &rows, &display, selected_idx, display_scroll, scanning, SPIN[si], term_w, term_h, None)?;
                        }
                    }

                    KeyCode::Up => {
                        let rows = build_rows(&contacts, &pending, &fp_peer);
                        if !rows.is_empty() && selected_idx > 0 {
                            selected_idx -= 1;
                            let display = build_display(&rows);
                            if let Some(di) = find_display_idx(&display, selected_idx) {
                                ensure_visible(&mut display_scroll, di, max_visible(term_h));
                            }
                            draw_all(ui, &rows, &display, selected_idx, display_scroll, scanning, SPIN[si], term_w, term_h, None)?;
                        }
                    }

                    KeyCode::Enter => {
                        let rows = build_rows(&contacts, &pending, &fp_peer);
                        if rows.is_empty() || selected_idx >= rows.len() { continue; }

                        match rows[selected_idx].clone() {
                            Row::Pending(req) => {
                                drop(rows);
                                let accepted = handle_pending_inline(
                                    ui, storage_dir, identity_name, identity, &req, term_h,
                                )?;
                                // Reload state after mutation.
                                contacts = persistence::load_contacts(storage_dir, identity_name, identity).contacts;
                                pending  = persistence::load_pending_trust_requests(storage_dir, identity_name, identity);
                                let new_rows    = build_rows(&contacts, &pending, &fp_peer);
                                let new_display = build_display(&new_rows);
                                selected_idx = selected_idx.min(new_rows.len().saturating_sub(1));
                                if let Some(di) = find_display_idx(&new_display, selected_idx) {
                                    ensure_visible(&mut display_scroll, di, max_visible(term_h));
                                }
                                status_msg = if accepted {
                                    Some(("Contact added to your trusted list.".to_string(), false))
                                } else {
                                    None
                                };
                                draw_all(ui, &new_rows, &new_display, selected_idx, display_scroll, scanning, SPIN[si], term_w, term_h, status_msg.as_ref())?;
                                crate::sidebar::draw(storage_dir, term_w, ui.renderer.cap().unicode, identity)?;
                            }

                            Row::Contact { nickname, fingerprint, is_online } => {
                                drop(rows);
                                let fp_short = if fingerprint.len() >= 16 {
                                    format!("{}…", &fingerprint[..16])
                                } else {
                                    fingerprint.clone()
                                };

                                let _ = execute!(stdout(), cursor::Show);

                                // Show contact action sub-menu.
                                ui.clear()?;
                                let status_label = if is_online { "online \u{25cf}" } else { "offline" };
                                ui.renderer.draw_box_top(&format!("{} ({})", nickname, status_label))?;
                                println!("\r");
                                println!("  fp: {}\r", fp_short);
                                println!("\r");
                                println!("  [s] Start Chat       create a room and wait for peers to join\r");
                                if is_online {
                                    println!("  [j] Join their room  see rooms this contact is hosting\r");
                                }
                                println!("  [0] Back\r");
                                ui.renderer.draw_box_bottom()?;
                                std::io::stdout().flush()?;

                                let choice = ui.prompt("Choice:")?;

                                match choice.trim().to_lowercase().as_str() {
                                    "s" => {
                                        if let Some(launch) = start_chat_from_friends(
                                            ui, storage_dir, identity, identity_name,
                                        )? {
                                            return Ok(Some(launch));
                                        }
                                    }
                                    "j" if is_online => {
                                        if let Some(pid) = fp_peer.get(&fingerprint) {
                                            let data   = peer_data.get(pid);
                                            let addr   = data.and_then(|d| d.addr.clone());
                                            let topics = data.map(|d| d.topics.clone())
                                                .unwrap_or_default();
                                            let join = crate::commands::peer_scanner::enter_friend_rooms(
                                                ui, storage_dir, identity, identity_name,
                                                addr, &nickname, &fp_short, &topics,
                                                &room_by_hash, term_h,
                                            )?;
                                            if let Some(room_info) = join {
                                                return Ok(Some(room_info));
                                            }
                                        }
                                    }
                                    _ => {}
                                }

                                let _ = execute!(stdout(), cursor::Hide);
                                let redraw = build_rows(&contacts, &pending, &fp_peer);
                                let redisp = build_display(&redraw);
                                draw_all(ui, &redraw, &redisp, selected_idx, display_scroll, scanning, SPIN[si], term_w, term_h, None)?;
                                crate::sidebar::draw(storage_dir, term_w, ui.renderer.cap().unicode, identity)?;
                            }
                        }
                    }

                    _ => {}
                }
            }

            // ── Swarm events ──────────────────────────────────────────────
            event = next_event(&mut swarm) => {
                let mut needs_redraw = false;

                match event {
                    SwarmEvent::Behaviour(FriendsBehaviourEvent::Mdns(
                        mdns::Event::Discovered(list)
                    )) => {
                        for (peer_id, addr) in list {
                            peer_data.entry(peer_id.clone()).or_default().addr = Some(addr.clone());
                            if let Some(sw) = swarm.as_mut() { let _ = sw.dial(addr); }
                        }
                    }

                    SwarmEvent::Behaviour(FriendsBehaviourEvent::Mdns(
                        mdns::Event::Expired(list)
                    )) => {
                        for (peer_id, _) in list {
                            peer_data.remove(&peer_id);
                            if let Some(fp) = peer_fp.remove(&peer_id) {
                                fp_peer.remove(&fp);
                                needs_redraw = true;
                            }
                        }
                    }

                    SwarmEvent::Behaviour(FriendsBehaviourEvent::Gossipsub(
                        gossipsub::Event::Message { message, .. }
                    )) => {
                        if message.topic == announce_hash {
                            if let Some(msg) = TrustRequestMessage::from_bytes(&message.data) {
                                if msg.verify().is_ok() && msg.from_fingerprint != own_fp {
                                    let is_contact = contacts.iter()
                                        .any(|c| c.fingerprint == msg.from_fingerprint);
                                    if is_contact {
                                        if let Some(source) = message.source {
                                            peer_fp.insert(source.clone(), msg.from_fingerprint.clone());
                                            fp_peer.insert(msg.from_fingerprint.clone(), source.clone());
                                            peer_data.entry(source).or_default();
                                            needs_redraw = true;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    SwarmEvent::Behaviour(FriendsBehaviourEvent::Gossipsub(
                        gossipsub::Event::Subscribed { peer_id, topic }
                    )) => {
                        peer_data.entry(peer_id.clone()).or_default()
                            .topics.insert(topic.to_string());
                        if topic == announce_hash {
                            publish_announce(&mut swarm, identity);
                        }
                    }

                    SwarmEvent::Behaviour(FriendsBehaviourEvent::Gossipsub(
                        gossipsub::Event::Unsubscribed { peer_id, topic }
                    )) => {
                        if let Some(data) = peer_data.get_mut(&peer_id) {
                            data.topics.remove(&topic.to_string());
                        }
                    }

                    SwarmEvent::ConnectionEstablished { .. } => {
                        publish_announce(&mut swarm, identity);
                    }

                    _ => {}
                }

                if needs_redraw {
                    let rows    = build_rows(&contacts, &pending, &fp_peer);
                    let display = build_display(&rows);
                    if let Some(di) = find_display_idx(&display, selected_idx) {
                        ensure_visible(&mut display_scroll, di, max_visible(term_h));
                    }
                    draw_all(ui, &rows, &display, selected_idx, display_scroll, scanning, SPIN[si], term_w, term_h, status_msg.as_ref())?;
                    stdout().flush()?;
                }
            }

            // ── Spinner tick ──────────────────────────────────────────────
            _ = tick.tick() => {
                si = (si + 1) % SPIN.len();
                execute!(stdout(),
                    cursor::SavePosition,
                    cursor::MoveTo(0, spin_row(term_h)),
                    terminal::Clear(terminal::ClearType::CurrentLine),
                    SetForegroundColor(ui.renderer.palette().accent),
                    Print(format!("  {} Scanning for friends\u{2026}", SPIN[si])),
                    ResetColor,
                    cursor::RestorePosition,
                )?;
                stdout().flush()?;
                crate::sidebar::draw(storage_dir, term_w, ui.renderer.cap().unicode, identity)?;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Inline trust request prompt
// ---------------------------------------------------------------------------

fn handle_pending_inline(
    _ui:           &Ui,
    storage_dir:   &Path,
    identity_name: &str,
    identity:      &PgpIdentity,
    req:           &PendingTrustRequest,
    term_h:        u16,
) -> Result<bool> {
    use crossterm::event::{read, Event, KeyCode, KeyEventKind};

    let nick = crate::ui::sanitize_display(&req.from_nickname);
    let fp   = &req.from_fingerprint;

    execute!(stdout(),
        cursor::MoveTo(0, sep_row(term_h).saturating_sub(1)),
        terminal::Clear(terminal::ClearType::CurrentLine),
        SetForegroundColor(Color::Yellow),
        Print(format!("  Trust request from \"{}\"  fp:{}", nick, &fp[..fp.len().min(16)])),
        ResetColor,
        cursor::MoveTo(0, hint_row(term_h)),
        terminal::Clear(terminal::ClearType::CurrentLine),
        SetForegroundColor(Color::DarkGrey),
        Print("  [a] Accept   [r] Reject   [Esc] Cancel"),
        ResetColor,
        cursor::MoveTo(0, spin_row(term_h)),
        terminal::Clear(terminal::ClearType::CurrentLine),
        cursor::Show,
    )?;
    stdout().flush()?;

    let accepted = loop {
        let ev = read()?;
        let Event::Key(k) = ev else { continue; };
        if k.kind != KeyEventKind::Press { continue; }
        match k.code {
            KeyCode::Char('a') | KeyCode::Char('A') => {
                do_accept_trust(storage_dir, identity_name, identity, req);
                break true;
            }
            KeyCode::Char('r') | KeyCode::Char('R') => {
                do_reject_trust(storage_dir, identity_name, identity, req);
                break false;
            }
            KeyCode::Esc => break false,
            _ => {}
        }
    };

    execute!(stdout(), cursor::Hide)?;
    Ok(accepted)
}

// ---------------------------------------------------------------------------
// Announce
// ---------------------------------------------------------------------------

fn publish_announce(swarm: &mut Option<libp2p::Swarm<FriendsBehaviour>>, identity: &PgpIdentity) {
    if let Some(sw) = swarm.as_mut() {
        if let Ok(msg) = TrustRequestMessage::new(identity) {
            let _ = sw.behaviour_mut().gossipsub.publish(
                IdentTopic::new(ANNOUNCE_TOPIC),
                msg.to_bytes(),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Trust accept / reject helpers
// ---------------------------------------------------------------------------

fn do_accept_trust(
    storage_dir:   &Path,
    identity_name: &str,
    identity:      &PgpIdentity,
    req:           &PendingTrustRequest,
) {
    let tmp = PersistedContact {
        fingerprint:        req.from_fingerprint.clone(),
        nickname:           req.from_nickname.clone(),
        armored_public_key: req.from_public_key_armored.clone(),
        last_seen:          None,
    };
    if parse_contact(&tmp).is_err() {
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

fn do_reject_trust(
    storage_dir:   &Path,
    identity_name: &str,
    identity:      &PgpIdentity,
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
