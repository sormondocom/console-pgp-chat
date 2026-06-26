//! Live peer discovery — mDNS-based, flicker-free TUI.
//!
//! The screen is drawn once on entry and then updated in-place:
//!   • Peer rows      — written at their exact terminal row; never cleared.
//!   • Footer rows    — fixed at the last 3 rows of the terminal.
//!   • Spinner        — overwrites a single footer row; no screen clear.
//!
//! Navigation is arrow-key based.  Esc exits.  [S] stops scanning.

use std::collections::{BTreeSet, HashMap};
use std::io::{stdout, Write};
use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use crossterm::{
    cursor,
    event::{Event, EventStream, KeyCode, KeyEventKind},
    execute,
    style::{Attribute, Print, ResetColor, SetAttribute, SetForegroundColor},
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
    Multiaddr,
    PeerId,
    SwarmBuilder,
};

use pgp_chat_core::persistence::{self, AppConfig, PersistedRoom};
use crate::ui::Ui;

const IDENTIFY_PROTOCOL: &str = "/pgp-chat/1.0.0";
const SPIN: [char; 4] = ['|', '/', '-', '\\'];

// Fixed number of header rows (rows 0-3).
const HEADER: u16 = 4;
// Fixed number of footer rows at the bottom of the terminal.
const FOOTER: u16 = 3; // separator + nav-hint + spinner

// ---------------------------------------------------------------------------
// Layout helpers — all positions are 0-indexed terminal rows
// ---------------------------------------------------------------------------

fn max_visible(term_h: u16) -> usize {
    term_h.saturating_sub(HEADER + FOOTER) as usize
}
fn peer_row(visible_idx: usize) -> u16 { HEADER + visible_idx as u16 }
fn sep_row(h: u16)   -> u16 { h - FOOTER }
fn hint_row(h: u16)  -> u16 { h - 2 }
fn spin_row(h: u16)  -> u16 { h - 1 }

// ---------------------------------------------------------------------------
// Scanner-specific swarm behaviour (mDNS instead of Kademlia)
// ---------------------------------------------------------------------------

#[derive(NetworkBehaviour)]
struct ScannerBehaviour {
    gossipsub: gossipsub::Behaviour,
    identify:  identify::Behaviour,
    mdns:      mdns::tokio::Behaviour,
}

// ---------------------------------------------------------------------------
// Per-peer data
// ---------------------------------------------------------------------------

#[derive(Default)]
struct PeerInfo {
    agent_version: Option<String>,
    addrs:         Vec<String>,
    topics:        BTreeSet<String>,
}

impl PeerInfo {
    fn is_pgp_chat(&self) -> bool {
        self.agent_version.as_deref()
            .map(|v| v.starts_with("pgp-chat/"))
            .unwrap_or(false)
    }
    fn bootstrap_addr(&self) -> Option<Multiaddr> {
        self.addrs.iter().find_map(|a| a.parse().ok())
    }
}

// ---------------------------------------------------------------------------
// Build scanner swarm
// ---------------------------------------------------------------------------

fn build_scanner_swarm(keypair: Keypair) -> Result<libp2p::Swarm<ScannerBehaviour>> {
    let peer_id    = keypair.public().to_peer_id();
    let public_key = keypair.public();

    let gs_cfg = gossipsub::ConfigBuilder::default()
        .validation_mode(gossipsub::ValidationMode::Permissive)
        .build()
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(keypair.clone()), gs_cfg,
    ).map_err(|e| anyhow::anyhow!("{e}"))?;

    let identify = identify::Behaviour::new(
        identify::Config::new(IDENTIFY_PROTOCOL.to_string(), public_key)
            .with_agent_version(format!("pgp-chat/{}", env!("CARGO_PKG_VERSION"))),
    );
    let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let behaviour = ScannerBehaviour { gossipsub, identify, mdns };

    Ok(SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .with_quic()
        .with_behaviour(|_| behaviour)
        .unwrap()
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build())
}

async fn next_swarm_event(
    swarm: &mut Option<libp2p::Swarm<ScannerBehaviour>>,
) -> SwarmEvent<ScannerBehaviourEvent> {
    match swarm {
        Some(s) => s.select_next_some().await,
        None    => std::future::pending().await,
    }
}

// ---------------------------------------------------------------------------
// Ordered list of confirmed pgp-chat peers
// ---------------------------------------------------------------------------

fn pgp_peers<'a>(
    order: &'a [PeerId],
    map:   &'a HashMap<PeerId, PeerInfo>,
) -> Vec<(&'a PeerId, &'a PeerInfo)> {
    order.iter()
        .filter_map(|pid| {
            let info = map.get(pid)?;
            info.is_pgp_chat().then_some((pid, info))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// In-place draw primitives — each targets a specific terminal row
// ---------------------------------------------------------------------------

/// Erase one terminal row completely.
fn erase_row(row: u16) -> Result<()> {
    execute!(stdout(),
        cursor::MoveTo(0, row),
        terminal::Clear(terminal::ClearType::CurrentLine),
    )?;
    Ok(())
}

/// Draw or redraw a single peer row.
fn draw_peer_row(
    ui:           &Ui,
    abs_row:      u16,
    display_num:  usize,
    peer_id:      &PeerId,
    info:         &PeerInfo,
    room_by_hash: &HashMap<String, String>,
    selected:     bool,
) -> Result<()> {
    let pal     = ui.renderer.palette();
    let n       = info.topics.len();
    let matched: Vec<&str> = info.topics.iter()
        .filter_map(|h| room_by_hash.get(h).map(String::as_str))
        .collect();
    let room_tag = if n == 0 {
        "no rooms observed".to_string()
    } else if matched.is_empty() {
        format!("{} room(s) — none saved", n)
    } else {
        format!("{} room(s), saved: {}", n, matched.join(", "))
    };
    let version = info.agent_version.as_deref().unwrap_or("unknown");
    let pid_str = peer_id.to_string();
    let pid_short = &pid_str[..pid_str.len().min(20)];

    execute!(stdout(),
        cursor::MoveTo(0, abs_row),
        terminal::Clear(terminal::ClearType::CurrentLine),
    )?;

    if selected {
        execute!(stdout(),
            SetForegroundColor(pal.accent),
            SetAttribute(Attribute::Bold),
            Print(format!(" > [{}]  {}…  {}  —  {}", display_num, pid_short, version, room_tag)),
            SetAttribute(Attribute::Reset),
            ResetColor,
        )?;
    } else {
        execute!(stdout(),
            Print(format!("   [{}]  {}…  {}  —  {}", display_num, pid_short, version, room_tag)),
        )?;
    }
    Ok(())
}

/// Draw the "no peers yet" placeholder on the first peer row.
fn draw_no_peers(ui: &Ui) -> Result<()> {
    let pal = ui.renderer.palette();
    execute!(stdout(),
        cursor::MoveTo(0, peer_row(0)),
        terminal::Clear(terminal::ClearType::CurrentLine),
        SetForegroundColor(pal.dim),
        Print("    (no peers found yet — scanning...)"),
        ResetColor,
    )?;
    Ok(())
}

/// Redraw all visible peer rows.  Called on initial draw, resize, and scroll.
fn draw_peer_area(
    ui:           &Ui,
    list:         &[(&PeerId, &PeerInfo)],
    selected_idx: usize,
    scroll:       usize,
    term_h:       u16,
    room_by_hash: &HashMap<String, String>,
) -> Result<()> {
    let max = max_visible(term_h);
    if list.is_empty() {
        draw_no_peers(ui)?;
        for v in 1..max { erase_row(peer_row(v))?; }
    } else {
        for v in 0..max {
            let idx = scroll + v;
            if idx < list.len() {
                draw_peer_row(ui, peer_row(v), idx + 1,
                    list[idx].0, list[idx].1, room_by_hash, selected_idx == idx)?;
            } else {
                erase_row(peer_row(v))?;
            }
        }
    }
    Ok(())
}

/// Draw the fixed footer: separator + nav hint + spinner.
fn draw_footer(ui: &Ui, term_h: u16, scanning: bool, spin: char) -> Result<()> {
    let pal = ui.renderer.palette();

    // Separator
    execute!(stdout(),
        cursor::MoveTo(0, sep_row(term_h)),
        terminal::Clear(terminal::ClearType::CurrentLine),
    )?;
    ui.renderer.draw_box_separator()?;

    // Nav hint
    execute!(stdout(),
        cursor::MoveTo(0, hint_row(term_h)),
        terminal::Clear(terminal::ClearType::CurrentLine),
        SetForegroundColor(pal.dim),
        Print("  \u{2191}\u{2193} navigate   Enter view rooms"),
    )?;
    if scanning {
        execute!(stdout(), Print("   [S] stop scanning"))?;
    } else {
        execute!(stdout(), Print("   [R] restart scanning"))?;
    }
    execute!(stdout(), Print("   [Esc] back"), ResetColor)?;

    // Spinner / status
    draw_spinner_line(pal.accent, term_h, scanning, spin)?;

    stdout().flush()?;
    Ok(())
}

/// In-place spinner tick: rewrites only the bottom status row, no screen clear.
fn update_spinner(ui: &Ui, term_h: u16, spin: char) -> Result<()> {
    let pal = ui.renderer.palette();
    execute!(stdout(), cursor::SavePosition)?;
    draw_spinner_line(pal.accent, term_h, true, spin)?;
    execute!(stdout(), cursor::RestorePosition)?;
    stdout().flush()?;
    Ok(())
}

fn draw_spinner_line(
    accent:   crossterm::style::Color,
    term_h:   u16,
    scanning: bool,
    spin:     char,
) -> Result<()> {
    execute!(stdout(),
        cursor::MoveTo(0, spin_row(term_h)),
        terminal::Clear(terminal::ClearType::CurrentLine),
    )?;
    if scanning {
        execute!(stdout(),
            SetForegroundColor(accent),
            Print(format!("  {} Scanning", spin)),
            ResetColor,
        )?;
    } else {
        execute!(stdout(), Print("  \u{25a0} Scanning stopped"))?;
    }
    Ok(())
}

/// Full initial draw — called once on entry and on terminal resize.
fn draw_all(
    ui:           &Ui,
    list:         &[(&PeerId, &PeerInfo)],
    selected_idx: usize,
    scroll:       usize,
    scanning:     bool,
    spin:         char,
    term_h:       u16,
    room_by_hash: &HashMap<String, String>,
) -> Result<()> {
    ui.clear()?;

    // Header rows 0-3
    ui.renderer.draw_box_top("Scan for Peers")?;
    execute!(stdout(),
        Print("\r\n  Discovered pgp-chat peers:\r\n\r\n"),
    )?;

    // Peer area
    draw_peer_area(ui, list, selected_idx, scroll, term_h, room_by_hash)?;

    // Footer
    draw_footer(ui, term_h, scanning, spin)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub async fn run(ui: &Ui, storage_dir: &Path, config: &AppConfig) -> Result<()> {
    let _ = execute!(stdout(), cursor::Hide);
    let result = run_scanner(ui, storage_dir, config).await;
    let _ = execute!(stdout(), cursor::Show);
    result
}

async fn run_scanner(ui: &Ui, storage_dir: &Path, config: &AppConfig) -> Result<()> {
    let saved_rooms  = persistence::load_rooms(storage_dir);
    let room_by_hash: HashMap<String, String> = saved_rooms.iter()
        .map(|r| (IdentTopic::new(&r.name).hash().to_string(), r.name.clone()))
        .collect();

    let keypair = Keypair::generate_ed25519();
    let mut swarm = Some(build_scanner_swarm(keypair)?);
    if let Some(s) = swarm.as_mut() {
        s.listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())?;
        s.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap())?;
    }

    let mut peers:      HashMap<PeerId, PeerInfo> = HashMap::new();
    let mut peer_order: Vec<PeerId>               = Vec::new();
    let mut scanning    = true;
    let mut selected_idx: usize = 0;
    let mut scroll:       usize = 0;
    let mut event_stream = EventStream::new();
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    let mut si: usize = 0;

    let (_, mut term_h) = terminal::size().unwrap_or((80, 24));

    let empty: Vec<(&PeerId, &PeerInfo)> = vec![];
    draw_all(ui, &empty, selected_idx, scroll, scanning, SPIN[si], term_h, &room_by_hash)?;

    loop {
        tokio::select! {
            biased;

            // ── Keyboard ──────────────────────────────────────────────────
            kb = event_stream.next() => {
                let Some(Ok(ev)) = kb else { continue; };

                // Handle terminal resize
                if let Event::Resize(_, h) = ev {
                    term_h = h;
                    let list = pgp_peers(&peer_order, &peers);
                    // Clamp selection after resize
                    if !list.is_empty() {
                        selected_idx = selected_idx.min(list.len() - 1);
                        let max = max_visible(term_h);
                        if scroll + max <= selected_idx {
                            scroll = selected_idx.saturating_sub(max - 1);
                        }
                    }
                    draw_all(ui, &list, selected_idx, scroll, scanning, SPIN[si], term_h, &room_by_hash)?;
                    continue;
                }

                let Event::Key(k) = ev else { continue; };
                if k.kind != KeyEventKind::Press { continue; }

                match k.code {
                    // ── Exit ──────────────────────────────────────────────
                    KeyCode::Esc => return Ok(()),

                    // ── Stop scanning ─────────────────────────────────────
                    KeyCode::Char('s') | KeyCode::Char('S') if scanning => {
                        swarm.take();
                        scanning = false;
                        draw_footer(ui, term_h, scanning, SPIN[si])?;
                    }

                    // ── Restart scanning ──────────────────────────────────
                    KeyCode::Char('r') | KeyCode::Char('R') if !scanning => {
                        let keypair = Keypair::generate_ed25519();
                        match build_scanner_swarm(keypair) {
                            Ok(mut new_swarm) => {
                                let _ = new_swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap());
                                let _ = new_swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap());
                                swarm = Some(new_swarm);
                                scanning = true;
                                draw_footer(ui, term_h, scanning, SPIN[si])?;
                            }
                            Err(e) => {
                                // Show the error briefly in the spinner row and stay stopped
                                execute!(stdout(),
                                    cursor::MoveTo(0, spin_row(term_h)),
                                    terminal::Clear(terminal::ClearType::CurrentLine),
                                    Print(format!("  ! Failed to restart: {}", e)),
                                )?;
                                stdout().flush()?;
                            }
                        }
                    }

                    // ── Navigate down ─────────────────────────────────────
                    KeyCode::Down => {
                        let list = pgp_peers(&peer_order, &peers);
                        if list.is_empty() { continue; }
                        let max_idx = list.len() - 1;
                        if selected_idx < max_idx {
                            let old = selected_idx;
                            selected_idx += 1;
                            let max = max_visible(term_h);
                            if selected_idx >= scroll + max {
                                // Scroll down — redraw entire peer area
                                scroll = selected_idx - max + 1;
                                draw_peer_area(ui, &list, selected_idx, scroll, term_h, &room_by_hash)?;
                            } else {
                                // Just update the two affected rows
                                let old_v = old - scroll;
                                let new_v = selected_idx - scroll;
                                draw_peer_row(ui, peer_row(old_v), old + 1, list[old].0, list[old].1, &room_by_hash, false)?;
                                draw_peer_row(ui, peer_row(new_v), selected_idx + 1, list[selected_idx].0, list[selected_idx].1, &room_by_hash, true)?;
                            }
                            stdout().flush()?;
                        }
                    }

                    // ── Navigate up ───────────────────────────────────────
                    KeyCode::Up => {
                        let list = pgp_peers(&peer_order, &peers);
                        if list.is_empty() { continue; }
                        if selected_idx > 0 {
                            let old = selected_idx;
                            selected_idx -= 1;
                            if selected_idx < scroll {
                                // Scroll up — redraw entire peer area
                                scroll = selected_idx;
                                draw_peer_area(ui, &list, selected_idx, scroll, term_h, &room_by_hash)?;
                            } else {
                                let old_v = old - scroll;
                                let new_v = selected_idx - scroll;
                                draw_peer_row(ui, peer_row(old_v), old + 1, list[old].0, list[old].1, &room_by_hash, false)?;
                                draw_peer_row(ui, peer_row(new_v), selected_idx + 1, list[selected_idx].0, list[selected_idx].1, &room_by_hash, true)?;
                            }
                            stdout().flush()?;
                        }
                    }

                    // ── Select peer ───────────────────────────────────────
                    KeyCode::Enter => {
                        let list = pgp_peers(&peer_order, &peers);
                        if list.is_empty() { continue; }
                        if selected_idx < list.len() {
                            swarm.take();
                            let (peer_id, info) = list[selected_idx];
                            let _ = execute!(stdout(), cursor::Show);
                            select_room_for_peer(
                                ui, storage_dir, config,
                                peer_id, info, &room_by_hash, &saved_rooms,
                            ).await?;
                            return Ok(());
                        }
                    }

                    _ => {}
                }
            }

            // ── Swarm events ──────────────────────────────────────────────
            event = next_swarm_event(&mut swarm) => {
                match event {
                    SwarmEvent::Behaviour(ScannerBehaviourEvent::Mdns(
                        mdns::Event::Discovered(list)
                    )) => {
                        for (peer_id, addr) in list {
                            if !peers.contains_key(&peer_id) {
                                peer_order.push(peer_id.clone());
                            }
                            let e = peers.entry(peer_id).or_default();
                            let s = addr.to_string();
                            if !e.addrs.contains(&s) { e.addrs.push(s); }
                            if let Some(sw) = swarm.as_mut() { let _ = sw.dial(addr); }
                        }
                    }

                    // ── mDNS expired — remove stale peer entries ──────────
                    // Without this, peers that go offline or switch sessions
                    // (getting a new ephemeral PeerId) linger in the list.
                    SwarmEvent::Behaviour(ScannerBehaviourEvent::Mdns(
                        mdns::Event::Expired(list)
                    )) => {
                        for (peer_id, _) in list {
                            let was_pgp = peers.get(&peer_id)
                                .map(|p| p.is_pgp_chat()).unwrap_or(false);
                            peers.remove(&peer_id);
                            peer_order.retain(|pid| pid != &peer_id);
                            if was_pgp {
                                let pgp_list = pgp_peers(&peer_order, &peers);
                                if pgp_list.is_empty() {
                                    selected_idx = 0;
                                    scroll = 0;
                                } else {
                                    let max = max_visible(term_h);
                                    selected_idx = selected_idx.min(pgp_list.len() - 1);
                                    if scroll > 0 && scroll + max > pgp_list.len() {
                                        scroll = pgp_list.len().saturating_sub(max);
                                    }
                                }
                                draw_peer_area(ui, &pgp_list, selected_idx, scroll, term_h, &room_by_hash)?;
                                stdout().flush()?;
                            }
                        }
                    }
                    SwarmEvent::Behaviour(ScannerBehaviourEvent::Identify(
                        identify::Event::Received { peer_id, info, .. }
                    )) => {
                        let was_vis = peers.get(&peer_id)
                            .map(|p| p.is_pgp_chat()).unwrap_or(false);
                        if !peers.contains_key(&peer_id) {
                            peer_order.push(peer_id.clone());
                        }
                        let e = peers.entry(peer_id.clone()).or_default();
                        e.agent_version = Some(info.agent_version.clone());
                        for addr in &info.listen_addrs {
                            let s = addr.to_string();
                            if !e.addrs.contains(&s) { e.addrs.push(s); }
                        }
                        if e.is_pgp_chat() && !was_vis {
                            // New pgp-chat peer — append its row in-place
                            let list = pgp_peers(&peer_order, &peers);
                            let new_idx = list.len() - 1;
                            let max = max_visible(term_h);

                            if new_idx == 0 {
                                // Replace the "no peers yet" placeholder
                                draw_peer_row(ui, peer_row(0), 1,
                                    list[0].0, list[0].1, &room_by_hash, selected_idx == 0)?;
                            } else if new_idx >= scroll && new_idx < scroll + max {
                                draw_peer_row(ui, peer_row(new_idx - scroll), new_idx + 1,
                                    list[new_idx].0, list[new_idx].1, &room_by_hash, selected_idx == new_idx)?;
                            }
                            stdout().flush()?;
                        }
                    }
                    SwarmEvent::Behaviour(ScannerBehaviourEvent::Gossipsub(
                        gossipsub::Event::Subscribed { peer_id, topic }
                    )) => {
                        if !peers.contains_key(&peer_id) {
                            peer_order.push(peer_id.clone());
                        }
                        peers.entry(peer_id.clone()).or_default()
                            .topics.insert(topic.to_string());
                        // Refresh the row for this peer if it's visible
                        if peers.get(&peer_id).map(|p| p.is_pgp_chat()).unwrap_or(false) {
                            let list = pgp_peers(&peer_order, &peers);
                            if let Some(idx) = list.iter().position(|(pid, _)| *pid == &peer_id) {
                                let max = max_visible(term_h);
                                if idx >= scroll && idx < scroll + max {
                                    draw_peer_row(ui, peer_row(idx - scroll), idx + 1,
                                        list[idx].0, list[idx].1, &room_by_hash, selected_idx == idx)?;
                                    stdout().flush()?;
                                }
                            }
                        }
                    }
                    SwarmEvent::Behaviour(ScannerBehaviourEvent::Gossipsub(
                        gossipsub::Event::Unsubscribed { peer_id, topic }
                    )) => {
                        if let Some(p) = peers.get_mut(&peer_id) {
                            p.topics.remove(&topic.to_string());
                            if p.is_pgp_chat() {
                                let list = pgp_peers(&peer_order, &peers);
                                if let Some(idx) = list.iter().position(|(pid, _)| *pid == &peer_id) {
                                    let max = max_visible(term_h);
                                    if idx >= scroll && idx < scroll + max {
                                        draw_peer_row(ui, peer_row(idx - scroll), idx + 1,
                                            list[idx].0, list[idx].1, &room_by_hash, selected_idx == idx)?;
                                        stdout().flush()?;
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }

            // ── Spinner tick — single row, no screen clear ────────────────
            _ = tick.tick() => {
                if scanning {
                    si = (si + 1) % SPIN.len();
                    update_spinner(ui, term_h, SPIN[si])?;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Room selection — called after stopping the scanner swarm
// ---------------------------------------------------------------------------

async fn select_room_for_peer(
    ui:           &Ui,
    storage_dir:  &Path,
    config:       &AppConfig,
    peer_id:      &PeerId,
    info:         &PeerInfo,
    room_by_hash: &HashMap<String, String>,
    saved_rooms:  &[PersistedRoom],
) -> Result<()> {
    ui.clear()?;
    ui.renderer.draw_box_top("Room Selection")?;
    println!("  Peer     {}\r", peer_id);
    println!("  Client   {}\r", info.agent_version.as_deref().unwrap_or("unknown"));
    if info.addrs.is_empty() {
        println!("  Address  (none observed)\r");
    } else {
        for (i, addr) in info.addrs.iter().enumerate() {
            if i == 0 { println!("  Address  {}\r", addr); }
            else       { println!("           {}\r", addr); }
        }
    }
    println!("\r");

    let mut known:   Vec<PersistedRoom> = Vec::new();
    let mut unknown: Vec<String>        = Vec::new();
    for hash in &info.topics {
        if let Some(name) = room_by_hash.get(hash) {
            if let Some(r) = saved_rooms.iter().find(|r| &r.name == name) {
                known.push(r.clone());
                continue;
            }
        }
        unknown.push(hash.clone());
    }

    if known.is_empty() && unknown.is_empty() {
        println!("  No room subscriptions observed for this peer.\r");
        println!("\r");
        ui.wait_for_key("Press any key to go back...")?;
        return Ok(());
    }

    if !known.is_empty() {
        println!("  Rooms you have saved (passphrase already stored):\r");
        for (i, r) in known.iter().enumerate() {
            println!("  [{}] {}  ({})\r", i + 1, r.name, if r.is_owner { "owner" } else { "member" });
        }
    }
    if !unknown.is_empty() {
        if !known.is_empty() { println!("\r"); }
        println!("  Unknown rooms (you will need the room name and passphrase):\r");
        for i in 0..unknown.len() {
            println!("  [{}] [unknown room]\r", known.len() + i + 1);
        }
    }
    println!("\r");
    println!("  After joining, use /trust to approve the peer's PGP key.\r");
    println!("  They must do the same before encrypted messages will flow.\r");
    println!("\r");

    let bootstrap = info.bootstrap_addr();
    loop {
        let choice = ui.prompt("Select a room [0 to go back]:")?;
        let choice = choice.trim().to_string();
        if choice == "0" || choice.is_empty() { return Ok(()); }

        if let Ok(n) = choice.parse::<usize>() {
            let total = known.len() + unknown.len();
            if n >= 1 && n <= total {
                if n <= known.len() {
                    let room = known[n - 1].clone();
                    ui.success(&format!("Joining '{}' — starting chat session.", room.name))?;
                    if let Some(ref addr) = bootstrap { println!("  Bootstrap: {}\r", addr); }
                    println!("\r");
                    super::chat::run(ui, storage_dir, config, Some((room, bootstrap))).await?;
                    return Ok(());
                } else {
                    let hash = &unknown[n - known.len() - 1];
                    join_unknown_room(ui, storage_dir, config, hash, bootstrap.clone()).await?;
                    return Ok(());
                }
            }
        }
        ui.error("Invalid selection.")?;
    }
}

// ---------------------------------------------------------------------------
// Join a room whose name/passphrase are not yet saved
// ---------------------------------------------------------------------------

async fn join_unknown_room(
    ui:          &Ui,
    storage_dir: &Path,
    config:      &AppConfig,
    topic_hash:  &str,
    bootstrap:   Option<Multiaddr>,
) -> Result<()> {
    println!("\r\n  Enter the room name to verify it matches the peer's subscription.\r\n  (Ask the room owner — they know the name they chose.)\r\n\r");
    let name_input = ui.prompt("Room name [blank to cancel]:")?;
    let name_input = name_input.trim().to_string();
    if name_input.is_empty() { println!("  Cancelled.\r"); return Ok(()); }

    if IdentTopic::new(&name_input).hash().to_string() != topic_hash {
        ui.error("Room name does not match — check spelling and try again.")?;
        ui.wait_for_key("Press any key...")?;
        return Ok(());
    }

    ui.success(&format!("Room name '{}' verified.", name_input))?;
    println!("\r");
    let passphrase = ui.prompt_password("Room passphrase (from the room owner):")?;
    if passphrase.is_empty() {
        ui.error("A passphrase is required.")?;
        ui.wait_for_key("Press any key...")?;
        return Ok(());
    }

    let room = PersistedRoom {
        name: name_input.clone(), passphrase: passphrase.as_str().to_owned(), is_owner: false,
    };
    ui.success(&format!("Joining '{}' — starting chat session.", name_input))?;
    if let Some(ref addr) = bootstrap { println!("  Bootstrap: {}\r", addr); }
    println!("\r");
    super::chat::run(ui, storage_dir, config, Some((room, bootstrap))).await
}
