//! Live peer discovery — mDNS-based, flicker-free TUI.
//!
//! The screen is drawn once on entry and then updated in-place:
//!   • Peer rows      — written at their exact terminal row; never cleared.
//!   • Footer rows    — fixed at the last 3 rows of the terminal.
//!   • Spinner        — overwrites a single footer row; no screen clear.
//!
//! Navigation is arrow-key based.  Esc exits.  [S] stops scanning.

use std::collections::{BTreeSet, HashMap, HashSet};
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
    Multiaddr, PeerId,
    SwarmBuilder,
};

use pgp_chat_core::{
    crypto::identity::PgpIdentity,
    network::trust_message::{ANNOUNCE_TOPIC, TRUST_TOPIC, TrustRequestMessage},
    persistence::{
        self, AppConfig, PendingTrustRequest,
        PersistedRoom, decrypt_room_passphrase, encrypt_room_passphrase,
        save_pending_trust_requests,
    },
};
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
    agent_version:   Option<String>,
    addrs:           Vec<String>,
    topics:          BTreeSet<String>,
    // Filled in when we receive a signed ANNOUNCE_TOPIC message from this peer.
    pgp_fingerprint: Option<String>,
    pgp_nickname:    Option<String>,
    /// True when `pgp_fingerprint` is present in the local contacts list.
    is_trusted:      bool,
}

impl PeerInfo {
    fn is_pgp_chat(&self) -> bool {
        self.agent_version.as_deref()
            .map(|v| v.starts_with("pgp-chat/"))
            .unwrap_or(false)
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
    already_sent: bool,
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

    // Status tag: [friend] takes precedence over [req sent]
    let (tag_text, tag_color): (&str, crossterm::style::Color) = if info.is_trusted {
        ("  [friend]", crossterm::style::Color::Green)
    } else if already_sent {
        ("  [req sent]", pal.dim)
    } else {
        ("", pal.dim)
    };

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
    if !tag_text.is_empty() {
        execute!(stdout(),
            SetForegroundColor(tag_color),
            Print(tag_text),
            ResetColor,
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
    sent_to:      &HashSet<PeerId>,
) -> Result<()> {
    let max = max_visible(term_h);
    if list.is_empty() {
        draw_no_peers(ui)?;
        for v in 1..max { erase_row(peer_row(v))?; }
    } else {
        for v in 0..max {
            let idx = scroll + v;
            if idx < list.len() {
                draw_peer_row(
                    ui, peer_row(v), idx + 1,
                    list[idx].0, list[idx].1, room_by_hash,
                    selected_idx == idx,
                    sent_to.contains(list[idx].0),
                )?;
            } else {
                erase_row(peer_row(v))?;
            }
        }
    }
    Ok(())
}

/// Draw the fixed footer: separator + nav hint + spinner.
///
/// When `trust_alert` is Some, the hint and spinner rows display the incoming
/// trust request prompt instead of the normal navigation hint.
/// When `confirming` is true, the footer is suppressed so the confirm prompt
/// written inline by the Enter handler is not overwritten.
fn draw_footer(
    ui:          &Ui,
    term_h:      u16,
    scanning:    bool,
    spin:        char,
    trust_alert: Option<&PendingTrustRequest>,
    confirming:  bool,
) -> Result<()> {
    let pal = ui.renderer.palette();

    execute!(stdout(),
        cursor::MoveTo(0, sep_row(term_h)),
        terminal::Clear(terminal::ClearType::CurrentLine),
    )?;
    ui.renderer.draw_box_separator()?;

    if confirming {
        // Confirm prompt is already drawn inline — leave those rows alone.
        stdout().flush()?;
        return Ok(());
    }

    if let Some(req) = trust_alert {
        let fp = &req.from_fingerprint;
        let fp_short = &fp[..fp.len().min(20)];
        execute!(stdout(),
            cursor::MoveTo(0, hint_row(term_h)),
            terminal::Clear(terminal::ClearType::CurrentLine),
            SetForegroundColor(crossterm::style::Color::Yellow),
            Print(format!(
                "  ! Trust request from \"{}\"  fp: {}…",
                crate::ui::sanitize_display(&req.from_nickname), fp_short
            )),
            ResetColor,
        )?;
        execute!(stdout(),
            cursor::MoveTo(0, spin_row(term_h)),
            terminal::Clear(terminal::ClearType::CurrentLine),
            SetForegroundColor(pal.dim),
            Print("    [T] Trust   [D] Defer (handle later)   [R] Reject"),
            ResetColor,
        )?;
    } else {
        execute!(stdout(),
            cursor::MoveTo(0, hint_row(term_h)),
            terminal::Clear(terminal::ClearType::CurrentLine),
            SetForegroundColor(pal.dim),
            Print("  \u{2191}\u{2193} navigate   Enter peer request"),
        )?;
        if scanning {
            execute!(stdout(), Print("   [S] stop scanning"))?;
        } else {
            execute!(stdout(), Print("   [R] restart scanning"))?;
        }
        execute!(stdout(), Print("   [Esc] back"), ResetColor)?;
        draw_spinner_line(pal.accent, term_h, scanning, spin)?;
    }

    stdout().flush()?;
    Ok(())
}

/// In-place spinner tick: rewrites only the bottom status row, no screen clear.
/// Skipped when a trust alert or confirm prompt occupies those rows.
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
    trust_alert:  Option<&PendingTrustRequest>,
    sent_to:      &HashSet<PeerId>,
) -> Result<()> {
    ui.clear()?;

    ui.renderer.draw_box_top("Scan for Peers")?;
    execute!(stdout(),
        Print("\r\n  Discovered pgp-chat peers:\r\n\r\n"),
    )?;

    draw_peer_area(ui, list, selected_idx, scroll, term_h, room_by_hash, sent_to)?;
    draw_footer(ui, term_h, scanning, spin, trust_alert, false)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Scan for peers.  Returns `Some((room, addr))` when the user navigated into
/// a trusted friend's room list and selected a room to join — the caller
/// (menu) should then launch `chat::run` with that room and bootstrap address.
/// Returns `None` when the user exits the scanner normally.
pub async fn run(
    ui:          &Ui,
    storage_dir: &Path,
    config:      &AppConfig,
    identity:    &PgpIdentity,
) -> Result<Option<(PersistedRoom, Option<Multiaddr>, Option<u16>)>> {
    let _ = execute!(stdout(), cursor::Hide);
    let result = run_scanner(ui, storage_dir, config, identity).await;
    let _ = execute!(stdout(), cursor::Show);
    result
}

async fn run_scanner(
    ui:          &Ui,
    storage_dir: &Path,
    config:      &AppConfig,
    identity:    &PgpIdentity,
) -> Result<Option<(PersistedRoom, Option<Multiaddr>, Option<u16>)>> {
    let identity_name = config.active_identity.as_deref().unwrap_or("");

    let mut peers:        HashMap<PeerId, PeerInfo>  = HashMap::new();
    let mut peer_order:   Vec<PeerId>                = Vec::new();
    let mut scanning      = true;
    let mut selected_idx: usize = 0;
    let mut scroll:       usize = 0;
    let mut si:           usize = 0;
    let mut sent_to: HashSet<PeerId> = HashSet::new();
    let mut trust_alert:  Option<PendingTrustRequest> = None;
    let mut confirming         = false;
    let mut confirming_peer_id: Option<PeerId> = None;
    let (mut term_w, mut term_h) = terminal::size().unwrap_or((80, 24));

    // Draw before disk reads so the screen appears the moment the user selects this option.
    let empty: Vec<(&PeerId, &PeerInfo)> = vec![];
    let empty_rooms: HashMap<String, String> = HashMap::new();
    draw_all(ui, &empty, selected_idx, scroll, scanning, SPIN[si], term_h, &empty_rooms, None, &sent_to)?;

    // Load disk data after the initial draw.
    let saved_rooms   = persistence::load_rooms(storage_dir, identity_name, identity);
    let room_by_hash: HashMap<String, String> = saved_rooms.iter()
        .map(|r| (IdentTopic::new(&r.name).hash().to_string(), r.name.clone()))
        .collect();
    let contact_fps: HashSet<String> = {
        let store = persistence::load_contacts(storage_dir, identity_name, identity);
        store.contacts.iter().map(|c| c.fingerprint.clone()).collect()
    };
    let announce_topic_hash = IdentTopic::new(ANNOUNCE_TOPIC).hash();
    let trust_topic_hash    = IdentTopic::new(TRUST_TOPIC).hash();
    crate::sidebar::draw_auto(storage_dir, ui, Some(identity));

    // Build the swarm after the initial draw (OS socket allocation happens here).
    let keypair = Keypair::generate_ed25519();
    let mut swarm = Some(build_scanner_swarm(keypair)?);
    if let Some(s) = swarm.as_mut() {
        s.listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())?;
        s.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap())?;
    }

    let mut event_stream  = EventStream::new();
    let mut tick          = tokio::time::interval(Duration::from_millis(500));

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
                    let list = pgp_peers(&peer_order, &peers);
                    if !list.is_empty() {
                        selected_idx = selected_idx.min(list.len() - 1);
                        let max = max_visible(term_h);
                        if scroll + max <= selected_idx {
                            scroll = selected_idx.saturating_sub(max - 1);
                        }
                    }
                    confirming = false; // resize cancels confirm
                    draw_all(ui, &list, selected_idx, scroll, scanning, SPIN[si], term_h, &room_by_hash, trust_alert.as_ref(), &sent_to)?;
                    crate::sidebar::draw(storage_dir, term_w, ui.renderer.cap().unicode, identity)?;
                    continue;
                }

                let Event::Key(k) = ev else { continue; };
                if k.kind != KeyEventKind::Press { continue; }

                // ── Confirm-mode: waiting for y/n after Enter ─────────────
                if confirming {
                    match k.code {
                        KeyCode::Char('y') | KeyCode::Char('Y') => {
                            confirming = false;
                            let sent_pid = confirming_peer_id.take();
                            if let Some(sw) = swarm.as_mut() {
                                match TrustRequestMessage::new(identity) {
                                    Ok(msg) => {
                                        let topic = IdentTopic::new(TRUST_TOPIC);
                                        match sw.behaviour_mut().gossipsub.publish(topic, msg.to_bytes()) {
                                            Ok(_) => {
                                                if let Some(pid) = sent_pid {
                                                    sent_to.insert(pid);
                                                }
                                                execute!(stdout(),
                                                    cursor::MoveTo(0, hint_row(term_h)),
                                                    terminal::Clear(terminal::ClearType::CurrentLine),
                                                    SetForegroundColor(crossterm::style::Color::Green),
                                                    Print("  Peering request sent!  They will see it shortly."),
                                                    ResetColor,
                                                    cursor::MoveTo(0, spin_row(term_h)),
                                                    terminal::Clear(terminal::ClearType::CurrentLine),
                                                )?;
                                                stdout().flush()?;
                                                tokio::time::sleep(Duration::from_millis(1500)).await;
                                            }
                                            Err(e) => {
                                                execute!(stdout(),
                                                    cursor::MoveTo(0, hint_row(term_h)),
                                                    terminal::Clear(terminal::ClearType::CurrentLine),
                                                    Print(format!("  ! Publish error: {e}")),
                                                    cursor::MoveTo(0, spin_row(term_h)),
                                                    terminal::Clear(terminal::ClearType::CurrentLine),
                                                )?;
                                                stdout().flush()?;
                                                tokio::time::sleep(Duration::from_millis(1500)).await;
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        execute!(stdout(),
                                            cursor::MoveTo(0, hint_row(term_h)),
                                            terminal::Clear(terminal::ClearType::CurrentLine),
                                            Print(format!("  ! Error: {e}")),
                                        )?;
                                        stdout().flush()?;
                                        tokio::time::sleep(Duration::from_millis(1500)).await;
                                    }
                                }
                            }
                            let list = pgp_peers(&peer_order, &peers);
                            draw_peer_area(ui, &list, selected_idx, scroll, term_h, &room_by_hash, &sent_to)?;
                            draw_footer(ui, term_h, scanning, SPIN[si], trust_alert.as_ref(), false)?;
                            crate::sidebar::draw(storage_dir, term_w, ui.renderer.cap().unicode, identity)?;
                        }
                        _ => {
                            // Any other key cancels the confirm
                            confirming = false;
                            confirming_peer_id = None;
                            draw_footer(ui, term_h, scanning, SPIN[si], trust_alert.as_ref(), false)?;
                        }
                    }
                    continue;
                }

                // ── Trust-alert handling: T/D/R respond to incoming request ─
                if trust_alert.is_some() {
                    match k.code {
                        KeyCode::Char('t') | KeyCode::Char('T') => {
                            if let Some(req) = trust_alert.take() {
                                scanner_accept_trust(storage_dir, identity, identity_name, &req);
                            }
                            draw_footer(ui, term_h, scanning, SPIN[si], None, false)?;
                            crate::sidebar::draw(storage_dir, term_w, ui.renderer.cap().unicode, identity)?;
                            continue;
                        }
                        KeyCode::Char('d') | KeyCode::Char('D') => {
                            trust_alert = None;
                            draw_footer(ui, term_h, scanning, SPIN[si], None, false)?;
                            continue;
                        }
                        KeyCode::Char('r') | KeyCode::Char('R') => {
                            if let Some(req) = trust_alert.take() {
                                scanner_reject_trust(storage_dir, identity, identity_name, &req);
                            }
                            draw_footer(ui, term_h, scanning, SPIN[si], None, false)?;
                            crate::sidebar::draw(storage_dir, term_w, ui.renderer.cap().unicode, identity)?;
                            continue;
                        }
                        _ => {}
                    }
                }

                match k.code {
                    KeyCode::Esc => return Ok(None),

                    KeyCode::Char('s') | KeyCode::Char('S') if scanning => {
                        swarm.take();
                        scanning = false;
                        draw_footer(ui, term_h, scanning, SPIN[si], trust_alert.as_ref(), false)?;
                    }

                    KeyCode::Char('r') | KeyCode::Char('R') if !scanning => {
                        let keypair = Keypair::generate_ed25519();
                        match build_scanner_swarm(keypair) {
                            Ok(mut new_swarm) => {
                                let _ = new_swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap());
                                let _ = new_swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap());
                                swarm = Some(new_swarm);
                                scanning = true;
                                draw_footer(ui, term_h, scanning, SPIN[si], trust_alert.as_ref(), false)?;
                            }
                            Err(e) => {
                                execute!(stdout(),
                                    cursor::MoveTo(0, spin_row(term_h)),
                                    terminal::Clear(terminal::ClearType::CurrentLine),
                                    Print(format!("  ! Failed to restart: {}", e)),
                                )?;
                                stdout().flush()?;
                            }
                        }
                    }

                    KeyCode::Down => {
                        let list = pgp_peers(&peer_order, &peers);
                        if list.is_empty() { continue; }
                        let max_idx = list.len() - 1;
                        if selected_idx < max_idx {
                            let old = selected_idx;
                            selected_idx += 1;
                            let max = max_visible(term_h);
                            if selected_idx >= scroll + max {
                                scroll = selected_idx - max + 1;
                                draw_peer_area(ui, &list, selected_idx, scroll, term_h, &room_by_hash, &sent_to)?;
                            } else {
                                let old_v = old - scroll;
                                let new_v = selected_idx - scroll;
                                draw_peer_row(ui, peer_row(old_v), old + 1, list[old].0, list[old].1, &room_by_hash, false, sent_to.contains(list[old].0))?;
                                draw_peer_row(ui, peer_row(new_v), selected_idx + 1, list[selected_idx].0, list[selected_idx].1, &room_by_hash, true, sent_to.contains(list[selected_idx].0))?;
                            }
                            stdout().flush()?;
                        }
                    }

                    KeyCode::Up => {
                        let list = pgp_peers(&peer_order, &peers);
                        if list.is_empty() { continue; }
                        if selected_idx > 0 {
                            let old = selected_idx;
                            selected_idx -= 1;
                            if selected_idx < scroll {
                                scroll = selected_idx;
                                draw_peer_area(ui, &list, selected_idx, scroll, term_h, &room_by_hash, &sent_to)?;
                            } else {
                                let old_v = old - scroll;
                                let new_v = selected_idx - scroll;
                                draw_peer_row(ui, peer_row(old_v), old + 1, list[old].0, list[old].1, &room_by_hash, false, sent_to.contains(list[old].0))?;
                                draw_peer_row(ui, peer_row(new_v), selected_idx + 1, list[selected_idx].0, list[selected_idx].1, &room_by_hash, true, sent_to.contains(list[selected_idx].0))?;
                            }
                            stdout().flush()?;
                        }
                    }

                    // ── Enter: trusted peer → show their rooms; unknown → peering request ──
                    KeyCode::Enter => {
                        let list = pgp_peers(&peer_order, &peers);
                        if list.is_empty() || selected_idx >= list.len() { continue; }
                        let (peer_id, info) = list[selected_idx];

                        // Extract owned copies before releasing the list borrow.
                        let is_trusted      = info.is_trusted;
                        let peer_id_clone   = peer_id.clone();
                        let already_in_sent = sent_to.contains(peer_id);
                        let pid_str         = peer_id.to_string();
                        let pid_short       = pid_str[..pid_str.len().min(20)].to_string();

                        // For the friend-rooms sub-screen we need some owned info.
                        let friend_info = if is_trusted {
                            Some((
                                info.addrs.iter().find_map(|a| a.parse::<Multiaddr>().ok()),
                                info.pgp_nickname.clone()
                                    .unwrap_or_else(|| "Trusted peer".to_string()),
                                info.pgp_fingerprint.as_deref()
                                    .map(|fp| format!("{}…", &fp[..fp.len().min(16)]))
                                    .unwrap_or_default(),
                                info.topics.clone(),
                            ))
                        } else { None };

                        drop(list); // release borrows on `peers` / `peer_order`

                        if let Some((peer_addr, peer_nick, peer_fp_short, topics)) = friend_info {
                            // Show trusted peer's rooms sub-screen.
                            let _ = execute!(stdout(), cursor::Show);
                            let join = enter_friend_rooms(
                                ui, storage_dir, identity, identity_name,
                                peer_addr, &peer_nick, &peer_fp_short, &topics,
                                &room_by_hash, term_h,
                            )?;
                            let _ = execute!(stdout(), cursor::Hide);
                            if let Some(room_info) = join {
                                return Ok(Some(room_info));
                            }
                            // User pressed Esc — redraw the scanner.
                            let list = pgp_peers(&peer_order, &peers);
                            draw_all(ui, &list, selected_idx, scroll, scanning, SPIN[si], term_h, &room_by_hash, trust_alert.as_ref(), &sent_to)?;
                            crate::sidebar::draw(storage_dir, term_w, ui.renderer.cap().unicode, identity)?;
                            continue;
                        }

                        // Non-trusted peer handling.
                        if swarm.is_none() { continue; }

                        if already_in_sent {
                            execute!(stdout(),
                                cursor::MoveTo(0, hint_row(term_h)),
                                terminal::Clear(terminal::ClearType::CurrentLine),
                                SetForegroundColor(crossterm::style::Color::DarkGrey),
                                Print("  Peering request already sent to this peer."),
                                ResetColor,
                                cursor::MoveTo(0, spin_row(term_h)),
                                terminal::Clear(terminal::ClearType::CurrentLine),
                            )?;
                            stdout().flush()?;
                            continue;
                        }

                        confirming = true;
                        confirming_peer_id = Some(peer_id_clone);
                        execute!(stdout(),
                            cursor::MoveTo(0, hint_row(term_h)),
                            terminal::Clear(terminal::ClearType::CurrentLine),
                            SetForegroundColor(crossterm::style::Color::Cyan),
                            Print(format!("  Send peering request to {}…?", pid_short)),
                            ResetColor,
                            cursor::MoveTo(0, spin_row(term_h)),
                            terminal::Clear(terminal::ClearType::CurrentLine),
                            SetForegroundColor(crossterm::style::Color::DarkGrey),
                            Print("    [y] Yes, send request   [any other key] Cancel"),
                            ResetColor,
                        )?;
                        stdout().flush()?;
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
                                if !confirming {
                                    draw_peer_area(ui, &pgp_list, selected_idx, scroll, term_h, &room_by_hash, &sent_to)?;
                                    stdout().flush()?;
                                }
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
                        if e.is_pgp_chat() && !was_vis && !confirming {
                            let list = pgp_peers(&peer_order, &peers);
                            let new_idx = list.len() - 1;
                            let max = max_visible(term_h);
                            if new_idx == 0 {
                                draw_peer_row(ui, peer_row(0), 1,
                                    list[0].0, list[0].1, &room_by_hash, selected_idx == 0,
                                    sent_to.contains(list[0].0))?;
                            } else if new_idx >= scroll && new_idx < scroll + max {
                                draw_peer_row(ui, peer_row(new_idx - scroll), new_idx + 1,
                                    list[new_idx].0, list[new_idx].1, &room_by_hash, selected_idx == new_idx,
                                    sent_to.contains(list[new_idx].0))?;
                            }
                            stdout().flush()?;
                        }
                    }

                    SwarmEvent::Behaviour(ScannerBehaviourEvent::Gossipsub(
                        gossipsub::Event::Message { message, .. }
                    )) => {
                        if message.topic == announce_topic_hash {
                            // Peer announcing their PGP fingerprint → record it.
                            if let Some(msg) = TrustRequestMessage::from_bytes(&message.data) {
                                if msg.verify().is_ok()
                                    && msg.from_fingerprint != identity.fingerprint()
                                {
                                    if let Some(source) = message.source {
                                        if !peers.contains_key(&source) {
                                            peer_order.push(source.clone());
                                        }
                                        let e = peers.entry(source.clone()).or_default();
                                        e.pgp_fingerprint = Some(msg.from_fingerprint.clone());
                                        e.pgp_nickname    = Some(msg.from_nickname.clone());
                                        e.is_trusted      = contact_fps.contains(&msg.from_fingerprint);
                                        if e.is_pgp_chat() && !confirming {
                                            let list = pgp_peers(&peer_order, &peers);
                                            if let Some(idx) = list.iter().position(|(pid, _)| *pid == &source) {
                                                let max = max_visible(term_h);
                                                if idx >= scroll && idx < scroll + max {
                                                    draw_peer_row(ui, peer_row(idx - scroll), idx + 1,
                                                        list[idx].0, list[idx].1, &room_by_hash,
                                                        selected_idx == idx, sent_to.contains(list[idx].0))?;
                                                    stdout().flush()?;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        } else if message.topic == trust_topic_hash {
                            if let Some(msg) = TrustRequestMessage::from_bytes(&message.data) {
                                if msg.verify().is_err() {
                                    // Silently drop invalid trust requests.
                                } else if msg.from_fingerprint == identity.fingerprint() {
                                    // Silently drop our own broadcast.
                                } else {
                                    let trust_store = persistence::load_contacts(storage_dir, identity_name, identity);
                                    let skip = trust_store.contacts.iter().any(|c| c.fingerprint == msg.from_fingerprint)
                                        || trust_store.rejected.iter().any(|fp| fp == &msg.from_fingerprint);
                                    if !skip {
                                        let mut reqs = persistence::load_pending_trust_requests(storage_dir, identity_name, identity);
                                        let already = reqs.iter().any(|r| r.from_fingerprint == msg.from_fingerprint);
                                        if !already {
                                            let new_req = PendingTrustRequest {
                                                from_nickname:           msg.from_nickname,
                                                from_fingerprint:        msg.from_fingerprint,
                                                from_public_key_armored: msg.from_public_key_armored,
                                                received_at:             chrono::Utc::now(),
                                            };
                                            reqs.push(new_req.clone());
                                            let _ = save_pending_trust_requests(storage_dir, identity_name, &reqs, identity);
                                            if trust_alert.is_none() {
                                                trust_alert = Some(new_req);
                                            }
                                            if !confirming {
                                                draw_footer(ui, term_h, scanning, SPIN[si], trust_alert.as_ref(), false)?;
                                            }
                                            crate::sidebar::draw(storage_dir, term_w, ui.renderer.cap().unicode, identity)?;
                                        }
                                    }
                                }
                            }
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
                        if peers.get(&peer_id).map(|p| p.is_pgp_chat()).unwrap_or(false) && !confirming {
                            let list = pgp_peers(&peer_order, &peers);
                            if let Some(idx) = list.iter().position(|(pid, _)| *pid == &peer_id) {
                                let max = max_visible(term_h);
                                if idx >= scroll && idx < scroll + max {
                                    draw_peer_row(ui, peer_row(idx - scroll), idx + 1,
                                        list[idx].0, list[idx].1, &room_by_hash, selected_idx == idx,
                                        sent_to.contains(list[idx].0))?;
                                    stdout().flush()?;
                                }
                            }
                        }
                        // A peer subscribed to the announce topic — respond with our own announce
                        // so they can learn our fingerprint.
                        if topic == announce_topic_hash {
                            publish_announce(&mut swarm, identity);
                        }
                    }

                    SwarmEvent::Behaviour(ScannerBehaviourEvent::Gossipsub(
                        gossipsub::Event::Unsubscribed { peer_id, topic }
                    )) => {
                        if let Some(p) = peers.get_mut(&peer_id) {
                            p.topics.remove(&topic.to_string());
                            if p.is_pgp_chat() && !confirming {
                                let list = pgp_peers(&peer_order, &peers);
                                if let Some(idx) = list.iter().position(|(pid, _)| *pid == &peer_id) {
                                    let max = max_visible(term_h);
                                    if idx >= scroll && idx < scroll + max {
                                        draw_peer_row(ui, peer_row(idx - scroll), idx + 1,
                                            list[idx].0, list[idx].1, &room_by_hash, selected_idx == idx,
                                            sent_to.contains(list[idx].0))?;
                                        stdout().flush()?;
                                    }
                                }
                            }
                        }
                    }

                    // When a connection is established, broadcast our PGP fingerprint
                    // so the peer can identify us as a friend if we're in their contacts.
                    SwarmEvent::ConnectionEstablished { .. } => {
                        publish_announce(&mut swarm, identity);
                    }

                    _ => {}
                }
            }

            // ── Spinner tick ──────────────────────────────────────────────
            _ = tick.tick() => {
                if scanning && !trust_alert.is_some() && !confirming {
                    si = (si + 1) % SPIN.len();
                    update_spinner(ui, term_h, SPIN[si])?;
                }
                crate::sidebar::draw(storage_dir, term_w, ui.renderer.cap().unicode, identity)?;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Announce helper
// ---------------------------------------------------------------------------

/// Publish a signed PGP-fingerprint announcement on `ANNOUNCE_TOPIC`.
///
/// Fire-and-forget: we silently ignore publish errors (no subscribers yet is
/// the common case on startup).
fn publish_announce(swarm: &mut Option<libp2p::Swarm<ScannerBehaviour>>, identity: &PgpIdentity) {
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
// Friend rooms sub-screen
// ---------------------------------------------------------------------------

/// Show a modal sub-screen listing the topic subscriptions of a trusted peer.
/// The user can navigate and Enter to join a room (passphrase required).
///
/// Returns `Ok(Some((room, bootstrap_addr)))` when the user selects a room,
/// or `Ok(None)` when they press Esc to return to the scanner.
pub(crate) fn enter_friend_rooms(
    ui:            &Ui,
    storage_dir:   &Path,
    identity:      &PgpIdentity,
    identity_name: &str,
    peer_addr:     Option<Multiaddr>,
    peer_nickname: &str,
    peer_fp_short: &str,
    topics:        &BTreeSet<String>,
    room_by_hash:  &HashMap<String, String>,
    term_h:        u16,
) -> Result<Option<(PersistedRoom, Option<Multiaddr>, Option<u16>)>> {
    use crossterm::event::{read, Event, KeyCode, KeyEventKind};

    // Filter out non-room meta-topics so we only show actual chat rooms.
    let exclude: HashSet<String> = [
        IdentTopic::new(TRUST_TOPIC).hash().to_string(),
        IdentTopic::new(ANNOUNCE_TOPIC).hash().to_string(),
    ].into_iter().collect();

    let rooms: Vec<(String, Option<String>)> = topics.iter()
        .filter(|h| !exclude.contains(*h))
        .map(|h| (h.clone(), room_by_hash.get(h).cloned()))
        .collect();

    let mut selected:    usize = 0;
    let mut status:      Option<(String, bool)> = None; // (msg, is_error)

    loop {
        let pal = ui.renderer.palette();

        // ── Full redraw ───────────────────────────────────────────────────
        ui.clear()?;
        ui.renderer.draw_box_top(&format!("Rooms — \"{}\"", peer_nickname))?;
        execute!(stdout(),
            cursor::MoveTo(0, 2),
            SetForegroundColor(pal.dim),
            Print(format!("  Trusted peer: \"{}\"  fp: {}\r\n", peer_nickname, peer_fp_short)),
            ResetColor,
        )?;

        let list_top: u16 = 4;
        if rooms.is_empty() {
            execute!(stdout(),
                cursor::MoveTo(0, list_top),
                SetForegroundColor(pal.dim),
                Print("    (peer is not subscribed to any chat rooms right now)"),
                ResetColor,
            )?;
        } else {
            for (i, (_hash, maybe_name)) in rooms.iter().enumerate() {
                let display = maybe_name.as_deref()
                    .unwrap_or("(unknown room — needs passphrase + name to join)");
                let row = list_top + i as u16;
                if row >= sep_row(term_h) { break; }
                execute!(stdout(), cursor::MoveTo(0, row))?;
                if i == selected {
                    execute!(stdout(),
                        SetForegroundColor(pal.accent),
                        SetAttribute(Attribute::Bold),
                        Print(format!(" > [{}]  {}", i + 1, display)),
                        SetAttribute(Attribute::Reset),
                        ResetColor,
                    )?;
                } else {
                    execute!(stdout(), Print(format!("   [{}]  {}", i + 1, display)))?;
                }
            }
        }

        // Status line above the separator
        if let Some((ref msg, is_err)) = status {
            let color = if is_err {
                crossterm::style::Color::Red
            } else {
                crossterm::style::Color::Green
            };
            execute!(stdout(),
                cursor::MoveTo(0, sep_row(term_h).saturating_sub(1)),
                terminal::Clear(terminal::ClearType::CurrentLine),
                SetForegroundColor(color),
                Print(format!("  {}", msg)),
                ResetColor,
            )?;
        }

        // Footer
        execute!(stdout(),
            cursor::MoveTo(0, sep_row(term_h)),
            terminal::Clear(terminal::ClearType::CurrentLine),
        )?;
        ui.renderer.draw_box_separator()?;
        execute!(stdout(),
            cursor::MoveTo(0, hint_row(term_h)),
            terminal::Clear(terminal::ClearType::CurrentLine),
            SetForegroundColor(pal.dim),
            Print(if rooms.is_empty() {
                "  Esc back".to_string()
            } else {
                "  \u{2191}\u{2193} navigate   Enter join room   Esc back".to_string()
            }),
            ResetColor,
            cursor::MoveTo(0, spin_row(term_h)),
            terminal::Clear(terminal::ClearType::CurrentLine),
        )?;
        stdout().flush()?;

        status = None;

        // ── Key event loop (synchronous; network events queue while we wait) ──
        loop {
            let ev = read()?;
            let Event::Key(k) = ev else { continue; };
            if k.kind != KeyEventKind::Press { continue; }

            match k.code {
                KeyCode::Esc => return Ok(None),

                KeyCode::Up if !rooms.is_empty() && selected > 0 => {
                    selected -= 1;
                    break; // redraw
                }

                KeyCode::Down if !rooms.is_empty() && selected + 1 < rooms.len() => {
                    selected += 1;
                    break; // redraw
                }

                KeyCode::Enter if !rooms.is_empty() => {
                    let (hash, maybe_name) = &rooms[selected];

                    // ── Resolve room name ─────────────────────────────────
                    let room_name: String = match maybe_name {
                        Some(n) => n.clone(),
                        None => {
                            // Unknown hash: user must tell us the room name so we
                            // can verify it hashes to what the peer is subscribed to.
                            execute!(stdout(),
                                cursor::MoveTo(0, hint_row(term_h)),
                                terminal::Clear(terminal::ClearType::CurrentLine),
                                cursor::MoveTo(0, spin_row(term_h)),
                                terminal::Clear(terminal::ClearType::CurrentLine),
                                cursor::Show,
                            )?;
                            stdout().flush()?;
                            let name = ui.prompt("Room name (must match the topic hash):")?;
                            execute!(stdout(), cursor::Hide)?;
                            let name = name.trim().to_string();
                            if name.is_empty() { break; }
                            let expected = IdentTopic::new(&name).hash().to_string();
                            if &expected != hash {
                                status = Some(("Room name does not match this topic — check the spelling.".to_string(), true));
                                break;
                            }
                            name
                        }
                    };

                    // ── Passphrase prompt ─────────────────────────────────
                    execute!(stdout(),
                        cursor::MoveTo(0, hint_row(term_h)),
                        terminal::Clear(terminal::ClearType::CurrentLine),
                        cursor::MoveTo(0, spin_row(term_h)),
                        terminal::Clear(terminal::ClearType::CurrentLine),
                        cursor::Show,
                    )?;
                    stdout().flush()?;
                    let entered = ui.prompt_password(&format!("Passphrase for \"{}\":", room_name))?;
                    execute!(stdout(), cursor::Hide)?;
                    if entered.is_empty() { break; } // cancelled

                    // ── Check known rooms (passphrase must match stored) ───
                    let known = persistence::load_rooms(storage_dir, identity_name, identity);
                    if let Some(r) = known.iter().find(|r| r.name == room_name) {
                        let stored_plain = decrypt_room_passphrase(&r.passphrase, identity);
                        if entered.as_str() != stored_plain {
                            status = Some(("Incorrect passphrase.".to_string(), true));
                            break;
                        }
                        return Ok(Some((r.clone(), peer_addr, None)));
                    }

                    // ── New room: save and return ─────────────────────────
                    let encrypted = encrypt_room_passphrase(entered.as_str(), identity)
                        .unwrap_or_else(|_| entered.as_str().to_string());
                    let new_room = PersistedRoom {
                        name:       room_name.clone(),
                        passphrase: encrypted,
                        is_owner:   false,
                    };
                    let mut rooms_list = persistence::load_rooms(storage_dir, identity_name, identity);
                    rooms_list.push(new_room.clone());
                    let _ = persistence::save_rooms(storage_dir, identity_name, &rooms_list, identity);
                    return Ok(Some((new_room, peer_addr, None)));
                }

                _ => {}
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Trust helpers used by inline alert actions inside the scanner
// ---------------------------------------------------------------------------

fn scanner_accept_trust(
    storage_dir:   &Path,
    identity:      &PgpIdentity,
    identity_name: &str,
    req:           &PendingTrustRequest,
) {
    use pgp_chat_core::persistence::{PersistedContact, parse_contact};
    use chrono::Utc;

    let tmp = PersistedContact {
        fingerprint:        req.from_fingerprint.clone(),
        nickname:           req.from_nickname.clone(),
        armored_public_key: req.from_public_key_armored.clone(),
        last_seen:          None,
    };
    if parse_contact(&tmp).is_err() {
        let mut reqs = persistence::load_pending_trust_requests(storage_dir, identity_name, identity);
        reqs.retain(|r| r.from_fingerprint != req.from_fingerprint);
        let _ = save_pending_trust_requests(storage_dir, identity_name, &reqs, identity);
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
    let mut reqs = persistence::load_pending_trust_requests(storage_dir, identity_name, identity);
    reqs.retain(|r| r.from_fingerprint != req.from_fingerprint);
    let _ = save_pending_trust_requests(storage_dir, identity_name, &reqs, identity);
}

fn scanner_reject_trust(
    storage_dir:   &Path,
    identity:      &PgpIdentity,
    identity_name: &str,
    req:           &PendingTrustRequest,
) {
    let mut reqs = persistence::load_pending_trust_requests(storage_dir, identity_name, identity);
    reqs.retain(|r| r.from_fingerprint != req.from_fingerprint);
    let _ = save_pending_trust_requests(storage_dir, identity_name, &reqs, identity);
    let mut store = persistence::load_contacts(storage_dir, identity_name, identity);
    if !store.rejected.contains(&req.from_fingerprint) {
        store.rejected.push(req.from_fingerprint.clone());
        let _ = persistence::save_contacts(storage_dir, identity_name, &store, identity);
    }
}


