//! Chat room: the central async coordinator.
//!
//! `ChatRoom::run()` drives a `tokio::select!` loop that handles:
//!   1. libp2p swarm events (connections, gossipsub messages, kad, identify)
//!   2. UI commands sent via `ChatRoomHandle::cmd_tx`
//!   3. A 60-second periodic `StatusAnnounce` heartbeat
//!
//! ## Security layers (outermost → innermost)
//!
//! ```text
//!  libp2p Noise/QUIC  ← transport encryption (ephemeral keys, per-session)
//!      │
//!  room_cipher::seal  ← PGP symmetric AES-256 (room passphrase, out-of-band)
//!      │
//!  SignedChatMessage  ← detached PGP signature (long-term EdDSA key)
//!      │
//!  MessageKind::Encrypted  ← PGP public-key encryption (ECDH, per-recipient)
//! ```

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;

use chrono::Utc;
use futures::StreamExt;
use libp2p::{
    gossipsub::{self, IdentTopic},
    kad,
    swarm::SwarmEvent,
    PeerId, Swarm,
};
use tokio::sync::mpsc;
use tokio::time;
use tracing::{debug, info, warn};
use uuid::Uuid;
use zeroize::Zeroizing;

use sha2::{Sha256, Digest};

use crate::{
    chat::{
        keystore::PeerKeyStore,
        message::{ChatMessage, MessageKind, SignedChatMessage},
        transfer::{
            FileAccept, FileChunk, FileComplete, FileDecline, FileOffer, InboundTransfer,
            PendingOffer, SenderNetInfo, CHUNK_BYTES, MAX_DESCRIPTION_LEN,
        },
        trust::{NodeInfo, NodeStatus, TrustState},
    },
    crypto::{encrypt, identity::PgpIdentity, room_cipher, sign},
    error::{Error, Result},
    network::{
        behaviour::{ChatBehaviour, ChatBehaviourEvent},
        event::ChatNetEvent,
        peer_discovery,
    },
    persistence::{PersistedContact, PersistedTrustStore},
};

// ---------------------------------------------------------------------------
// Tunable constants
// ---------------------------------------------------------------------------

/// Number of recently-seen message UUIDs kept for replay deduplication.
const SEEN_MSG_CAPACITY: usize = 512;

/// Backpressure capacity for the network→UI event channel.
const EVENT_CHANNEL_CAP: usize = 128;

/// Backpressure capacity for the UI→room command channel.
const CMD_CHANNEL_CAP: usize = 64;

/// How often we broadcast a `StatusAnnounce` heartbeat.
const STATUS_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// Command type (UI → Room)
// ---------------------------------------------------------------------------

/// Commands the UI sends to the running `ChatRoom`.
pub enum RoomCommand {
    /// Publish an unencrypted plaintext message.
    SendPlaintext(String),
    /// Publish a PGP-encrypted message to all trusted room members.
    SendEncrypted { body: String },
    /// Re-broadcast our PGP public key to the room.
    AnnounceKey,
    /// Move a peer's key from pending/deferred → trusted.
    ApproveKey(String),
    /// Approve all pending and deferred keys at once.
    ApproveAll,
    /// Permanently reject a peer's key for this session.
    DenyKey(String),
    /// Toggle deferring mode.  When `true`, incoming key announcements are
    /// queued rather than presented for approval.
    SetDeferring(bool),
    /// Request a snapshot of the full peer node map.
    GetNodeMap,
    /// Broadcast a signed revocation, wipe all local state, disconnect.
    Nuke,
    /// Graceful disconnect.
    Disconnect,

    // ── File transfer ──────────────────────────────────────────────────────

    /// Offer to send a file to a specific peer (by fingerprint).
    ///
    /// * `recipient_fp` — PGP fingerprint of the intended recipient
    /// * `path`         — local filesystem path to the file
    /// * `description`  — optional description (capped at 256 chars)
    SendFile {
        recipient_fp: String,
        path:         String,
        description:  String,
    },

    /// Accept an inbound file offer.
    AcceptFile {
        transfer_id: uuid::Uuid,
        /// Where the decrypted file should be saved.
        save_path: String,
    },

    /// Decline an inbound file offer.
    DeclineFile { transfer_id: uuid::Uuid },

    /// Cast this node's vote on a pending unanimous admission request.
    CastVote {
        candidate_fp: String,
        /// `true` = admit, `false` = veto.
        approved:     bool,
    },
}

/// Tracks the in-progress unanimous admission vote for one candidate.
struct ApprovalState {
    nickname:        String,
    peer_id:         PeerId,
    armored_key:     String,
    /// Fingerprints of all peers whose vote is required (includes this node).
    required_voters: HashSet<String>,
    /// Votes collected so far: voter_fp → approved.
    votes:           HashMap<String, bool>,
}

// ---------------------------------------------------------------------------
// Handle (given to the UI)
// ---------------------------------------------------------------------------

/// The UI-facing handle to a running `ChatRoom`.
pub struct ChatRoomHandle {
    /// Receive network / chat events here.
    pub event_rx: mpsc::Receiver<ChatNetEvent>,
    /// Send commands here.
    pub cmd_tx: mpsc::Sender<RoomCommand>,
    /// Local libp2p PeerId (for display purposes).
    pub local_peer_id: PeerId,
}

// ---------------------------------------------------------------------------
// Room
// ---------------------------------------------------------------------------

/// The async chat room coordinator — run via `tokio::spawn(room.run())`.
pub struct ChatRoom {
    swarm:            Swarm<ChatBehaviour>,
    topic:            IdentTopic,
    identity:         PgpIdentity,
    room_passphrase:  Zeroizing<String>,
    keystore:         PeerKeyStore,
    /// Node map: fingerprint → NodeInfo for all known peers.
    node_map:         HashMap<String, NodeInfo>,
    /// Fingerprints that have been revoked; messages from these are dropped.
    revoked_fps:      HashSet<String>,
    /// Whether we are currently deferring new key requests.
    is_deferring:     bool,
    event_tx:         mpsc::Sender<ChatNetEvent>,
    cmd_rx:           mpsc::Receiver<RoomCommand>,
    /// Rolling window of recently-seen message IDs for replay deduplication.
    seen_messages:    VecDeque<Uuid>,

    // ── Join admission state ───────────────────────────────────────────────
    /// In-flight unanimous join votes: candidate_fp → ApprovalState.
    pending_approvals: HashMap<String, ApprovalState>,

    // ── File transfer state ────────────────────────────────────────────────
    /// Outbound offers awaiting acceptance: transfer_id → PendingOffer.
    pending_offers:   HashMap<Uuid, PendingOffer>,
    /// Inbound transfers being assembled: transfer_id → InboundTransfer.
    inbound_transfers: HashMap<Uuid, InboundTransfer>,
    /// Save paths chosen by the user for accepted inbound transfers.
    accepted_saves:   HashMap<Uuid, String>,
}

impl ChatRoom {
    /// Create a `ChatRoom` and its `ChatRoomHandle`.
    ///
    /// Does not start listening or running — call `swarm.listen_on()` before
    /// handing the swarm here, then `tokio::spawn(room.run())`.
    ///
    /// `initial_keystore` may be pre-populated with trusted contacts loaded
    /// from disk; pass `PeerKeyStore::new()` for a fresh session.
    pub fn new(
        swarm: Swarm<ChatBehaviour>,
        room_name: &str,
        identity: PgpIdentity,
        room_passphrase: Zeroizing<String>,
        initial_keystore: PeerKeyStore,
    ) -> (Self, ChatRoomHandle) {
        let local_peer_id = *swarm.local_peer_id();
        let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAP);
        let (cmd_tx, cmd_rx)     = mpsc::channel(CMD_CHANNEL_CAP);

        let room = Self {
            swarm,
            topic: IdentTopic::new(room_name),
            identity,
            room_passphrase,
            keystore: initial_keystore,
            node_map: HashMap::new(),
            revoked_fps: HashSet::new(),
            is_deferring: false,
            event_tx,
            cmd_rx,
            seen_messages: VecDeque::with_capacity(SEEN_MSG_CAPACITY),
            pending_approvals: HashMap::new(),
            pending_offers: HashMap::new(),
            inbound_transfers: HashMap::new(),
            accepted_saves: HashMap::new(),
        };
        let handle = ChatRoomHandle { event_rx, cmd_tx, local_peer_id };
        (room, handle)
    }

    // -----------------------------------------------------------------------
    // Main loop
    // -----------------------------------------------------------------------

    /// Drive the swarm and command channel until `RoomCommand::Disconnect` or
    /// `RoomCommand::Nuke`.
    ///
    /// Returns `Some(PersistedTrustStore)` on a graceful disconnect so the
    /// caller can save contacts to disk.  Returns `None` after a Nuke (all
    /// state has been deliberately wiped) or an unexpected channel drop.
    pub async fn run(mut self) -> Option<PersistedTrustStore> {
        // Subscribe to the gossipsub topic
        if let Err(e) = self.swarm.behaviour_mut().gossipsub.subscribe(&self.topic) {
            warn!("gossipsub subscribe failed: {e}");
        }

        // Announce our PGP key to any peers already in the room
        if let Err(e) = self.publish_announce_key().await {
            warn!("initial key announcement failed: {e}");
        }

        let mut status_ticker = time::interval(STATUS_ANNOUNCE_INTERVAL);
        // Skip the immediate first tick so we don't announce twice on start
        status_ticker.tick().await;

        loop {
            tokio::select! {
                // ── swarm events ──────────────────────────────────────────
                event = self.swarm.next() => {
                    let Some(event) = event else { break };
                    self.handle_swarm_event(event).await;
                }

                // ── UI commands ───────────────────────────────────────────
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(RoomCommand::Disconnect) => {
                            info!("chat room disconnecting — saving trust snapshot");
                            return Some(self.build_trust_snapshot());
                        }
                        Some(RoomCommand::Nuke) => {
                            // 1. Broadcast a signed revocation (best-effort)
                            let fp = self.identity.fingerprint();
                            let msg = ChatMessage::new_revoke(
                                &self.topic.hash().to_string(),
                                &fp,
                                self.identity.nickname(),
                            );
                            let _ = self.publish_message(msg).await;

                            // 2. Wipe all state
                            self.keystore.nuke();
                            self.node_map.clear();
                            self.seen_messages.clear();
                            self.revoked_fps.clear();

                            // 3. Notify UI
                            let _ = self.event_tx.send(ChatNetEvent::NukeComplete).await;

                            info!("chat room nuked — state wiped, not saving contacts");
                            return None;
                        }
                        Some(cmd) => {
                            self.handle_command(cmd).await;
                        }
                        None => break,
                    }
                }

                // ── periodic status announce ──────────────────────────────
                _ = status_ticker.tick() => {
                    if let Err(e) = self.publish_status_announce().await {
                        warn!("status announce failed: {e}");
                    }
                }
            }
        }

        info!("chat room shutting down unexpectedly");
        None
    }

    /// Build a `PersistedTrustStore` snapshot from the current in-memory state.
    fn build_trust_snapshot(&self) -> PersistedTrustStore {
        use pgp::ArmorOptions;

        let contacts: Vec<PersistedContact> = self
            .keystore
            .export_trusted()
            .into_iter()
            .filter_map(|(fp, nick, key)| {
                let armored = key
                    .to_armored_string(ArmorOptions::default())
                    .ok()?;
                let last_seen = self.node_map.get(&fp).map(|n| n.last_seen);
                Some(PersistedContact {
                    fingerprint: fp,
                    nickname: nick,
                    armored_public_key: armored,
                    last_seen,
                })
            })
            .collect();

        PersistedTrustStore {
            contacts,
            rejected: self.keystore.rejected_fingerprints(),
        }
    }

    // -----------------------------------------------------------------------
    // Command dispatch — returns true to break the run() loop
    // -----------------------------------------------------------------------

    async fn handle_command(&mut self, cmd: RoomCommand) {
        match cmd {
            // Disconnect and Nuke are handled directly in run() — they must not reach here.
            RoomCommand::Disconnect | RoomCommand::Nuke => {
                warn!("Disconnect/Nuke reached handle_command — this is a bug");
            }

            RoomCommand::SendPlaintext(text) => {
                if let Err(e) = self.publish_plaintext(&text).await {
                    warn!("publish plaintext failed: {e}");
                }
            }

            RoomCommand::SendEncrypted { body } => {
                if let Err(e) = self.publish_encrypted(&body).await {
                    warn!("publish encrypted failed: {e}");
                    let _ = self.event_tx.send(ChatNetEvent::Warning(e.to_string())).await;
                }
            }

            RoomCommand::AnnounceKey => {
                if let Err(e) = self.publish_announce_key().await {
                    warn!("key announcement failed: {e}");
                }
            }

            RoomCommand::ApproveKey(fp) => {
                if let Some(nick) = self.keystore.approve(&fp) {
                    info!(%fp, %nick, "peer key approved");
                    self.node_map_set_trust(&fp, TrustState::Trusted);
                    // Re-announce our key so the newly trusted peer can encrypt back
                    let _ = self.publish_announce_key().await;
                } else {
                    warn!(%fp, "ApproveKey: fingerprint not in pending/deferred");
                }
            }

            RoomCommand::ApproveAll => {
                let count = self.keystore.approve_all();
                info!(count, "approved all pending/deferred keys");
                // Update node map trust state for all newly trusted fps
                for fp in self.keystore.known_fingerprints() {
                    self.node_map_set_trust(&fp, TrustState::Trusted);
                }
                if count > 0 {
                    let _ = self.publish_announce_key().await;
                }
            }

            RoomCommand::DenyKey(fp) => {
                self.keystore.reject(&fp);
                self.node_map_set_trust(&fp, TrustState::Rejected);
                info!(%fp, "peer key rejected");
            }

            RoomCommand::SetDeferring(deferring) => {
                let was_deferring = self.is_deferring;
                self.is_deferring = deferring;
                info!(deferring, "deferring mode changed");

                // Broadcast our new status
                let _ = self.publish_status_announce().await;

                // Promote deferred → pending when leaving deferring mode
                if was_deferring && !deferring {
                    let promoted = self.keystore.promote_deferred_to_pending();
                    if promoted > 0 {
                        let _ = self.event_tx
                            .send(ChatNetEvent::DeferredKeysAvailable(promoted))
                            .await;
                        // Emit KeyApprovalRequired for each promoted key
                        for (fp, nick) in self.keystore.pending_keys() {
                            // We don't have the peer_id at hand here; use a zeroed sentinel.
                            // The UI only needs fp + nick for display.
                            let _ = self.event_tx.send(ChatNetEvent::KeyApprovalRequired {
                                peer_id: PeerId::random(),
                                fingerprint: fp,
                                nickname: nick,
                            }).await;
                        }
                    }
                }
            }

            RoomCommand::GetNodeMap => {
                let snapshot: Vec<NodeInfo> = self.node_map.values().cloned().collect();
                let _ = self.event_tx.send(ChatNetEvent::NodeMapSnapshot(snapshot)).await;
            }

            RoomCommand::SendFile { recipient_fp, path, description } => {
                if let Err(e) = self.handle_send_file(&recipient_fp, &path, &description).await {
                    warn!("file send failed: {e}");
                    let _ = self.event_tx.send(ChatNetEvent::Warning(
                        format!("File send failed: {e}")
                    )).await;
                }
            }

            RoomCommand::AcceptFile { transfer_id, save_path } => {
                self.accepted_saves.insert(transfer_id, save_path.clone());
                // Send FileAccept back to sender
                let msg = ChatMessage::new_file_accept(
                    &self.topic.hash().to_string(),
                    &self.identity.fingerprint(),
                    self.identity.nickname(),
                    FileAccept {
                        transfer_id,
                        receiver_fp: self.identity.fingerprint(),
                    },
                );
                if let Err(e) = self.publish_message(msg).await {
                    warn!("FileAccept publish failed: {e}");
                }
            }

            RoomCommand::DeclineFile { transfer_id } => {
                self.inbound_transfers.remove(&transfer_id);
                self.accepted_saves.remove(&transfer_id);
                let msg = ChatMessage::new_file_decline(
                    &self.topic.hash().to_string(),
                    &self.identity.fingerprint(),
                    self.identity.nickname(),
                    FileDecline {
                        transfer_id,
                        receiver_fp: self.identity.fingerprint(),
                    },
                );
                if let Err(e) = self.publish_message(msg).await {
                    warn!("FileDecline publish failed: {e}");
                }
            }

            RoomCommand::CastVote { candidate_fp, approved } => {
                let my_fp = self.identity.fingerprint();
                if let Some(state) = self.pending_approvals.get_mut(&candidate_fp) {
                    state.votes.insert(my_fp, approved);
                } else {
                    warn!(%candidate_fp, "CastVote: no pending approval for fingerprint");
                    return;
                }
                let msg = ChatMessage::new_join_vote(
                    &self.topic.hash().to_string(),
                    &self.identity.fingerprint(),
                    self.identity.nickname(),
                    candidate_fp.clone(),
                    approved,
                );
                if let Err(e) = self.publish_message(msg).await {
                    warn!("JoinVote broadcast failed: {e}");
                }
                self.check_and_resolve_join(&candidate_fp).await;
            }

        }
    }

    // -----------------------------------------------------------------------
    // Swarm event dispatch
    // -----------------------------------------------------------------------

    async fn handle_swarm_event(&mut self, event: SwarmEvent<ChatBehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!(%address, "listening");
                let _ = self.event_tx.send(ChatNetEvent::ListeningOn(address)).await;
            }

            SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                let addr = endpoint.get_remote_address().clone();
                info!(%peer_id, %addr, "connection established");
                peer_discovery::add_gossipsub_peer(&mut self.swarm, peer_id);
                let _ = self.event_tx
                    .send(ChatNetEvent::ConnectionEstablished { peer_id, addr })
                    .await;
            }

            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                info!(%peer_id, "connection closed");
                let offline_fp = self.keystore.fingerprint_for_peer(&peer_id)
                    .map(|s| s.to_string());
                if let Some(ref fp) = offline_fp {
                    if let Some(info) = self.node_map.get_mut(fp.as_str()) {
                        info.status = NodeStatus::Offline;
                    }
                    self.apply_offline_veto(fp).await;
                }
                let _ = self.event_tx.send(ChatNetEvent::ConnectionClosed(peer_id)).await;
            }

            SwarmEvent::Behaviour(bev) => self.handle_behaviour_event(bev).await,

            _ => {}
        }
    }

    // -----------------------------------------------------------------------
    // Behaviour event dispatch
    // -----------------------------------------------------------------------

    async fn handle_behaviour_event(&mut self, event: ChatBehaviourEvent) {
        match event {
            // ── Gossipsub — incoming chat message ─────────────────────────
            ChatBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                propagation_source,
                message,
                ..
            }) => {
                debug!(%propagation_source, "gossipsub message");
                let topic = message.topic.to_string();

                // ── Room-level symmetric decryption ────────────────────────
                let decrypted_bytes = match room_cipher::open(
                    &message.data,
                    &self.room_passphrase,
                ) {
                    Ok(b)  => b,
                    Err(_) => {
                        // Wrong passphrase or corrupt packet — drop silently.
                        debug!("room cipher decryption failed — dropping message");
                        return;
                    }
                };

                // ── Deserialise ────────────────────────────────────────────
                let signed = match serde_json::from_slice::<SignedChatMessage>(&decrypted_bytes) {
                    Ok(s)  => s,
                    Err(e) => { debug!("failed to deserialise message: {e}"); return; }
                };

                // ── Timestamp window — replay protection ───────────────────
                // Reject messages older than 5 minutes or more than 60 seconds
                // in the future (clock skew tolerance).  This limits the window
                // for cross-session replay attacks even when seen_messages is
                // reset on restart.
                let age_secs = (Utc::now() - signed.message.timestamp).num_seconds();
                if age_secs > 300 || age_secs < -60 {
                    debug!(%age_secs, "dropping message outside ±5-min / +60s window");
                    return;
                }

                // ── Replay deduplication ───────────────────────────────────
                let msg_id = signed.message.id;
                if self.seen_messages.contains(&msg_id) {
                    debug!(%msg_id, "dropping duplicate message");
                    return;
                }
                if self.seen_messages.len() >= SEEN_MSG_CAPACITY {
                    self.seen_messages.pop_front();
                }
                self.seen_messages.push_back(msg_id);

                let sender_fp = &signed.message.sender_fp;

                // ── Revoked fingerprint check ──────────────────────────────
                if self.revoked_fps.contains(sender_fp) {
                    debug!(%sender_fp, "dropping message from revoked fingerprint");
                    return;
                }

                // ── Signature verification ─────────────────────────────────
                let is_announce = matches!(signed.message.kind, MessageKind::AnnounceKey { .. });
                let verified = self
                    .keystore
                    .get_by_fingerprint(sender_fp)
                    .map(|pub_key| {
                        serde_json::to_vec(&signed.message)
                            .ok()
                            .and_then(|bytes| {
                                sign::verify_data(&bytes, &signed.signature, pub_key).ok()
                            })
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);

                // Encrypted messages MUST be verified; drop unverifiable ones.
                if matches!(signed.message.kind, MessageKind::Encrypted { .. }) && !verified {
                    debug!(%sender_fp, "dropping unverified encrypted message");
                    return;
                }

                if !verified && !is_announce {
                    debug!(%sender_fp, "unverified message (key not yet known)");
                }

                // ── Dispatch by kind ───────────────────────────────────────
                match &signed.message.kind {
                    MessageKind::AnnounceKey { public_key_armored, nickname } => {
                        self.handle_key_announcement(
                            propagation_source,
                            sender_fp,
                            nickname,
                            public_key_armored,
                            verified,
                        ).await;
                    }

                    // Status updates are accepted only from verified senders.
                    // An unverified peer cannot manipulate another peer's online/offline status.
                    MessageKind::StatusAnnounce { status } if verified => {
                        let is_offline = matches!(status, NodeStatus::Offline);
                        let fp_owned   = sender_fp.to_string();
                        self.handle_status_announce(&fp_owned, &signed.message.sender_nick, status.clone());
                        if is_offline {
                            self.apply_offline_veto(&fp_owned).await;
                        }
                    }

                    MessageKind::Revoke { fingerprint } if verified => {
                        // A peer may only revoke their own fingerprint — never someone else's.
                        if fingerprint != sender_fp {
                            warn!(
                                %sender_fp, %fingerprint,
                                "peer tried to revoke a different fingerprint — ignoring"
                            );
                        } else {
                            self.handle_revocation(fingerprint, &signed.message.sender_nick).await;
                        }
                    }

                    MessageKind::FileOffer { encrypted_offer, recipient_fp } if verified => {
                        if recipient_fp == &self.identity.fingerprint() {
                            // Pass the outer verified sender_fp so handle_inbound_offer
                            // can cross-check the inner offer's claimed sender identity.
                            self.handle_inbound_offer(encrypted_offer, sender_fp).await;
                        }
                    }

                    MessageKind::FileAccept(accept) if verified => {
                        self.handle_file_accept(accept.clone(), &signed.message.sender_fp).await;
                    }

                    MessageKind::FileDecline(decline) if verified => {
                        self.handle_file_decline(decline.clone(), sender_fp).await;
                    }

                    MessageKind::FileChunk(chunk) if verified => {
                        self.handle_file_chunk(chunk.clone()).await;
                    }

                    MessageKind::FileComplete(complete) if verified => {
                        self.handle_file_complete(complete.clone()).await;
                    }

                    MessageKind::JoinVote { candidate_fingerprint, approved } if verified => {
                        let voter_fp = sender_fp.to_string();
                        let cand_fp  = candidate_fingerprint.to_string();
                        let voted    = *approved;
                        self.handle_join_vote(&voter_fp, &cand_fp, voted).await;
                    }

                    _ => {}
                }

                // ── PGP per-recipient decryption ──────────────────────────
                // If the inner payload is PGP-encrypted, attempt to decrypt it
                // with our private key.  On success, rebuild the SignedChatMessage
                // with the plaintext kind so the UI can display the message.
                // On failure (message was not addressed to us), pass the ciphertext
                // through unchanged — the UI shows a "received encrypted" notice.
                let payload_for_ui = if let MessageKind::Encrypted { ref ciphertext, .. } = signed.message.kind {
                    match encrypt::decrypt_message(
                        ciphertext,
                        self.identity.secret_key(),
                        self.identity.passphrase_fn(),
                    ) {
                        Ok(plaintext_bytes) => {
                            match String::from_utf8(plaintext_bytes) {
                                Ok(text) => {
                                    let mut display = signed.clone();
                                    display.message.kind = MessageKind::Plaintext(text);
                                    serde_json::to_vec(&display).unwrap_or(decrypted_bytes)
                                }
                                Err(_) => decrypted_bytes, // Shouldn't happen; pass through
                            }
                        }
                        Err(_) => decrypted_bytes, // Not encrypted to us
                    }
                } else {
                    decrypted_bytes
                };

                // Forward to UI for display.
                // `verified` tells the UI whether the sender's PGP signature
                // checked out against a trusted key — it MUST show a visual
                // warning for unverified senders to prevent nick spoofing.
                let _ = self
                    .event_tx
                    .send(ChatNetEvent::MessageReceived {
                        from:     propagation_source,
                        topic,
                        payload:  payload_for_ui,
                        verified,
                    })
                    .await;
            }

            // ── Identify — exchange listen addresses for Kademlia ─────────
            ChatBehaviourEvent::Identify(ref ev) => {
                peer_discovery::handle_identify_event(&mut self.swarm, ev);
            }

            // ── Kademlia — routing table events ───────────────────────────
            ChatBehaviourEvent::Kademlia(kad::Event::RoutingUpdated { peer, .. }) => {
                debug!(%peer, "kademlia routing updated");
                let _ = self
                    .event_tx
                    .send(ChatNetEvent::PeerDiscovered(peer))
                    .await;
            }

            _ => {}
        }
    }

    // -----------------------------------------------------------------------
    // Key announcement
    // -----------------------------------------------------------------------

    async fn handle_key_announcement(
        &mut self,
        peer_id: PeerId,
        announced_fp: &str,
        nickname: &str,
        armored: &str,
        was_verified: bool,
    ) {
        use pgp::composed::{Deserializable, SignedPublicKey};
        use pgp::types::KeyTrait;
        use std::io::Cursor;

        // Silently drop revoked / already-rejected fingerprints
        if self.revoked_fps.contains(announced_fp) || self.keystore.is_rejected(announced_fp) {
            return;
        }

        // If we already know this fingerprint, check whether it's a previously-
        // trusted contact reconnecting from a new ephemeral libp2p identity.
        // Update the peer_map so encryption / lookup by PeerId keeps working.
        if self.keystore.is_known(announced_fp) {
            if self.keystore.trust_state(announced_fp) == Some(TrustState::Trusted) {
                // Require a valid signature before updating any trusted-contact state.
                // Without this check, any room participant who observed a contact's
                // fingerprint could forge a reconnect event and hijack the peer_map.
                if !was_verified {
                    warn!(
                        %peer_id, %announced_fp,
                        "ignoring unverified AnnounceKey for trusted fingerprint — possible impersonation"
                    );
                    return;
                }
                // Use the locally-stored nickname (authoritative) instead of the
                // wire-supplied one so a peer cannot rename themselves in our UI.
                let display_nick = self.keystore.trusted_nick(announced_fp).unwrap_or(nickname).to_string();
                self.keystore.update_peer_mapping(peer_id, announced_fp);
                self.node_map_upsert(announced_fp, &display_nick, TrustState::Trusted, NodeStatus::Online);
                info!(%peer_id, %announced_fp, %display_nick, "trusted contact reconnected");
                let _ = self.event_tx.send(ChatNetEvent::PeerDiscovered(peer_id)).await;
            }
            return;
        }

        // Parse and cross-check the fingerprint
        let key = match SignedPublicKey::from_armor_single(Cursor::new(armored.as_bytes())) {
            Ok((k, _))  => k,
            Err(e) => { warn!("failed to parse announced public key: {e}"); return; }
        };

        let actual_fp = hex::encode(key.fingerprint());
        if actual_fp != announced_fp {
            warn!(
                %peer_id, %announced_fp, %actual_fp,
                "key announcement fingerprint mismatch — ignoring"
            );
            let _ = self.event_tx.send(ChatNetEvent::Warning(format!(
                "Peer {peer_id} sent a key whose fingerprint ({actual_fp}) \
                 does not match the announced fingerprint ({announced_fp}) — ignored"
            ))).await;
            return;
        }

        info!(%peer_id, %announced_fp, %nickname, "received key announcement");

        // Insert into the appropriate bucket
        if self.is_deferring {
            self.keystore.insert_deferred(
                peer_id, actual_fp.clone(), key, nickname.to_string(),
            );
            self.node_map_upsert(&actual_fp, nickname, TrustState::Deferred, NodeStatus::Online);
            let _ = self.event_tx.send(ChatNetEvent::Warning(format!(
                "Key from {nickname} ({actual_fp}) deferred — approve with 'a' or 'y'"
            ))).await;
        } else {
            let my_fp = self.identity.fingerprint();
            // Count trusted+online peers (excluding the candidate) to decide
            // whether unanimous admission control is required.
            let trusted_online: HashSet<String> = self.node_map.values()
                .filter(|n| {
                    n.trust  == TrustState::Trusted
                        && n.status == NodeStatus::Online
                        && n.fingerprint != actual_fp
                })
                .map(|n| n.fingerprint.clone())
                .collect();

            if trusted_online.is_empty() {
                // No trusted peers online — use the single-approver path.
                self.keystore.insert_pending(
                    peer_id, actual_fp.clone(), key, nickname.to_string(),
                );
                self.node_map_upsert(&actual_fp, nickname, TrustState::Pending, NodeStatus::Online);
                let _ = self.event_tx.send(ChatNetEvent::KeyApprovalRequired {
                    peer_id,
                    fingerprint: actual_fp,
                    nickname: nickname.to_string(),
                }).await;
            } else {
                // Unanimous admission: all trusted online peers (including us) must vote YES.
                let mut required_voters = trusted_online;
                required_voters.insert(my_fp);
                let voter_count = required_voters.len();

                self.pending_approvals.insert(actual_fp.clone(), ApprovalState {
                    nickname:        nickname.to_string(),
                    peer_id,
                    armored_key:     armored.to_string(),
                    required_voters,
                    votes:           HashMap::new(),
                });
                self.node_map_upsert(&actual_fp, nickname, TrustState::Pending, NodeStatus::Online);
                let _ = self.event_tx.send(ChatNetEvent::JoinApprovalRequired {
                    fingerprint: actual_fp,
                    nickname:    nickname.to_string(),
                    voter_count,
                }).await;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Status announce
    // -----------------------------------------------------------------------

    fn handle_status_announce(&mut self, sender_fp: &str, sender_nick: &str, status: NodeStatus) {
        if let Some(info) = self.node_map.get_mut(sender_fp) {
            info.status = status;
            info.last_seen = Utc::now();
        } else {
            // Peer not yet in node map (trusted or not) — add as Offline until key is approved
            self.node_map.insert(sender_fp.to_string(), NodeInfo {
                fingerprint: sender_fp.to_string(),
                nickname:    sender_nick.to_string(),
                trust:       TrustState::Pending,
                status,
                last_seen:   Utc::now(),
            });
        }
    }

    // -----------------------------------------------------------------------
    // Revocation
    // -----------------------------------------------------------------------

    async fn handle_revocation(&mut self, fingerprint: &str, nickname: &str) {
        info!(%fingerprint, %nickname, "peer revoked their identity");
        self.revoked_fps.insert(fingerprint.to_string());
        self.keystore.remove_fingerprint(fingerprint);
        if let Some(info) = self.node_map.get_mut(fingerprint) {
            info.trust = TrustState::Rejected;
            info.status = NodeStatus::Offline;
        }
        let _ = self.event_tx.send(ChatNetEvent::PeerRevoked {
            fingerprint: fingerprint.to_string(),
            nickname: nickname.to_string(),
        }).await;
    }

    // -----------------------------------------------------------------------
    // Unanimous join admission
    // -----------------------------------------------------------------------

    async fn handle_join_vote(&mut self, voter_fp: &str, candidate_fp: &str, approved: bool) {
        if let Some(state) = self.pending_approvals.get_mut(candidate_fp) {
            if state.required_voters.contains(voter_fp) {
                state.votes.insert(voter_fp.to_string(), approved);
            }
        }
        self.check_and_resolve_join(candidate_fp).await;
    }

    async fn check_and_resolve_join(&mut self, candidate_fp: &str) {
        let resolution = {
            let state = match self.pending_approvals.get(candidate_fp) {
                Some(s) => s,
                None    => return,
            };
            let all_voted = state.required_voters.iter().all(|fp| state.votes.contains_key(fp));
            if !all_voted { return; }
            let veto_fp = state.votes.iter()
                .find(|(_, &v)| !v)
                .map(|(fp, _)| fp.clone());
            (state.nickname.clone(), state.peer_id, state.armored_key.clone(), veto_fp)
        };

        let (nickname, peer_id, armored_key, veto_fp) = resolution;
        let candidate_fp = candidate_fp.to_string();
        self.pending_approvals.remove(&candidate_fp);

        let approved      = veto_fp.is_none();
        let vetoed_by_nick = veto_fp.as_deref()
            .and_then(|fp| self.node_map.get(fp))
            .map(|n| n.nickname.clone());

        if approved {
            use pgp::composed::{Deserializable, SignedPublicKey};
            use std::io::Cursor;
            match SignedPublicKey::from_armor_single(Cursor::new(armored_key.as_bytes())) {
                Ok((key, _)) => {
                    self.keystore.insert_pending(
                        peer_id, candidate_fp.clone(), key, nickname.clone(),
                    );
                    self.keystore.approve(&candidate_fp);
                    self.node_map_upsert(
                        &candidate_fp, &nickname, TrustState::Trusted, NodeStatus::Online,
                    );
                    let _ = self.publish_announce_key().await;
                    info!(%candidate_fp, %nickname, "unanimous admission granted");
                }
                Err(e) => {
                    warn!(%candidate_fp, "re-parse of admitted peer key failed: {e}");
                }
            }
        } else {
            self.node_map_set_trust(&candidate_fp, TrustState::Rejected);
            info!(%candidate_fp, %nickname, "unanimous admission vetoed");
        }

        let _ = self.event_tx.send(ChatNetEvent::JoinDecided {
            fingerprint:    candidate_fp,
            nickname,
            approved,
            vetoed_by_nick,
        }).await;
    }

    async fn apply_offline_veto(&mut self, offline_fp: &str) {
        let candidates: Vec<String> = self.pending_approvals.keys().cloned().collect();
        for candidate_fp in candidates {
            let needs_veto = self.pending_approvals.get(&candidate_fp)
                .map(|s| {
                    s.required_voters.contains(offline_fp)
                        && !s.votes.contains_key(offline_fp)
                })
                .unwrap_or(false);
            if needs_veto {
                if let Some(state) = self.pending_approvals.get_mut(&candidate_fp) {
                    state.votes.insert(offline_fp.to_string(), false);
                }
            }
            self.check_and_resolve_join(&candidate_fp).await;
        }
    }

    // -----------------------------------------------------------------------
    // Node map helpers
    // -----------------------------------------------------------------------

    fn node_map_upsert(
        &mut self,
        fp: &str,
        nick: &str,
        trust: TrustState,
        status: NodeStatus,
    ) {
        let info = self.node_map.entry(fp.to_string()).or_insert_with(|| NodeInfo {
            fingerprint: fp.to_string(),
            nickname:    nick.to_string(),
            trust:       trust.clone(),
            status:      status.clone(),
            last_seen:   Utc::now(),
        });
        info.trust     = trust;
        info.status    = status;
        info.last_seen = Utc::now();
    }

    fn node_map_set_trust(&mut self, fp: &str, trust: TrustState) {
        if let Some(info) = self.node_map.get_mut(fp) {
            info.trust = trust;
        }
    }

    // -----------------------------------------------------------------------
    // Publish helpers
    // -----------------------------------------------------------------------

    async fn publish_plaintext(&mut self, text: &str) -> Result<()> {
        let msg = ChatMessage::new_plaintext(
            &self.topic.hash().to_string(),
            &self.identity.fingerprint(),
            self.identity.nickname(),
            text,
        );
        self.publish_message(msg).await
    }

    async fn publish_announce_key(&mut self) -> Result<()> {
        let armored = self.identity.public_key_armored()?;
        let msg = ChatMessage::new_announce_key(
            &self.topic.hash().to_string(),
            &self.identity.fingerprint(),
            self.identity.nickname(),
            armored,
        );
        self.publish_message(msg).await
    }

    async fn publish_status_announce(&mut self) -> Result<()> {
        let status = if self.is_deferring {
            NodeStatus::Deferring
        } else {
            NodeStatus::Online
        };
        let msg = ChatMessage::new_status_announce(
            &self.topic.hash().to_string(),
            &self.identity.fingerprint(),
            self.identity.nickname(),
            status,
        );
        self.publish_message(msg).await
    }

    async fn publish_encrypted(&mut self, body: &str) -> Result<()> {
        use crate::crypto::encrypt;

        let recipients: Vec<_> = self.keystore.all_public_keys();
        if recipients.is_empty() {
            // Refuse to silently downgrade to plaintext — the caller explicitly
            // requested encryption.  Return an error so the UI can surface it.
            return Err(Error::PgpEncryption(
                "no trusted peers — approve at least one key before sending encrypted messages"
                    .to_string(),
            ));
        }

        let recipient_count = recipients.len();

        // Include our own public key so we can decrypt echoed messages.
        // `recipient_count` intentionally excludes self — it reflects the number
        // of trusted peers the message was addressed to, for display purposes.
        let own_key = self.identity.public_key();
        let mut all_recipients = recipients;
        all_recipients.push(own_key);

        let ciphertext = encrypt::encrypt_for_recipients(body.as_bytes(), &all_recipients)?;

        // Pass only the count — never the fingerprints.  Putting the full
        // recipient list on the wire would let anyone with the room passphrase
        // (including unapproved peers) reconstruct the social graph.
        let msg = ChatMessage::new_encrypted(
            &self.topic.hash().to_string(),
            &self.identity.fingerprint(),
            self.identity.nickname(),
            ciphertext,
            recipient_count,
        );
        self.publish_message(msg).await
    }

    // -----------------------------------------------------------------------
    // File transfer — outbound
    // -----------------------------------------------------------------------

    async fn handle_send_file(
        &mut self,
        recipient_fp: &str,
        path: &str,
        description: &str,
    ) -> Result<()> {
        // Recipient must be trusted
        let recipient_key = self.keystore.get_by_fingerprint(recipient_fp)
            .ok_or_else(|| Error::KeyNotFound(recipient_fp.to_string()))?
            .clone();

        // Read file
        let file_bytes = std::fs::read(path)
            .map_err(|e| Error::Io(e))?;
        let filename = std::path::Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();

        // Cap description — use char boundary to avoid panicking on multi-byte UTF-8.
        let description = description
            .char_indices()
            .nth(MAX_DESCRIPTION_LEN)
            .map(|(i, _)| &description[..i])
            .unwrap_or(description)
            .to_string();

        let transfer_id = Uuid::new_v4();
        let size_bytes = file_bytes.len() as u64;

        // Build the offer (contains metadata only, not the file data)
        let listen_addrs: Vec<String> = self.swarm.listeners()
            .map(|a| a.to_string())
            .collect();

        let offer = FileOffer {
            transfer_id,
            filename: filename.clone(),
            size_bytes,
            description,
            recipient_fp: recipient_fp.to_string(),
            sender_info: SenderNetInfo {
                fingerprint: self.identity.fingerprint(),
                nickname:    self.identity.nickname().to_string(),
                listen_addrs,
            },
        };

        // PGP-encrypt the offer to the recipient's ECDH subkey
        let offer_json = serde_json::to_vec(&offer)
            .map_err(|e| Error::Serialisation(e))?;
        let encrypted_offer = encrypt::encrypt_for_recipients(
            &offer_json,
            &[&recipient_key],
        )?;

        // Store pending offer
        self.pending_offers.insert(transfer_id, PendingOffer {
            offer,
            file_bytes,
        });

        // Publish the FileOffer message
        let msg = ChatMessage::new_file_offer(
            &self.topic.hash().to_string(),
            &self.identity.fingerprint(),
            self.identity.nickname(),
            encrypted_offer,
            recipient_fp.to_string(),
        );
        self.publish_message(msg).await?;
        info!(%transfer_id, %recipient_fp, "file offer sent: {filename}");
        Ok(())
    }

    async fn handle_file_accept(&mut self, accept: FileAccept, sender_fp: &str) {
        let tid = accept.transfer_id;

        // Verify the accept is from the intended recipient
        let pending = match self.pending_offers.get(&tid) {
            Some(p) => p,
            None => {
                warn!(%tid, "FileAccept for unknown transfer");
                return;
            }
        };
        if accept.receiver_fp != pending.offer.recipient_fp {
            warn!(%tid, "FileAccept receiver_fp mismatch");
            return;
        }
        if sender_fp != accept.receiver_fp {
            warn!(%tid, "FileAccept sender_fp != receiver_fp");
            return;
        }

        info!(%tid, "file offer accepted — starting chunked send");

        // Move pending offer out so we can use self mutably
        let PendingOffer { offer, file_bytes } = self.pending_offers.remove(&tid).unwrap();

        let recipient_key = match self.keystore.get_by_fingerprint(&offer.recipient_fp) {
            Some(k) => k.clone(),
            None => {
                warn!(%tid, "recipient key gone before send");
                return;
            }
        };

        // Chunk and send
        let chunks: Vec<&[u8]> = file_bytes.chunks(CHUNK_BYTES).collect();
        let total = chunks.len() as u32;

        for (i, chunk_data) in chunks.iter().enumerate() {
            let encrypted_data = match encrypt::encrypt_for_recipients(chunk_data, &[&recipient_key]) {
                Ok(d) => d,
                Err(e) => {
                    warn!(%tid, "chunk encryption failed: {e}");
                    let _ = self.event_tx.send(ChatNetEvent::FileTransferError {
                        transfer_id: tid,
                        reason: e.to_string(),
                    }).await;
                    return;
                }
            };

            let chunk_msg = ChatMessage::new_file_chunk(
                &self.topic.hash().to_string(),
                &self.identity.fingerprint(),
                self.identity.nickname(),
                FileChunk {
                    transfer_id: tid,
                    index: i as u32,
                    total,
                    encrypted_data,
                },
            );
            if let Err(e) = self.publish_message(chunk_msg).await {
                warn!(%tid, "chunk publish failed: {e}");
                let _ = self.event_tx.send(ChatNetEvent::FileTransferError {
                    transfer_id: tid,
                    reason: e.to_string(),
                }).await;
                return;
            }

            let _ = self.event_tx.send(ChatNetEvent::FileSendProgress {
                transfer_id: tid,
                sent_chunks: i as u32 + 1,
                total_chunks: total,
            }).await;
        }

        // Send SHA-256 completion message (real SHA-256 via sha2 crate).
        let sha256 = {
            let mut h = Sha256::new();
            h.update(&file_bytes);
            format!("{:x}", h.finalize())
        };

        let complete_msg = ChatMessage::new_file_complete(
            &self.topic.hash().to_string(),
            &self.identity.fingerprint(),
            self.identity.nickname(),
            FileComplete { transfer_id: tid, sha256: sha256.clone() },
        );
        let _ = self.publish_message(complete_msg).await;
        info!(%tid, "file transfer complete, sha256={sha256}");
    }

    async fn handle_file_decline(&mut self, decline: FileDecline, sender_fp: &str) {
        let tid = decline.transfer_id;

        // Verify the decliner is the peer the offer was actually addressed to.
        // A verified-but-wrong peer (Carol) cannot cancel a transfer offered to Alice.
        // Also return early for unknown transfer IDs so verified peers cannot
        // inject spurious FileDeclined events for non-existent transfers.
        let pending = match self.pending_offers.get(&tid) {
            Some(p) => p,
            None => {
                warn!(%tid, "FileDecline for unknown transfer — ignoring");
                return;
            }
        };
        if decline.receiver_fp != pending.offer.recipient_fp {
            warn!(%tid, "FileDecline receiver_fp does not match offer recipient — ignoring");
            return;
        }
        if sender_fp != decline.receiver_fp {
            warn!(%tid, "FileDecline signer does not match receiver_fp — ignoring");
            return;
        }

        self.pending_offers.remove(&tid);
        info!(%tid, "file offer declined by recipient");
        let _ = self.event_tx.send(ChatNetEvent::FileDeclined { transfer_id: tid }).await;
    }

    // -----------------------------------------------------------------------
    // File transfer — inbound
    // -----------------------------------------------------------------------

    async fn handle_inbound_offer(&mut self, encrypted_offer: &[u8], verified_sender_fp: &str) {
        // Decrypt the offer with our secret key
        let offer_bytes = match encrypt::decrypt_message(
            encrypted_offer,
            self.identity.secret_key(),
            self.identity.passphrase_fn(),
        ) {
            Ok(b) => b,
            Err(e) => {
                warn!("failed to decrypt inbound FileOffer: {e}");
                return;
            }
        };

        let offer: FileOffer = match serde_json::from_slice(&offer_bytes) {
            Ok(o) => o,
            Err(e) => {
                warn!("failed to parse inbound FileOffer: {e}");
                return;
            }
        };

        // The outer SignedChatMessage was signed by verified_sender_fp.
        // Reject offers where the inner sender_info claims a DIFFERENT fingerprint —
        // a trusted peer must not be able to impersonate another trusted peer in
        // the consent dialog by crafting a mismatched inner payload.
        if offer.sender_info.fingerprint != verified_sender_fp {
            warn!(
                outer_fp = %verified_sender_fp,
                inner_fp = %offer.sender_info.fingerprint,
                "FileOffer inner sender fingerprint does not match outer signature — ignoring"
            );
            return;
        }

        let tid = offer.transfer_id;

        // Reject absurdly large offers before the u32 chunk-count arithmetic can overflow.
        const MAX_OFFER_BYTES: u64 = 512 * 1024 * 1024; // 512 MiB
        if offer.size_bytes > MAX_OFFER_BYTES {
            warn!(%tid, size = offer.size_bytes, "rejecting oversized file offer");
            return;
        }

        let total_chunks = (offer.size_bytes as usize).div_ceil(CHUNK_BYTES) as u32;

        // Strip path separators from the remote-supplied filename so a peer cannot
        // write outside the receiver's chosen save directory via "../" traversal.
        let safe_filename = std::path::Path::new(&offer.filename)
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("unknown")
            .to_string();

        // Emit event to UI for consent
        let _ = self.event_tx.send(ChatNetEvent::InboundFileOffer {
            transfer_id:  tid,
            filename:     safe_filename,
            size_bytes:   offer.size_bytes,
            description:  offer.description.clone(),
            sender_fp:    offer.sender_info.fingerprint.clone(),
            sender_nick:  offer.sender_info.nickname.clone(),
            sender_addrs: offer.sender_info.listen_addrs.clone(),
        }).await.ok();

        self.inbound_transfers.insert(tid, InboundTransfer::new(offer, total_chunks));
        info!(%tid, %verified_sender_fp, "inbound file offer, total_chunks={total_chunks}");
    }

    async fn handle_file_chunk(&mut self, chunk: FileChunk) {
        let tid = chunk.transfer_id;
        let transfer = match self.inbound_transfers.get_mut(&tid) {
            Some(t) => t,
            None => return, // not accepted or unknown
        };

        // Decrypt chunk data
        let plain = match encrypt::decrypt_message(
            &chunk.encrypted_data,
            self.identity.secret_key(),
            self.identity.passphrase_fn(),
        ) {
            Ok(b) => b,
            Err(e) => {
                warn!(%tid, "chunk decryption failed: {e}");
                return;
            }
        };

        let complete = transfer.store_chunk(chunk.index, plain);
        debug!(%tid, chunk=%chunk.index, "stored chunk");

        if complete {
            // will be finalised in handle_file_complete
        }
    }

    async fn handle_file_complete(&mut self, complete: FileComplete) {
        let tid = complete.transfer_id;

        let transfer = match self.inbound_transfers.remove(&tid) {
            Some(t) => t,
            None => return,
        };

        let save_path = match self.accepted_saves.remove(&tid) {
            Some(p) => p,
            None => {
                warn!(%tid, "FileComplete received but no save path (not accepted?)");
                return;
            }
        };

        if !transfer.is_complete() {
            let _ = self.event_tx.send(ChatNetEvent::FileTransferError {
                transfer_id: tid,
                reason: "not all chunks received before FileComplete".to_string(),
            }).await;
            return;
        }

        let plaintext = transfer.assemble();

        // Verify integrity with real SHA-256.
        let computed = {
            let mut h = Sha256::new();
            h.update(&plaintext);
            format!("{:x}", h.finalize())
        };
        if computed != complete.sha256 {
            let _ = self.event_tx.send(ChatNetEvent::FileTransferError {
                transfer_id: tid,
                reason: format!(
                    "integrity check failed (expected {}, got {})",
                    complete.sha256, computed
                ),
            }).await;
            return;
        }

        // Write to disk
        if let Err(e) = std::fs::write(&save_path, &plaintext) {
            let _ = self.event_tx.send(ChatNetEvent::FileTransferError {
                transfer_id: tid,
                reason: format!("failed to write file: {e}"),
            }).await;
            return;
        }

        info!(%tid, save_path=%save_path, "file received and saved");
        let filename = std::path::Path::new(&save_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();

        let _ = self.event_tx.send(ChatNetEvent::FileReceived {
            transfer_id: tid,
            filename,
            save_path,
        }).await;
    }

    /// Sign, room-encrypt, and publish a `ChatMessage` to gossipsub.
    async fn publish_message(&mut self, msg: ChatMessage) -> Result<()> {
        let msg_bytes  = serde_json::to_vec(&msg)?;
        let signature  = sign::sign_data(
            &msg_bytes,
            self.identity.secret_key(),
            self.identity.passphrase_fn(),
        )?;
        let signed_msg = SignedChatMessage { message: msg, signature };
        let inner      = serde_json::to_vec(&signed_msg)?;

        // Wrap in room-level symmetric encryption before publishing
        let payload = room_cipher::seal(&inner, &self.room_passphrase)?;

        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(self.topic.clone(), payload)
            .map_err(|e| crate::error::Error::Network(e.to_string()))?;
        Ok(())
    }
}
