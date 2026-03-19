//! High-level network events emitted by [`crate::chat::room::ChatRoom`].
//!
//! These are the events that the UI layer needs to handle — the raw libp2p
//! `SwarmEvent` variants are translated here to keep UI code free of libp2p
//! imports.

use libp2p::{Multiaddr, PeerId};

use crate::chat::trust::NodeInfo;

/// Network-level events that the UI / application layer should react to.
#[derive(Debug)]
pub enum ChatNetEvent {
    /// A complete (possibly encrypted) chat payload was received.
    MessageReceived {
        /// libp2p identity of the sender.
        from:    PeerId,
        /// Gossipsub topic name (= room name hash).
        topic:   String,
        /// Raw serialised `SignedChatMessage` bytes (already room-decrypted).
        payload: Vec<u8>,
    },

    /// Kademlia or Gossipsub found a new peer.
    PeerDiscovered(PeerId),

    /// A previously known peer is no longer reachable.
    PeerExpired(PeerId),

    /// The local node is now listening on this address.
    ListeningOn(Multiaddr),

    /// A transport connection was established.
    ConnectionEstablished { peer_id: PeerId, addr: Multiaddr },

    /// A transport connection was closed.
    ConnectionClosed(PeerId),

    /// A non-fatal error worth showing in the status bar.
    Warning(String),

    /// A new peer's key arrived and needs explicit user approval before
    /// messages from that peer will be decrypted or encrypted to them.
    KeyApprovalRequired {
        peer_id:    PeerId,
        fingerprint: String,
        nickname:   String,
    },

    /// When leaving deferring mode, `n` previously-deferred keys have been
    /// promoted to pending and are now awaiting approval.
    DeferredKeysAvailable(usize),

    /// Response to [`crate::chat::room::RoomCommand::GetNodeMap`].
    /// Contains a snapshot of every peer we are aware of.
    NodeMapSnapshot(Vec<NodeInfo>),

    /// A peer broadcast a signed revocation of their PGP identity.
    /// The UI should warn the user and remove them from any display.
    PeerRevoked { fingerprint: String, nickname: String },

    /// All local identity material and state has been wiped (Nuke complete).
    NukeComplete,

    // ── File transfer ──────────────────────────────────────────────────────

    /// An incoming file offer arrived and is waiting for user consent.
    ///
    /// The UI should display all fields and ask the user to accept or decline.
    InboundFileOffer {
        transfer_id:  uuid::Uuid,
        filename:     String,
        size_bytes:   u64,
        description:  String,
        sender_fp:    String,
        sender_nick:  String,
        sender_addrs: Vec<String>,
    },

    /// A file transfer completed successfully.
    ///
    /// `save_path` is the path where the decrypted file was written.
    FileReceived {
        transfer_id: uuid::Uuid,
        filename:    String,
        save_path:   String,
    },

    /// The remote peer declined our file offer.
    FileDeclined { transfer_id: uuid::Uuid },

    /// Progress update while sending a file (sent_chunks / total_chunks).
    FileSendProgress {
        transfer_id:  uuid::Uuid,
        sent_chunks:  u32,
        total_chunks: u32,
    },

    /// A file transfer failed (download or upload side).
    FileTransferError { transfer_id: uuid::Uuid, reason: String },
}
