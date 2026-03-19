//! Wire message types exchanged over gossipsub.
//!
//! Every message published to a room topic is a JSON-serialised
//! [`SignedChatMessage`].  JSON is used (not bincode) for human-readability
//! during development and cross-implementation compatibility.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::chat::{
    transfer::{FileAccept, FileChunk, FileComplete, FileDecline},
    trust::NodeStatus,
};

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// The application-level content of a chat message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    /// Globally unique message ID (UUIDv4).
    pub id: Uuid,
    /// Room name (gossipsub topic string).
    pub room: String,
    /// PGP fingerprint of the sender (hex).
    pub sender_fp: String,
    /// Human-readable sender nickname.
    pub sender_nick: String,
    /// UTC timestamp when the message was created.
    pub timestamp: DateTime<Utc>,
    /// The actual payload.
    pub kind: MessageKind,
}

/// The payload variants a chat message can carry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageKind {
    /// Unencrypted plaintext — for public rooms or demos.
    Plaintext(String),

    /// PGP-encrypted ciphertext.
    ///
    /// The `ciphertext` bytes were produced by encrypting to all `recipients`
    /// public keys simultaneously (standard PGP multi-recipient encryption).
    Encrypted {
        /// Raw PGP packet bytes (binary, not armoured).
        ciphertext: Vec<u8>,
        /// Fingerprints of all intended recipients.
        recipients: Vec<String>,
    },

    /// Peer is announcing their long-term PGP public key to the room.
    ///
    /// Receivers store the key in their [`crate::chat::keystore::PeerKeyStore`]
    /// so they can encrypt future messages and verify signatures.
    AnnounceKey {
        /// ASCII-armoured OpenPGP public key block.
        public_key_armored: String,
        /// The nickname the peer wants to be known as.
        nickname: String,
    },

    /// Informational system notification (join, leave, key rotate, …).
    System(String),

    /// Peer announcing their current online/deferring status.
    ///
    /// Broadcast on join, on status change, and every 60 seconds.
    StatusAnnounce {
        /// The node's current presence status.
        status: NodeStatus,
    },

    /// Peer revoking their long-term PGP identity.
    ///
    /// All receivers should move this fingerprint to their permanent drop list
    /// and stop encrypting or verifying messages from it.  The message MUST
    /// carry a valid detached signature from the key being revoked.
    Revoke {
        /// The PGP fingerprint (hex) being revoked.
        fingerprint: String,
    },

    // ── File transfer ──────────────────────────────────────────────────────

    /// Sender proposes an encrypted file transfer to a specific recipient.
    ///
    /// `encrypted_offer` holds the PGP-encrypted, JSON-serialised
    /// [`crate::chat::transfer::FileOffer`], readable only by the recipient.
    FileOffer {
        /// PGP-encrypted, serialised `FileOffer` bytes.
        encrypted_offer: Vec<u8>,
        /// Fingerprint of the intended recipient (unencrypted, for routing).
        recipient_fp: String,
    },

    /// Receiver accepts a pending file offer.
    FileAccept(FileAccept),

    /// Receiver declines a pending file offer.
    FileDecline(FileDecline),

    /// One chunk of an in-progress transfer.
    ///
    /// `FileChunk::encrypted_data` holds the PGP-encrypted raw chunk bytes.
    FileChunk(FileChunk),

    /// Sender signals all chunks have been sent; includes SHA-256 of plaintext.
    FileComplete(FileComplete),
}

/// A [`ChatMessage`] together with a detached PGP signature.
///
/// The signature covers `serde_json::to_vec(&self.message)` so that any peer
/// with the sender's public key can verify it, even without decrypting the
/// payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedChatMessage {
    pub message: ChatMessage,
    /// Raw detached PGP signature bytes.
    pub signature: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Constructors
// ---------------------------------------------------------------------------

impl ChatMessage {
    pub fn new_plaintext(
        room: &str,
        sender_fp: &str,
        sender_nick: &str,
        text: impl Into<String>,
    ) -> Self {
        Self {
            id:          Uuid::new_v4(),
            room:        room.to_string(),
            sender_fp:   sender_fp.to_string(),
            sender_nick: sender_nick.to_string(),
            timestamp:   Utc::now(),
            kind:        MessageKind::Plaintext(text.into()),
        }
    }

    pub fn new_encrypted(
        room: &str,
        sender_fp: &str,
        sender_nick: &str,
        ciphertext: Vec<u8>,
        recipients: Vec<String>,
    ) -> Self {
        Self {
            id:          Uuid::new_v4(),
            room:        room.to_string(),
            sender_fp:   sender_fp.to_string(),
            sender_nick: sender_nick.to_string(),
            timestamp:   Utc::now(),
            kind:        MessageKind::Encrypted { ciphertext, recipients },
        }
    }

    pub fn new_announce_key(
        room: &str,
        sender_fp: &str,
        nickname: &str,
        public_key_armored: impl Into<String>,
    ) -> Self {
        Self {
            id:          Uuid::new_v4(),
            room:        room.to_string(),
            sender_fp:   sender_fp.to_string(),
            sender_nick: nickname.to_string(),
            timestamp:   Utc::now(),
            kind:        MessageKind::AnnounceKey {
                public_key_armored: public_key_armored.into(),
                nickname: nickname.to_string(),
            },
        }
    }

    pub fn new_system(room: &str, text: impl Into<String>) -> Self {
        Self {
            id:          Uuid::new_v4(),
            room:        room.to_string(),
            sender_fp:   String::new(),
            sender_nick: "system".to_string(),
            timestamp:   Utc::now(),
            kind:        MessageKind::System(text.into()),
        }
    }

    pub fn new_status_announce(
        room: &str,
        sender_fp: &str,
        sender_nick: &str,
        status: NodeStatus,
    ) -> Self {
        Self {
            id:          Uuid::new_v4(),
            room:        room.to_string(),
            sender_fp:   sender_fp.to_string(),
            sender_nick: sender_nick.to_string(),
            timestamp:   Utc::now(),
            kind:        MessageKind::StatusAnnounce { status },
        }
    }

    pub fn new_revoke(room: &str, sender_fp: &str, sender_nick: &str) -> Self {
        Self {
            id:          Uuid::new_v4(),
            room:        room.to_string(),
            sender_fp:   sender_fp.to_string(),
            sender_nick: sender_nick.to_string(),
            timestamp:   Utc::now(),
            kind:        MessageKind::Revoke { fingerprint: sender_fp.to_string() },
        }
    }

    pub fn new_file_offer(
        room: &str,
        sender_fp: &str,
        sender_nick: &str,
        encrypted_offer: Vec<u8>,
        recipient_fp: String,
    ) -> Self {
        Self {
            id:          Uuid::new_v4(),
            room:        room.to_string(),
            sender_fp:   sender_fp.to_string(),
            sender_nick: sender_nick.to_string(),
            timestamp:   Utc::now(),
            kind:        MessageKind::FileOffer { encrypted_offer, recipient_fp },
        }
    }

    pub fn new_file_accept(
        room: &str,
        sender_fp: &str,
        sender_nick: &str,
        accept: FileAccept,
    ) -> Self {
        Self {
            id:          Uuid::new_v4(),
            room:        room.to_string(),
            sender_fp:   sender_fp.to_string(),
            sender_nick: sender_nick.to_string(),
            timestamp:   Utc::now(),
            kind:        MessageKind::FileAccept(accept),
        }
    }

    pub fn new_file_decline(
        room: &str,
        sender_fp: &str,
        sender_nick: &str,
        decline: FileDecline,
    ) -> Self {
        Self {
            id:          Uuid::new_v4(),
            room:        room.to_string(),
            sender_fp:   sender_fp.to_string(),
            sender_nick: sender_nick.to_string(),
            timestamp:   Utc::now(),
            kind:        MessageKind::FileDecline(decline),
        }
    }

    pub fn new_file_chunk(
        room: &str,
        sender_fp: &str,
        sender_nick: &str,
        chunk: FileChunk,
    ) -> Self {
        Self {
            id:          Uuid::new_v4(),
            room:        room.to_string(),
            sender_fp:   sender_fp.to_string(),
            sender_nick: sender_nick.to_string(),
            timestamp:   Utc::now(),
            kind:        MessageKind::FileChunk(chunk),
        }
    }

    pub fn new_file_complete(
        room: &str,
        sender_fp: &str,
        sender_nick: &str,
        complete: FileComplete,
    ) -> Self {
        Self {
            id:          Uuid::new_v4(),
            room:        room.to_string(),
            sender_fp:   sender_fp.to_string(),
            sender_nick: sender_nick.to_string(),
            timestamp:   Utc::now(),
            kind:        MessageKind::FileComplete(complete),
        }
    }
}
