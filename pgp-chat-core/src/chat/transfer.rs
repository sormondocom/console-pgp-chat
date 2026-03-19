//! Encrypted file transfer support.
//!
//! ## Protocol flow
//!
//! ```text
//!  Sender                                          Receiver
//!    │                                                │
//!    │──── FileOffer {id, filename, size, desc} ────►│
//!    │     (PGP-encrypted to receiver's key)          │
//!    │     (room-symmetric-encrypted, like all msgs)  │
//!    │                                                │
//!    │                     ◄── FileAccept {id} ───────│
//!    │                         OR FileDecline {id}    │
//!    │                                                │
//!    │──── FileChunk {id, index, total, data} ───────►│  (repeated)
//!    │     (each chunk PGP-encrypted + room-wrapped)  │
//!    │                                                │
//!    │──── FileComplete {id, sha256} ────────────────►│
//!    │                                                │
//!    │                     Receiver verifies SHA-256, │
//!    │                     decrypts, saves to disk    │
//! ```
//!
//! ## Security properties
//!
//! - The filename, file size, description, and all chunk data are PGP-encrypted
//!   to the recipient's ECDH subkey — no one else can read the offer or content.
//! - The outer room-symmetric layer (AES-256) hides even the fact that a file
//!   transfer is occurring from observers without the room passphrase.
//! - The SHA-256 integrity check is signed by the sender's EdDSA key via the
//!   normal `SignedChatMessage` wrapper.
//! - Both sides must be trusted peers (keys approved) before a transfer can
//!   begin — the room's keystore enforces this.
//!
//! ## Chunk size
//!
//! `CHUNK_BYTES` is set conservatively to stay under gossipsub's default
//! 1 MiB message size limit after PGP + JSON overhead.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Maximum length of the file description (bytes).
pub const MAX_DESCRIPTION_LEN: usize = 256;

/// Maximum bytes of raw file data per gossipsub chunk (before encryption).
pub const CHUNK_BYTES: usize = 512 * 1024; // 512 KiB

// ---------------------------------------------------------------------------
// Wire types (embedded in MessageKind)
// ---------------------------------------------------------------------------

/// Sender proposes a file transfer to a specific recipient.
///
/// The entire struct is PGP-encrypted to the recipient's key before being
/// wrapped in `MessageKind::FileOffer`.  Observers (even room members)
/// cannot see the filename, size, or description.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOffer {
    /// Unique transfer ID.
    pub transfer_id: Uuid,
    /// Original filename (basename only — no path components).
    pub filename: String,
    /// File size in bytes.
    pub size_bytes: u64,
    /// Optional human-readable description (max 256 chars).
    pub description: String,
    /// PGP fingerprint of the intended recipient.
    pub recipient_fp: String,
    /// Network info captured at offer time (for consent display).
    pub sender_info: SenderNetInfo,
}

/// Subset of network information the receiver sees before accepting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderNetInfo {
    /// Sender's PGP fingerprint (hex).
    pub fingerprint: String,
    /// Sender's nickname.
    pub nickname: String,
    /// Sender's libp2p multiaddrs (display only — no routing use).
    pub listen_addrs: Vec<String>,
}

/// Receiver accepts a pending file offer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAccept {
    pub transfer_id: Uuid,
    /// Receiver's PGP fingerprint — sender verifies this is the intended peer.
    pub receiver_fp: String,
}

/// Receiver declines a pending file offer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDecline {
    pub transfer_id: Uuid,
    pub receiver_fp: String,
}

/// One chunk of an in-progress file transfer.
///
/// `data` contains the raw chunk bytes PGP-encrypted to the recipient.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChunk {
    pub transfer_id: Uuid,
    /// Zero-based chunk index.
    pub index: u32,
    /// Total number of chunks.
    pub total: u32,
    /// PGP-encrypted raw bytes for this chunk.
    pub encrypted_data: Vec<u8>,
}

/// Sender signals that all chunks have been sent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileComplete {
    pub transfer_id: Uuid,
    /// Lowercase hex SHA-256 of the original (plaintext) file bytes.
    pub sha256: String,
}

// ---------------------------------------------------------------------------
// In-progress transfer tracking (receiver side)
// ---------------------------------------------------------------------------

/// State tracked by the receiver while assembling an inbound file.
pub struct InboundTransfer {
    pub offer:       FileOffer,
    pub chunks:      Vec<Option<Vec<u8>>>,  // indexed by chunk index
    pub total_chunks: u32,
}

impl InboundTransfer {
    pub fn new(offer: FileOffer, total_chunks: u32) -> Self {
        Self {
            chunks: vec![None; total_chunks as usize],
            total_chunks,
            offer,
        }
    }

    /// Store a received chunk.  Returns `true` if all chunks are now present.
    pub fn store_chunk(&mut self, index: u32, data: Vec<u8>) -> bool {
        if (index as usize) < self.chunks.len() {
            self.chunks[index as usize] = Some(data);
        }
        self.is_complete()
    }

    /// `true` when every chunk slot is filled.
    pub fn is_complete(&self) -> bool {
        self.chunks.iter().all(|c| c.is_some())
    }

    /// Assemble all chunks into the full plaintext file bytes.
    ///
    /// Only call after `is_complete()` returns `true`.
    pub fn assemble(self) -> Vec<u8> {
        self.chunks
            .into_iter()
            .flat_map(|c| c.unwrap_or_default())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Outbound transfer tracking (sender side)
// ---------------------------------------------------------------------------

/// State kept by the sender while waiting for acceptance.
pub struct PendingOffer {
    pub offer:          FileOffer,
    pub file_bytes:     Vec<u8>,
}
