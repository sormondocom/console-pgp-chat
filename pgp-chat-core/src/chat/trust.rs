//! Trust state types for peer key management.
//!
//! Peers move through a lifecycle as we interact with them:
//!
//! ```text
//!   (key arrives)
//!       │
//!       ├─ deferring=true  ──► Deferred ──► (promote on exit deferring) ──► Pending
//!       │
//!       └─ deferring=false ──► Pending ──► Trusted  (user approved)
//!                                      └─► Rejected (user denied; permanent)
//! ```
//!
//! Revoked fingerprints are tracked separately in `ChatRoom::revoked_fps` and
//! are never admitted into any trust bucket.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The trust level assigned to a peer's PGP key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustState {
    /// User has explicitly approved this key.
    Trusted,
    /// Key received, waiting for user approval.
    Pending,
    /// Local node is in deferring mode; key queued for later review.
    Deferred,
    /// User explicitly denied this key.  Messages from this fingerprint are
    /// silently dropped.  This state is permanent for the session.
    Rejected,
}

/// Online presence status of a remote node, as announced via
/// [`crate::chat::message::MessageKind::StatusAnnounce`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeStatus {
    /// Node is online and accepting new peer keys.
    Online,
    /// Node is online but deferring all new key requests.
    Deferring,
    /// Node has disconnected or gone silent.
    Offline,
}

/// A snapshot of everything we know about a remote peer.
#[derive(Debug, Clone)]
pub struct NodeInfo {
    /// PGP fingerprint (hex).
    pub fingerprint: String,
    /// Human-readable nickname.
    pub nickname: String,
    /// Current trust assignment.
    pub trust: TrustState,
    /// Last announced network status.
    pub status: NodeStatus,
    /// When we last heard from this peer.
    pub last_seen: DateTime<Utc>,
}
