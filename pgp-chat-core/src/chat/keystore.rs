//! In-memory peer key store with trust-bucket management.
//!
//! Peers flow through four buckets:
//!
//! ```text
//!  (key arrives)
//!      ├─ deferring mode  ──► deferred ──┐
//!      └─ normal mode     ──► pending    │
//!                                        ▼
//!                             promote_deferred_to_pending()
//!                                        │
//!                             (user approves / rejects)
//!                                        │
//!                         ┌─────────────┴──────────────┐
//!                      trusted                       rejected
//! ```
//!
//! Only `trusted` keys are returned by `all_public_keys()`, so the rest of
//! the codebase (encryption, verification) is unaffected by the refactor.

use std::collections::{HashMap, HashSet};

use libp2p::PeerId;
use pgp::composed::SignedPublicKey;

use crate::chat::trust::TrustState;

// ---------------------------------------------------------------------------
// Storage types
// ---------------------------------------------------------------------------

/// Metadata stored alongside a key in the pending / deferred bucket.
#[derive(Clone)]
struct PendingEntry {
    peer_id: PeerId,
    key:     SignedPublicKey,
    nick:    String,
}

/// Maps `libp2p::PeerId` ↔ PGP fingerprint ↔ `SignedPublicKey`,
/// split into four trust buckets.
#[derive(Default)]
pub struct PeerKeyStore {
    /// Explicitly approved keys — used for encryption and signature verification.
    trusted:  HashMap<String, SignedPublicKey>,
    /// Keys received while normal mode is active; awaiting user approval.
    pending:  HashMap<String, PendingEntry>,
    /// Keys received while deferring mode is active; promoted to pending on exit.
    deferred: HashMap<String, PendingEntry>,
    /// Permanently rejected fingerprints.  No key material is stored.
    rejected: HashSet<String>,
    /// libp2p PeerId → fingerprint (for all trusted peers).
    peer_map: HashMap<PeerId, String>,
}

impl PeerKeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    // -----------------------------------------------------------------------
    // Insertion
    // -----------------------------------------------------------------------

    /// Queue a key for user approval (normal mode).
    ///
    /// Returns `true` if this is a new fingerprint; `false` if already known.
    pub fn insert_pending(
        &mut self,
        peer_id: PeerId,
        fingerprint: String,
        key: SignedPublicKey,
        nick: String,
    ) -> bool {
        if self.is_known(&fingerprint) {
            return false;
        }
        self.pending.insert(fingerprint, PendingEntry { peer_id, key, nick });
        true
    }

    /// Queue a key into the deferred bucket (deferring mode).
    ///
    /// Returns `true` if this is a new fingerprint; `false` if already known.
    pub fn insert_deferred(
        &mut self,
        peer_id: PeerId,
        fingerprint: String,
        key: SignedPublicKey,
        nick: String,
    ) -> bool {
        if self.is_known(&fingerprint) {
            return false;
        }
        self.deferred.insert(fingerprint, PendingEntry { peer_id, key, nick });
        true
    }

    // -----------------------------------------------------------------------
    // Trust management
    // -----------------------------------------------------------------------

    /// Move a key from pending or deferred → trusted.
    ///
    /// Returns `Some(nickname)` on success, `None` if the fingerprint is
    /// not in any bucket (already trusted, unknown, or rejected).
    pub fn approve(&mut self, fingerprint: &str) -> Option<String> {
        let entry = self.pending.remove(fingerprint)
            .or_else(|| self.deferred.remove(fingerprint))?;
        let nick = entry.nick.clone();
        self.peer_map.insert(entry.peer_id, fingerprint.to_string());
        self.trusted.insert(fingerprint.to_string(), entry.key);
        Some(nick)
    }

    /// Approve all pending and deferred keys.
    ///
    /// Returns the number of keys that were approved.
    pub fn approve_all(&mut self) -> usize {
        let fps: Vec<String> = self.pending.keys()
            .chain(self.deferred.keys())
            .cloned()
            .collect();
        let count = fps.len();
        for fp in fps {
            self.approve(&fp);
        }
        count
    }

    /// Move a key to the rejected set.  Future keys from this fingerprint
    /// will be silently ignored.
    pub fn reject(&mut self, fingerprint: &str) {
        self.pending.remove(fingerprint);
        self.deferred.remove(fingerprint);
        self.rejected.insert(fingerprint.to_string());
    }

    /// Promote all deferred keys to pending (call when leaving deferring mode).
    ///
    /// Returns the number of keys promoted.
    pub fn promote_deferred_to_pending(&mut self) -> usize {
        let entries: Vec<(String, PendingEntry)> = self.deferred.drain().collect();
        let count = entries.len();
        for (fp, entry) in entries {
            self.pending.insert(fp, entry);
        }
        count
    }

    // -----------------------------------------------------------------------
    // Queries
    // -----------------------------------------------------------------------

    /// `true` if the fingerprint exists in any bucket.
    pub fn is_known(&self, fp: &str) -> bool {
        self.trusted.contains_key(fp)
            || self.pending.contains_key(fp)
            || self.deferred.contains_key(fp)
            || self.rejected.contains(fp)
    }

    pub fn is_rejected(&self, fp: &str) -> bool {
        self.rejected.contains(fp)
    }

    pub fn trust_state(&self, fp: &str) -> Option<TrustState> {
        if self.trusted.contains_key(fp)   { return Some(TrustState::Trusted);  }
        if self.pending.contains_key(fp)   { return Some(TrustState::Pending);  }
        if self.deferred.contains_key(fp)  { return Some(TrustState::Deferred); }
        if self.rejected.contains(fp)      { return Some(TrustState::Rejected); }
        None
    }

    /// Look up a *trusted* key by fingerprint.
    pub fn get_by_fingerprint(&self, fp: &str) -> Option<&SignedPublicKey> {
        self.trusted.get(fp)
    }

    /// Look up a *trusted* key by libp2p `PeerId`.
    pub fn get_by_peer(&self, peer_id: &PeerId) -> Option<&SignedPublicKey> {
        self.peer_map
            .get(peer_id)
            .and_then(|fp| self.trusted.get(fp))
    }

    /// Fingerprint of a trusted peer, if known.
    pub fn fingerprint_for_peer(&self, peer_id: &PeerId) -> Option<&str> {
        self.peer_map.get(peer_id).map(String::as_str)
    }

    /// All *trusted* public keys (for multi-recipient encryption).
    pub fn all_public_keys(&self) -> Vec<&SignedPublicKey> {
        self.trusted.values().collect()
    }

    /// All *trusted* fingerprints (for building the recipient list).
    pub fn known_fingerprints(&self) -> Vec<String> {
        self.trusted.keys().cloned().collect()
    }

    /// (fp, nickname) pairs for all pending keys.
    pub fn pending_keys(&self) -> Vec<(String, String)> {
        self.pending
            .iter()
            .map(|(fp, e)| (fp.clone(), e.nick.clone()))
            .collect()
    }

    /// (fp, nickname) pairs for all deferred keys.
    pub fn deferred_keys(&self) -> Vec<(String, String)> {
        self.deferred
            .iter()
            .map(|(fp, e)| (fp.clone(), e.nick.clone()))
            .collect()
    }

    /// Number of trusted peers.
    pub fn len(&self) -> usize {
        self.trusted.len()
    }

    pub fn is_empty(&self) -> bool {
        self.trusted.is_empty()
    }

    // -----------------------------------------------------------------------
    // Destructive operations
    // -----------------------------------------------------------------------

    /// Remove a trusted peer (e.g. after key rotation).
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        if let Some(fp) = self.peer_map.remove(peer_id) {
            self.trusted.remove(&fp);
        }
    }

    /// Remove a key from all buckets by fingerprint (used on revocation).
    pub fn remove_fingerprint(&mut self, fp: &str) {
        self.trusted.remove(fp);
        self.pending.remove(fp);
        self.deferred.remove(fp);
        // Clean up reverse mapping
        self.peer_map.retain(|_, v| v != fp);
    }

    /// Wipe all state — called by the Nuke command.
    pub fn nuke(&mut self) {
        self.trusted.clear();
        self.pending.clear();
        self.deferred.clear();
        self.rejected.clear();
        self.peer_map.clear();
    }
}
