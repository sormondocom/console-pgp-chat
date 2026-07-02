use chrono::Utc;
use serde::{Deserialize, Serialize};

use pgp::composed::{Deserializable, SignedPublicKey};
use pgp::types::KeyTrait;
use std::io::Cursor;

use crate::crypto::{identity::PgpIdentity, sign};
use crate::error::{Error, Result};

pub const TRUST_TOPIC:     &str = "pgp-chat-trust-v1";

/// Gossipsub topic where peers broadcast a signed announcement of their PGP
/// fingerprint when they connect.  Allows the scanner to map libp2p PeerIds
/// to PGP identities and detect trusted contacts without a prior trust exchange.
pub const ANNOUNCE_TOPIC:  &str = "pgp-chat-announce-v1";

/// Maximum age (seconds) for an incoming trust request — older ones are replays.
pub const TRUST_MAX_AGE_SECS: i64 = 1800; // 30 minutes

/// A trust-request broadcast on the `pgp-chat-trust-v1` gossipsub topic.
///
/// ## Authenticity guarantee
///
/// The `pgp_signature` field is a detached EdDSA signature over the canonical
/// bytes (`canonical_bytes()`) produced by the sender's long-term PGP identity
/// key.  Receivers MUST verify:
///
/// 1. The `from_public_key_armored` parses as a valid OpenPGP public key.
/// 2. The derived fingerprint of that key equals `from_fingerprint`.
/// 3. The `pgp_signature` verifies against the parsed key and canonical bytes.
/// 4. The `timestamp` is within [`TRUST_MAX_AGE_SECS`] of the current time.
///
/// A message that fails any of these checks MUST be silently discarded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustRequestMessage {
    pub from_nickname:           String,
    pub from_fingerprint:        String,
    pub from_public_key_armored: String,
    pub timestamp:               i64,
    /// Detached EdDSA signature over `canonical_bytes()` — proves the sender
    /// holds the private key corresponding to `from_fingerprint`.
    pub pgp_signature:           Vec<u8>,
}

impl TrustRequestMessage {
    /// Build and sign a new trust request from `identity`.
    pub fn new(identity: &PgpIdentity) -> Result<Self> {
        let pub_armored = identity.public_key_armored()
            .map_err(|e| Error::PgpEncryption(e.to_string()))?;

        let mut msg = Self {
            from_nickname:           identity.nickname().to_string(),
            from_fingerprint:        identity.fingerprint(),
            from_public_key_armored: pub_armored,
            timestamp:               Utc::now().timestamp(),
            pgp_signature:           Vec::new(),
        };

        let canonical = msg.canonical_bytes();
        msg.pgp_signature = sign::sign_data(
            &canonical,
            identity.secret_key(),
            identity.passphrase_fn(),
        )?;

        Ok(msg)
    }

    /// Verify the message is authentic and fresh.
    ///
    /// Returns `Ok(())` on success; `Err` describes why it was rejected.
    pub fn verify(&self) -> Result<()> {
        // 1. Freshness check — reject stale / future-dated messages.
        let age = Utc::now().timestamp() - self.timestamp;
        if age > TRUST_MAX_AGE_SECS || age < -60 {
            return Err(Error::PgpSignature(
                "trust request timestamp out of acceptable range".to_string(),
            ));
        }

        // 2. Parse the embedded public key.
        let (key, _) =
            SignedPublicKey::from_armor_single(Cursor::new(self.from_public_key_armored.as_bytes()))
                .map_err(|e| Error::PgpKeyParse(e.to_string()))?;

        // 3. Fingerprint consistency: ensure the key is the one being claimed.
        let derived_fp = hex::encode(key.fingerprint());
        if derived_fp != self.from_fingerprint {
            return Err(Error::PgpKeyParse(format!(
                "fingerprint mismatch: claimed {}, key derives {}",
                self.from_fingerprint, derived_fp
            )));
        }

        // 4. Signature verification: proves the sender holds the private key.
        let canonical = self.canonical_bytes();
        let valid = sign::verify_data(&canonical, &self.pgp_signature, &key)
            .unwrap_or(false);
        if !valid {
            return Err(Error::PgpSignature(
                "trust request PGP signature invalid".to_string(),
            ));
        }

        Ok(())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }

    /// Canonical byte representation that is signed and verified.
    ///
    /// Covers all fields that describe the sender's identity, excluding the
    /// signature itself to avoid a circular dependency.
    fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "from_nickname":           self.from_nickname,
            "from_fingerprint":        self.from_fingerprint,
            "from_public_key_armored": self.from_public_key_armored,
            "timestamp":               self.timestamp,
        })).unwrap_or_default()
    }
}
