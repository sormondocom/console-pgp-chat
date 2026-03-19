//! Room-level symmetric encryption for gossipsub payloads.
//!
//! Every byte published to or received from the gossipsub network is wrapped
//! in a PGP symmetric-key packet (AES-256, Argon2-based S2K) keyed by the
//! room passphrase.  Observers without the passphrase see only opaque binary
//! OpenPGP packets that are not specific to this application.
//!
//! ## Wire format
//!
//! ```text
//! gossipsub payload = pgp_sym_encrypt(room_passphrase, signed_chat_message_json)
//! ```
//!
//! The inner payload is the JSON-serialised `SignedChatMessage`, already
//! signed and optionally PGP-encrypted per-recipient — this outer layer adds
//! an additional confidentiality boundary for all room traffic.

use std::io::Cursor;

use pgp::{
    composed::{message::Message, Deserializable},
    crypto::sym::SymmetricKeyAlgorithm,
    ser::Serialize,
    types::StringToKey,
};

use crate::error::{Error, Result};

/// Symmetrically encrypt `plaintext` with the room `passphrase` (AES-256).
///
/// Returns raw OpenPGP packet bytes suitable for publishing to gossipsub.
pub fn seal(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();
    let s2k = StringToKey::new_default(&mut rng);

    let pw = passphrase.to_string();
    let msg = Message::new_literal_bytes("", plaintext);

    let encrypted = msg
        .encrypt_with_password(&mut rng, s2k, SymmetricKeyAlgorithm::AES256, || {
            pw.clone()
        })
        .map_err(|e| Error::PgpEncryption(e.to_string()))?;

    let mut buf = Vec::new();
    encrypted
        .to_writer(&mut buf)
        .map_err(|e| Error::PgpEncryption(e.to_string()))?;

    Ok(buf)
}

/// Decrypt a room-symmetric-encrypted payload.
///
/// Returns the original plaintext bytes.
/// Returns `Err` if the passphrase is wrong, the packet is corrupt, or the
/// data is not a password-protected OpenPGP message.
pub fn open(ciphertext: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    let pw = passphrase.to_string();

    let msg = Message::from_bytes(Cursor::new(ciphertext))
        .map_err(|e| Error::PgpDecryption(e.to_string()))?;

    let decrypted = msg
        .decrypt_with_password(|| pw)
        .map_err(|_| Error::DecryptionFailed)?;

    decrypted
        .get_content()
        .map_err(|e| Error::PgpDecryption(e.to_string()))?
        .ok_or(Error::DecryptionFailed)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let plaintext = b"Hello, room!";
        let ct = seal(plaintext, "s3cret").expect("seal failed");
        let pt = open(&ct, "s3cret").expect("open failed");
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let ct = seal(b"secret data", "correct").expect("seal failed");
        let result = open(&ct, "wrong");
        assert!(result.is_err(), "wrong passphrase should not decrypt");
    }

    #[test]
    fn corrupt_ciphertext_fails() {
        let mut ct = seal(b"data", "pass").expect("seal failed");
        // Flip bytes in the middle of the ciphertext
        let mid = ct.len() / 2;
        ct[mid] ^= 0xFF;
        ct[mid + 1] ^= 0xFF;
        let result = open(&ct, "pass");
        assert!(result.is_err(), "corrupt ciphertext should fail");
    }
}
