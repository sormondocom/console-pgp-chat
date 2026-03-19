//! PGP cryptography layer.
//!
//! Built on [rPGP](https://docs.rs/pgp) — a pure-Rust OpenPGP implementation
//! with no native/C dependencies, so it compiles on every Rust target tier.
//!
//! ## Design
//!
//! ```text
//!  PgpIdentity          ← long-term identity (EdDSA primary + ECDH subkey)
//!      │
//!      ├── encrypt::encrypt_for_recipients()   ← PGP public-key encryption
//!      ├── encrypt::decrypt_message()          ← PGP private-key decryption
//!      ├── sign::sign_data()                   ← detached binary signature
//!      └── sign::verify_data()                 ← signature verification
//! ```
//!
//! The libp2p transport identity (ed25519 `Keypair`) is separate and
//! ephemeral — it is regenerated each session.  The PGP identity is the
//! long-term cryptographic identity for message authenticity and E2E
//! encryption.

pub mod encrypt;
pub mod identity;
pub mod room_cipher;
pub mod sign;

pub use identity::PgpIdentity;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;
    use super::{encrypt, identity::PgpIdentity, sign};

    /// Generate a test identity with an empty passphrase.
    fn test_identity(nick: &str) -> PgpIdentity {
        PgpIdentity::generate(nick, Zeroizing::new(String::new()))
            .expect("test key generation failed")
    }

    // ── encrypt / decrypt ────────────────────────────────────────────────────

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let id = test_identity("alice");
        let plaintext = b"Hello, encrypted world!";
        let ct = encrypt::encrypt_for_recipients(plaintext, &[id.public_key()])
            .expect("encryption failed");
        let recovered = encrypt::decrypt_message(&ct, id.secret_key(), || String::new())
            .expect("decryption failed");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let alice = test_identity("alice");
        let bob   = test_identity("bob");
        let ct = encrypt::encrypt_for_recipients(b"secret", &[alice.public_key()])
            .expect("encryption failed");
        // Bob's key cannot decrypt a message meant for Alice
        let result = encrypt::decrypt_message(&ct, bob.secret_key(), || String::new());
        assert!(result.is_err(), "expected decryption to fail with wrong key");
    }

    #[test]
    fn encrypt_no_recipients_is_error() {
        let result = encrypt::encrypt_for_recipients(b"data", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn encrypt_to_multiple_recipients() {
        let alice = test_identity("alice");
        let bob   = test_identity("bob");
        let plaintext = b"broadcast";
        let ct = encrypt::encrypt_for_recipients(
            plaintext,
            &[alice.public_key(), bob.public_key()],
        ).expect("encryption failed");
        // Both Alice and Bob should be able to decrypt
        let ra = encrypt::decrypt_message(&ct, alice.secret_key(), || String::new())
            .expect("alice decrypt failed");
        let rb = encrypt::decrypt_message(&ct, bob.secret_key(), || String::new())
            .expect("bob decrypt failed");
        assert_eq!(ra, plaintext);
        assert_eq!(rb, plaintext);
    }

    // ── sign / verify ────────────────────────────────────────────────────────

    #[test]
    fn sign_verify_roundtrip() {
        let id = test_identity("carol");
        let data = b"authentic message";
        let sig = sign::sign_data(data, id.secret_key(), || String::new())
            .expect("signing failed");
        let valid = sign::verify_data(data, &sig, id.public_key())
            .expect("verify failed");
        assert!(valid, "signature should be valid");
    }

    #[test]
    fn tampered_data_fails_verification() {
        let id = test_identity("dave");
        let data = b"original data";
        let sig = sign::sign_data(data, id.secret_key(), || String::new())
            .expect("signing failed");
        let valid = sign::verify_data(b"tampered data", &sig, id.public_key())
            .expect("verify call failed");
        assert!(!valid, "tampered data should not verify");
    }

    #[test]
    fn verify_with_wrong_key_fails() {
        let alice = test_identity("alice");
        let eve   = test_identity("eve");
        let data  = b"alice's message";
        let sig = sign::sign_data(data, alice.secret_key(), || String::new())
            .expect("signing failed");
        // Eve's public key should NOT verify Alice's signature
        let valid = sign::verify_data(data, &sig, eve.public_key())
            .expect("verify call failed");
        assert!(!valid, "wrong key should not verify signature");
    }

    #[test]
    fn corrupt_signature_is_rejected() {
        let id = test_identity("frank");
        let data = b"data";
        let mut sig = sign::sign_data(data, id.secret_key(), || String::new())
            .expect("signing failed");
        // Flip a byte in the signature body
        if let Some(b) = sig.last_mut() { *b ^= 0xFF; }
        // Either verify returns Ok(false) or an Err — both are acceptable
        match sign::verify_data(data, &sig, id.public_key()) {
            Ok(false) | Err(_) => {}
            Ok(true) => panic!("corrupt signature must not verify"),
        }
    }

    // ── key import roundtrip ─────────────────────────────────────────────────

    #[test]
    fn import_armored_secret_key_roundtrip() {
        let original = test_identity("grace");
        let armored  = original.secret_key_armored().expect("armour failed");
        let imported = PgpIdentity::from_armored_secret_key(
            "grace",
            &armored,
            Zeroizing::new(String::new()),
        ).expect("import failed");
        assert_eq!(original.fingerprint(), imported.fingerprint());
    }
}
