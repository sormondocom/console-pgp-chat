//! PGP message encryption and decryption.
//!
//! `encrypt_for_recipients` encrypts a plaintext blob to one or more
//! recipients' public keys using AES-256.
//!
//! `decrypt_message` decrypts a blob that was encrypted to *our* public key.

use std::io::Cursor;

use pgp::{
    composed::{message::Message, Deserializable, SignedPublicKey, SignedSecretKey},
    crypto::sym::SymmetricKeyAlgorithm,
    ser::Serialize,
};

use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` to one or more recipients' public keys (AES-256).
///
/// Internally this uses each recipient's ECDH encryption subkey — the EdDSA
/// primary key is sign-only and cannot be used for encryption.
///
/// Returns raw PGP packet bytes.
pub fn encrypt_for_recipients(
    plaintext: &[u8],
    recipients: &[&SignedPublicKey],
) -> Result<Vec<u8>> {
    if recipients.is_empty() {
        return Err(Error::PgpEncryption("no recipients specified".to_string()));
    }

    // Collect the ECDH encryption subkeys from all recipients.
    // The EdDSA primary key can only sign — encryption requires the subkey.
    let enc_subkeys: Vec<_> = recipients
        .iter()
        .flat_map(|pk| pk.public_subkeys.iter())
        .collect();

    if enc_subkeys.is_empty() {
        return Err(Error::PgpEncryption(
            "recipients have no encryption subkeys".to_string(),
        ));
    }

    let literal = Message::new_literal_bytes("msg", plaintext);

    let encrypted = literal
        .encrypt_to_keys(
            &mut rand::thread_rng(),
            SymmetricKeyAlgorithm::AES256,
            &enc_subkeys,
        )
        .map_err(|e| Error::PgpEncryption(e.to_string()))?;

    let mut buf = Vec::new();
    encrypted
        .to_writer(&mut buf)
        .map_err(|e| Error::PgpEncryption(e.to_string()))?;

    Ok(buf)
}

// ---------------------------------------------------------------------------
// Decryption
// ---------------------------------------------------------------------------

/// Decrypt a PGP-encrypted blob using `secret_key`.
///
/// The `passphrase` closure is called by rPGP to unlock the secret key.
/// Pass `|| String::new()` for unprotected keys.
pub fn decrypt_message(
    ciphertext: &[u8],
    secret_key: &SignedSecretKey,
    passphrase: impl FnOnce() -> String + Clone,
) -> Result<Vec<u8>> {
    // Deserializable::from_bytes is brought into scope by the import above
    let msg = Message::from_bytes(Cursor::new(ciphertext))
        .map_err(|e| Error::PgpDecryption(e.to_string()))?;

    // decrypt() takes one passphrase closure + a slice of secret keys
    let (decrypted, _key_ids) = msg
        .decrypt(passphrase, &[secret_key])
        .map_err(|_| Error::DecryptionFailed)?;

    // get_content() handles Literal and Compressed variants automatically
    decrypted
        .get_content()
        .map_err(|e| Error::PgpDecryption(e.to_string()))?
        .ok_or(Error::DecryptionFailed)
}
