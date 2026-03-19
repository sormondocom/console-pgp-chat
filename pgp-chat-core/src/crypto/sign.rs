//! Detached PGP signatures using `StandaloneSignature`.
//!
//! Used to authenticate [`crate::chat::message::SignedChatMessage`] payloads
//! published over gossipsub.  Any peer with the sender's public key can verify
//! the signature without needing to decrypt the content.

use std::io::Cursor;

use pgp::{
    composed::{Deserializable, SignedPublicKey, SignedSecretKey, StandaloneSignature},
    crypto::hash::HashAlgorithm,
    // SignatureConfig and SignatureVersion are re-exported at pgp::packet (not pgp::packet::signature)
    packet::{SignatureConfig, SignatureType, SignatureVersion},
    ser::Serialize,
    types::KeyTrait,
};

use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// Sign
// ---------------------------------------------------------------------------

/// Create a detached PGP signature (v4, EdDSA) over `data`.
///
/// `passphrase` is called by rPGP to unlock the secret key.
/// Pass `|| String::new()` for unprotected keys.
///
/// Returns a serialised `StandaloneSignature` packet — a standard PGP binary
/// signature that can be transmitted alongside the plaintext.
pub fn sign_data(
    data: &[u8],
    secret_key: &SignedSecretKey,
    passphrase: impl Fn() -> String,
) -> Result<Vec<u8>> {
    // Build a v4 binary-document signature config
    let config = SignatureConfig::new_v4(
        SignatureVersion::V4,
        SignatureType::Binary,
        secret_key.algorithm(), // from KeyTrait — EdDSA for our primary key
        HashAlgorithm::SHA2_256,
        vec![], // hashed subpackets (creation time is added automatically)
        vec![], // unhashed subpackets
    );

    // Sign the data bytes
    let sig_packet = config
        .sign(secret_key, passphrase, Cursor::new(data))
        .map_err(|e| Error::PgpSignature(e.to_string()))?;

    // Wrap in StandaloneSignature and serialise to bytes
    let standalone = StandaloneSignature::new(sig_packet);
    let mut buf = Vec::new();
    standalone
        .to_writer(&mut buf)
        .map_err(|e| Error::PgpSignature(e.to_string()))?;

    Ok(buf)
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

/// Verify a detached signature produced by [`sign_data`].
///
/// Returns `Ok(true)` if valid, `Ok(false)` if the signature doesn't match.
/// Does NOT return an `Err` on an invalid signature — that allows the caller
/// to display a warning rather than abort.
pub fn verify_data(
    data: &[u8],
    signature_bytes: &[u8],
    public_key: &SignedPublicKey,
) -> Result<bool> {
    let standalone = StandaloneSignature::from_bytes(Cursor::new(signature_bytes))
        .map_err(|e| Error::PgpKeyParse(e.to_string()))?;

    Ok(standalone.verify(public_key, data).is_ok())
}
