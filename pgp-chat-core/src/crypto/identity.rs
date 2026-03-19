//! PGP identity: key generation, import from existing keys, armoured export.
//!
//! Uses rPGP (pgp 0.13).  Primary key: EdDSA (sign + certify).
//! Encryption subkey: ECDH with Curve25519.
//!
//! The `generate` constructor accepts a passphrase (`Zeroizing<String>`)
//! which is used to protect the secret key.  Pass an empty `Zeroizing` string
//! for an unprotected key (not recommended in production).

use std::io::Cursor;

use pgp::{
    composed::{
        key::{SecretKeyParamsBuilder, SubkeyParamsBuilder},
        Deserializable, KeyType, SignedPublicKey, SignedSecretKey,
    },
    crypto::{ecc_curve::ECCCurve, hash::HashAlgorithm, sym::SymmetricKeyAlgorithm},
    types::{CompressionAlgorithm, KeyTrait, SecretKeyTrait},
    ArmorOptions,
};
use smallvec::smallvec;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// Public type
// ---------------------------------------------------------------------------

/// A user's long-term PGP identity.
///
/// The internal `passphrase` field is wrapped in `Zeroizing` so it is wiped
/// from memory when `PgpIdentity` is dropped.  The `SignedSecretKey` itself
/// does not implement `ZeroizeOnDrop` in rPGP 0.13, but we zero the passphrase
/// copy we hold so it cannot be recovered from a heap dump.
pub struct PgpIdentity {
    secret_key: SignedSecretKey,
    public_key: SignedPublicKey,
    user_id:    String,
    nickname:   String,
    /// Passphrase used to lock/unlock the secret key — zeroed on drop.
    passphrase: Zeroizing<String>,
}

// Zeroize the passphrase explicitly when this type is dropped.
impl Drop for PgpIdentity {
    fn drop(&mut self) {
        self.passphrase.zeroize();
    }
}

impl PgpIdentity {
    // -----------------------------------------------------------------------
    // Construction — generate a fresh keypair
    // -----------------------------------------------------------------------

    /// Generate a fresh EdDSA + ECDH keypair for `nickname`.
    ///
    /// - Primary key: EdDSA (sign + certify)
    /// - Subkey: ECDH Curve25519 (encrypt)
    /// - User ID: `"<nickname> <nickname@pgp-chat>"`
    /// - `passphrase`: protects the secret key; use `Zeroizing::new(String::new())`
    ///   for an unprotected key (demo / testing only).
    pub fn generate(nickname: &str, passphrase: Zeroizing<String>) -> Result<Self> {
        let user_id = format!("{} <{}@pgp-chat>", nickname, nickname.to_lowercase());

        // Capture passphrase for use in closures — clone into Zeroizing wrappers
        // so the copies are also zeroed when they go out of scope.
        let pw_for_sign  = passphrase.clone();
        let pw_for_pub   = passphrase.clone();

        let params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::EdDSA)
            .can_certify(true)
            .can_sign(true)
            .primary_user_id(user_id.clone())
            .preferred_symmetric_algorithms(smallvec![
                SymmetricKeyAlgorithm::AES256,
                SymmetricKeyAlgorithm::AES128,
            ])
            .preferred_hash_algorithms(smallvec![
                HashAlgorithm::SHA2_256,
                HashAlgorithm::SHA2_512,
            ])
            .preferred_compression_algorithms(smallvec![
                CompressionAlgorithm::ZLIB,
                CompressionAlgorithm::ZIP,
            ])
            .subkeys(vec![
                SubkeyParamsBuilder::default()
                    .key_type(KeyType::ECDH(ECCCurve::Curve25519))
                    .can_encrypt(true)
                    .build()
                    .map_err(|e| Error::PgpKeyFormat(e.to_string()))?,
            ])
            .build()
            .map_err(|e| Error::PgpKeyFormat(e.to_string()))?;

        // Generate unsigned key (no RNG arg needed in pgp 0.13)
        let secret_key = params
            .generate()
            .map_err(|e| Error::PgpKeyFormat(e.to_string()))?;

        // Self-sign with the supplied passphrase
        let signed_secret = secret_key
            .sign(move || pw_for_sign.as_str().to_owned())
            .map_err(|e| Error::PgpKeyFormat(e.to_string()))?;

        // Get the unsigned public key via SecretKeyTrait, then sign it
        let pub_key = signed_secret.public_key();
        let signed_public = pub_key
            .sign(&signed_secret, move || pw_for_pub.as_str().to_owned())
            .map_err(|e| Error::PgpKeyFormat(e.to_string()))?;

        Ok(Self {
            secret_key: signed_secret,
            public_key: signed_public,
            user_id,
            nickname: nickname.to_string(),
            passphrase,
        })
    }

    // -----------------------------------------------------------------------
    // Construction — import an existing ASCII-armoured secret key
    // -----------------------------------------------------------------------

    /// Load a `PgpIdentity` from an ASCII-armoured secret key string.
    ///
    /// The `nickname` is used for display; it does not have to match the
    /// User-ID packet embedded in the key.  The `passphrase` must match
    /// whatever was used when the key was originally created / exported.
    ///
    /// ```text
    /// let armored = std::fs::read_to_string("my_key.asc")?;
    /// let identity = PgpIdentity::from_armored_secret_key(
    ///     "Alice",
    ///     &armored,
    ///     Zeroizing::new("hunter2".to_owned()),
    /// )?;
    /// ```
    pub fn from_armored_secret_key(
        nickname: &str,
        armored: &str,
        passphrase: Zeroizing<String>,
    ) -> Result<Self> {
        let pw_for_pub = passphrase.clone();

        // from_bytes reads binary PGP packets; armoured input needs from_armor_single
        let (signed_secret, _headers) =
            SignedSecretKey::from_armor_single(Cursor::new(armored.as_bytes()))
                .map_err(|e| Error::PgpKeyParse(e.to_string()))?;

        // Derive the public key and sign it
        let pub_key = signed_secret.public_key();
        let signed_public = pub_key
            .sign(&signed_secret, move || pw_for_pub.as_str().to_owned())
            .map_err(|e| Error::PgpKeyFormat(e.to_string()))?;

        // Extract primary User-ID from the key if available, fall back to nickname
        let user_id = signed_secret
            .details
            .users
            .first()
            .map(|u| u.id.id().to_string())
            .unwrap_or_else(|| format!("{} <{}@pgp-chat>", nickname, nickname.to_lowercase()));

        Ok(Self {
            secret_key: signed_secret,
            public_key: signed_public,
            user_id,
            nickname: nickname.to_string(),
            passphrase,
        })
    }

    /// Load a `PgpIdentity` from raw (binary) secret key bytes.
    ///
    /// Accepts standard PGP binary packet format (non-armoured).
    /// Use [`from_armored_secret_key`] for the ASCII-armoured `-----BEGIN PGP PRIVATE KEY BLOCK-----` form.
    pub fn from_secret_key_bytes(
        nickname: &str,
        bytes: &[u8],
        passphrase: Zeroizing<String>,
    ) -> Result<Self> {
        let pw_for_pub = passphrase.clone();

        let signed_secret = SignedSecretKey::from_bytes(Cursor::new(bytes))
            .map_err(|e| Error::PgpKeyParse(e.to_string()))?;

        let pub_key = signed_secret.public_key();
        let signed_public = pub_key
            .sign(&signed_secret, move || pw_for_pub.as_str().to_owned())
            .map_err(|e| Error::PgpKeyFormat(e.to_string()))?;

        let user_id = signed_secret
            .details
            .users
            .first()
            .map(|u| u.id.id().to_string())
            .unwrap_or_else(|| format!("{} <{}@pgp-chat>", nickname, nickname.to_lowercase()));

        Ok(Self {
            secret_key: signed_secret,
            public_key: signed_public,
            user_id,
            nickname: nickname.to_string(),
            passphrase,
        })
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    pub fn nickname(&self) -> &str { &self.nickname }
    pub fn user_id(&self)  -> &str { &self.user_id }

    pub fn public_key(&self)  -> &SignedPublicKey  { &self.public_key }
    pub fn secret_key(&self)  -> &SignedSecretKey  { &self.secret_key }

    /// Hex-encoded key fingerprint (lowercase, no spaces).
    pub fn fingerprint(&self) -> String {
        hex::encode(self.public_key.fingerprint())
    }

    // -----------------------------------------------------------------------
    // Armoured I/O
    // -----------------------------------------------------------------------

    /// Export the public key as an ASCII-armoured string.
    pub fn public_key_armored(&self) -> Result<String> {
        self.public_key
            .to_armored_string(ArmorOptions::default())
            .map_err(|e| Error::PgpKeyFormat(e.to_string()))
    }

    /// Export the secret key as an ASCII-armoured string.
    ///
    /// The exported key is protected with the same passphrase that was
    /// supplied at construction / import time.
    pub fn secret_key_armored(&self) -> Result<String> {
        self.secret_key
            .to_armored_string(ArmorOptions::default())
            .map_err(|e| Error::PgpKeyFormat(e.to_string()))
    }

    /// Passphrase closure suitable for passing to rPGP sign/decrypt calls.
    ///
    /// Returns a closure that yields a clone of the stored passphrase each
    /// time it is called.  Only use this when you need to delegate signing
    /// or decryption to rPGP internals directly.
    pub(crate) fn passphrase_fn(&self) -> impl Fn() -> String + Clone + '_ {
        let pw = self.passphrase.clone();
        move || pw.as_str().to_owned()
    }
}

impl std::fmt::Debug for PgpIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgpIdentity")
            .field("user_id",     &self.user_id)
            .field("fingerprint", &self.fingerprint())
            .finish()
    }
}
