use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    // --- PGP errors (split by operation so callers can distinguish) ---------
    /// Key parsing / deserialization failed (e.g. bad armour, wrong format).
    #[error("PGP key parse error: {0}")]
    PgpKeyParse(String),

    /// Key generation or self-signing failed.
    #[error("PGP key format error: {0}")]
    PgpKeyFormat(String),

    /// Encryption operation failed.
    #[error("PGP encryption error: {0}")]
    PgpEncryption(String),

    /// Decryption operation failed (distinct from wrong key / corrupt data).
    #[error("PGP decryption error: {0}")]
    PgpDecryption(String),

    /// Signing operation failed.
    #[error("PGP signature error: {0}")]
    PgpSignature(String),

    // --- Higher-level semantic errors ----------------------------------------
    #[error("decryption failed — wrong key or corrupt data")]
    DecryptionFailed,

    #[error("signature invalid")]
    SignatureInvalid,

    #[error("key not found: {0}")]
    KeyNotFound(String),

    #[error("fingerprint mismatch: announced={announced} actual={actual}")]
    FingerprintMismatch { announced: String, actual: String },

    // --- Infrastructure errors -----------------------------------------------
    #[error("network error: {0}")]
    Network(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialisation error: {0}")]
    Serialisation(#[from] serde_json::Error),

    #[error("invalid address: {0}")]
    InvalidAddress(String),
}

pub type Result<T> = std::result::Result<T, Error>;
