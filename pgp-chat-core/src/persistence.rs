//! Disk persistence for PGP identity and peer trust store.
//!
//! ## Storage layout
//!
//! ```text
//! %APPDATA%\pgp-chat\     (Windows)
//! ~/.pgp-chat/             (Unix / macOS)
//!   identity.asc   ← ASCII-armoured secret key (passphrase-protected by user)
//!   contacts.json  ← trusted peer public keys + rejected fingerprints
//!   rooms.json     ← room names + passphrases (AES-256 room keys — protect this file!)
//! ```
//!
//! ## Security note
//!
//! `rooms.json` stores each room's AES-256 passphrase encrypted with the user's
//! PGP identity key (prefix `pgpenc:`).  An attacker who steals `rooms.json`
//! cannot decrypt room traffic without also obtaining the identity secret key
//! *and* cracking its PGP passphrase.  On Unix the file is created with mode
//! 0600 (owner-readable only).  On Windows, restrict access to the
//! `%APPDATA%\pgp-chat\` directory.
//!
//! The secret key is protected by the user's chosen passphrase.  The contacts
//! file contains only public keys so it carries no secret material.

use std::path::{Path, PathBuf};
use std::io::Cursor;

use chrono::{DateTime, Utc};
use pgp::composed::{Deserializable, SignedPublicKey};
use zeroize::Zeroize;
use serde::{Deserialize, Serialize};

use crate::crypto::{encrypt, identity::PgpIdentity};
use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// Room passphrase encryption helpers
// ---------------------------------------------------------------------------

/// Prefix written in front of PGP-encrypted room passphrases in `rooms.json`.
pub const PASSPHRASE_ENC_PREFIX: &str = "pgpenc:";

/// Returns `true` when `stored` is a PGP-encrypted passphrase written by
/// [`encrypt_room_passphrase`].
pub fn passphrase_is_encrypted(stored: &str) -> bool {
    stored.starts_with(PASSPHRASE_ENC_PREFIX)
}

/// Encrypt a room passphrase to `identity`'s public key.
///
/// Returns `"pgpenc:" + hex(PGP packet bytes)` on success.
pub fn encrypt_room_passphrase(pass: &str, identity: &PgpIdentity) -> Result<String> {
    let bytes = encrypt::encrypt_for_recipients(pass.as_bytes(), &[identity.public_key()])?;
    Ok(format!("{}{}", PASSPHRASE_ENC_PREFIX, hex::encode(bytes)))
}

/// Decrypt a room passphrase that was stored by [`encrypt_room_passphrase`].
///
/// If `stored` does not carry the `pgpenc:` prefix (old plaintext format or
/// a newly-entered value not yet encrypted) the original string is returned
/// unchanged so callers are migration-transparent.
///
/// Returns the original string if decryption fails, so callers don't need to
/// handle the error path specially when reading legacy data.
pub fn decrypt_room_passphrase(stored: &str, identity: &PgpIdentity) -> String {
    stored.strip_prefix(PASSPHRASE_ENC_PREFIX)
        .and_then(|hex_part| hex::decode(hex_part).ok())
        .and_then(|bytes| {
            encrypt::decrypt_message(
                &bytes,
                identity.secret_key(),
                identity.passphrase_fn(),
            ).ok()
        })
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_else(|| stored.to_string())
}

// ---------------------------------------------------------------------------
// Serialisable structs
// ---------------------------------------------------------------------------

/// One entry in the persisted contacts file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedContact {
    pub fingerprint:        String,
    pub nickname:           String,
    pub armored_public_key: String,
    pub last_seen:          Option<DateTime<Utc>>,
}

/// Full snapshot of the trust store written to `contacts.json`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PersistedTrustStore {
    pub contacts: Vec<PersistedContact>,
    /// Fingerprints the user has permanently rejected this session.
    pub rejected: Vec<String>,
}

// ---------------------------------------------------------------------------
// Directory helpers
// ---------------------------------------------------------------------------

/// Returns the platform-appropriate storage directory.
///
/// - Windows: `%APPDATA%\pgp-chat`
/// - Unix/macOS: `~/.pgp-chat`
pub fn storage_dir() -> PathBuf {
    #[cfg(windows)]
    let base = std::env::var("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    #[cfg(not(windows))]
    let base = std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    base.join("pgp-chat")
}

/// Full path to the identity file inside `dir`.
pub fn identity_path(dir: &Path) -> PathBuf { dir.join("identity.asc") }

/// Full path to the contacts file inside `dir`.
pub fn contacts_path(dir: &Path) -> PathBuf { dir.join("contacts.json") }

/// Full path to the rooms list file inside `dir`.
pub fn rooms_path(dir: &Path) -> PathBuf { dir.join("rooms.json") }

// ---------------------------------------------------------------------------
// Identity persistence
// ---------------------------------------------------------------------------

/// Save the armoured secret key to `{dir}/identity.asc`.
///
/// The nickname is embedded as a comment header so it can be recovered on the
/// next startup without asking the user to retype it.
///
/// On Unix the file permissions are set to 0600 (owner-read/write only)
/// so the secret key is not visible to other users on a shared machine.
pub fn save_identity(dir: &Path, nickname: &str, armored_sk: &str) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let path = identity_path(dir);
    let content = format!("# pgp-chat nickname: {}\n{}", nickname, armored_sk);

    // Write to a temp file then rename — this is atomic on Linux and Windows ≥1607,
    // so a crash during write can never leave a half-written (unreadable) identity file.
    let tmp = path.with_extension("asc.tmp");
    std::fs::write(&tmp, &content)?;
    std::fs::rename(&tmp, &path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&path, perms)?;
    }

    Ok(())
}

/// Load `{dir}/identity.asc`.
///
/// Returns `None` if the file does not exist.
/// Returns `Some((nickname, armored_sk))` if it does.
pub fn load_identity(dir: &Path) -> Result<Option<(String, String)>> {
    let path = identity_path(dir);
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&path)?;
    let nickname = content
        .lines()
        .find(|l| l.starts_with("# pgp-chat nickname: "))
        .and_then(|l| l.strip_prefix("# pgp-chat nickname: "))
        .unwrap_or("anonymous")
        .to_string();
    let armored: String = content
        .lines()
        .filter(|l| !l.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    Ok(Some((nickname, armored)))
}

// ---------------------------------------------------------------------------
// Trust store persistence
// ---------------------------------------------------------------------------

/// Save the trust store snapshot to `{dir}/contacts.json`.
pub fn save_contacts(dir: &Path, store: &PersistedTrustStore) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let json = serde_json::to_string_pretty(store)?;
    // Atomic write-then-rename so a crash never leaves a partial contacts file.
    let path = contacts_path(dir);
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Load the trust store from `{dir}/contacts.json`.
///
/// Returns an empty store if the file does not exist or cannot be parsed
/// (e.g. after a format migration) rather than propagating an error, so
/// the application always starts cleanly.
pub fn load_contacts(dir: &Path) -> PersistedTrustStore {
    let path = contacts_path(dir);
    if !path.exists() {
        return PersistedTrustStore::default();
    }
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Room list persistence
// ---------------------------------------------------------------------------

/// A room this client has previously joined or created.
///
/// The passphrase is stored so the user does not have to re-enter it every
/// session.  The same passphrase must be shared out-of-band with every peer
/// who wants to participate — storing it locally is required for reconnection.
///
/// `is_owner` distinguishes the peer who created (generated or chose) the
/// passphrase from peers who were given it by someone else.  Only the owner
/// may delete the room; non-owners can only unjoin (leave).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedRoom {
    /// Gossipsub topic / display name.
    pub name: String,
    /// AES-256 room passphrase (symmetric, shared out-of-band).
    /// On disk this is PGP-encrypted and prefixed with `pgpenc:` when an
    /// identity is available at save time.  In memory it holds the plaintext
    /// value so the rest of the code can use it directly.
    pub passphrase: String,
    /// `true` when this client initiated the room (generated / chose the
    /// first passphrase).  `false` for rooms joined with a passphrase that
    /// someone else created.
    pub is_owner: bool,
}

impl Drop for PersistedRoom {
    fn drop(&mut self) {
        self.passphrase.zeroize();
    }
}

/// Load the persisted room list from `{dir}/rooms.json`.
///
/// When `identity` is `Some`, passphrases that carry the `pgpenc:` prefix are
/// decrypted using that identity's secret key so callers always receive the
/// plaintext value in `PersistedRoom::passphrase`.
///
/// When `identity` is `None` the raw stored value is returned — useful when
/// only `PersistedRoom::name` is needed (e.g. the peer scanner).
///
/// Returns an empty list if the file does not exist or cannot be parsed.
pub fn load_rooms(dir: &Path, identity: Option<&PgpIdentity>) -> Vec<PersistedRoom> {
    let path = rooms_path(dir);
    if !path.exists() {
        return Vec::new();
    }
    let raw: Vec<PersistedRoom> = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    if let Some(id) = identity {
        raw.into_iter().map(|r| PersistedRoom {
            name:       r.name.clone(),
            passphrase: decrypt_room_passphrase(&r.passphrase, id),
            is_owner:   r.is_owner,
        }).collect()
    } else {
        raw
    }
}

/// Save the room list to `{dir}/rooms.json`.
///
/// When `identity` is `Some`, each room passphrase that is not already
/// encrypted is PGP-encrypted to that identity's public key before writing.
/// Passphrases that already carry the `pgpenc:` prefix are left as-is (they
/// were encrypted on a previous save to the same key).
///
/// When `identity` is `None` the plaintext values are written unchanged —
/// useful from the room manager which doesn't hold a loaded identity; the chat
/// session will re-encrypt on its next save.
///
/// Uses an atomic write-then-rename so a crash never leaves a partial file.
pub fn save_rooms(
    dir:      &Path,
    rooms:    &[PersistedRoom],
    identity: Option<&PgpIdentity>,
) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;

    let rooms_on_disk: Vec<PersistedRoom> = if let Some(id) = identity {
        rooms.iter().map(|r| {
            let pass = if passphrase_is_encrypted(&r.passphrase) {
                r.passphrase.clone()
            } else {
                encrypt_room_passphrase(&r.passphrase, id)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?
            };
            Ok(PersistedRoom {
                name:       r.name.clone(),
                passphrase: pass,
                is_owner:   r.is_owner,
            })
        }).collect::<std::io::Result<Vec<_>>>()?
    } else {
        rooms.to_vec()
    };

    let json = serde_json::to_string_pretty(&rooms_on_disk)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let path = rooms_path(dir);
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, &path)?;

    // Restrict read access on Unix — rooms.json contains AES-256 room keys.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&path, perms)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Chat theme
// ---------------------------------------------------------------------------

/// A named color that can be persisted and applied at any terminal color depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThemeColor {
    Default,
    White,
    Grey,
    DarkGrey,
    Black,
    Cyan,
    Green,
    Yellow,
    Magenta,
    Blue,
    Red,
}

impl ThemeColor {
    pub fn display_name(self) -> &'static str {
        match self {
            Self::Default  => "Default",
            Self::White    => "White",
            Self::Grey     => "Grey",
            Self::DarkGrey => "Dark Grey",
            Self::Black    => "Black",
            Self::Cyan     => "Cyan",
            Self::Green    => "Green",
            Self::Yellow   => "Yellow",
            Self::Magenta  => "Magenta",
            Self::Blue     => "Blue",
            Self::Red      => "Red",
        }
    }

    /// Every variant in display order — used by the color picker UI.
    pub fn all() -> [ThemeColor; 11] {
        [
            Self::Default, Self::White,    Self::Grey,    Self::DarkGrey,
            Self::Black,   Self::Cyan,     Self::Green,   Self::Yellow,
            Self::Magenta, Self::Blue,     Self::Red,
        ]
    }
}

impl Default for ThemeColor {
    fn default() -> Self { Self::Default }
}

/// Color settings for every themeable element of the chat display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatTheme {
    /// Human-readable label (used when saving/loading themes).
    pub name:      String,
    /// Color of the `YYYY-MM-DD HH:MM:SS` prefix on all messages.
    pub timestamp: ThemeColor,
    /// Color of the `[You]` sender label on outgoing messages.
    pub own_id:    ThemeColor,
    /// Color of the body text on outgoing messages.
    pub own_text:  ThemeColor,
    /// Color of peer sender labels (`<Alice>`).  `Default` = rotating colors.
    #[serde(default)]
    pub peer_id:    ThemeColor,
    /// Color of the body text on incoming peer messages.
    pub peer_text:  ThemeColor,
    /// Background fill behind message rows.  `Default` = terminal default.
    #[serde(default)]
    pub background: ThemeColor,
    /// Color of box-drawing border characters.  `Default` = palette default.
    #[serde(default)]
    pub border:      ThemeColor,
    /// Color of timestamped system / status messages.
    #[serde(default = "default_system_text")]
    pub system_text: ThemeColor,
}

fn default_system_text() -> ThemeColor { ThemeColor::Grey }

impl Default for ChatTheme {
    fn default() -> Self {
        Self {
            name:        "Default".to_string(),
            timestamp:   ThemeColor::White,
            own_id:      ThemeColor::Cyan,
            own_text:    ThemeColor::White,
            peer_id:     ThemeColor::Default,
            peer_text:   ThemeColor::White,
            background:  ThemeColor::Default,
            border:      ThemeColor::Default,
            system_text: ThemeColor::Grey,
        }
    }
}

// ---------------------------------------------------------------------------
// Application configuration
// ---------------------------------------------------------------------------

pub fn config_path(dir: &Path) -> PathBuf { dir.join("config.json") }

/// Returns the platform default directory for saving received files.
pub fn default_downloads_dir() -> PathBuf {
    #[cfg(windows)]
    let base = std::env::var("USERPROFILE").map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    #[cfg(not(windows))]
    let base = std::env::var("HOME").map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    base.join("Downloads")
}

/// Persisted application configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Directory where per-identity `.asc` files and the index live.
    pub identities_dir:  PathBuf,
    /// Default directory for files received via `/accept`.
    pub downloads_dir:   PathBuf,
    /// Name slug of the identity that loads automatically at startup.
    pub active_identity: Option<String>,
    /// Active chat color theme.
    #[serde(default)]
    pub chat_theme:      ChatTheme,
    /// User-saved named themes.
    #[serde(default)]
    pub saved_themes:    Vec<ChatTheme>,
}

impl AppConfig {
    pub fn default_for(storage_dir: &Path) -> Self {
        Self {
            identities_dir:  storage_dir.join("identities"),
            downloads_dir:   default_downloads_dir(),
            active_identity: None,
            chat_theme:      ChatTheme::default(),
            saved_themes:    Vec::new(),
        }
    }
}

pub fn load_config(storage_dir: &Path) -> AppConfig {
    let path = config_path(storage_dir);
    if !path.exists() {
        return AppConfig::default_for(storage_dir);
    }
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str::<AppConfig>(&s).ok())
        .unwrap_or_else(|| AppConfig::default_for(storage_dir))
}

pub fn save_config(storage_dir: &Path, config: &AppConfig) -> std::io::Result<()> {
    std::fs::create_dir_all(storage_dir)?;
    let json = serde_json::to_string_pretty(config)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let path = config_path(storage_dir);
    let tmp  = path.with_extension("json.tmp");
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Multiple identity index
// ---------------------------------------------------------------------------

/// One entry in the per-user identity index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityEntry {
    /// Unique local label — used as the `.asc` file basename.
    pub name:        String,
    /// Display nickname broadcast to peers in chat.
    pub nickname:    String,
    /// Hex-encoded fingerprint of the public key.
    pub fingerprint: String,
    /// When this identity was created or imported (UTC).
    pub created_at:  chrono::DateTime<chrono::Utc>,
}

/// Path to the identity index file inside `identities_dir`.
pub fn identities_index_path(identities_dir: &Path) -> PathBuf {
    identities_dir.join("index.json")
}

/// Path to the armoured secret-key file for a named identity.
pub fn identity_file_path(identities_dir: &Path, name: &str) -> PathBuf {
    identities_dir.join(format!("{}.asc", name))
}

pub fn load_identity_entries(identities_dir: &Path) -> Vec<IdentityEntry> {
    let path = identities_index_path(identities_dir);
    if !path.exists() {
        return Vec::new();
    }
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str::<Vec<IdentityEntry>>(&s).ok())
        .unwrap_or_default()
}

pub fn save_identity_entries(identities_dir: &Path, entries: &[IdentityEntry]) -> std::io::Result<()> {
    std::fs::create_dir_all(identities_dir)?;
    let json = serde_json::to_string_pretty(entries)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let path = identities_index_path(identities_dir);
    let tmp  = path.with_extension("json.tmp");
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Save an armoured secret key to `<identities_dir>/<name>.asc`.
///
/// Uses an atomic write-then-rename.  Sets `0600` permissions on Unix.
pub fn save_named_identity(identities_dir: &Path, name: &str, armored_sk: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(identities_dir)?;
    let path = identity_file_path(identities_dir, name);
    let tmp  = path.with_extension("asc.tmp");
    std::fs::write(&tmp, armored_sk)?;
    std::fs::rename(&tmp, &path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&path, perms)?;
    }
    Ok(())
}

/// Load the armoured secret key for the named identity.
///
/// Returns `None` if the `.asc` file does not exist.
pub fn load_named_identity(identities_dir: &Path, name: &str) -> std::io::Result<Option<String>> {
    let path = identity_file_path(identities_dir, name);
    if !path.exists() {
        return Ok(None);
    }
    std::fs::read_to_string(&path).map(Some)
}

// ---------------------------------------------------------------------------
// Contact parsing
// ---------------------------------------------------------------------------

/// Parse a `PersistedContact` back into `(fingerprint, nickname, SignedPublicKey)`.
///
/// The fingerprint is re-derived from the parsed key material and compared
/// against the stored value.  A mismatch means the file was tampered with
/// (attacker-swapped key under a legitimate peer's fingerprint) and the
/// contact is rejected rather than trusted.
pub fn parse_contact(c: &PersistedContact) -> Result<(String, String, SignedPublicKey)> {
    use pgp::types::KeyTrait;
    let (key, _) = SignedPublicKey::from_armor_single(Cursor::new(c.armored_public_key.as_bytes()))
        .map_err(|e| Error::PgpKeyParse(e.to_string()))?;
    let derived_fp = hex::encode(key.fingerprint());
    if derived_fp != c.fingerprint {
        return Err(Error::PgpKeyParse(format!(
            "contacts.json fingerprint mismatch for '{}': stored '{}', derived '{}' — contact rejected",
            c.nickname, c.fingerprint, derived_fp
        )));
    }
    Ok((derived_fp, c.nickname.clone(), key))
}
