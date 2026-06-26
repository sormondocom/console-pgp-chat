<img src="docs/header.svg" alt="console-pgp-chat — Locky mascot header" width="900"/>

# console-pgp-chat

> **Peer-to-peer, end-to-end encrypted chat — no servers, no surveillance, no trust required.**

[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/sormondocom)
[![Latest Release](https://img.shields.io/github/v/release/sormondocom/console-pgp-chat?style=for-the-badge&label=Latest%20Release&color=2ea44f)](https://github.com/sormondocom/console-pgp-chat/releases/latest)

---

## The Problem

Most chat platforms run on centralised servers. You register an account, your messages travel through someone else's infrastructure, and you have to trust that operator with:

- **Who** you talk to (social graph)
- **When** you talk (metadata)
- **What** you say — even if the app claims "end-to-end encryption", the server still decides whose keys are legitimate

Even well-intentioned providers can be compelled by governments to retain or disclose logs. Breaches expose years of message history. Closed-source clients may silently ship keys to corporate infrastructure. You simply cannot verify what happens to your data once it leaves your device.

The root cause is centralisation: a single trusted party sits between every conversation.

**console-pgp-chat removes that party entirely.**

---

## What It Is

A fully peer-to-peer encrypted chat room written in pure Rust, designed to run on any terminal from a VT-100 to a 24-bit true-color modern shell. The entire dependency tree is pure Rust — no C libraries, no native dependencies — which means it compiles and runs on every platform Rust supports.

```
Workspace layout
────────────────
pgp-chat-core/    ← library: crypto, networking, terminal detection, persistence
pgp-chat/         ← interactive binary (menu-driven UI)  →  binary name: pgp-chat
```

---

## Main Menu

On launch you are presented with a four-item menu and an ASCII mascot (two CRT terminals connected by an encrypted channel with a padlock in the centre):

| Key | Option | Description |
|---|---|---|
| `1` | Start Chat | Connect to a room and exchange encrypted messages |
| `2` | Manage Identities | Create, import, view, set active, or delete PGP identities |
| `3` | Manage Rooms | Add, rename, update passphrase, or forget saved rooms |
| `4` | Settings | Configure file paths and chat color theme |
| `q` | Quit | Exit the application |

---

## Diagrams

### Peer Connection & Key Exchange Handshake

![Handshake diagram](docs/handshake.svg)

### Message Transport — 4-Layer Security Stack

![Message transport diagram](docs/message-transport.svg)

---

## How It Works

### 1. Identities — Two Separate Layers

The design maintains a strict separation between **transport identity** and **application identity**:

| Layer | Type | Purpose | Lifetime |
|---|---|---|---|
| libp2p `Keypair` | ed25519 | Authenticate TCP/QUIC connections (Noise handshake) | Ephemeral — new each session |
| `PgpIdentity` | EdDSA primary + ECDH subkey | Sign messages, encrypt content | Long-term — stored by the user |

Your PGP key is *yours*. The network never sees the private key. The transport keypair is throwaway — losing it costs nothing.

### 2. Understanding Public and Secret Keys

Every user has **two mathematically linked keys** that serve opposite roles:

| Key | Also called | Who holds it | What it does |
|---|---|---|---|
| **Secret key** | Private key | **You only** — never shared | Signs your outgoing messages; decrypts incoming encrypted messages |
| **Public key** | Signing/encryption key | Shared freely with all peers | Lets peers verify your signatures and encrypt messages only you can read |

The public key is derived from the secret key. You only need to safeguard one thing: **your secret key file**.

#### What the app asks for at each step

| Prompt | Which key | Why |
|---|---|---|
| Generate new keypair | Creates **both** (secret + public) | Secret stays local; public is announced to peers automatically |
| Import existing key | Your **secret key** file (`.asc`) | Starts with `-----BEGIN PGP PRIVATE KEY BLOCK-----`. The public key is derived from it — do NOT import a public-only key here |
| Key passphrase | Protects the **secret key** | Encrypts the secret key on disk (S2K); you must enter it each session to unlock it |

> **Common mistake:** exporting the public key from GnuPG (`gpg --export --armor`) and trying to import it here will fail — the app specifically needs the *secret* key (`gpg --export-secret-keys --armor`).

#### Managing Multiple Identities

The app supports multiple named identities stored in the identities directory. Use **[2] Manage Identities** from the main menu to:

- **[n] New identity** — generate a fresh EdDSA primary key (signing) + ECDH Curve25519 subkey (encryption), optionally protected with a passphrase. The key is stored with S2K protection when a passphrase is set; a wrong passphrase at login is detected and rejected.
- **[i] Import** — load an existing PGP secret key from an ASCII-armoured `.asc` file you already control (e.g. exported from GnuPG, Kleopatra, or another pgp-chat instance). The app reads only the secret key file; it derives and announces the public key itself.
- **Enter a number** — view fingerprint, creation date, and set the identity as active.
- **[d] Delete** — permanently remove an identity and its key file.

One identity is designated **active** — this is the one used automatically when you start a chat session. If you have only one identity it is set active at creation time.

Passphrases are handled with `Zeroizing<String>` — the passphrase is wiped from memory as soon as it is no longer needed.

### 3. Room Passphrase — Outer Encryption Layer

Every room has a **room passphrase** — a shared secret that all legitimate participants know before joining. You exchange it out-of-band (a Signal message, a QR code, a phone call).

Every byte published to Gossipsub is **PGP-symmetrically encrypted** (AES-256) with the room passphrase before it leaves your node. Nodes without the passphrase see only opaque OpenPGP binary packets — they cannot even determine whether a packet is a chat message, a key announcement, or a file transfer.

#### Managing Saved Rooms

Use **[3] Manage Rooms** to pre-configure rooms before starting a session:

- **[n] Add room** — enter a name and passphrase. Leave the passphrase blank to **generate** a cryptographically random one (you become the room **owner** and the passphrase is displayed for sharing). Enter an existing passphrase to join as a **member**.
- **Enter a number** — open the room detail screen:
  - **[s] Show passphrase** — reveal the stored passphrase in a copy-friendly box
  - **[n] Rename** — change the room's local label (does not affect the room network topic)
  - **[p] Update passphrase** — replace the stored passphrase; blank generates a new one
- **[f] Forget** — remove a room from the list. Owners must confirm with the stored passphrase; members confirm with `y`.

When starting a chat session, you pick from your saved rooms. If no saved rooms exist, you are prompted to enter a room name and passphrase directly.

If you leave the passphrase blank when entering manually, a synthetic passphrase is derived from the room name (`pgp-chat:room:{name}`) — enough to distinguish rooms on the same network, but not a substitute for a real out-of-band passphrase in a sensitive session.

This is implemented in `pgp-chat-core/src/crypto/room_cipher.rs` (`seal` / `open`).

### 4. Peer Discovery — No Central Directory

There is no signup, no account, no DNS name to contact. Discovery works in two stages:

1. **Bootstrap** — you provide the multiaddr of at least one known peer (e.g. a friend's IP + port). This is a one-time out-of-band exchange.
2. **Kademlia DHT** — once connected to one peer, the Kademlia distributed hash table propagates addresses to all peers in the room automatically.

No mDNS is used (unreliable on Windows). Nodes listen on **both TCP and QUIC/UDP**:

```
Alice:  Listening on /ip4/0.0.0.0/tcp/9000
Alice:  Listening on /ip4/0.0.0.0/udp/9000/quic-v1
```

QUIC frames are TLS 1.3 over UDP — indistinguishable from HTTPS traffic to deep-packet inspection.

### 5. Room Broadcast — Gossipsub

Messages are broadcast to all room members using **Gossipsub**, a pubsub protocol built on libp2p. Every node subscribes to a named topic (the room name). When you publish a message, Gossipsub fans it out through the mesh to every subscriber.

Each Gossipsub payload is the **room-cipher sealed** binary blob. The Gossipsub message ID is derived by hashing the raw ciphertext bytes — deduplication at the application level is handled by the `seen_messages: VecDeque<Uuid>` rolling window (last 512 IDs).

### 6. Trust System — Four-Bucket Keystore

Keys are **never auto-trusted**. On receipt of a peer's `AnnounceKey` message, the key is placed into one of two queues depending on your current mode:

| Mode | Incoming key goes to… |
|---|---|
| Normal | `pending` — requires explicit `/trust` approval |
| Deferring | `deferred` — held until you exit deferring mode |

The keystore has four buckets:

| Bucket | Meaning |
|---|---|
| `trusted` | Approved by you; used for encryption and signature verification |
| `pending` | Received, fingerprint cross-checked, awaiting your decision |
| `deferred` | Held while in deferring mode; promoted to pending on exit |
| `rejected` | Denied by you; all messages from this fingerprint are silently dropped |

Only keys in `trusted` are returned by `all_public_keys()` — rejected peers cannot receive encrypted messages and their signatures are not verified.

**Fingerprint cross-check** — the fingerprint field in the announcement header is verified against `key.fingerprint()` computed from the actual transmitted key. Mismatch = hard reject (cannot be manipulated or phished).

**Deferring mode** (`/defer`) — useful when joining a high-traffic room and you want to review all new keys at once rather than being interrupted by approval prompts. Toggle with `/defer`; on exit, all deferred keys are promoted to pending.

**Persistent contacts** — when you leave a session, trusted peers are saved to `contacts.json`. When you rejoin, they are loaded back and recognised automatically without re-approval.

**Status announcements** — every node broadcasts its current status (`Online` / `Deferring`) on join, on status change, and every 60 seconds. A node that stops announcing is eventually marked `Offline`.

### 7. Message Format

Every message published over Gossipsub is a JSON `SignedChatMessage`, wrapped in room-cipher AES-256 before transmission:

```
gossipsub payload = room_cipher::seal(
    serde_json::to_vec(SignedChatMessage { message, signature }),
    room_passphrase
)
```

`MessageKind` has nine variants:

| Variant | Description |
|---|---|
| `Plaintext(String)` | Unencrypted text — for demos and public channels |
| `Encrypted { ciphertext, recipients }` | PGP public-key encrypted to all trusted room members |
| `AnnounceKey { public_key_armored, nickname }` | Peer broadcasting their long-term PGP public key |
| `System(String)` | Internal notifications (join, leave, warnings) |
| `StatusAnnounce { status }` | Peer heartbeat: `Online` or `Deferring` |
| `Revoke { fingerprint }` | Signed revocation — all peers must drop this fingerprint permanently |
| `FileOffer { encrypted_offer, recipient_fp }` | PGP-encrypted file metadata to a specific recipient |
| `FileAccept / FileDecline` | Receiver's consent or refusal |
| `FileChunk / FileComplete` | Chunked encrypted transfer + SHA-256 integrity confirmation |

### 8. Signing — Authenticity Without Decryption

Every message (including `AnnounceKey`, `StatusAnnounce`, and `Revoke`) carries a **detached PGP signature** over the JSON-serialised `ChatMessage`. This means:

- Any peer can verify **who sent a message** without decrypting the content
- A passive observer who captures the Gossipsub stream (post room-cipher decryption) cannot forge messages from a known sender
- Signature verification uses `StandaloneSignature` from rPGP — standard OpenPGP binary format
- `Revoke` messages that fail signature verification are **rejected** — a peer cannot revoke another peer's identity

### 9. Encryption — Confidentiality for Trusted Room Members

`Encrypted` messages use **PGP public-key encryption** (AES-256 session key, wrapped for each recipient's ECDH Curve25519 subkey). The same ciphertext blob is decryptable by all trusted room members simultaneously.

A message is only sent as `Encrypted` if at least one peer's key is trusted. Otherwise it falls back to `Plaintext` with a console warning.

### 10. File Transfer — End-to-End Encrypted Consent Flow

File transfer requires **mutual explicit consent** before any data moves:

```
/send
    → Enter recipient fingerprint
    → Enter file path
    → Enter description (≤256 chars, encrypted)

Receiver sees:
    [?] Incoming file from Alice (a1b2c3...)
        File:    report.pdf  (1.4 MB)
        Network: /ip4/192.168.1.10/tcp/9000, /ip4/.../udp/.../quic-v1
        Desc:    [decrypted description]
    /accept → Enter save path
    /decline
```

**Privacy guarantees:**

- The `FileOffer` struct (filename, size, description, sender network addresses) is **PGP-encrypted** to the recipient's ECDH subkey — no other node can read it
- Each chunk (512 KiB) is individually PGP-encrypted to the recipient
- All file transfer messages are wrapped in room-cipher AES-256 like all other traffic
- A SHA-256 hash of the plaintext is transmitted in `FileComplete`; the receiver verifies integrity before saving
- The `recipient_fp` field in `FileOffer` is in plaintext for routing — this is the only observable metadata

---

## 4-Layer Security Stack

Security is applied from the **outside in** on send and **inside out** on receive:

| Layer | Mechanism | Scope |
|---|---|---|
| **1 — Transport** | libp2p Noise (X25519 ECDH) + QUIC TLS 1.3 | Per-connection, ephemeral |
| **2 — Room cipher** | PGP symmetric AES-256 keyed by room passphrase | All gossipsub traffic |
| **3 — Signature** | EdDSA detached signature (long-term key) | Every ChatMessage |
| **4 — Content** | PGP public-key encryption (ECDH per-recipient) | `Encrypted` + file payloads |

A passive adversary on the network sees Noise/QUIC ciphertext. An adversary who breaks the transport layer sees room-cipher AES-256 ciphertext. An adversary who learns the room passphrase sees signed-but-encrypted `ChatMessage` JSON. Only a peer with the correct ECDH private key can decrypt `Encrypted` content.

---

## Security Properties

### What Is Guaranteed

| Property | Mechanism |
|---|---|
| **Message authenticity** | Every message is signed with the sender's EdDSA key; receivers verify before displaying |
| **Content confidentiality** | Encrypted messages use AES-256 wrapped with each recipient's ECDH Curve25519 subkey |
| **Room-level confidentiality** | All gossipsub payloads sealed with PGP symmetric AES-256; wrong-passphrase nodes see opaque binary |
| **Transport confidentiality** | Noise (X25519) over TCP; TLS 1.3 over QUIC/UDP — both ephemeral session keys |
| **No central trust** | No server, no certificate authority, no account system |
| **Key ownership** | You generate or import your own key; the private key never leaves your device |
| **Tamper detection** | Detached signatures cover the full `ChatMessage` JSON including UUID and timestamp |
| **Explicit trust** | Keys require manual approval (`/trust`/`/trustall`) — no TOFU auto-trust |
| **Revocation** | Signed `Revoke` message; revoked fingerprint added to permanent drop list on all peers |
| **Passphrase protection** | Keys are S2K-protected on disk; a wrong passphrase is detected and rejected at login |
| **Passphrase zeroization** | `Zeroizing<String>` throughout; `Drop` impl on `PgpIdentity` zeroes passphrase field |

### Replay Protection

Each `ChatMessage` carries a UUIDv4. The room keeps a rolling window of the last 512 message IDs and silently drops duplicates. This prevents Gossipsub re-deliveries and active replay attacks.

### Key Revocation — Nuke

`/nuke` triggers **Nuke** — a nuclear option for compromised or retiring identities:

1. Broadcasts a signed `Revoke` message (peers add your fingerprint to their permanent drop list)
2. Clears keystore, node map, seen messages, and revoked fingerprint set in memory
3. Zeroizes the passphrase (`Zeroizing<String>` drop)
4. Breaks the run loop — all connections drop, the swarm shuts down

Peers who receive the `Revoke` can never again receive encrypted messages from or verify signatures by that fingerprint.

---

## Proving Out Security: End-to-End Sequence

### Step 0 — Create Identities

Each participant opens **[2] Manage Identities** and presses **[n]** to generate a fresh identity:

```
Identity name: work
Display nickname: Alice
Passphrase: ••••••••••••
Confirm passphrase: ••••••••••••
Generating EdDSA + ECDH keypair for "Alice"…
[✓] Identity 'work' created.
    Fingerprint: a1b2c3d4e5f6...
```

### Step 1 — Set Up a Room

Alice opens **[3] Manage Rooms**, presses **[n]**, enters a room name, and leaves the passphrase blank to generate one:

```
Room name: secret-ops
Room passphrase [blank = generate]: (blank)

  ╔══ Generated Room Passphrase (you are the owner) ════╗
  ║  3f9a21bc4d8e7012c5ab...                            ║
  ╚═══════════════════════════════════════════════════════╝
  Share this with peers BEFORE they join.
```

Alice shares the passphrase with Bob out-of-band. Bob opens **[3] Manage Rooms**, presses **[n]**, enters the same room name, and pastes Alice's passphrase.

### Step 2 — Start Chat Nodes

Both participants open **[1] Start Chat**.

Alice selects her `work` identity, enters her passphrase, chooses a listen port, and picks `secret-ops` from her room list. She skips bootstrap (she is first):

```
  Listening on /ip4/192.168.1.10/tcp/9000
  Listening on /ip4/192.168.1.10/udp/9000/quic-v1
  Room: secret-ops  [owner]
```

Bob selects his identity, picks `secret-ops`, and bootstraps to Alice:

```
Bootstrap peer multiaddr: /ip4/192.168.1.10/tcp/9000
[*] Discovered peer: <Alice's PeerId>
```

### Step 3 — Key Exchange and Approval

Alice's `AnnounceKey` arrives at Bob (room-cipher decrypted → signature verified → fingerprint cross-checked):

```
Bob:  [?] New key from Alice (a1b2c3...) — /trust to approve  /deny to reject
Bob:  /trust   →   Alice moved to trusted
```

Alice approves Bob's key. Both are now in each other's `trusted` bucket.

### Step 4 — Encrypted Messaging

```
Alice:  Hello, Bob!
Bob:    14:32 <Alice ✓> Hello, Bob!
```

`✓` — EdDSA signature verified against Alice's trusted key.

### Step 5 — File Transfer

```
Alice:  /send → recipient: 7f3e9d... → file: /home/alice/report.pdf → desc: "Q1 numbers"
Bob:    [?] Incoming file from Alice — report.pdf (1.4 MB) — desc: "Q1 numbers"
Bob:    /accept → save to: /home/bob/downloads/report.pdf
        [✓] report.pdf received — SHA-256 verified
```

### Step 6 — Nuke

```
Alice:  /nuke
        Type NUKE to confirm: NUKE
        [!] NUKE complete — all identity material wiped.
Bob:    [!] Peer a1b2c3... (Alice) has revoked their identity.
```

---

## Chat Commands

Once inside a chat session, type a message and press Enter to send. Commands begin with `/`:

| Command | Action |
|---|---|
| `/help` | List all available commands |
| `/quit` | Disconnect and return to the main menu |
| `/peers` | Show connected peer list with trust state and last-seen time |
| `/rooms` | Manage rooms (switch / join / leave / delete) during a session |
| `/join <room>` | Switch to a different room by name |
| `/trust [fp]` | Approve the last pending key, or a specific fingerprint |
| `/deny [fp]` | Reject the last pending key, or a specific fingerprint |
| `/trustall` | Approve all pending and deferred keys at once |
| `/defer` | Toggle key-deferral mode on/off |
| `/send` | Send a file (prompts for recipient fingerprint, file path, description) |
| `/accept [path]` | Accept an incoming file offer and save to the given path |
| `/decline` | Decline the current incoming file offer |
| `/nuke` | Broadcast revocation, wipe all in-memory state, disconnect |
| `Ctrl-C` / `Ctrl-D` | Quit immediately |

---

## Settings

**[4] Settings** from the main menu provides three configuration areas:

### Identities Directory

The directory where named identity files (`.asc`) and the identity index (`identities.json`) are stored. Changing this path does not move existing files.

### Downloads Directory

The default save location for files received via `/accept`. You can override the path per-transfer at the `/accept` prompt.

### Chat Theme

An 8-field color editor for the chat display:

| Field | What it colors |
|---|---|
| Timestamp | The `HH:MM:SS` prefix on each message |
| Your ID | Your `[You]` sender label |
| Your Text | Your message body |
| Peer Name | The `<Nickname>` sender label for received messages |
| Peer Text | Received message body |
| Background | Row background (Default = transparent) |
| Border | Box-drawing border characters |
| System Msgs | System / status lines |

Available colors: Default, White, Grey, DarkGrey, Black, Cyan, Green, Yellow, Magenta, Blue, Red.

Named themes can be saved (`[s]`), loaded (`[l]`), and deleted (`[x]`). Reset to defaults at any time with `[r]`.

---

## Terminal Support

The library auto-detects terminal capability at startup:

| Environment | Detected Depth | Output |
|---|---|---|
| `NO_COLOR=1` set | Monochrome | Plain text only |
| Basic VT-100, dumb | Monochrome | ASCII box-drawing |
| ANSI (xterm, etc.) | 16-color | Named ANSI colors |
| 256-color terminal | 256-color | xterm-256 palette |
| `COLORTERM=truecolor`, Windows Terminal, iTerm2 | 24-bit TrueColor | Full RGB |

Unicode box-drawing characters are used when the locale or terminal indicates UTF-8 support; ASCII fallback (`+`, `-`, `|`) is used otherwise. Every rendering path goes through `crossterm`, which handles Windows Console API and Unix termios transparently.

---

## Building

```sh
# Requires Rust 1.75 or later (pure Rust, no C toolchain needed)
cargo build --release

# Run the interactive demo
cargo run -p pgp-chat

# Run the crypto unit tests
cargo test -p pgp-chat-core
```

### Environment Variables

| Variable | Effect |
|---|---|
| `RUST_LOG=info` | Show connection and peer discovery events |
| `RUST_LOG=debug` | Show all libp2p internals (verbose) |
| `NO_COLOR=1` | Force monochrome output |
| `COLORTERM=truecolor` | Force 24-bit color detection |

---

## Storage Layout

```
%APPDATA%\pgp-chat\          (Windows)
~/.pgp-chat/                  (Unix / macOS)
  config.json             ← app configuration (directories, active identity, saved themes)
  rooms.json              ← saved rooms: name, passphrase, and owner/member role
  contacts.json           ← trusted peer public keys + rejected fingerprints
  identities/
    identities.json       ← index: name, nickname, fingerprint, created timestamp
    {name}.asc            ← individual ASCII-armoured secret key files (S2K-protected)
```

The secret key files are protected by the user's chosen passphrase (S2K). The contacts file contains only public keys so it carries no secret material. Rooms are stored with their passphrases — protect access to this directory on shared machines.

---

## Architecture Reference

```
pgp-chat-core/
├── crypto/
│   ├── identity.rs       PgpIdentity — generate, import, armoured I/O, S2K passphrase, zeroization
│   ├── encrypt.rs        encrypt_for_recipients, decrypt_message (ECDH subkeys)
│   ├── sign.rs           sign_data, verify_data (StandaloneSignature / EdDSA)
│   └── room_cipher.rs    seal / open — PGP symmetric AES-256 keyed by room passphrase
├── chat/
│   ├── message.rs        ChatMessage, SignedChatMessage, MessageKind (9 variants)
│   ├── keystore.rs       PeerKeyStore — four-bucket (trusted/pending/deferred/rejected)
│   ├── trust.rs          TrustState, NodeStatus, NodeInfo
│   ├── transfer.rs       FileOffer, FileAccept, FileDecline, FileChunk, FileComplete,
│   │                     InboundTransfer, PendingOffer — file transfer wire types
│   └── room.rs           ChatRoom — async coordinator, room cipher, trust gating,
│                         replay dedup, sig enforcement, nuke, file transfer
├── network/
│   ├── behaviour.rs      ChatBehaviour (#[derive(NetworkBehaviour)])
│   ├── transport.rs      build_swarm — TCP+Noise+Yamux + QUIC + Gossipsub + Kademlia + Identify
│   ├── peer_discovery.rs bootstrap, handle_identify_event, add_gossipsub_peer
│   └── event.rs          ChatNetEvent — typed events from network layer to UI
├── terminal/
│   ├── capability.rs     ColorDepth detection, TerminalCapability
│   ├── color.rs          ColorPalette — semantic color roles per depth tier
│   └── renderer.rs       Renderer — adaptive box/message/menu drawing via crossterm
└── persistence.rs        AppConfig, ChatTheme, ThemeColor, IdentityEntry,
                          PersistedRoom, PersistedContact, PersistedTrustStore

pgp-chat/
└── src/
    ├── main.rs
    ├── menu.rs                  main menu — 4 entries + quit, mascot render
    ├── ui.rs                    Ui — prompts, password input, mascot, passphrase reveal box
    └── commands/
        ├── identity_manager.rs  Manage Identities — list, create, import, view, set active, delete
        ├── room_manager.rs      Manage Rooms — add, detail, show passphrase, rename, update, forget
        ├── network_demo.rs      Start Chat — swarm startup, room loop, slash-command handler
        └── settings.rs          Settings — directories, chat theme editor, named theme save/load
```

---

## License

GNU General Public License v3 (GPLv3)
