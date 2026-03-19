//! Build the libp2p [`Swarm`] for a chat node.
//!
//! ## Transport stack
//!
//! ```text
//!  TCP  → Noise (XX handshake, X25519 ECDH) → Yamux multiplexing
//!  QUIC (quic-v1) — TLS 1.3 built-in, stream multiplexing built-in
//! ```
//!
//! Both transports are active simultaneously.  QUIC traffic is
//! indistinguishable from HTTPS to deep-packet inspection, providing
//! protocol-level camouflage on any port.
//!
//! ## Protocols
//!
//! ```text
//!  Gossipsub  — room broadcast (all payloads room-symmetric-encrypted)
//!  Kademlia   — distributed peer discovery (no mDNS; unreliable on Windows)
//!  Identify   — multiaddr exchange so Kademlia can populate its routing table
//! ```

use std::time::Duration;

use libp2p::{
    gossipsub, identify, kad, noise, tcp, yamux,
    identity::Keypair,
    swarm::Swarm,
    SwarmBuilder,
};

use crate::{
    error::{Error, Result},
    network::behaviour::ChatBehaviour,
};

// ---------------------------------------------------------------------------
// Network constants
// ---------------------------------------------------------------------------

/// How often Gossipsub sends heartbeat control messages (mesh maintenance).
const GOSSIPSUB_HEARTBEAT: Duration = Duration::from_secs(10);

/// How long an idle connection is kept open before being closed.
const IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);

/// Identify protocol ID — bump the minor version on breaking protocol changes.
const IDENTIFY_PROTOCOL: &str = "/pgp-chat/1.0.0";

// ---------------------------------------------------------------------------
// Swarm builder
// ---------------------------------------------------------------------------

/// Build a ready-to-use libp2p swarm with TCP + QUIC transports.
///
/// The swarm is configured but not yet listening — call
/// `swarm.listen_on(addr)` after construction.
///
/// # Arguments
///
/// * `keypair` — ephemeral ed25519 keypair for transport authentication
pub fn build_swarm(keypair: Keypair) -> Result<Swarm<ChatBehaviour>> {
    let peer_id = keypair.public().to_peer_id();

    // ── Gossipsub config ───────────────────────────────────────────────────
    //
    // message_id_fn: all gossipsub payloads are now room-symmetrically
    // encrypted, so we can no longer peek at the inner SignedChatMessage.
    // Hash the raw ciphertext bytes for gossipsub-level dedup.
    // Application-layer dedup still uses the inner UUID via seen_messages.
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(GOSSIPSUB_HEARTBEAT)
        .validation_mode(gossipsub::ValidationMode::Strict)
        .message_id_fn(|msg: &gossipsub::Message| {
            use std::hash::{Hash, Hasher};
            let mut s = std::collections::hash_map::DefaultHasher::new();
            msg.data.hash(&mut s);
            gossipsub::MessageId::new(&s.finish().to_be_bytes())
        })
        .build()
        .map_err(|e| Error::Network(e.to_string()))?;

    let swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        // TCP transport with Noise handshake + Yamux multiplexing
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| Error::Network(e.to_string()))?
        // QUIC/UDP transport — looks like HTTPS (TLS 1.3 over UDP) to DPI
        .with_quic()
        .with_behaviour(|key| {
            // --- Gossipsub ------------------------------------------------
            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )
            .map_err(|e| Error::Network(e.to_string()))?;

            // --- Kademlia -------------------------------------------------
            let mut kademlia = kad::Behaviour::new(
                peer_id,
                kad::store::MemoryStore::new(peer_id),
            );
            // Server mode: participate in routing (not just client lookups)
            kademlia.set_mode(Some(kad::Mode::Server));

            // --- Identify -------------------------------------------------
            let identify = identify::Behaviour::new(
                identify::Config::new(
                    IDENTIFY_PROTOCOL.to_string(),
                    key.public(),
                )
                .with_agent_version(format!("pgp-chat/{}", env!("CARGO_PKG_VERSION"))),
            );

            Ok(ChatBehaviour { gossipsub, kademlia, identify })
        })
        .map_err(|e| Error::Network(e.to_string()))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(IDLE_CONNECTION_TIMEOUT))
        .build();

    Ok(swarm)
}
