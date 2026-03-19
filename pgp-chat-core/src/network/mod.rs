//! libp2p-based P2P networking layer.
//!
//! ## Architecture
//!
//! ```text
//!  transport::build_swarm()
//!         │  Swarm<ChatBehaviour>
//!         │
//!         ├── TCP transport  (cross-platform: Windows, Linux, BSD, …)
//!         ├── Noise handshake (encrypted transport)
//!         ├── Yamux multiplexer
//!         │
//!         ├── Gossipsub  ← chat-room broadcast (publish / subscribe)
//!         ├── Kademlia   ← peer discovery via DHT (replaces mDNS)
//!         └── Identify   ← exchange listen addrs so Kad can route
//! ```
//!
//! mDNS is intentionally excluded — it is LAN-only and unreliable on Windows.
//! Kademlia DHT + Identify lets peers find each other with only one known
//! bootstrap address, which scales to the internet.

pub mod behaviour;
pub mod event;
pub mod peer_discovery;
pub mod transport;

pub use behaviour::ChatBehaviour;
pub use event::ChatNetEvent;
pub use transport::build_swarm;
