//! High-level chat session.
//!
//! ## Layers
//!
//! ```text
//! ┌────────────────────────────────────────────────────────┐
//! │  ChatRoom::run()   ← tokio::select! event loop         │
//! │  ┌──────────────┐   ┌──────────────┐                  │
//! │  │  swarm events│   │  RoomCommand │  ← from UI        │
//! │  └──────┬───────┘   └──────┬───────┘                  │
//! │         │                  │                           │
//! │  ┌──────▼──────────────────▼───────────┐              │
//! │  │     ChatNetEvent  →  event_tx        │ → UI layer   │
//! │  └─────────────────────────────────────┘              │
//! └────────────────────────────────────────────────────────┘
//!
//!  PeerKeyStore  ← maps libp2p PeerId → PGP SignedPublicKey
//!  message.rs    ← wire types (JSON-serialisable over gossipsub)
//! ```

pub mod keystore;
pub mod message;
pub mod room;
pub mod transfer;
pub mod trust;

pub use keystore::PeerKeyStore;
pub use message::{ChatMessage, MessageKind, SignedChatMessage};
pub use room::{ChatRoom, ChatRoomHandle, RoomCommand};
pub use trust::{NodeInfo, NodeStatus, TrustState};
