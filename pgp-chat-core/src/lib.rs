//! # pgp-chat-core
//!
//! Core library for the Console PGP Chat project.
//!
//! ## Modules
//!
//! - [`terminal`] — capability detection (VT-100 → 24-bit true colour) and
//!   adaptive rendering that degrades gracefully across every terminal type.
//! - [`crypto`] — PGP identity management, message encryption/decryption,
//!   and detached signatures via rPGP (pure Rust).
//! - [`network`] — libp2p swarm wiring: TCP transport, Noise encryption,
//!   Yamux multiplexing, Gossipsub room broadcast, Kademlia peer discovery.
//! - [`chat`] — high-level chat session: room lifecycle, wire message types,
//!   and the in-memory peer key store.
//! - [`error`] — unified `Error` / `Result` types.

pub mod chat;
pub mod crypto;
pub mod error;
pub mod network;
pub mod terminal;

pub use error::{Error, Result};
