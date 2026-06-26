//! Composed libp2p `NetworkBehaviour` for the chat node.
//!
//! The `#[derive(NetworkBehaviour)]` macro from libp2p generates the
//! `SwarmEvent` dispatch and the `OutEvent` enum automatically.

use libp2p::{
    gossipsub, identify, kad, mdns,
    swarm::NetworkBehaviour,
};

/// The combined network behaviour for a chat node.
///
/// Each field corresponds to a libp2p *protocol*:
///
/// | Field       | Protocol    | Purpose                                      |
/// |-------------|-------------|----------------------------------------------|
/// | `gossipsub` | GossipSub   | Chat-room message broadcast (pub/sub)        |
/// | `kademlia`  | Kademlia    | Distributed peer discovery (DHT)             |
/// | `identify`  | Identify    | Exchange listen addrs; feeds Kademlia        |
/// | `mdns`      | mDNS        | Local network broadcasting (zero-config)     |
///
/// mDNS is included so that chat nodes respond to scanner queries even while
/// in a room — without it, active chatters are invisible to the peer scanner.
///
/// The `#[derive(NetworkBehaviour)]` macro generates `ChatBehaviourEvent`
/// in this same module.  It is a `pub enum` with variants named after the
/// fields: `Gossipsub(gossipsub::Event)`, `Kademlia(kad::Event)`,
/// `Identify(identify::Event)`, `Mdns(mdns::Event)`.
#[derive(NetworkBehaviour)]
pub struct ChatBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia:  kad::Behaviour<kad::store::MemoryStore>,
    pub identify:  identify::Behaviour,
    pub mdns:      mdns::tokio::Behaviour,
}

// Note: the `#[derive(NetworkBehaviour)]` macro generates `pub enum ChatBehaviourEvent`
// in this same module with variants:
//   Gossipsub(gossipsub::Event)
//   Kademlia(kad::Event)
//   Identify(identify::Event)
//   Mdns(mdns::Event)
// It is accessible as `crate::network::behaviour::ChatBehaviourEvent`.
