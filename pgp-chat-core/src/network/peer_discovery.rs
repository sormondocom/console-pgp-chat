//! Kademlia peer-discovery helpers.
//!
//! Because we don't use mDNS, we rely on:
//!  1. **Bootstrap peers** — manually dialled at startup to join the DHT
//!  2. **Identify events** — when any peer connects, Identify exchanges listen
//!     addresses which are then fed into the Kademlia routing table

use libp2p::{identify, Multiaddr, PeerId, Swarm};
use tracing::{debug, info, warn};

use crate::network::behaviour::ChatBehaviour;

/// Feed listen addresses discovered via the Identify protocol into Kademlia.
///
/// Call this inside the swarm event loop whenever an `identify::Event` fires.
pub fn handle_identify_event(swarm: &mut Swarm<ChatBehaviour>, event: &identify::Event) {
    if let identify::Event::Received { peer_id, info, .. } = event {
        debug!(peer=%peer_id, "identify received");
        for addr in &info.listen_addrs {
            swarm
                .behaviour_mut()
                .kademlia
                .add_address(peer_id, addr.clone());
        }
    }
}

/// Dial known bootstrap peers and seed the Kademlia routing table.
///
/// `peers` is a slice of `(PeerId, Multiaddr)` pairs obtained out-of-band
/// (config file, command-line argument, hard-coded well-known nodes, …).
///
/// After dialling, Kademlia starts a bootstrap query to fill its routing
/// table with peers closer to the local node ID.
pub fn bootstrap(
    swarm: &mut Swarm<ChatBehaviour>,
    peers: &[(PeerId, Multiaddr)],
) {
    for (peer_id, addr) in peers {
        info!(%peer_id, %addr, "adding bootstrap peer");
        swarm
            .behaviour_mut()
            .kademlia
            .add_address(peer_id, addr.clone());
        if let Err(e) = swarm.dial(addr.clone()) {
            warn!(%peer_id, %addr, "bootstrap dial failed: {e}");
        }
    }

    if !peers.is_empty() {
        if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
            warn!("kademlia bootstrap query failed: {e}");
        }
    }
}

/// Add a peer to gossipsub's explicit peer list once a connection is open.
///
/// Gossipsub will try to maintain a mesh connection to explicit peers even
/// when the mesh degree would otherwise be sufficient.
pub fn add_gossipsub_peer(swarm: &mut Swarm<ChatBehaviour>, peer_id: PeerId) {
    swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
}
