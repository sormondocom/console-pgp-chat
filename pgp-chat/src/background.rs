use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use chrono::Utc;
use futures::StreamExt;
use libp2p::{
    gossipsub::{self, IdentTopic},
    identify,
    identity::Keypair,
    mdns,
    noise, tcp, yamux,
    swarm::{NetworkBehaviour, SwarmEvent},
    SwarmBuilder,
};
use pgp_chat_core::{
    network::trust_message::{TRUST_TOPIC, TrustRequestMessage},
    persistence::{self, PendingTrustRequest},
};

#[derive(NetworkBehaviour)]
struct BgBehaviour {
    gossipsub: gossipsub::Behaviour,
    identify:  identify::Behaviour,
    mdns:      mdns::tokio::Behaviour,
}

pub async fn run(storage_dir: PathBuf, own_fingerprint: String, identity_name: String) {
    loop {
        if let Err(e) = run_inner(&storage_dir, &own_fingerprint, &identity_name).await {
            eprintln!("background trust listener restarting after error: {e}");
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
}

async fn run_inner(storage_dir: &PathBuf, own_fingerprint: &str, identity_name: &str) -> anyhow::Result<()> {
    let keypair    = Keypair::generate_ed25519();
    let peer_id    = keypair.public().to_peer_id();
    let public_key = keypair.public();

    let gs_cfg = gossipsub::ConfigBuilder::default()
        .validation_mode(gossipsub::ValidationMode::Strict)
        .build()
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let mut gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(keypair.clone()), gs_cfg,
    ).map_err(|e| anyhow::anyhow!("{e}"))?;

    let trust_topic = IdentTopic::new(TRUST_TOPIC);
    gossipsub.subscribe(&trust_topic)?;

    let identify = identify::Behaviour::new(
        identify::Config::new("/pgp-chat/1.0.0".to_string(), public_key)
            .with_agent_version(format!("pgp-chat-bg/{}", env!("CARGO_PKG_VERSION"))),
    );
    let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let behaviour = BgBehaviour { gossipsub, identify, mdns };

    let mut swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .with_quic()
        .with_behaviour(|_| behaviour)
        .unwrap()
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())?;
    swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap())?;

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::Behaviour(BgBehaviourEvent::Gossipsub(
                gossipsub::Event::Message { message, .. }
            )) => {
                if message.topic == trust_topic.hash() {
                    if let Some(msg) = TrustRequestMessage::from_bytes(&message.data) {
                        handle_trust_request(storage_dir, own_fingerprint, identity_name, msg);
                    }
                }
            }
            SwarmEvent::Behaviour(BgBehaviourEvent::Mdns(
                mdns::Event::Discovered(list)
            )) => {
                for (_, addr) in list {
                    let _ = swarm.dial(addr);
                }
            }
            _ => {}
        }
    }
}

fn handle_trust_request(storage_dir: &PathBuf, own_fingerprint: &str, identity_name: &str, msg: TrustRequestMessage) {
    // Verify freshness, key/fingerprint consistency, and PGP signature.
    // Silently discard any message that fails these checks.
    if let Err(e) = msg.verify() {
        eprintln!("discarding invalid trust request: {e}");
        return;
    }

    // Discard our own broadcast (background listener receives it too).
    if msg.from_fingerprint == own_fingerprint {
        return;
    }

    let trust_store = persistence::load_contacts(storage_dir, identity_name);

    // Peer is already trusted — no need to re-queue a request.
    if trust_store.contacts.iter().any(|c| c.fingerprint == msg.from_fingerprint) {
        return;
    }
    // Peer was explicitly rejected — silently discard.
    if trust_store.rejected.iter().any(|fp| fp == &msg.from_fingerprint) {
        return;
    }

    let mut requests = persistence::load_pending_trust_requests(storage_dir, identity_name);
    let already = requests.iter().any(|r| r.from_fingerprint == msg.from_fingerprint);
    if !already {
        requests.push(PendingTrustRequest {
            from_nickname:           msg.from_nickname,
            from_fingerprint:        msg.from_fingerprint,
            from_public_key_armored: msg.from_public_key_armored,
            received_at:             Utc::now(),
        });
        if let Err(e) = persistence::save_pending_trust_requests(storage_dir, identity_name, &requests) {
            eprintln!("failed to save pending trust request: {e}");
        } else {
            // Ring terminal bell so the user notices regardless of which screen they're on.
            print!("\x07");
            let _ = std::io::stdout().flush();
        }
    }
}
