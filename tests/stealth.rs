//! Stealth gates must not answer anything until a valid knock arrives from
//! that exact address: not even a well-formed QUIC handshake. A device's own
//! gate must treat a peer you've hidden from exactly like a stranger.

use filepigeon::app::App;
use filepigeon::config::{save_json, Config, Paths, Peer};
use filepigeon::gate::{make_knock, Gate, GatedSocket, StaticKey, RDV_CONTEXT};
use filepigeon::identity::{device_id, Identity};
use filepigeon::netutil::BoundEndpoint;
use filepigeon::peergate::{knock_context, Knocker, PeerKeys};
use filepigeon::tls::{client_config, server_config, KeyPolicy, ALPN_PEER, ALPN_RDV};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

fn home(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("fp-stealth-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn app(name: &str) -> App {
    let home = home(name);
    let identity = Identity::load_or_create(&home.join("identity.pem")).unwrap();
    App { paths: Paths { home }, config: Config::default(), identity }
}

fn peer_entry(of: &App, hidden: bool) -> Peer {
    let pk = of.identity.public_key();
    Peer {
        name: "x".into(),
        device_id: device_id(&pk),
        public_key: hex::encode(pk),
        paired_at: 0,
        allow_browse: false,
        auto_accept: false,
        hidden,
        server_invite: None,
    }
}

/// A QUIC server behind `gate`, accepting and holding connections.
fn gated_server(id: &Identity, policy: KeyPolicy, alpn: &[u8], gate: Arc<Gate>) -> SocketAddr {
    let runtime: Arc<dyn quinn::Runtime> = Arc::new(quinn::TokioRuntime);
    let raw = runtime.wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap()).unwrap();
    let cfg = server_config(id, policy, alpn).unwrap();
    let server = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(cfg),
        GatedSocket::new(raw, gate),
        runtime,
    )
    .unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        while let Some(incoming) = server.accept().await {
            tokio::spawn(async move {
                if let Ok(conn) = incoming.await {
                    conn.closed().await;
                }
            });
        }
    });
    addr
}

async fn handshake(ep: &BoundEndpoint, cfg: quinn::ClientConfig, addr: SocketAddr, wait: Duration) -> bool {
    matches!(tokio::time::timeout(wait, ep.endpoint.connect_with(cfg, addr, "x").unwrap()).await, Ok(Ok(_)))
}

#[tokio::test]
async fn rendezvous_gate_is_silent_until_knocked_from_that_socket() {
    let server_id = Identity::ephemeral().unwrap();
    let client_id = Identity::ephemeral().unwrap();
    let secret = [42u8; 32];
    let gate = Gate::new(RDV_CONTEXT, StaticKey::new(secret));
    let addr = gated_server(&server_id, KeyPolicy::Any, ALPN_RDV, gate.clone());
    let cfg = client_config(&client_id, KeyPolicy::only(server_id.public_key()), ALPN_RDV).unwrap();

    // 1. Random bytes get no reply at all.
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    probe.send_to(b"hello? anyone there?", addr).await.unwrap();
    let mut buf = [0u8; 1500];
    assert!(tokio::time::timeout(Duration::from_millis(600), probe.recv_from(&mut buf)).await.is_err());

    // 2. A valid QUIC/TLS handshake without a knock goes unanswered.
    let client = BoundEndpoint::bind(0, None).unwrap();
    assert!(!handshake(&client, cfg.clone(), addr, Duration::from_secs(2)).await);

    // 3. A knock under the wrong key, or for another context, doesn't help.
    client.send_raw(&make_knock(&[1u8; 32], RDV_CONTEXT), addr);
    client.send_raw(&make_knock(&secret, b"some-other-service"), addr);
    let other = BoundEndpoint::bind(0, None).unwrap();
    assert!(!handshake(&other, cfg.clone(), addr, Duration::from_secs(2)).await);

    // 4. A valid knock admits exactly the socket that sent it...
    client.send_raw(&make_knock(&secret, RDV_CONTEXT), addr);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(handshake(&client, cfg.clone(), addr, Duration::from_secs(5)).await, "knocked socket must get in");
    // ...not another socket on the same IP.
    let neighbour = BoundEndpoint::bind(0, None).unwrap();
    assert!(!handshake(&neighbour, cfg, addr, Duration::from_secs(2)).await, "admission must be per address");
}

#[tokio::test]
async fn device_gate_treats_hidden_peers_like_strangers() {
    let alice = app("alice");
    let bob = app("bob");
    let stranger = app("stranger");
    save_json(&alice.paths.peers(), &vec![peer_entry(&bob, false)]).unwrap();
    save_json(&bob.paths.peers(), &vec![peer_entry(&alice, false)]).unwrap();
    save_json(&stranger.paths.peers(), &vec![peer_entry(&alice, false)]).unwrap();

    let keys = PeerKeys::new(&alice).unwrap();
    let gate = Gate::new(&knock_context(&alice.identity.public_key()), keys);
    let addr = gated_server(&alice.identity, KeyPolicy::PairedPeers(alice.paths.peers()), ALPN_PEER, gate);
    let to_alice = |me: &App| client_config(&me.identity, KeyPolicy::only(alice.identity.public_key()), ALPN_PEER).unwrap();
    let alice_as_peer = peer_entry(&alice, false);

    // A stranger who knows Alice's key and address still gets silence.
    let s_ep = BoundEndpoint::bind(0, None).unwrap();
    s_ep.send_raw(&Knocker::new(&stranger, &alice_as_peer).unwrap().knock(), addr);
    assert!(!handshake(&s_ep, to_alice(&stranger), addr, Duration::from_secs(2)).await, "stranger got an answer");

    // Bob, a paired peer, knocks and gets in.
    let b_ep = BoundEndpoint::bind(0, None).unwrap();
    let bob_knocker = Knocker::new(&bob, &alice_as_peer).unwrap();
    b_ep.send_raw(&bob_knocker.knock(), addr);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(handshake(&b_ep, to_alice(&bob), addr, Duration::from_secs(5)).await, "paired peer must get in");

    // Alice hides from Bob: from a fresh socket, Bob's knocks now open nothing,
    // so he sees exactly what an offline device would show (silence).
    save_json(&alice.paths.peers(), &vec![peer_entry(&bob, true)]).unwrap();
    tokio::time::sleep(Duration::from_millis(1200)).await; // key cache refresh
    let b2 = BoundEndpoint::bind(0, None).unwrap();
    b2.send_raw(&bob_knocker.knock(), addr);
    let probe_reply = {
        let mut buf = [0u8; 1500];
        let raw = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        raw.send_to(&bob_knocker.knock(), addr).await.unwrap();
        tokio::time::timeout(Duration::from_millis(600), raw.recv_from(&mut buf)).await.is_ok()
    };
    assert!(!probe_reply, "a knock must never be answered");
    assert!(!handshake(&b2, to_alice(&bob), addr, Duration::from_secs(2)).await, "hidden peer got an answer");
}
