//! The core security property: only pinned keys can complete a handshake,
//! in both directions.

use filepigeon::identity::Identity;
use filepigeon::tls::{client_config, peer_public_key, server_config, KeyPolicy, ALPN_PEER};
use std::net::SocketAddr;

fn identity(name: &str) -> Identity {
    let dir = std::env::temp_dir().join(format!("fp-hs-{}-{name}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    Identity::load_or_create(&dir.join("id.pem")).unwrap()
}

async fn try_connect(server: &Identity, server_trusts: KeyPolicy, client: &Identity, client_trusts: KeyPolicy) -> bool {
    let ep_server = quinn::Endpoint::server(
        server_config(server, server_trusts, ALPN_PEER).unwrap(),
        "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
    )
    .unwrap();
    let addr = ep_server.local_addr().unwrap();
    let accept = tokio::spawn(async move {
        let conn = ep_server.accept().await?.await.ok()?;
        Some(peer_public_key(&conn).unwrap())
    });

    let ep_client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let cfg = client_config(client, client_trusts, ALPN_PEER).unwrap();
    // In TLS 1.3 the client finishes first and the server verifies the client
    // certificate afterwards, so a rejected client may briefly look connected.
    let client_ok = ep_client.connect_with(cfg, addr, "filepigeon").unwrap().await.is_ok();
    let server_saw = accept.await.unwrap();
    if let Some(key) = server_saw {
        assert_eq!(key, client.public_key(), "server must see the client's real key");
    }
    client_ok && server_saw.is_some()
}

#[tokio::test]
async fn paired_devices_connect() {
    let (alice, bob) = (identity("alice1"), identity("bob1"));
    assert!(try_connect(&alice, KeyPolicy::only(bob.public_key()), &bob, KeyPolicy::only(alice.public_key())).await);
}

#[tokio::test]
async fn stranger_cannot_connect_to_device() {
    let (alice, bob, eve) = (identity("alice2"), identity("bob2"), identity("eve2"));
    // Eve knows Alice's key, but Alice only trusts Bob.
    assert!(!try_connect(&alice, KeyPolicy::only(bob.public_key()), &eve, KeyPolicy::only(alice.public_key())).await);
}

#[tokio::test]
async fn client_rejects_impostor_server() {
    let (alice, bob, eve) = (identity("alice3"), identity("bob3"), identity("eve3"));
    // Bob expects Alice; Eve answers at that address and would even accept Bob.
    assert!(!try_connect(&eve, KeyPolicy::Any, &bob, KeyPolicy::only(alice.public_key())).await);
}
