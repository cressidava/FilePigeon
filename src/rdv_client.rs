use crate::app::App;
use crate::netutil::BoundEndpoint;
use crate::proto::{RdvRequest, RdvResponse};
use crate::tls::{client_config, KeyPolicy, ALPN_RDV};
use crate::wire::{read_msg, write_msg};
use anyhow::{Context, Result};
use std::time::Duration;

/// Connect to the rendezvous server: knock from the very socket we connect
/// from (the stealth gate admits that exact address), then a QUIC connection
/// pinned to the server's key.
pub async fn connect(app: &App, ep: &BoundEndpoint) -> Result<quinn::Connection> {
    let target = app.rendezvous().await?;
    connect_to(&app.identity, &target, ep).await
}

/// Connect to a server that isn't (yet) this PC's configured one, e.g. the
/// one named in an invite link.
pub async fn connect_to(
    identity: &crate::identity::Identity,
    target: &crate::app::RdvTarget,
    ep: &BoundEndpoint,
) -> Result<quinn::Connection> {
    connect_with(identity, target, KeyPolicy::only(target.server_key), ep).await
}

/// For joining with an invite code, before we know the server's key. Safe
/// only because nothing is trusted from this connection: the pairing over it
/// is end-to-end authenticated, and the pinned key comes out of the pairing.
pub async fn connect_unpinned(
    identity: &crate::identity::Identity,
    target: &crate::app::RdvTarget,
    ep: &BoundEndpoint,
) -> Result<quinn::Connection> {
    connect_with(identity, target, KeyPolicy::Any, ep).await
}

async fn connect_with(
    identity: &crate::identity::Identity,
    target: &crate::app::RdvTarget,
    policy: KeyPolicy,
    ep: &BoundEndpoint,
) -> Result<quinn::Connection> {
    ep.expect_replies_from(target.addr);
    let knock = || crate::gate::make_knock(&target.knock_secret, crate::gate::RDV_CONTEXT);
    ep.send_raw(&knock(), target.addr);
    tokio::time::sleep(Duration::from_millis(30)).await;
    ep.send_raw(&knock(), target.addr); // in case the first one was lost
    let cfg = client_config(identity, policy, ALPN_RDV)?;
    let connecting = ep.endpoint.connect_with(cfg, target.addr, "rendezvous")?;
    // Keep knocking until the handshake completes: a knock can be lost, and a
    // brand-new key takes the server a moment to pick up.
    let knocking = async {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            ep.send_raw(&knock(), target.addr);
        }
    };
    let connected = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            r = connecting => r,
            _ = knocking => unreachable!(),
        }
    });
    connected
        .await
        .context("rendezvous server did not answer (check the address and server key)")?
        .context("could not connect to rendezvous server (check the address and server key)")
}

/// Knock again every 20 s for as long as a connection lives: the server's gate
/// needs a fresh knock every few minutes, and if a router changes our public
/// port mid-connection the new address gets admitted within seconds.
pub async fn keep_knocking(app: &App, ep: &BoundEndpoint) {
    let Ok(target) = app.rendezvous().await else { return std::future::pending().await };
    keep_knocking_to(&target, ep).await
}

pub async fn keep_knocking_to(target: &crate::app::RdvTarget, ep: &BoundEndpoint) {
    loop {
        tokio::time::sleep(Duration::from_secs(20)).await;
        ep.send_raw(&crate::gate::make_knock(&target.knock_secret, crate::gate::RDV_CONTEXT), target.addr);
    }
}

/// Open a stream, send one request, read one response.
pub async fn request(
    conn: &quinn::Connection,
    req: &RdvRequest,
) -> Result<(quinn::SendStream, quinn::RecvStream, RdvResponse)> {
    let (mut send, mut recv) = conn.open_bi().await?;
    write_msg(&mut send, req).await?;
    let resp = read_msg(&mut recv).await?;
    Ok((send, recv, resp))
}
