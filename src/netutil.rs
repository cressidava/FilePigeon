use anyhow::Result;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

/// The LAN address the OS would use for internet traffic. No packet is sent:
/// "connecting" a UDP socket only picks a route.
/// An address on a local network (not reachable from the internet).
pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

pub fn primary_local_ip() -> Option<IpAddr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("8.8.8.8:80").ok()?;
    let ip = s.local_addr().ok()?.ip();
    (!ip.is_unspecified()).then_some(ip)
}

pub fn local_candidates(port: u16) -> Vec<SocketAddr> {
    primary_local_ip().map(|ip| SocketAddr::new(ip, port)).into_iter().collect()
}

/// A QUIC endpoint plus a second handle on the same UDP socket, used to send
/// hole-punching packets and knocks from the exact port QUIC uses.
pub struct BoundEndpoint {
    pub endpoint: quinn::Endpoint,
    punch: UdpSocket,
    gate: Option<Arc<crate::gate::Gate>>,
}

impl BoundEndpoint {
    pub fn bind(port: u16, server: Option<quinn::ServerConfig>) -> Result<Self> {
        Self::bind_gated(port, server, None)
    }

    /// Bind behind a stealth gate: nothing reaches QUIC unless it knocked first
    /// (or comes from an address we contacted ourselves).
    pub fn bind_gated(
        port: u16,
        server: Option<quinn::ServerConfig>,
        gate: Option<Arc<crate::gate::Gate>>,
    ) -> Result<Self> {
        let sock = UdpSocket::bind(("0.0.0.0", port))?;
        // The OS defaults (64 KiB on Windows) drop packets at transfer speeds,
        // which makes QUIC back off. Best effort: the OS may cap these.
        let tuning = socket2::SockRef::from(&sock);
        let _ = tuning.set_recv_buffer_size(4 << 20);
        let _ = tuning.set_send_buffer_size(4 << 20);
        let punch = sock.try_clone()?;
        let runtime: Arc<dyn quinn::Runtime> = Arc::new(quinn::TokioRuntime);
        let raw = runtime.wrap_udp_socket(sock)?;
        let socket: Arc<dyn quinn::AsyncUdpSocket> = match &gate {
            Some(g) => crate::gate::GatedSocket::new(raw, g.clone()),
            None => raw,
        };
        let endpoint = quinn::Endpoint::new_with_abstract_socket(quinn::EndpointConfig::default(), server, socket, runtime)?;
        Ok(Self { endpoint, punch, gate })
    }

    /// We're about to talk to `addr`: let its replies through our gate.
    pub fn expect_replies_from(&self, addr: SocketAddr) {
        if let Some(g) = &self.gate {
            g.admit_outbound(addr);
        }
    }

    pub fn gate(&self) -> Option<&Arc<crate::gate::Gate>> {
        self.gate.as_ref()
    }

    pub fn port(&self) -> u16 {
        self.endpoint.local_addr().map(|a| a.port()).unwrap_or(0)
    }

    /// Another handle on the QUIC socket, for a background task to send from.
    pub fn raw_clone(&self) -> Option<UdpSocket> {
        self.punch.try_clone().ok()
    }

    /// Send one raw datagram from the QUIC socket (relay binding).
    pub fn send_raw(&self, data: &[u8], to: SocketAddr) {
        let _ = self.punch.send_to(data, to);
    }

    /// Send a few junk datagrams to each candidate for ~3 seconds. They open a
    /// mapping in our own NAT/firewall so the peer's QUIC handshake gets in;
    /// the peer's QUIC stack silently drops them.
    pub async fn punch(&self, targets: &[SocketAddr]) {
        for _ in 0..15 {
            for t in targets {
                let _ = self.punch.send_to(b"\0fp", t);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
}
