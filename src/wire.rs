//! Length-prefixed JSON control messages. File bytes travel raw between them.

use anyhow::{bail, Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest control message anyone may send (offer lists can be big).
pub const MAX_FRAME: usize = 4 << 20;
/// Limit for a peer's first request, before any approval. Memory only grows
/// as bytes really arrive, so this can be the full frame size (big offers).
pub const MAX_REQUEST: usize = MAX_FRAME;
/// Limit for rendezvous control messages, which are always tiny.
pub const MAX_SMALL: usize = 16 << 10;

pub async fn write_msg<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, msg: &T) -> Result<()> {
    let body = serde_json::to_vec(msg)?;
    if body.len() > MAX_FRAME {
        bail!("message too large");
    }
    w.write_all(&(body.len() as u32).to_be_bytes()).await?;
    w.write_all(&body).await?;
    Ok(())
}

pub async fn read_msg<R: AsyncRead + Unpin, T: DeserializeOwned>(r: &mut R) -> Result<T> {
    read_msg_max(r, MAX_FRAME).await
}

/// Read one message of at most `max` bytes. Memory grows only as bytes really
/// arrive, so a length header alone can't make us reserve megabytes.
pub async fn read_msg_max<R: AsyncRead + Unpin, T: DeserializeOwned>(r: &mut R, max: usize) -> Result<T> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await.context("connection closed")?;
    let len = u32::from_be_bytes(len) as usize;
    if len > max {
        bail!("remote sent an oversized message");
    }
    let mut buf = Vec::with_capacity(len.min(64 << 10));
    AsyncReadExt::take(&mut *r, len as u64).read_to_end(&mut buf).await.context("connection closed")?;
    if buf.len() != len {
        bail!("connection closed");
    }
    serde_json::from_slice(&buf).context("malformed message")
}
