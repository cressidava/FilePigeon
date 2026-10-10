//! Streaming files of any size with resume and end-to-end integrity checks.
//!
//! Per file the sender streams `size - offset` raw bytes, then a `FileDone`
//! carrying the BLAKE3 hash of the *whole* file. The receiver writes into a
//! `.part` file, hashes the resumed prefix plus new bytes, and only moves the
//! file into place if the hash matches.

use crate::progress::Progress;
use crate::proto::{Complete, FileDone, FileMeta};
use crate::text::{display_safe, is_deceptive};
use crate::wire::{read_msg, write_msg};
use anyhow::{bail, Context, Result};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const CHUNK: usize = 1 << 20;
pub const PARTIAL_DIR: &str = ".filepigeon-partial";
pub const MAX_FILES: usize = 1_000_000;
/// No single file or offer may claim more than this (1 PiB): anything larger
/// is a lie meant to confuse the size shown in the approval prompt.
pub const MAX_TOTAL: u64 = 1 << 50;
/// Directory walks stop this deep (protects against pathological trees).
const MAX_DEPTH: usize = 64;

/// Names Windows treats as devices in every directory, whatever the extension.
const RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$", "COM0", "COM1", "COM2", "COM3", "COM4", "COM5",
    "COM6", "COM7", "COM8", "COM9", "COM¹", "COM²", "COM³", "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6",
    "LPT7", "LPT8", "LPT9", "LPT¹", "LPT²", "LPT³",
];

/// A local file paired with how it is described to the peer.
pub struct LocalFile {
    pub local: PathBuf,
    pub meta: FileMeta,
    /// For files served from a share: the share root they must stay inside.
    pub root: Option<PathBuf>,
}

/// Turn a peer-supplied relative path into a safe relative `PathBuf`.
/// Rejects anything that could escape the destination folder, misbehave on
/// Windows, or display as something it isn't.
pub fn sanitize_rel(path: &str) -> Result<PathBuf> {
    let shown = || display_safe(path, 80);
    if path.is_empty() || path.len() > 4096 {
        bail!("invalid path {:?}", shown());
    }
    let mut out = PathBuf::new();
    for (i, comp) in path.split('/').enumerate() {
        let bad_char = comp
            .chars()
            .any(|c| is_deceptive(c) || matches!(c, '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|'))
            || crate::text::has_dangling_joiner(comp);
        // "NAME~1" is how Windows abbreviates long names (8.3 aliases); such a
        // component could reach a folder under a different name.
        let short_alias = comp
            .char_indices()
            .any(|(i, c)| c == '~' && comp[i + 1..].starts_with(|d: char| d.is_ascii_digit()));
        // Windows ignores trailing dots/spaces before the extension, so "NUL .txt" is NUL.
        let stem = comp.split('.').next().unwrap_or("").trim_end_matches([' ', '.']).to_uppercase();
        if comp.is_empty()
            || comp == "."
            || comp == ".."
            || bad_char
            || short_alias
            || comp.ends_with('.')
            || comp.ends_with(' ')
            || comp.len() > 255
            || RESERVED.contains(&stem.as_str())
            || (i == 0 && comp.eq_ignore_ascii_case(PARTIAL_DIR))
        {
            bail!("unsafe path {:?}", shown());
        }
        out.push(comp);
    }
    Ok(out)
}

/// Validate a list of files offered by a peer before accepting anything.
/// Returns the total size (overflow-checked and capped).
pub fn validate_metas(metas: &[FileMeta]) -> Result<u64> {
    if metas.len() > MAX_FILES {
        bail!("too many files");
    }
    let mut seen = HashSet::new();
    let mut total: u64 = 0;
    for m in metas {
        sanitize_rel(&m.path)?;
        if !seen.insert(m.path.to_lowercase()) {
            bail!("duplicate path {:?}", display_safe(&m.path, 80));
        }
        total = total
            .checked_add(m.size)
            .filter(|t| *t <= MAX_TOTAL && m.size <= MAX_TOTAL)
            .context("declared size is impossibly large")?;
    }
    Ok(total)
}

/// Expand the paths given on the command line into a flat file list.
/// Directories are walked recursively; symlinks inside them are skipped.
pub fn collect_for_send(paths: &[PathBuf]) -> Result<Vec<LocalFile>> {
    let mut out = Vec::new();
    for p in paths {
        let p = p.canonicalize().with_context(|| format!("cannot open {}", p.display()))?;
        let name = p
            .file_name()
            .context("cannot send a drive root; pick a folder")?
            .to_string_lossy()
            .into_owned();
        let md = std::fs::metadata(&p)?;
        if md.is_dir() {
            walk_dir(&p, &name, &mut out, None)?;
        } else {
            out.push(LocalFile { local: p, meta: FileMeta { path: name, size: md.len() }, root: None });
        }
    }
    let metas: Vec<_> = out.iter().map(|f| f.meta.clone()).collect();
    validate_metas(&metas)?;
    Ok(out)
}

pub fn walk_dir(dir: &Path, prefix: &str, out: &mut Vec<LocalFile>, root: Option<&Path>) -> Result<()> {
    walk(dir, prefix, out, root, 0)
}

fn walk(dir: &Path, prefix: &str, out: &mut Vec<LocalFile>, root: Option<&Path>, depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        bail!("folder is nested too deeply");
    }
    let mut entries = std::fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        if out.len() >= MAX_FILES {
            bail!("too many files");
        }
        // DirEntry::file_type does not follow links (junctions count as links on Windows).
        let ft = e.file_type()?;
        if ft.is_symlink() {
            continue;
        }
        let rel = format!("{prefix}/{}", e.file_name().to_string_lossy());
        if ft.is_dir() {
            walk(&e.path(), &rel, out, root, depth + 1)?;
        } else if ft.is_file() {
            out.push(LocalFile {
                local: e.path(),
                meta: FileMeta { path: rel, size: e.metadata()?.len() },
                root: root.map(Path::to_path_buf),
            });
        }
    }
    Ok(())
}

/// Sum of sizes for display; never overflows (offers are validated separately).
pub fn total_size(metas: &[FileMeta]) -> u64 {
    metas.iter().fold(0u64, |t, m| t.saturating_add(m.size))
}

/// Partial files are keyed by peer + destination + path + size, so a resume
/// can only ever continue the same file from the same peer (and the final hash
/// check catches anything else).
pub fn partial_path(dest: &Path, peer_id: &str, meta: &FileMeta) -> PathBuf {
    let h = blake3::hash(format!("{peer_id}\n{}\n{}\n{}", dest.display(), meta.path, meta.size).as_bytes());
    dest.join(PARTIAL_DIR).join(format!("{}.part", &h.to_hex()[..32]))
}

pub fn resume_offsets(dest: &Path, peer_id: &str, metas: &[FileMeta]) -> Vec<u64> {
    metas
        .iter()
        .map(|m| {
            // Only an ordinary file counts; anything else is ignored.
            std::fs::symlink_metadata(partial_path(dest, peer_id, m))
                .ok()
                .filter(|md| md.file_type().is_file())
                .map(|md| md.len())
                .filter(|&len| len <= m.size)
                .unwrap_or(0)
        })
        .collect()
}

/// Delete partial files nobody has resumed for `max_age`. Returns how many.
pub fn cleanup_stale_partials(dest: &Path, max_age: Duration) -> usize {
    let Ok(entries) = std::fs::read_dir(dest.join(PARTIAL_DIR)) else { return 0 };
    let mut removed = 0;
    for e in entries.flatten() {
        let old = e
            .metadata()
            .ok()
            .and_then(|md| md.modified().ok())
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age > max_age);
        let gone = old
            && match e.file_type() {
                Ok(t) if t.is_dir() => std::fs::remove_dir_all(e.path()).is_ok(),
                _ => std::fs::remove_file(e.path()).is_ok(),
            };
        if gone {
            removed += 1;
        }
    }
    let _ = std::fs::remove_dir(dest.join(PARTIAL_DIR));
    removed
}

/// Partial files currently being written, so two transfers never share one.
static ACTIVE_PARTIALS: LazyLock<Mutex<HashSet<PathBuf>>> = LazyLock::new(Default::default);

struct PartialClaim(PathBuf);

impl PartialClaim {
    fn take(path: &Path) -> Option<Self> {
        ACTIVE_PARTIALS.lock().unwrap().insert(path.to_path_buf()).then(|| Self(path.to_path_buf()))
    }
}

/// The partial files of one incoming transfer, reserved for it until dropped.
/// Taken before accepting, so a second copy of a transfer that is already
/// arriving gets a clear "already receiving" answer instead of a broken stream.
pub struct PartialClaims(#[allow(dead_code)] Vec<PartialClaim>);

/// Reserve every partial file for this transfer; None if any is in use.
pub fn claim_partials(dest: &Path, peer_id: &str, metas: &[FileMeta]) -> Option<PartialClaims> {
    metas.iter().map(|m| PartialClaim::take(&partial_path(dest, peer_id, m))).collect::<Option<Vec<_>>>().map(PartialClaims)
}

impl Drop for PartialClaim {
    fn drop(&mut self) {
        ACTIVE_PARTIALS.lock().unwrap().remove(&self.0);
    }
}

fn chunk_len(left: u64) -> usize {
    left.min(CHUNK as u64) as usize
}

/// For share files: refuse if the path was swapped for a link, or now points
/// outside the share, since it was listed (checked right before reading).
fn recheck_containment(f: &LocalFile) -> Result<()> {
    let Some(root) = &f.root else { return Ok(()) };
    let link = std::fs::symlink_metadata(&f.local).map(|m| m.file_type().is_symlink()).unwrap_or(true);
    let inside = f.local.canonicalize().map(|c| c.starts_with(root)).unwrap_or(false);
    if link || !inside {
        bail!("a shared file changed while waiting for approval; refusing to send it");
    }
    Ok(())
}

pub async fn send_files(
    send: &mut quinn::SendStream,
    files: &[LocalFile],
    offsets: &[u64],
    progress: &Progress,
) -> Result<()> {
    if offsets.len() != files.len() {
        bail!("peer sent the wrong number of resume offsets");
    }
    let mut buf = vec![0u8; CHUNK];
    for (i, (f, &offset)) in files.iter().zip(offsets).enumerate() {
        progress.set_file(i + 1, files.len(), &f.meta.path);
        recheck_containment(f)?;
        let offset = offset.min(f.meta.size);
        let mut file = tokio::fs::File::open(&f.local)
            .await
            .with_context(|| format!("cannot open {}", f.local.display()))?;
        let mut hasher = blake3::Hasher::new();

        // Hash the part the receiver already has (read locally, not sent).
        let mut left = offset;
        while left > 0 {
            let n = file.read(&mut buf[..chunk_len(left)]).await?;
            if n == 0 {
                bail!("{} changed during transfer", f.local.display());
            }
            hasher.update(&buf[..n]);
            left -= n as u64;
        }
        progress.skip(offset);

        let mut left = f.meta.size - offset;
        while left > 0 {
            let n = file.read(&mut buf[..chunk_len(left)]).await?;
            if n == 0 {
                bail!("{} changed during transfer", f.local.display());
            }
            if progress.is_cancelled() {
                bail!("cancelled");
            }
            send.write_all(&buf[..n]).await?;
            hasher.update(&buf[..n]);
            progress.add(n as u64);
            left -= n as u64;
        }
        write_msg(send, &FileDone { blake3: hasher.finalize().to_hex().to_string() }).await?;
    }
    Ok(())
}

pub async fn recv_files(
    recv: &mut quinn::RecvStream,
    dest: &Path,
    peer_id: &str,
    metas: &[FileMeta],
    offsets: &[u64],
    progress: &Progress,
    _claims: &PartialClaims,
) -> Result<Complete> {
    tokio::fs::create_dir_all(dest.join(PARTIAL_DIR)).await?;
    let mut buf = vec![0u8; CHUNK];
    let mut received = 0;
    let mut failed = Vec::new();

    for (i, (meta, &offset)) in metas.iter().zip(offsets).enumerate() {
        progress.set_file(i + 1, metas.len(), &meta.path);
        let rel = sanitize_rel(&meta.path)?;
        let part = partial_path(dest, peer_id, meta);
        // Never resume from (or write through) anything but an ordinary file
        // that still holds at least the bytes we told the sender we have.
        match std::fs::symlink_metadata(&part) {
            Ok(md) if !md.file_type().is_file() => bail!("unexpected item in the partial-files folder"),
            Ok(md) if md.len() >= offset => {}
            _ if offset > 0 => bail!("the unfinished download changed; send it again to start over"),
            _ => {}
        }
        let mut hasher = blake3::Hasher::new();
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&part)
            .await?;
        file.set_len(offset).await?;

        let mut left = offset;
        while left > 0 {
            let n = file.read(&mut buf[..chunk_len(left)]).await?;
            if n == 0 {
                bail!("partial file shrank unexpectedly");
            }
            hasher.update(&buf[..n]);
            left -= n as u64;
        }
        progress.skip(offset);

        let mut left = meta.size - offset;
        while left > 0 {
            let n = recv
                .read(&mut buf[..chunk_len(left)])
                .await?
                .context("sender stopped mid-file (progress kept; run it again to resume)")?;
            hasher.update(&buf[..n]);
            file.write_all(&buf[..n]).await?;
            if progress.is_cancelled() {
                bail!("cancelled");
            }
            progress.add(n as u64);
            left -= n as u64;
        }
        file.flush().await?;
        drop(file);

        let done: FileDone = read_msg(recv).await?;
        if done.blake3 == hasher.finalize().to_hex().as_str() {
            let final_path = finalize(&part, &dest.join(&rel)).await?;
            mark_downloaded(&final_path);
            received += 1;
        } else {
            let _ = tokio::fs::remove_file(&part).await;
            failed.push(display_safe(&meta.path, 200));
        }
    }
    // Only succeeds if nothing is left to resume.
    let _ = std::fs::remove_dir(dest.join(PARTIAL_DIR));
    Ok(Complete { received, failed })
}

/// Move a verified partial into place without ever replacing an existing file:
/// `photo.jpg` -> `photo (1).jpg` -> ... The name is reserved atomically with
/// `create_new`, so two transfers can't both pick it, and we then rename over
/// our own empty placeholder.
async fn finalize(part: &Path, wanted: &Path) -> Result<PathBuf> {
    if let Some(parent) = wanted.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let stem = wanted.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let ext = wanted.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default();
    for i in 0..10_000u32 {
        let candidate = if i == 0 { wanted.to_path_buf() } else { wanted.with_file_name(format!("{stem} ({i}){ext}")) };
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&candidate) {
            Ok(placeholder) => {
                drop(placeholder);
                if let Err(e) = tokio::fs::rename(part, &candidate).await {
                    let _ = std::fs::remove_file(&candidate);
                    return Err(e.into());
                }
                return Ok(candidate);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e).with_context(|| format!("cannot create {}", candidate.display())),
        }
    }
    bail!("could not find a free file name for {}", wanted.display())
}

/// Tag received files as "from the internet" (Mark of the Web), so Windows
/// SmartScreen and Office Protected View treat them like browser downloads.
fn mark_downloaded(path: &Path) {
    #[cfg(windows)]
    {
        let ads = format!("{}:Zone.Identifier", path.display());
        let _ = std::fs::write(ads, "[ZoneTransfer]\r\nZoneId=3\r\n");
    }
    #[cfg(not(windows))]
    let _ = path;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_traversal_and_windows_tricks() {
        for bad in [
            "", "..", "../x", "a/../b", "/abs", "a//b", "C:/x", "c:", "a\\b", "CON", "nul.txt", "aux/x",
            "dots.", "space ", "a/./b", "x\u{0}y", "COM¹", "lpt0.log", "NUL .txt", "conin$", "x/CLOCK$",
            "invoice\u{202E}fdp.exe", "a\u{200B}b", "a\u{2215}b", ".filepigeon-partial/x.part",
            ".FILEPIGEON-PARTIAL/y", "FILEPI~1/x.part", "a/PROGRA~2/b", "\u{200D}lead",
        ] {
            assert!(sanitize_rel(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn accepts_normal_paths() {
        for ok in [
            "file.txt", "folder/sub/photo (1).jpg", ".hidden", "con-tract.pdf", "über/日本.txt", "COM10",
            "sub/.filepigeon-partial", "\u{0645}\u{06CC}\u{200C}\u{062E}\u{0648}\u{0627}\u{0647}\u{0645}.txt",
            "family \u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}.jpg", "~$draft.docx", "a~b",
        ] {
            assert!(sanitize_rel(ok).is_ok(), "{ok:?} should be accepted");
        }
    }

    #[test]
    fn duplicate_paths_rejected() {
        let m = |p: &str| FileMeta { path: p.into(), size: 1 };
        assert!(validate_metas(&[m("a.txt"), m("A.TXT")]).is_err());
    }

    #[test]
    fn sizes_cannot_wrap_or_lie() {
        let m = |p: &str, size| FileMeta { path: p.into(), size };
        assert!(validate_metas(&[m("a", u64::MAX), m("b", 2)]).is_err(), "overflow must be rejected");
        assert!(validate_metas(&[m("a", MAX_TOTAL), m("b", 1)]).is_err(), "over the cap");
        assert_eq!(validate_metas(&[m("a", 5), m("b", 7)]).unwrap(), 12);
    }

    #[test]
    fn errors_do_not_echo_huge_paths() {
        let long = format!("{}\u{e000}", "x/".repeat(3000));
        let msg = sanitize_rel(&long).unwrap_err().to_string();
        assert!(msg.len() < 300, "error message was {} bytes", msg.len());
    }

    #[tokio::test]
    async fn finalize_never_overwrites() {
        let dir = std::env::temp_dir().join(format!("fp-finalize-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("photo.jpg"), b"original").unwrap();
        for content in [b"one".as_slice(), b"two".as_slice()] {
            let part = dir.join("p.part");
            std::fs::write(&part, content).unwrap();
            finalize(&part, &dir.join("photo.jpg")).await.unwrap();
        }
        assert_eq!(std::fs::read(dir.join("photo.jpg")).unwrap(), b"original");
        assert_eq!(std::fs::read(dir.join("photo (1).jpg")).unwrap(), b"one");
        assert_eq!(std::fs::read(dir.join("photo (2).jpg")).unwrap(), b"two");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
