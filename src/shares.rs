//! Read-only shared folders. Every path a peer asks for is resolved and
//! canonicalized, then checked to still be inside the share's root, so a
//! peer can never read anything outside what you chose to share.

use crate::config::Shares;
use crate::proto::{DirEntry, FileMeta};
use crate::transfer::{sanitize_rel, walk_dir, LocalFile};
use anyhow::{bail, Context, Result};
use std::path::PathBuf;

pub struct Resolved {
    pub root: PathBuf,
    pub target: PathBuf,
}

pub fn resolve(shares: &Shares, path: &str) -> Result<Resolved> {
    let path = path.trim_matches('/');
    let (share, rest) = path.split_once('/').unwrap_or((path, ""));
    let root = shares
        .get(share)
        .with_context(|| format!("no share named {:?}", crate::text::display_safe(share, 64)))?;
    let root = root.canonicalize().context("shared folder is missing")?;
    let target = if rest.is_empty() { root.clone() } else { root.join(sanitize_rel(rest)?) };
    let target = target.canonicalize().context("no such file or folder")?;
    if !target.starts_with(&root) {
        bail!("path is outside the share");
    }
    if std::fs::symlink_metadata(&target)?.file_type().is_symlink() {
        bail!("links are not shared");
    }
    Ok(Resolved { root, target })
}

pub fn list(shares: &Shares, path: &str) -> Result<Vec<DirEntry>> {
    if path.trim_matches('/').is_empty() {
        return Ok(shares
            .keys()
            .map(|name| DirEntry { name: name.clone(), is_dir: true, size: 0 })
            .collect());
    }
    let r = resolve(shares, path)?;
    let md = std::fs::metadata(&r.target)?;
    if md.is_file() {
        let name = r.target.file_name().unwrap_or_default().to_string_lossy().into_owned();
        return Ok(vec![DirEntry { name, is_dir: false, size: md.len() }]);
    }
    let mut out = Vec::new();
    for e in std::fs::read_dir(&r.target)? {
        let e = e?;
        let ft = e.file_type()?;
        if ft.is_symlink() {
            continue;
        }
        let size = if ft.is_file() { e.metadata()?.len() } else { 0 };
        out.push(DirEntry { name: e.file_name().to_string_lossy().into_owned(), is_dir: ft.is_dir(), size });
    }
    out.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
    Ok(out)
}

/// Files to send for a Fetch of `path` (a file or a whole folder).
pub fn collect_for_fetch(shares: &Shares, path: &str) -> Result<Vec<LocalFile>> {
    let r = resolve(shares, path)?;
    let trimmed = path.trim_matches('/');
    // A whole share is sent under the share's name (what the requester asked
    // for), an item under its own on-disk name.
    let name = if !trimmed.contains('/') {
        trimmed.to_string()
    } else {
        r.target.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| trimmed.to_string())
    };
    let md = std::fs::metadata(&r.target)?;
    let mut files = Vec::new();
    if md.is_dir() {
        walk_dir(&r.target, &name, &mut files, Some(&r.root))?;
    } else {
        files.push(LocalFile {
            local: r.target.clone(),
            meta: FileMeta { path: name, size: md.len() },
            root: Some(r.root.clone()),
        });
    }
    // Belt and braces: every file must still canonicalize inside the share.
    for f in &files {
        if !f.local.canonicalize()?.starts_with(&r.root) {
            bail!("path is outside the share");
        }
        // A hard link could point at a file outside the share; skip the
        // ambiguity (Unix can tell; Windows hard links aren't detected).
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if std::fs::metadata(&f.local)?.nlink() > 1 {
                bail!("{} is a hard link; hard-linked files aren't shared", f.meta.path);
            }
        }
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cannot_escape_share() {
        let base = std::env::temp_dir().join(format!("fp-share-test-{}", std::process::id()));
        let shared = base.join("shared");
        std::fs::create_dir_all(shared.join("sub")).unwrap();
        std::fs::write(base.join("secret.txt"), "nope").unwrap();
        std::fs::write(shared.join("sub/ok.txt"), "yes").unwrap();
        let shares: Shares = [("pub".to_string(), shared.clone())].into();

        assert!(resolve(&shares, "pub/sub/ok.txt").is_ok());
        assert!(resolve(&shares, "pub/../secret.txt").is_err());
        assert!(resolve(&shares, "pub/sub/../../secret.txt").is_err());
        assert!(resolve(&shares, "other/x").is_err());
        assert_eq!(collect_for_fetch(&shares, "pub").unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&base);
    }
}
