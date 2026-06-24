//! Crash-safe persistence helpers for ce-mail.
//!
//! A mailbox rewrites its store as recipients deliver and drain. A naive `fs::write` truncates the
//! file before writing, so a crash or a full disk mid-write leaves a **truncated, corrupt** store —
//! losing every recipient's mail. [`atomic_write`] avoids that: it writes to a sibling temp file,
//! `fsync`s it, then `rename`s it over the target. `rename` within a directory is atomic on POSIX,
//! so a reader (or a restart) always sees either the old complete file or the new complete file,
//! never a half-written one. We also `fsync` the directory so the rename itself is durable.

use anyhow::{Context, Result};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

/// Write `bytes` to `path` atomically and durably (temp file + fsync + rename + dir fsync). The
/// temp file lives in the same directory as `path` so the rename never crosses a filesystem.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir).with_context(|| format!("create dir {}", dir.display()))?;

    // A unique-ish temp name in the same dir; the pid keeps concurrent mailbox processes apart.
    let file_name = path
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_else(|| "store".to_string());
    let tmp = dir.join(format!(".{file_name}.tmp.{}", std::process::id()));

    {
        let mut f = File::create(&tmp).with_context(|| format!("create temp {}", tmp.display()))?;
        f.write_all(bytes).with_context(|| format!("write temp {}", tmp.display()))?;
        f.flush().context("flush temp")?;
        // Durably flush the file contents before the rename.
        f.sync_all().with_context(|| format!("fsync temp {}", tmp.display()))?;
    }

    fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;

    // Best-effort: fsync the directory so the rename survives a power loss. Not all platforms allow
    // opening a directory as a File (e.g. Windows); a failure here is non-fatal — the rename already
    // happened and the contents were synced.
    if let Ok(dir_file) = File::open(dir) {
        let _ = dir_file.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("ce-mail-persist-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn atomic_write_creates_and_reads_back() {
        let dir = tmp_dir("create");
        let p = dir.join("store.bin");
        atomic_write(&p, b"hello world").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"hello world");
    }

    #[test]
    fn atomic_write_overwrites_without_leaving_temp() {
        let dir = tmp_dir("overwrite");
        let p = dir.join("store.bin");
        atomic_write(&p, b"v1").unwrap();
        atomic_write(&p, b"v2-longer").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"v2-longer");
        // No stray temp files remain.
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "temp file was not renamed away");
    }

    #[test]
    fn atomic_write_creates_missing_parent_dir() {
        let dir = tmp_dir("mkdir").join("nested").join("deep");
        let p = dir.join("s.bin");
        atomic_write(&p, b"x").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"x");
    }

    #[test]
    fn atomic_write_is_durable_across_many_writes() {
        // Simulate the serve loop: many sequential rewrites; the last one always wins intact.
        let dir = tmp_dir("many");
        let p = dir.join("s.bin");
        for i in 0..50u32 {
            atomic_write(&p, format!("write-{i}").as_bytes()).unwrap();
        }
        assert_eq!(fs::read(&p).unwrap(), b"write-49");
    }
}
