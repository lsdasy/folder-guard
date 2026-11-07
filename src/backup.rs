//! Теневые резервные копии защищённых файлов.
//!
//! Раз в N минут программа проходит по защищённым папкам и копирует изменившиеся
//! файлы в своё хранилище (несколько последних версий каждого файла).
//! После атаки файлы восстанавливаются из версии, сделанной до начала инцидента.
//!
//! Файлы, которые уже выглядят зашифрованными, в копии не попадают —
//! чтобы испорченная версия не вытеснила хорошие.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::UNIX_EPOCH;

use anyhow::{Context, Result};
use chrono::{DateTime, Local};
use rusqlite::{Connection, OptionalExtension, params};

use crate::analysis;
use crate::canary;

pub struct BackupStore {
    root: PathBuf,
    conn: Connection,
}

#[derive(Debug, Default, Clone)]
pub struct SnapshotReport {
    pub scanned: u64,
    pub copied: u64,
    pub skipped_suspicious: u64,
    pub errors: u64,
}

#[derive(Debug, Clone)]
pub struct Version {
    pub id: i64,
    pub path: PathBuf,
}

pub struct SnapshotParams<'a> {
    pub folders: &'a [PathBuf],
    pub is_excluded: &'a dyn Fn(&Path) -> bool,
    pub max_file_bytes: u64,
    pub keep_versions: u32,
}

fn mtime_of(meta: &std::fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs() as i64)
}

impl BackupStore {
    pub fn open(root: &Path) -> Result<Self> {
        std::fs::create_dir_all(root.join("blobs"))
            .with_context(|| format!("папка копий {}", root.display()))?;
        let conn = Connection::open(root.join("index.db"))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             CREATE TABLE IF NOT EXISTS versions (
                 id INTEGER PRIMARY KEY,
                 path TEXT NOT NULL,
                 mtime INTEGER NOT NULL,
                 size INTEGER NOT NULL,
                 taken INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS versions_path ON versions(path);",
        )?;
        Ok(Self {
            root: root.to_path_buf(),
            conn,
        })
    }

    fn blob(&self, id: i64) -> PathBuf {
        self.root.join("blobs").join(format!("{id}.bak"))
    }

    pub fn snapshot(&mut self, p: &SnapshotParams, stop: &AtomicBool) -> Result<SnapshotReport> {
        let mut report = SnapshotReport::default();
        let root = self.root.clone();
        for folder in p.folders {
            let walker = walkdir::WalkDir::new(folder)
                .follow_links(false)
                .into_iter()
                .filter_entry(|e| {
                    // Не заходим в исключённые папки и в само хранилище копий.
                    !(e.file_type().is_dir()
                        && ((p.is_excluded)(e.path()) || e.path().starts_with(&root)))
                });
            for entry in walker {
                if stop.load(Ordering::Relaxed) {
                    return Ok(report);
                }
                let Ok(entry) = entry else {
                    report.errors += 1;
                    continue;
                };
                if !entry.file_type().is_file() || canary::is_canary_name(entry.path()) {
                    continue;
                }
                report.scanned += 1;
                match self.backup_file(entry.path(), p) {
                    Ok(Outcome::Copied) => report.copied += 1,
                    Ok(Outcome::Suspicious) => report.skipped_suspicious += 1,
                    Ok(Outcome::Unchanged) => {}
                    Err(e) => {
                        log::debug!("копия {}: {e:#}", entry.path().display());
                        report.errors += 1;
                    }
                }
            }
        }
        Ok(report)
    }

    fn backup_file(&mut self, path: &Path, p: &SnapshotParams) -> Result<Outcome> {
        let meta = std::fs::metadata(path)?;
        if meta.len() > p.max_file_bytes {
            return Ok(Outcome::Unchanged);
        }
        let mtime = mtime_of(&meta);
        let key = path.to_string_lossy().into_owned();
        let last: Option<(i64, i64)> = self
            .conn
            .query_row(
                "SELECT mtime, size FROM versions WHERE path = ?1 ORDER BY id DESC LIMIT 1",
                params![key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if last == Some((mtime, meta.len() as i64)) {
            return Ok(Outcome::Unchanged);
        }
        let report = analysis::analyze_file(path)?;
        if report.header_broken || report.unexpected_high_entropy {
            return Ok(Outcome::Suspicious);
        }
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO versions (path, mtime, size, taken) VALUES (?1, ?2, ?3, ?4)",
            params![key, mtime, meta.len() as i64, Local::now().timestamp()],
        )?;
        let id = tx.last_insert_rowid();
        let blob = self.root.join("blobs").join(format!("{id}.bak"));
        std::fs::copy(path, &blob)?;
        tx.commit()?;
        self.prune(&key, p.keep_versions)?;
        Ok(Outcome::Copied)
    }

    fn prune(&mut self, key: &str, keep: u32) -> Result<()> {
        let mut st = self.conn.prepare(
            "SELECT id FROM versions WHERE path = ?1 ORDER BY id DESC LIMIT -1 OFFSET ?2",
        )?;
        let old: Vec<i64> = st
            .query_map(params![key, keep.max(1) as i64], |r| r.get(0))?
            .filter_map(|r| r.ok())
            .collect();
        drop(st);
        for id in old {
            let _ = std::fs::remove_file(self.blob(id));
            self.conn
                .execute("DELETE FROM versions WHERE id = ?1", params![id])?;
        }
        Ok(())
    }

    /// Последняя версия файла, изменённого строго раньше `before`.
    pub fn version_before(&self, path: &Path, before: DateTime<Local>) -> Result<Option<Version>> {
        let key = path.to_string_lossy().into_owned();
        Ok(self
            .conn
            .query_row(
                "SELECT id FROM versions WHERE path = ?1 AND mtime < ?2 ORDER BY mtime DESC, id DESC LIMIT 1",
                params![key, before.timestamp()],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            .map(|id| Version { id, path: path.to_path_buf() }))
    }

    /// Восстанавливает версию по исходному пути.
    pub fn restore(&self, v: &Version) -> Result<()> {
        if let Some(parent) = v.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = v.path.with_extension("fg-restore.tmp");
        std::fs::copy(self.blob(v.id), &tmp)?;
        std::fs::rename(&tmp, &v.path)?;
        Ok(())
    }

    pub fn stats(&self) -> Result<(u64, u64)> {
        let (files, bytes): (i64, Option<i64>) = self.conn.query_row(
            "SELECT COUNT(DISTINCT path), SUM(size) FROM versions",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok((files as u64, bytes.unwrap_or(0) as u64))
    }
}

enum Outcome {
    Copied,
    Unchanged,
    Suspicious,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_restore_cycle() {
        let base = std::env::temp_dir().join(format!("fg-backup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let docs = base.join("docs");
        std::fs::create_dir_all(docs.join("target")).unwrap();
        let file = docs.join("курсовая.txt");
        std::fs::write(&file, "Глава 1. Введение. ".repeat(100)).unwrap();
        std::fs::write(docs.join("target").join("junk.bin"), b"skip me").unwrap();

        let mut store = BackupStore::open(&base.join("store")).unwrap();
        let folders = vec![docs.clone()];
        let excl = |p: &Path| p.file_name().is_some_and(|n| n == "target");
        let params = SnapshotParams {
            folders: &folders,
            is_excluded: &excl,
            max_file_bytes: 1 << 20,
            keep_versions: 2,
        };
        let stop = AtomicBool::new(false);
        let r = store.snapshot(&params, &stop).unwrap();
        assert_eq!(r.copied, 1, "исключённая папка не копируется");
        assert_eq!(
            store.snapshot(&params, &stop).unwrap().copied,
            0,
            "без изменений — без копий"
        );

        // «Шифруем» файл: случайные байты. Такую версию не сохраняем.
        let mut junk = vec![0u8; 4096];
        rand::fill(&mut junk[..]);
        std::fs::write(&file, &junk).unwrap();
        let r = store.snapshot(&params, &stop).unwrap();
        assert_eq!((r.copied, r.skipped_suspicious), (0, 1));

        let v = store
            .version_before(&file, Local::now() + chrono::Duration::seconds(5))
            .unwrap()
            .unwrap();
        store.restore(&v).unwrap();
        assert!(
            std::fs::read_to_string(&file)
                .unwrap()
                .starts_with("Глава 1")
        );
        assert_eq!(store.stats().unwrap().0, 1);
        let _ = std::fs::remove_dir_all(base);
    }
}
