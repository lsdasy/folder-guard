//! Журнал событий и инцидентов в SQLite.

use std::path::Path;

use anyhow::Result;
use chrono::{DateTime, Local};
use rusqlite::{Connection, OptionalExtension, params};

use crate::model::{Incident, Level, LogEntry};

pub struct Journal {
    conn: Connection,
}

fn level_str(l: Level) -> &'static str {
    match l {
        Level::Info => "info",
        Level::Ok => "ok",
        Level::Warning => "warning",
        Level::Threat => "threat",
    }
}

fn level_from(s: &str) -> Level {
    match s {
        "ok" => Level::Ok,
        "warning" => Level::Warning,
        "threat" => Level::Threat,
        _ => Level::Info,
    }
}

impl Journal {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        Self::init(Connection::open(path)?)
    }

    #[cfg(test)]
    pub fn in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             CREATE TABLE IF NOT EXISTS events (
                 id INTEGER PRIMARY KEY,
                 ts TEXT NOT NULL,
                 level TEXT NOT NULL,
                 process TEXT,
                 message TEXT NOT NULL,
                 incident_id INTEGER
             );
             CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
             CREATE TABLE IF NOT EXISTS incidents (
                 id INTEGER PRIMARY KEY,
                 ts TEXT NOT NULL,
                 data TEXT NOT NULL
             );",
        )?;
        Ok(Self { conn })
    }

    pub fn log(&self, e: &LogEntry) -> Result<()> {
        self.conn.execute(
            "INSERT INTO events (ts, level, process, message, incident_id) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![e.time.to_rfc3339(), level_str(e.level), e.process, e.message, e.incident_id],
        )?;
        Ok(())
    }

    pub fn recent(&self, limit: usize) -> Result<Vec<LogEntry>> {
        let mut st = self.conn.prepare(
            "SELECT ts, level, process, message, incident_id FROM events ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = st.query_map(params![limit as i64], |r| {
            let ts: String = r.get(0)?;
            let level: String = r.get(1)?;
            Ok(LogEntry {
                time: DateTime::parse_from_rfc3339(&ts)
                    .map(|t| t.with_timezone(&Local))
                    .unwrap_or_else(|_| Local::now()),
                level: level_from(&level),
                process: r.get(2)?,
                message: r.get(3)?,
                incident_id: r.get(4)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    /// Новый номер инцидента.
    pub fn next_incident_id(&self) -> Result<i64> {
        let max: Option<i64> = self
            .conn
            .query_row("SELECT MAX(id) FROM incidents", [], |r| r.get(0))
            .optional()?
            .flatten();
        Ok(max.unwrap_or(0) + 1)
    }

    pub fn save_incident(&self, inc: &Incident) -> Result<()> {
        self.conn.execute(
            "INSERT INTO incidents (id, ts, data) VALUES (?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET data = excluded.data",
            params![
                inc.id,
                inc.started.to_rfc3339(),
                serde_json::to_string(inc)?
            ],
        )?;
        Ok(())
    }

    pub fn incidents(&self, limit: usize) -> Result<Vec<Incident>> {
        let mut st = self
            .conn
            .prepare("SELECT data FROM incidents ORDER BY id DESC LIMIT ?1")?;
        let rows = st.query_map(params![limit as i64], |r| r.get::<_, String>(0))?;
        Ok(rows
            .filter_map(|r| r.ok())
            .filter_map(|s| serde_json::from_str(&s).ok())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    #[test]
    fn log_and_read_back() {
        let j = Journal::in_memory().unwrap();
        for i in 0..5 {
            j.log(&LogEntry {
                time: Local::now(),
                level: Level::Info,
                process: Some("a.exe".into()),
                message: format!("m{i}"),
                incident_id: None,
            })
            .unwrap();
        }
        let r = j.recent(3).unwrap();
        assert_eq!(r.len(), 3);
        assert_eq!(r[0].message, "m4");
    }

    #[test]
    fn incidents_upsert() {
        let j = Journal::in_memory().unwrap();
        let mut inc = Incident {
            id: j.next_incident_id().unwrap(),
            pid: Some(10),
            process_name: "setup.exe".into(),
            exe_path: None,
            signed: Some(false),
            severity: Severity::Critical,
            state: IncidentState::AwaitingDecision,
            score: 120,
            reasons: vec!["тест".into()],
            files: vec![],
            started: Local::now(),
            deadline: None,
            restored_files: 0,
        };
        j.save_incident(&inc).unwrap();
        inc.state = IncidentState::Killed;
        j.save_incident(&inc).unwrap();
        let all = j.incidents(10).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].state, IncidentState::Killed);
        assert_eq!(j.next_incident_id().unwrap(), 2);
    }
}
