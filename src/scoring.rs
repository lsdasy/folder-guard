//! Подсчёт баллов подозрительности для каждого процесса.
//!
//! Каждый процесс копит «сигналы» (см. [`Signal`]). Баллы сигналов за последнюю
//! минуту складываются — это и есть текущая подозрительность процесса.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use chrono::Local;

use crate::model::{FileOp, Pid, ProcessRow, Signal, TouchedFile};

/// Сколько времени сигнал влияет на балл.
pub const SCORE_WINDOW: Duration = Duration::from_secs(60);
/// Через сколько бездействия процесс исчезает из таблицы.
const IDLE_FORGET: Duration = Duration::from_secs(5 * 60);
const MAX_TOUCHED: usize = 20_000;

/// Ключ процесса. `None` — источник событий не знает PID (ограниченный режим).
pub type ProcKey = Option<Pid>;

#[derive(Debug)]
pub struct Track {
    pub name: String,
    pub exe: Option<PathBuf>,
    pub whitelisted: bool,
    ops: VecDeque<Instant>,
    signals: VecDeque<(Instant, Signal)>,
    entropy: VecDeque<f64>,
    touched: Vec<TouchedFile>,
    touched_index: HashMap<PathBuf, usize>,
    last_burst: Option<Instant>,
    last_activity: Instant,
}

impl Track {
    fn new(name: String, exe: Option<PathBuf>, whitelisted: bool, now: Instant) -> Self {
        Self {
            name,
            exe,
            whitelisted,
            ops: VecDeque::new(),
            signals: VecDeque::new(),
            entropy: VecDeque::new(),
            touched: Vec::new(),
            touched_index: HashMap::new(),
            last_burst: None,
            last_activity: now,
        }
    }

    pub fn signals(&self) -> impl Iterator<Item = &Signal> {
        self.signals.iter().map(|(_, s)| s)
    }

    pub fn touched(&self) -> &[TouchedFile] {
        &self.touched
    }

    fn touch(&mut self, path: &Path, op: &FileOp) {
        // Если это файл, в который мы уже переименовали ранее задетый — продолжаем цепочку.
        let idx = match self.touched_index.get(path) {
            Some(&i) => i,
            None => {
                if self.touched.len() >= MAX_TOUCHED {
                    return;
                }
                self.touched.push(TouchedFile {
                    original: path.to_path_buf(),
                    renamed_to: None,
                    modified: false,
                    deleted: false,
                    first_touch: Local::now(),
                });
                let i = self.touched.len() - 1;
                self.touched_index.insert(path.to_path_buf(), i);
                i
            }
        };
        let t = &mut self.touched[idx];
        match op {
            FileOp::Write | FileOp::Create => t.modified = true,
            FileOp::Delete => t.deleted = true,
            FileOp::Rename { to: Some(to) } => {
                t.renamed_to = Some(to.clone());
                self.touched_index.insert(to.clone(), idx);
            }
            FileOp::Rename { to: None } => {}
        }
    }
}

pub struct Scorer {
    tracks: HashMap<ProcKey, Track>,
    pub burst_files: u32,
    pub burst_window: Duration,
}

impl Scorer {
    pub fn new(burst_files: u32, burst_window: Duration) -> Self {
        Self {
            tracks: HashMap::new(),
            burst_files,
            burst_window,
        }
    }

    /// Регистрирует процесс (или обновляет его данные).
    pub fn ensure(
        &mut self,
        key: ProcKey,
        name: impl FnOnce() -> (String, Option<PathBuf>, bool),
        now: Instant,
    ) -> &mut Track {
        self.tracks.entry(key).or_insert_with(|| {
            let (n, exe, wl) = name();
            Track::new(n, exe, wl, now)
        })
    }

    pub fn get(&self, key: ProcKey) -> Option<&Track> {
        self.tracks.get(&key)
    }

    pub fn set_whitelisted(&mut self, key: ProcKey, value: bool) {
        if let Some(t) = self.tracks.get_mut(&key) {
            t.whitelisted = value;
        }
    }

    /// Учитывает файловую операцию. Возвращает сигнал «всплеск», если он только что сработал.
    pub fn record_op(
        &mut self,
        key: ProcKey,
        path: &Path,
        op: &FileOp,
        now: Instant,
    ) -> Option<Signal> {
        let window = self.burst_window;
        let limit = self.burst_files;
        let t = self.tracks.get_mut(&key)?;
        t.last_activity = now;
        t.touch(path, op);
        t.ops.push_back(now);
        while t
            .ops
            .front()
            .is_some_and(|&o| now.duration_since(o) > SCORE_WINDOW)
        {
            t.ops.pop_front();
        }
        let in_window = t
            .ops
            .iter()
            .rev()
            .take_while(|&&o| now.duration_since(o) <= window)
            .count() as u32;
        let cooled_down = t.last_burst.is_none_or(|b| now.duration_since(b) > window);
        if in_window >= limit && cooled_down {
            t.last_burst = Some(now);
            let s = Signal::Burst {
                files: in_window,
                window_secs: window.as_secs(),
            };
            t.signals.push_back((now, s.clone()));
            return Some(s);
        }
        None
    }

    pub fn record_entropy(&mut self, key: ProcKey, entropy: f64) {
        if let Some(t) = self.tracks.get_mut(&key) {
            t.entropy.push_back(entropy);
            if t.entropy.len() > 50 {
                t.entropy.pop_front();
            }
        }
    }

    pub fn add_signal(&mut self, key: ProcKey, signal: Signal, now: Instant) {
        if let Some(t) = self.tracks.get_mut(&key) {
            t.last_activity = now;
            t.signals.push_back((now, signal));
        }
    }

    pub fn score(&self, key: ProcKey, now: Instant) -> u32 {
        self.tracks.get(&key).map_or(0, |t| score_of(t, now))
    }

    /// Сбросить историю процесса (после решения пользователя «разрешить»).
    pub fn reset(&mut self, key: ProcKey) {
        if let Some(t) = self.tracks.get_mut(&key) {
            t.signals.clear();
            t.touched.clear();
            t.touched_index.clear();
            t.last_burst = None;
        }
    }

    pub fn remove(&mut self, key: ProcKey) {
        self.tracks.remove(&key);
    }

    /// Убирает давно бездействующие процессы и устаревшие сигналы.
    pub fn housekeeping(&mut self, now: Instant) {
        self.tracks
            .retain(|_, t| now.duration_since(t.last_activity) < IDLE_FORGET);
        for t in self.tracks.values_mut() {
            while t
                .signals
                .front()
                .is_some_and(|(at, _)| now.duration_since(*at) > SCORE_WINDOW)
            {
                t.signals.pop_front();
            }
            while t
                .ops
                .front()
                .is_some_and(|&o| now.duration_since(o) > SCORE_WINDOW)
            {
                t.ops.pop_front();
            }
        }
    }

    pub fn rows(&self, now: Instant) -> Vec<ProcessRow> {
        let mut rows: Vec<ProcessRow> = self
            .tracks
            .iter()
            .map(|(key, t)| ProcessRow {
                pid: *key,
                name: t.name.clone(),
                files_per_min: t
                    .ops
                    .iter()
                    .filter(|&&o| now.duration_since(o) <= SCORE_WINDOW)
                    .count() as u32,
                avg_entropy: (!t.entropy.is_empty())
                    .then(|| t.entropy.iter().sum::<f64>() / t.entropy.len() as f64),
                score: score_of(t, now),
                whitelisted: t.whitelisted,
            })
            .collect();
        rows.sort_by(|a, b| {
            b.score
                .cmp(&a.score)
                .then(b.files_per_min.cmp(&a.files_per_min))
        });
        rows
    }
}

fn score_of(t: &Track, now: Instant) -> u32 {
    t.signals
        .iter()
        .filter(|(at, _)| now.duration_since(*at) <= SCORE_WINDOW)
        .map(|(_, s)| s.points())
        .sum::<u32>()
        .min(999)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scorer() -> Scorer {
        Scorer::new(5, Duration::from_secs(10))
    }

    #[test]
    fn burst_fires_once_per_window() {
        let mut s = scorer();
        let now = Instant::now();
        s.ensure(Some(1), || ("x.exe".into(), None, false), now);
        let mut bursts = 0;
        for i in 0..12 {
            let p = PathBuf::from(format!("/d/f{i}.txt"));
            if s.record_op(
                Some(1),
                &p,
                &FileOp::Write,
                now + Duration::from_millis(i * 100),
            )
            .is_some()
            {
                bursts += 1;
            }
        }
        assert_eq!(bursts, 1);
        assert_eq!(s.score(Some(1), now + Duration::from_secs(2)), 30);
        // Через минуту балл обнуляется.
        assert_eq!(s.score(Some(1), now + Duration::from_secs(120)), 0);
    }

    #[test]
    fn canary_makes_critical_score() {
        let mut s = scorer();
        let now = Instant::now();
        s.ensure(Some(7), || ("setup.exe".into(), None, false), now);
        s.add_signal(
            Some(7),
            Signal::CanaryTouched {
                path: "/d/!000.docx".into(),
            },
            now,
        );
        assert!(s.score(Some(7), now) >= 100);
    }

    #[test]
    fn rename_chain_is_tracked() {
        let mut s = scorer();
        let now = Instant::now();
        s.ensure(Some(3), || ("a.exe".into(), None, false), now);
        let a = PathBuf::from("/d/report.docx");
        let b = PathBuf::from("/d/report.docx.locked");
        s.record_op(Some(3), &a, &FileOp::Write, now);
        s.record_op(
            Some(3),
            &a,
            &FileOp::Rename {
                to: Some(b.clone()),
            },
            now,
        );
        s.record_op(Some(3), &b, &FileOp::Write, now);
        let t = s.get(Some(3)).unwrap();
        assert_eq!(t.touched().len(), 1);
        assert_eq!(t.touched()[0].original, a);
        assert_eq!(t.touched()[0].renamed_to.as_ref(), Some(&b));
        assert!(t.touched()[0].modified);
    }

    #[test]
    fn rows_sorted_by_score() {
        let mut s = scorer();
        let now = Instant::now();
        s.ensure(Some(1), || ("calm.exe".into(), None, false), now);
        s.ensure(Some(2), || ("bad.exe".into(), None, false), now);
        s.add_signal(
            Some(2),
            Signal::BrokenHeader {
                path: "/d/a.png".into(),
            },
            now,
        );
        let rows = s.rows(now);
        assert_eq!(rows[0].name, "bad.exe");
        assert_eq!(rows[0].score, 15);
    }
}
