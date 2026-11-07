//! Движок: получает события от источников, считает подозрительность,
//! открывает инциденты, замораживает/завершает процессы, восстанавливает файлы.
//!
//! Работает в отдельном потоке и не зависит от интерфейса: интерфейс только
//! читает [`UiState`] и шлёт [`Command`].

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::Result;
use chrono::{DateTime, Local};
use crossbeam_channel::{Receiver, Sender, select, unbounded};
use parking_lot::RwLock;

use crate::analysis;
use crate::backup::{BackupStore, SnapshotParams, SnapshotReport};
use crate::canary;
use crate::config::{AppDirs, Config, WhitelistEntry, path_starts_with};
use crate::journal::Journal;
use crate::model::*;
use crate::monitor::Monitors;
use crate::platform::{self, ToastAction, ToastRequest};
use crate::scoring::{ProcKey, Scorer};

const TICK: Duration = Duration::from_millis(500);
const CANARY_CHECK_EVERY: Duration = Duration::from_secs(60);
/// Сколько ждём парное событие (ETW-переименование ↔ новое имя от наблюдателя).
const PAIRING_WINDOW: Duration = Duration::from_millis(1500);
/// Через сколько после события наблюдателя о приманке считаем, что ETW его не увидел.
const CANARY_GRACE: Duration = Duration::from_millis(1500);
/// Сколько после собственной записи (приманки, восстановление) не реагируем на этот файл.
const OWN_WRITE_WINDOW: Duration = Duration::from_millis(1500);
const BACKUP_FIRST_DELAY: Duration = Duration::from_secs(20);
const UNKNOWN_PROCESS: &str = "Неизвестный процесс";
const SHADOW_TOOLS: [&str; 6] = [
    "vssadmin.exe",
    "wmic.exe",
    "wbadmin.exe",
    "bcdedit.exe",
    "powershell.exe",
    "pwsh.exe",
];

pub type RepaintHook = Arc<RwLock<Option<Box<dyn Fn() + Send + Sync>>>>;

/// То, что получает интерфейс.
#[derive(Clone)]
pub struct EngineHandle {
    pub state: Arc<RwLock<UiState>>,
    pub config: Arc<RwLock<Config>>,
    pub commands: Sender<Command>,
    pub notices: Receiver<Notice>,
    pub repaint: RepaintHook,
    pub dirs: AppDirs,
}

impl EngineHandle {
    pub fn send(&self, c: Command) {
        let _ = self.commands.send(c);
    }
}

pub fn spawn(cfg: Config, dirs: AppDirs) -> Result<(EngineHandle, JoinHandle<()>)> {
    let journal = Journal::open(&dirs.journal_db)?;
    let state = Arc::new(RwLock::new(UiState::default()));
    let config = Arc::new(RwLock::new(cfg.clone()));
    let (cmd_tx, cmd_rx) = unbounded();
    let (notice_tx, notice_rx) = unbounded();
    let repaint: RepaintHook = Arc::new(RwLock::new(None));
    let handle = EngineHandle {
        state: state.clone(),
        config: config.clone(),
        commands: cmd_tx.clone(),
        notices: notice_rx,
        repaint: repaint.clone(),
        dirs: dirs.clone(),
    };
    let mut engine = Engine::new(
        cfg, dirs, journal, state, config, cmd_tx, cmd_rx, notice_tx, repaint,
    );
    let thread = std::thread::Builder::new()
        .name("engine".into())
        .spawn(move || engine.run())?;
    Ok((handle, thread))
}

struct ProcInfo {
    name: String,
    exe: Option<PathBuf>,
    seen: Instant,
}

struct OpenIncident {
    id: i64,
    opened: Instant,
}

struct BackupJob {
    thread: JoinHandle<Result<SnapshotReport>>,
    stop: Arc<AtomicBool>,
}

pub struct Engine {
    cfg: Config,
    dirs: AppDirs,
    journal: Journal,
    shared: Arc<RwLock<UiState>>,
    shared_cfg: Arc<RwLock<Config>>,
    cmd_tx: Sender<Command>,
    cmd_rx: Receiver<Command>,
    notice_tx: Sender<Notice>,
    repaint: RepaintHook,

    raw_tx: Sender<RawEvent>,
    raw_rx: Receiver<RawEvent>,
    monitors: Option<Monitors>,
    full_mode: bool,

    scorer: Scorer,
    procs: HashMap<Pid, ProcInfo>,
    incidents: Vec<Incident>,
    open: HashMap<ProcKey, OpenIncident>,

    /// ETW сообщил о переименовании без нового имени: ждём событие от наблюдателя.
    etw_renames: HashMap<PathBuf, (Pid, Instant)>,
    /// Наблюдатель сообщил новое имя: ждём, кто это сделал, от ETW.
    watch_renames: HashMap<PathBuf, (PathBuf, Instant)>,
    /// События наблюдателя о приманках — проверяем, увидел ли их ETW.
    canary_watch: Vec<(PathBuf, FileOp, Instant)>,
    canary_seen_by_etw: HashMap<PathBuf, Instant>,
    /// Файлы, которые меняем мы сами (приманки, восстановление).
    own_writes: HashMap<PathBuf, Instant>,
    note_dirs: HashMap<ProcKey, HashSet<PathBuf>>,
    whitelist_warned: HashMap<String, Instant>,

    paused_until: Option<(Instant, DateTime<Local>)>,
    last_canary_check: Option<Instant>,
    last_backup: Option<Instant>,
    started: Instant,
    backup: Option<BackupJob>,
    events_today: u64,
    today: chrono::NaiveDate,
}

impl Engine {
    #[allow(clippy::too_many_arguments)]
    fn new(
        cfg: Config,
        dirs: AppDirs,
        journal: Journal,
        shared: Arc<RwLock<UiState>>,
        shared_cfg: Arc<RwLock<Config>>,
        cmd_tx: Sender<Command>,
        cmd_rx: Receiver<Command>,
        notice_tx: Sender<Notice>,
        repaint: RepaintHook,
    ) -> Self {
        let (raw_tx, raw_rx) = unbounded();
        let scorer = Scorer::new(cfg.burst_files, Duration::from_secs(cfg.burst_window_secs));
        Self {
            cfg,
            dirs,
            journal,
            shared,
            shared_cfg,
            cmd_tx,
            cmd_rx,
            notice_tx,
            repaint,
            raw_tx,
            raw_rx,
            monitors: None,
            full_mode: false,
            scorer,
            procs: HashMap::new(),
            incidents: Vec::new(),
            open: HashMap::new(),
            etw_renames: HashMap::new(),
            watch_renames: HashMap::new(),
            canary_watch: Vec::new(),
            canary_seen_by_etw: HashMap::new(),
            own_writes: HashMap::new(),
            note_dirs: HashMap::new(),
            whitelist_warned: HashMap::new(),
            paused_until: None,
            last_canary_check: None,
            last_backup: None,
            started: Instant::now(),
            backup: None,
            events_today: 0,
            today: Local::now().date_naive(),
        }
    }

    // ------------------------------------------------------------------ цикл

    fn run(&mut self) {
        self.startup();
        let mut last_tick = Instant::now();
        loop {
            select! {
                recv(self.raw_rx) -> ev => if let Ok(ev) = ev { self.on_raw(ev) },
                recv(self.cmd_rx) -> cmd => match cmd {
                    Ok(Command::Shutdown) | Err(_) => break,
                    Ok(c) => self.on_command(c),
                },
                default(TICK) => {}
            }
            if last_tick.elapsed() >= TICK {
                last_tick = Instant::now();
                self.tick();
            }
        }
        if let Some(job) = self.backup.take() {
            job.stop.store(true, Ordering::Relaxed);
        }
        self.log(Level::Info, None, "Защита остановлена".into(), None);
    }

    fn startup(&mut self) {
        // История из журнала — чтобы после перезапуска интерфейс не был пустым.
        if let Ok(entries) = self.journal.recent(UiState::LOG_LIMIT) {
            let mut st = self.shared.write();
            st.log = entries.into_iter().collect();
        }
        if let Ok(list) = self.journal.incidents(200) {
            self.incidents = list;
            // Незавершённые инциденты прошлого запуска закрываем: процесса уже нет.
            for inc in &mut self.incidents {
                if inc.state == IncidentState::AwaitingDecision {
                    inc.state = IncidentState::Exited;
                    let _ = self.journal.save_incident(inc);
                }
            }
        }
        {
            let mut st = self.shared.write();
            st.is_admin = platform::is_admin();
            st.threats_stopped = self
                .incidents
                .iter()
                .filter(|i| i.state == IncidentState::Killed)
                .count() as u64;
        }
        if let Ok((files, bytes)) =
            BackupStore::open(&self.dirs.backup_dir(&self.cfg)).and_then(|s| s.stats())
        {
            let mut st = self.shared.write();
            st.backup.files = files;
            st.backup.bytes = bytes;
        }
        platform::register_toast_app();
        self.restart_monitors();
        self.check_canaries(true);
        self.publish();
    }

    fn restart_monitors(&mut self) {
        self.monitors = None;
        let folders: Vec<PathBuf> = self
            .cfg
            .protected_folders
            .iter()
            .filter(|f| f.exists())
            .cloned()
            .collect();
        let m = Monitors::start(&folders, self.raw_tx.clone(), platform::is_admin());
        self.full_mode = m.mode == MonitorMode::Full;
        let msg = match m.mode {
            MonitorMode::Full => format!(
                "Защита запущена: папок — {}, полный режим (ETW)",
                folders.len()
            ),
            _ => format!(
                "Защита запущена: папок — {}, ограниченный режим",
                folders.len()
            ),
        };
        {
            let mut st = self.shared.write();
            st.mode = m.mode;
            st.mode_note = m.note.clone();
            st.protected_count = folders.len();
        }
        self.log(
            if self.full_mode {
                Level::Ok
            } else {
                Level::Warning
            },
            None,
            msg,
            None,
        );
        self.monitors = Some(m);
    }

    fn tick(&mut self) {
        let now = Instant::now();
        if Local::now().date_naive() != self.today {
            self.today = Local::now().date_naive();
            self.events_today = 0;
        }
        if let Some((until, _)) = self.paused_until
            && now >= until
        {
            self.paused_until = None;
            self.log(Level::Info, None, "Защита возобновлена".into(), None);
        }
        self.flush_pairings(now);
        self.flush_canary_watch(now);
        self.scorer.housekeeping(now);
        self.own_writes
            .retain(|_, t| now.duration_since(*t) < OWN_WRITE_WINDOW);
        self.procs
            .retain(|_, p| now.duration_since(p.seen) < Duration::from_secs(600));
        self.refresh_open_incidents(now);
        self.enforce_deadlines();

        if self
            .last_canary_check
            .is_none_or(|t| now.duration_since(t) >= CANARY_CHECK_EVERY)
        {
            self.check_canaries(false);
        }
        self.manage_backup(now);
        self.publish_processes(now);
    }

    // ------------------------------------------------------------ события

    fn on_raw(&mut self, ev: RawEvent) {
        if self.paused_until.is_some() {
            return;
        }
        match ev {
            RawEvent::File {
                pid,
                path,
                op,
                at,
                source,
            } => self.on_file(pid, path, op, at, source),
            RawEvent::ProcessStart {
                pid,
                parent,
                image,
                at,
            } => self.on_process_start(pid, parent, &image, at),
        }
    }

    fn is_own_path(&self, path: &Path) -> bool {
        path_starts_with(path, &self.dirs.data_dir)
            || path_starts_with(path, &self.dirs.backup_dir(&self.cfg))
    }

    fn on_file(
        &mut self,
        pid: Option<Pid>,
        path: PathBuf,
        op: FileOp,
        at: Instant,
        source: EventSource,
    ) {
        if pid == Some(std::process::id())
            || self.is_own_path(&path)
            || !self.cfg.is_protected(&path)
        {
            return;
        }
        let is_canary = canary::is_canary_name(&path);
        if self.cfg.is_excluded(&path) && !is_canary {
            return;
        }
        if source == EventSource::Watcher
            && self
                .own_writes
                .get(&path)
                .is_some_and(|t| at.saturating_duration_since(*t) < OWN_WRITE_WINDOW)
        {
            return;
        }

        // В полном режиме наблюдатель нужен только для имён при переименовании и как подстраховка для приманок.
        if self.full_mode && source == EventSource::Watcher {
            if is_canary && op != FileOp::Create {
                self.canary_watch.push((path.clone(), op.clone(), at));
            }
            if let FileOp::Rename { to: Some(to) } = op {
                match self.etw_renames.remove(&path) {
                    Some((etw_pid, _)) => {
                        self.process_file(Some(etw_pid), path, FileOp::Rename { to: Some(to) }, at)
                    }
                    None => {
                        self.watch_renames.insert(path, (to, at));
                    }
                }
            }
            return;
        }
        if source == EventSource::Etw {
            if is_canary {
                self.canary_seen_by_etw.insert(path.clone(), at);
            }
            if let (FileOp::Rename { to: None }, Some(p)) = (&op, pid) {
                match self.watch_renames.remove(&path) {
                    Some((to, _)) => {
                        self.process_file(pid, path, FileOp::Rename { to: Some(to) }, at)
                    }
                    None => {
                        self.etw_renames.insert(path, (p, at));
                    }
                }
                return;
            }
        }
        // Приманки создаём мы сами: в ограниченном режиме PID неизвестен, поэтому создание не считаем.
        if is_canary && op == FileOp::Create && pid.is_none() {
            return;
        }
        self.process_file(pid, path, op, at);
    }

    /// Переименования, для которых пара не пришла: обрабатываем без нового имени.
    fn flush_pairings(&mut self, now: Instant) {
        let expired: Vec<(PathBuf, Pid, Instant)> = self
            .etw_renames
            .iter()
            .filter(|(_, (_, t))| now.duration_since(*t) > PAIRING_WINDOW)
            .map(|(p, (pid, t))| (p.clone(), *pid, *t))
            .collect();
        for (path, pid, at) in expired {
            self.etw_renames.remove(&path);
            self.process_file(Some(pid), path, FileOp::Rename { to: None }, at);
        }
        self.watch_renames
            .retain(|_, (_, t)| now.duration_since(*t) <= PAIRING_WINDOW * 2);
    }

    /// Приманку изменили, а ETW этого не увидел (например, запись через отображение в память).
    fn flush_canary_watch(&mut self, now: Instant) {
        let (due, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut self.canary_watch)
            .into_iter()
            .partition(|(_, _, t)| now.duration_since(*t) > CANARY_GRACE);
        self.canary_watch = rest;
        for (path, op, at) in due {
            let seen = self.canary_seen_by_etw.get(&path).is_some_and(|t| {
                t.duration_since(at) < Duration::from_secs(5)
                    || at.duration_since(*t) < Duration::from_secs(5)
            });
            if !seen {
                self.process_file(None, path, op, at);
            }
        }
        self.canary_seen_by_etw
            .retain(|_, t| now.duration_since(*t) < Duration::from_secs(30));
    }

    fn proc_identity(&mut self, key: ProcKey) -> (String, Option<PathBuf>, bool) {
        let (name, exe) = match key {
            Some(pid) => {
                let info = self.procs.entry(pid).or_insert_with(|| {
                    let (name, exe) = platform::process_info(pid);
                    ProcInfo {
                        name,
                        exe,
                        seen: Instant::now(),
                    }
                });
                info.seen = Instant::now();
                (info.name.clone(), info.exe.clone())
            }
            None => (UNKNOWN_PROCESS.to_string(), None),
        };
        let wl = key.is_some() && self.cfg.is_whitelisted(&name, exe.as_deref());
        (name, exe, wl)
    }

    /// Главная обработка файловой операции процесса.
    fn process_file(&mut self, key: ProcKey, path: PathBuf, op: FileOp, at: Instant) {
        self.events_today += 1;
        let ident = self.proc_identity(key);
        self.scorer.ensure(key, || ident, at);
        let mut signals = Vec::new();

        if canary::is_canary_name(&path) && !matches!(op, FileOp::Create) {
            signals.push(Signal::CanaryTouched { path: path.clone() });
        }
        if let Some(burst) = self.scorer.record_op(key, &path, &op, at) {
            // Сигнал уже добавлен в трекер — только для журнала.
            log::debug!("всплеск: {}", burst.describe());
        }

        match &op {
            FileOp::Write | FileOp::Create => {
                if let Ok(r) = analysis::analyze_file(&path) {
                    if r.size > 0 {
                        self.scorer.record_entropy(key, r.entropy);
                    }
                    if r.unexpected_high_entropy {
                        signals.push(Signal::UnexpectedHighEntropy {
                            path: path.clone(),
                            entropy: r.entropy,
                        });
                    }
                    if r.header_broken && r.size >= 16 {
                        signals.push(Signal::BrokenHeader { path: path.clone() });
                    }
                }
                if op == FileOp::Create && analysis::looks_like_ransom_note(&path) {
                    let dirs = self.note_dirs.entry(key).or_default();
                    if let Some(d) = path.parent() {
                        dirs.insert(d.to_path_buf());
                    }
                    // Одна записка — ещё не повод; одинаковые записки в разных папках — повод.
                    if dirs.len() >= 2 {
                        signals.push(Signal::RansomNote { path: path.clone() });
                    }
                }
            }
            FileOp::Rename { to: Some(to) } => {
                if analysis::is_suspicious_rename(&path, to) {
                    signals.push(Signal::SuspiciousRename {
                        from: path.clone(),
                        to: to.clone(),
                    });
                }
                // Содержимое оцениваем по исходному расширению: «docx» без сигнатуры zip — испорчен.
                if let Ok(data) = read_sample(to) {
                    let r = analysis::analyze_bytes(&path, &data, data.len() as u64);
                    if r.header_broken && data.len() >= 16 {
                        signals.push(Signal::BrokenHeader { path: to.clone() });
                    }
                }
            }
            _ => {}
        }
        for s in signals {
            self.scorer.add_signal(key, s, at);
        }
        self.evaluate(key, at);
    }

    fn on_process_start(&mut self, pid: Pid, parent: Pid, image: &str, at: Instant) {
        let exe_name = image
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(image)
            .to_lowercase();
        if !SHADOW_TOOLS.contains(&exe_name.as_str()) {
            return;
        }
        let Some(cmd) = platform::process_cmdline(pid) else {
            return;
        };
        if !is_shadow_deletion(&cmd) {
            return;
        }
        if !self.cfg.learning_mode {
            let _ = platform::kill(pid);
        }
        let key = Some(parent);
        let ident = self.proc_identity(key);
        self.scorer.ensure(key, || ident, at);
        self.scorer.add_signal(
            key,
            Signal::ShadowCopyDeletion {
                command: cmd.clone(),
            },
            at,
        );
        self.log(
            Level::Threat,
            Some(exe_name),
            format!("Попытка удалить теневые копии остановлена: {cmd}"),
            None,
        );
        self.evaluate(key, at);
    }

    // ---------------------------------------------------------- инциденты

    fn evaluate(&mut self, key: ProcKey, now: Instant) {
        let score = self.scorer.score(key, now);
        let Some(track) = self.scorer.get(key) else {
            return;
        };
        let critical_signal = track.signals().any(Signal::is_critical);
        let whitelisted = track.whitelisted;
        let name = track.name.clone();

        if let Some(open) = self.open.get(&key) {
            // Инцидент уже открыт — обновляем его; при необходимости повышаем до критического.
            let id = open.id;
            let reasons = reasons_of(track.signals());
            let escalate = critical_signal || score >= self.cfg.critical_score;
            let mut escalated = false;
            if let Some(inc) = self.incidents.iter_mut().find(|i| i.id == id) {
                inc.score = inc.score.max(score);
                let extra: Vec<String> = inc
                    .reasons
                    .iter()
                    .filter(|r| {
                        r.starts_with("не удалось")
                            || r.contains("режим")
                            || r.contains("системный")
                            || r.contains("не определён")
                    })
                    .cloned()
                    .collect();
                inc.reasons = reasons;
                inc.reasons.extend(extra);
                if escalate && inc.severity == Severity::Suspicious {
                    inc.severity = Severity::Critical;
                    escalated = true;
                }
            }
            if escalated {
                let _ = self.notice_tx.send(Notice::IncidentOpened {
                    id,
                    severity: Severity::Critical,
                });
                self.publish();
            }
            return;
        }

        if score < self.cfg.suspend_score && !critical_signal {
            if whitelisted && score >= self.cfg.suspend_score / 2 {
                self.warn_whitelisted(&name, score);
            }
            return;
        }
        if whitelisted && !critical_signal {
            self.warn_whitelisted(&name, score);
            return;
        }
        self.open_incident(key, score, critical_signal, now);
    }

    fn warn_whitelisted(&mut self, name: &str, score: u32) {
        let due = self
            .whitelist_warned
            .get(name)
            .is_none_or(|t| t.elapsed() > Duration::from_secs(300));
        if due {
            self.whitelist_warned
                .insert(name.to_string(), Instant::now());
            self.log(
                Level::Warning,
                Some(name.to_string()),
                format!("{name} — высокая активность (балл {score}), процесс в белом списке"),
                None,
            );
        }
    }

    fn open_incident(&mut self, key: ProcKey, score: u32, critical_signal: bool, now: Instant) {
        let track = self.scorer.get(key).expect("трек существует");
        let name = track.name.clone();
        let exe = track.exe.clone();
        let whitelisted = track.whitelisted;
        let reasons = reasons_of(track.signals());
        let files = track.touched().to_vec();
        let severity = if critical_signal || score >= self.cfg.critical_score {
            Severity::Critical
        } else {
            Severity::Suspicious
        };
        let signed = exe.as_deref().and_then(platform::is_signed);
        let id = self
            .journal
            .next_incident_id()
            .unwrap_or_else(|_| self.incidents.iter().map(|i| i.id).max().unwrap_or(0) + 1);

        let mut state = IncidentState::DetectedOnly;
        let mut deadline = None;
        let mut extra_reason = None;
        match key {
            Some(pid)
                if !self.cfg.learning_mode
                    && !whitelisted
                    && !platform::is_critical_process(&name) =>
            {
                match platform::suspend(pid) {
                    Ok(()) => {
                        state = IncidentState::AwaitingDecision;
                        deadline = Some(
                            Local::now()
                                + chrono::Duration::seconds(self.cfg.auto_kill_secs as i64),
                        );
                    }
                    Err(e) => extra_reason = Some(format!("не удалось заморозить процесс: {e:#}")),
                }
            }
            Some(_) if self.cfg.learning_mode => {
                extra_reason = Some("режим обучения: процесс не остановлен".into())
            }
            Some(_) if platform::is_critical_process(&name) => {
                extra_reason = Some("системный процесс — заморозка небезопасна".into())
            }
            Some(_) => {}
            None => extra_reason = Some("процесс не определён (ограниченный режим)".into()),
        }

        let mut inc = Incident {
            id,
            pid: key,
            process_name: name.clone(),
            exe_path: exe,
            signed,
            severity,
            state,
            score,
            reasons,
            files,
            started: Local::now(),
            deadline,
            restored_files: 0,
        };
        if let Some(r) = extra_reason {
            inc.reasons.push(r);
        }
        let _ = self.journal.save_incident(&inc);
        let action = match state {
            IncidentState::AwaitingDecision => "процесс заморожен",
            _ => "процесс не остановлен",
        };
        let msg = format!(
            "{} — {}: {}",
            name,
            inc.reasons.first().cloned().unwrap_or_default(),
            action
        );
        self.log(Level::Threat, Some(name.clone()), msg, Some(id));
        self.show_toast(&inc);
        self.incidents.insert(0, inc);
        self.open.insert(key, OpenIncident { id, opened: now });
        let _ = self.notice_tx.send(Notice::IncidentOpened { id, severity });
        self.publish();
    }

    fn show_toast(&self, inc: &Incident) {
        if !self.cfg.notifications {
            return;
        }
        let awaiting = inc.state == IncidentState::AwaitingDecision;
        let title = match inc.severity {
            Severity::Critical => "Похоже на шифровальщик",
            Severity::Suspicious => "Подозрительная активность",
        };
        let body = format!(
            "{} изменил {} за короткое время.{}",
            inc.process_name,
            inc.files_summary(),
            if awaiting {
                " Процесс заморожен."
            } else {
                ""
            }
        );
        let footer = awaiting.then(|| {
            format!(
                "Будет завершён автоматически через {} с",
                self.cfg.auto_kill_secs
            )
        });
        let id = inc.id;
        let cmd = self.cmd_tx.clone();
        let notices = self.notice_tx.clone();
        let repaint = self.repaint.clone();
        platform::show_toast(
            ToastRequest {
                title: title.into(),
                body,
                footer,
                with_buttons: awaiting,
                compat_app_id: self.cfg.notifications_compat,
            },
            Box::new(move |action| {
                match action {
                    Some(ToastAction::Kill) => {
                        let _ = cmd.send(Command::Kill {
                            incident: id,
                            restore: false,
                        });
                    }
                    Some(ToastAction::Allow) => {
                        let _ = cmd.send(Command::Allow {
                            incident: id,
                            add_to_whitelist: false,
                        });
                    }
                    Some(ToastAction::Details) | None => {
                        let _ = notices.send(Notice::IncidentOpened {
                            id,
                            severity: Severity::Critical,
                        });
                    }
                }
                if let Some(f) = repaint.read().as_ref() {
                    f();
                }
            }),
        );
    }

    /// Обновляем список файлов открытых инцидентов (раз в тик, а не на каждое событие).
    fn refresh_open_incidents(&mut self, now: Instant) {
        let mut changed = false;
        let mut to_close = Vec::new();
        for (key, open) in &self.open {
            let Some(inc) = self.incidents.iter_mut().find(|i| i.id == open.id) else {
                continue;
            };
            if let Some(track) = self.scorer.get(*key)
                && track.touched().len() != inc.files.len()
            {
                inc.files = track.touched().to_vec();
                let _ = self.journal.save_incident(inc);
                changed = true;
            }
            // Инцидент без заморозки «закрывается» через минуту, чтобы следующая волна открыла новый.
            if inc.state != IncidentState::AwaitingDecision
                && now.duration_since(open.opened) > Duration::from_secs(60)
            {
                to_close.push(*key);
            }
            if inc.state == IncidentState::AwaitingDecision
                && let Some(pid) = inc.pid
                && !platform::process_alive(pid)
            {
                inc.state = IncidentState::Exited;
                inc.deadline = None;
                to_close.push(*key);
                changed = true;
            }
        }
        for key in to_close {
            if let Some(o) = self.open.remove(&key) {
                if let Some(inc) = self.incidents.iter().find(|i| i.id == o.id) {
                    let _ = self.journal.save_incident(inc);
                }
                self.scorer.reset(key);
                let _ = self.notice_tx.send(Notice::IncidentClosed { id: o.id });
            }
        }
        if changed {
            self.publish();
        }
    }

    fn enforce_deadlines(&mut self) {
        let now = Local::now();
        let due: Vec<i64> = self
            .incidents
            .iter()
            .filter(|i| {
                i.state == IncidentState::AwaitingDecision && i.deadline.is_some_and(|d| d <= now)
            })
            .map(|i| i.id)
            .collect();
        for id in due {
            self.log(
                Level::Info,
                None,
                "Нет ответа пользователя — процесс завершается автоматически".into(),
                Some(id),
            );
            self.kill_incident(id, false);
        }
    }

    fn incident_key(&self, id: i64) -> Option<ProcKey> {
        self.open.iter().find(|(_, o)| o.id == id).map(|(k, _)| *k)
    }

    fn kill_incident(&mut self, id: i64, restore: bool) {
        let Some(idx) = self.incidents.iter().position(|i| i.id == id) else {
            return;
        };
        let (pid, name) = (
            self.incidents[idx].pid,
            self.incidents[idx].process_name.clone(),
        );
        let result = match pid {
            Some(pid) => platform::kill(pid),
            None => Err(anyhow::anyhow!("процесс не определён")),
        };
        match result {
            Ok(()) => {
                self.incidents[idx].state = IncidentState::Killed;
                self.incidents[idx].deadline = None;
                self.shared.write().threats_stopped += 1;
                self.log(
                    Level::Ok,
                    Some(name.clone()),
                    format!("{name} завершён"),
                    Some(id),
                );
            }
            Err(e) => self.log(
                Level::Warning,
                Some(name.clone()),
                format!("Не удалось завершить {name}: {e:#}"),
                Some(id),
            ),
        }
        if let Some(key) = self.incident_key(id) {
            self.open.remove(&key);
            self.scorer.remove(key);
        }
        let _ = self.journal.save_incident(&self.incidents[idx]);
        let _ = self.notice_tx.send(Notice::IncidentClosed { id });
        if restore {
            self.restore_incident(id);
        }
        self.check_canaries(true);
        self.publish();
    }

    fn allow_incident(&mut self, id: i64, add_to_whitelist: bool) {
        let Some(idx) = self.incidents.iter().position(|i| i.id == id) else {
            return;
        };
        let inc = &mut self.incidents[idx];
        let name = inc.process_name.clone();
        let exe = inc.exe_path.clone();
        if let (Some(pid), IncidentState::AwaitingDecision) = (inc.pid, inc.state)
            && let Err(e) = platform::resume(pid)
        {
            log::warn!("не удалось разморозить {pid}: {e:#}");
        }
        inc.state = IncidentState::Allowed;
        inc.deadline = None;
        let _ = self.journal.save_incident(inc);
        if let Some(key) = self.incident_key(id) {
            self.open.remove(&key);
            self.scorer.reset(key);
            // До конца сеанса процесс не тревожит повторно.
            self.scorer.set_whitelisted(key, true);
        }
        if add_to_whitelist && key_is_known(&name) {
            self.cfg.whitelist.push(WhitelistEntry {
                name: name.clone(),
                path: exe,
            });
            let _ = self.cfg.save(&self.dirs.config_file);
            *self.shared_cfg.write() = self.cfg.clone();
            self.log(
                Level::Info,
                Some(name.clone()),
                format!("{name} добавлен в белый список"),
                Some(id),
            );
        } else {
            self.log(
                Level::Info,
                Some(name.clone()),
                format!("{name} разрешён пользователем"),
                Some(id),
            );
        }
        let _ = self.notice_tx.send(Notice::IncidentClosed { id });
        self.check_canaries(true);
        self.publish();
    }

    /// Возвращает файлы из резервных копий, а зашифрованные версии убирает в карантин.
    fn restore_incident(&mut self, id: i64) {
        let Some(idx) = self.incidents.iter().position(|i| i.id == id) else {
            return;
        };
        let inc = self.incidents[idx].clone();
        let before = inc
            .files
            .iter()
            .map(|f| f.first_touch)
            .min()
            .unwrap_or(inc.started)
            .min(inc.started);
        let store = match BackupStore::open(&self.dirs.backup_dir(&self.cfg)) {
            Ok(s) => s,
            Err(e) => {
                self.log(
                    Level::Warning,
                    None,
                    format!("Хранилище копий недоступно: {e:#}"),
                    Some(id),
                );
                return;
            }
        };
        let quarantine = self.dirs.quarantine_dir.join(format!("incident-{id}"));
        let mut restored = 0u32;
        let mut missing = 0u32;
        for f in &inc.files {
            if canary::is_canary_name(&f.original) {
                continue; // приманки чинит check_canaries
            }
            if let Some(renamed) = &f.renamed_to
                && renamed.exists()
            {
                let _ = move_to_quarantine(renamed, &quarantine);
            }
            match store.version_before(&f.original, before) {
                Ok(Some(v)) => {
                    if f.original.exists() && f.modified {
                        let _ = move_to_quarantine(&f.original, &quarantine);
                    }
                    self.own_writes.insert(f.original.clone(), Instant::now());
                    match store.restore(&v) {
                        Ok(()) => restored += 1,
                        Err(e) => log::warn!("восстановление {}: {e:#}", f.original.display()),
                    }
                }
                _ => missing += 1,
            }
        }
        self.incidents[idx].restored_files += restored;
        let _ = self.journal.save_incident(&self.incidents[idx]);
        let mut msg = format!(
            "{restored} {} восстановлено из резервной копии",
            plural(restored as u64, "файл", "файла", "файлов")
        );
        if missing > 0 {
            msg += &format!(", для {missing} копии не нашлось");
        }
        self.log(
            if restored > 0 {
                Level::Ok
            } else {
                Level::Warning
            },
            None,
            msg,
            Some(id),
        );
        self.publish();
    }

    // ------------------------------------------------------------ команды

    fn on_command(&mut self, c: Command) {
        match c {
            Command::Kill { incident, restore } => self.kill_incident(incident, restore),
            Command::Allow {
                incident,
                add_to_whitelist,
            } => self.allow_incident(incident, add_to_whitelist),
            Command::Restore { incident } => self.restore_incident(incident),
            Command::PauseFor(d) => {
                let until = Local::now() + chrono::Duration::from_std(d).unwrap_or_default();
                self.paused_until = Some((Instant::now() + d, until));
                self.log(
                    Level::Warning,
                    None,
                    format!("Защита приостановлена до {}", until.format("%H:%M")),
                    None,
                );
            }
            Command::Resume => {
                self.paused_until = None;
                self.log(Level::Info, None, "Защита возобновлена".into(), None);
            }
            Command::ApplyConfig(cfg) => self.apply_config(*cfg),
            Command::BackupNow => {
                self.last_backup = None;
                self.start_backup();
            }
            Command::VerifyCanaries => self.check_canaries(true),
            Command::Shutdown => {}
        }
        self.publish();
    }

    fn apply_config(&mut self, cfg: Config) {
        let folders_changed = cfg.protected_folders != self.cfg.protected_folders;
        for old in &self.cfg.protected_folders {
            if !cfg.protected_folders.contains(old) {
                canary::remove_from(old);
            }
        }
        if !cfg.canaries_enabled && self.cfg.canaries_enabled {
            for f in &self.cfg.protected_folders {
                canary::remove_from(f);
            }
        }
        self.scorer.burst_files = cfg.burst_files;
        self.scorer.burst_window = Duration::from_secs(cfg.burst_window_secs);
        self.cfg = cfg;
        if let Err(e) = self.cfg.save(&self.dirs.config_file) {
            self.log(
                Level::Warning,
                None,
                format!("Настройки не сохранены: {e:#}"),
                None,
            );
        }
        *self.shared_cfg.write() = self.cfg.clone();
        if folders_changed {
            self.restart_monitors();
        }
        self.check_canaries(true);
        self.log(Level::Info, None, "Настройки применены".into(), None);
    }

    // ------------------------------------------------------------ приманки

    fn check_canaries(&mut self, repair: bool) {
        self.last_canary_check = Some(Instant::now());
        let folders: Vec<PathBuf> = self
            .cfg
            .protected_folders
            .iter()
            .filter(|f| f.exists())
            .cloned()
            .collect();
        if !self.cfg.canaries_enabled {
            let mut st = self.shared.write();
            st.canaries_total = 0;
            st.canaries_ok = 0;
            return;
        }
        // Пока процесс заморожен, приманки не трогаем — это улики.
        let busy = self
            .incidents
            .iter()
            .any(|i| i.state == IncidentState::AwaitingDecision);
        let mut report = canary::verify(&folders);
        if repair && !busy && !report.problems.is_empty() {
            for p in &report.problems {
                let path = match p {
                    canary::CanaryProblem::Missing(p) | canary::CanaryProblem::Modified(p) => p,
                };
                self.own_writes.insert(path.clone(), Instant::now());
                let _ = canary::repair(path, self.cfg.canaries_hidden);
            }
            report = canary::verify(&folders);
        } else if !busy {
            for p in canary::canary_paths(&folders) {
                if !p.exists() {
                    self.own_writes.insert(p, Instant::now());
                }
            }
            let _ = canary::ensure(&folders, self.cfg.canaries_hidden);
            report = canary::verify(&folders);
        }
        {
            let mut st = self.shared.write();
            st.canaries_total = report.total;
            st.canaries_ok = report.ok;
        }
        if repair {
            let level = if report.ok == report.total {
                Level::Ok
            } else {
                Level::Warning
            };
            self.log(
                level,
                None,
                format!(
                    "Приманки проверены: {} из {} на месте",
                    report.ok, report.total
                ),
                None,
            );
        }
    }

    // ------------------------------------------------------------ копии

    fn manage_backup(&mut self, now: Instant) {
        if let Some(job) = &self.backup {
            if job.thread.is_finished() {
                let job = self.backup.take().unwrap();
                let result = job
                    .thread
                    .join()
                    .unwrap_or_else(|_| Err(anyhow::anyhow!("поток копирования упал")));
                self.on_backup_done(result);
            }
            return;
        }
        if !self.cfg.backup.enabled || self.paused_until.is_some() {
            return;
        }
        let interval = Duration::from_secs(self.cfg.backup.interval_minutes.max(1) * 60);
        let due = match self.last_backup {
            None => now.duration_since(self.started) >= BACKUP_FIRST_DELAY,
            Some(t) => now.duration_since(t) >= interval,
        };
        let busy = self
            .incidents
            .iter()
            .any(|i| i.state == IncidentState::AwaitingDecision);
        if due && !busy {
            self.start_backup();
        }
    }

    fn start_backup(&mut self) {
        if self.backup.is_some() {
            return;
        }
        self.last_backup = Some(Instant::now());
        let folders: Vec<PathBuf> = self.cfg.protected_folders.clone();
        let excluded = self.cfg.excluded_dir_names.clone();
        let dir = self.dirs.backup_dir(&self.cfg);
        let max = self.cfg.backup.max_file_mb * 1024 * 1024;
        let keep = self.cfg.backup.keep_versions;
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        self.shared.write().backup.running = true;
        self.request_repaint();
        let thread = std::thread::spawn(move || {
            let mut store = BackupStore::open(&dir)?;
            let is_excluded = move |p: &Path| {
                p.file_name()
                    .map(|n| n.to_string_lossy())
                    .is_some_and(|n| excluded.iter().any(|e| e.eq_ignore_ascii_case(&n)))
            };
            store.snapshot(
                &SnapshotParams {
                    folders: &folders,
                    is_excluded: &is_excluded,
                    max_file_bytes: max,
                    keep_versions: keep,
                },
                &stop2,
            )
        });
        self.backup = Some(BackupJob { thread, stop });
    }

    fn on_backup_done(&mut self, result: Result<SnapshotReport>) {
        let stats = BackupStore::open(&self.dirs.backup_dir(&self.cfg))
            .and_then(|s| s.stats())
            .unwrap_or((0, 0));
        {
            let mut st = self.shared.write();
            st.backup.running = false;
            st.backup.last_run = Some(Local::now());
            st.backup.files = stats.0;
            st.backup.bytes = stats.1;
            st.backup.last_error = result.as_ref().err().map(|e| format!("{e:#}"));
        }
        match result {
            // Ничего не изменилось — не засоряем журнал.
            Ok(r) if r.copied == 0 && r.skipped_suspicious == 0 => {}
            Ok(r) => {
                let mut msg = format!(
                    "Резервная копия обновлена: новых версий — {}, всего файлов — {}",
                    r.copied, stats.0
                );
                if r.skipped_suspicious > 0 {
                    msg += &format!(
                        " (пропущено похожих на зашифрованные: {})",
                        r.skipped_suspicious
                    );
                }
                let level = if r.skipped_suspicious > 0 {
                    Level::Warning
                } else {
                    Level::Ok
                };
                self.log(level, None, msg, None);
            }
            Err(e) => self.log(
                Level::Warning,
                None,
                format!("Резервное копирование не удалось: {e:#}"),
                None,
            ),
        }
    }

    // ------------------------------------------------------------ публикация

    fn log(
        &self,
        level: Level,
        process: Option<String>,
        message: String,
        incident_id: Option<i64>,
    ) {
        log::info!("{message}");
        let e = LogEntry {
            time: Local::now(),
            level,
            process,
            message,
            incident_id,
        };
        let _ = self.journal.log(&e);
        self.shared.write().push_log(e);
        self.request_repaint();
    }

    fn publish(&self) {
        {
            let mut st = self.shared.write();
            st.incidents = self.incidents.clone();
            st.paused_until = self.paused_until.map(|(_, t)| t);
            st.learning_mode = self.cfg.learning_mode;
            st.events_today = self.events_today;
        }
        self.request_repaint();
    }

    fn publish_processes(&self, now: Instant) {
        let rows = self.scorer.rows(now);
        let mut st = self.shared.write();
        st.processes = rows;
        st.events_today = self.events_today;
        st.paused_until = self.paused_until.map(|(_, t)| t);
        drop(st);
        self.request_repaint();
    }

    fn request_repaint(&self) {
        if let Some(f) = self.repaint.read().as_ref() {
            f();
        }
    }
}

fn reasons_of<'a>(signals: impl Iterator<Item = &'a Signal>) -> Vec<String> {
    // Группируем однотипные сигналы, чтобы не было сорока строк «высокая энтропия».
    let mut out: Vec<String> = Vec::new();
    let mut counts: Vec<(&'static str, u32, String)> = Vec::new();
    for s in signals {
        let kind = match s {
            Signal::CanaryTouched { .. } => "canary",
            Signal::UnexpectedHighEntropy { .. } => "entropy",
            Signal::BrokenHeader { .. } => "header",
            Signal::SuspiciousRename { .. } => "rename",
            Signal::RansomNote { .. } => "note",
            Signal::Burst { .. } => "burst",
            Signal::ShadowCopyDeletion { .. } => "shadow",
        };
        match counts.iter_mut().find(|(k, _, _)| *k == kind) {
            Some(c) => c.1 += 1,
            None => counts.push((kind, 1, s.describe())),
        }
    }
    let order = [
        "canary", "shadow", "note", "burst", "rename", "header", "entropy",
    ];
    counts.sort_by_key(|(k, _, _)| order.iter().position(|o| o == k));
    for (_, n, first) in counts {
        out.push(if n > 1 {
            format!("{first} (и ещё {})", n - 1)
        } else {
            first
        });
    }
    out
}

fn key_is_known(name: &str) -> bool {
    name != UNKNOWN_PROCESS && !name.starts_with("PID ")
}

pub fn is_shadow_deletion(cmd: &str) -> bool {
    let c = cmd.to_lowercase();
    (c.contains("delete") && c.contains("shadow"))
        || c.contains("resize shadowstorage")
        || (c.contains("wbadmin") && c.contains("delete catalog"))
        || c.contains("recoveryenabled no")
        || (c.contains("win32_shadowcopy") && (c.contains("delete") || c.contains("remove-")))
}

fn read_sample(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut buf = vec![0u8; analysis::SAMPLE_SIZE];
    let n = f.read(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

fn move_to_quarantine(path: &Path, quarantine: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(quarantine)?;
    let name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    let mut target = quarantine.join(&name);
    let mut i = 1;
    while target.exists() {
        target = quarantine.join(format!("{}.{i}", name.to_string_lossy()));
        i += 1;
    }
    if std::fs::rename(path, &target).is_err() {
        // Другой диск — копируем и удаляем.
        std::fs::copy(path, &target)?;
        std::fs::remove_file(path)?;
    }
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Полный цикл на реальном процессе: приманка → заморозка → «убить и восстановить».
    #[cfg(unix)]
    #[test]
    fn full_incident_cycle_with_real_process() {
        let base = std::env::temp_dir().join(format!("fg-engine-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let docs = base.join("docs");
        std::fs::create_dir_all(&docs).unwrap();
        let report = docs.join("курсовая.txt");
        std::fs::write(&report, "Глава 1. ".repeat(500)).unwrap();
        // mtime файла должен быть раньше инцидента (точность — секунды).
        std::thread::sleep(Duration::from_millis(1100));

        let dirs = AppDirs::in_dir(&base.join("data"));
        let mut cfg = Config::default();
        cfg.protected_folders = vec![docs.clone()];
        cfg.notifications = false;
        cfg.whitelist.clear();
        let (cmd_tx, cmd_rx) = unbounded();
        let (notice_tx, notice_rx) = unbounded();
        let mut e = Engine::new(
            cfg.clone(),
            dirs.clone(),
            Journal::open(&dirs.journal_db).unwrap(),
            Arc::new(RwLock::new(UiState::default())),
            Arc::new(RwLock::new(cfg)),
            cmd_tx,
            cmd_rx,
            notice_tx,
            Arc::new(RwLock::new(None)),
        );
        e.check_canaries(true);
        // Резервная копия до атаки.
        e.start_backup();
        let job = e.backup.take().unwrap();
        e.on_backup_done(job.thread.join().unwrap());

        let mut victim = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = victim.id();
        let now = Instant::now();
        // «Шифровальщик» портит документ и переименовывает его.
        let mut junk = vec![0u8; 8192];
        rand::fill(&mut junk[..]);
        std::fs::write(&report, &junk).unwrap();
        let locked = docs.join("курсовая.txt.locked");
        std::fs::rename(&report, &locked).unwrap();
        e.process_file(Some(pid), report.clone(), FileOp::Write, now);
        e.process_file(
            Some(pid),
            report.clone(),
            FileOp::Rename {
                to: Some(locked.clone()),
            },
            now,
        );
        // ...и трогает приманку.
        let canary = docs.join(canary::CANARY_NAMES[0]);
        std::fs::write(&canary, &junk).unwrap();
        e.process_file(Some(pid), canary.clone(), FileOp::Write, now);

        let inc = e.incidents.first().cloned().expect("инцидент открыт");
        assert_eq!(inc.severity, Severity::Critical);
        assert_eq!(
            inc.state,
            IncidentState::AwaitingDecision,
            "{:?}",
            inc.reasons
        );
        assert!(matches!(
            notice_rx.try_recv(),
            Ok(Notice::IncidentOpened { .. })
        ));
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
        assert!(
            stat.contains(") T "),
            "процесс должен быть заморожен: {stat}"
        );

        e.on_command(Command::Kill {
            incident: inc.id,
            restore: true,
        });
        let status = victim.wait().unwrap();
        assert!(!status.success(), "процесс завершён принудительно");
        let inc = e.incidents.first().unwrap();
        assert_eq!(inc.state, IncidentState::Killed);
        assert_eq!(inc.restored_files, 1);
        assert!(
            std::fs::read_to_string(&report)
                .unwrap()
                .starts_with("Глава 1"),
            "файл восстановлен"
        );
        assert!(!locked.exists(), "зашифрованная версия убрана в карантин");
        assert_eq!(
            canary::verify(std::slice::from_ref(&docs)).ok,
            3,
            "приманки починены"
        );
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn shadow_commands() {
        assert!(is_shadow_deletion(
            "vssadmin.exe Delete Shadows /All /Quiet"
        ));
        assert!(is_shadow_deletion("wmic shadowcopy delete"));
        assert!(is_shadow_deletion(
            "bcdedit /set {default} recoveryenabled No"
        ));
        assert!(is_shadow_deletion(
            "powershell Get-WmiObject Win32_Shadowcopy | ForEach-Object { $_.Delete() }"
        ));
        assert!(!is_shadow_deletion("vssadmin list shadows"));
    }

    #[test]
    fn reasons_grouped() {
        let s = [
            Signal::UnexpectedHighEntropy {
                path: "/a.txt".into(),
                entropy: 7.9,
            },
            Signal::UnexpectedHighEntropy {
                path: "/b.txt".into(),
                entropy: 7.9,
            },
            Signal::CanaryTouched {
                path: "/!000.docx".into(),
            },
        ];
        let r = reasons_of(s.iter());
        assert_eq!(r.len(), 2);
        assert!(r[0].contains("приманка"));
        assert!(r[1].contains("и ещё 1"));
    }
}
