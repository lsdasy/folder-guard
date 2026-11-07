//! Общие типы: события файловой системы, сигналы, инциденты и состояние для интерфейса.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::Instant;

use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

pub type Pid = u32;

/// Что произошло с файлом.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileOp {
    /// Файл изменён (запись завершена).
    Write,
    /// Создан новый файл.
    Create,
    /// Переименован. `to` может быть неизвестен, если источник события его не сообщил.
    Rename {
        to: Option<PathBuf>,
    },
    Delete,
}

/// «Сырое» событие от источника наблюдения (ETW или ReadDirectoryChangesW).
#[derive(Clone, Debug)]
pub enum RawEvent {
    File {
        pid: Option<Pid>,
        path: PathBuf,
        op: FileOp,
        at: Instant,
        source: EventSource,
    },
    ProcessStart {
        pid: Pid,
        parent: Pid,
        image: String,
        at: Instant,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventSource {
    Etw,
    Watcher,
}

/// Признак, за который процесс получает баллы подозрительности.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Signal {
    CanaryTouched { path: PathBuf },
    UnexpectedHighEntropy { path: PathBuf, entropy: f64 },
    BrokenHeader { path: PathBuf },
    SuspiciousRename { from: PathBuf, to: PathBuf },
    RansomNote { path: PathBuf },
    Burst { files: u32, window_secs: u64 },
    ShadowCopyDeletion { command: String },
}

impl Signal {
    pub fn points(&self) -> u32 {
        match self {
            Signal::CanaryTouched { .. } => 100,
            Signal::ShadowCopyDeletion { .. } => 100,
            Signal::RansomNote { .. } => 25,
            Signal::Burst { .. } => 30,
            Signal::BrokenHeader { .. } => 15,
            Signal::UnexpectedHighEntropy { .. } => 15,
            Signal::SuspiciousRename { .. } => 10,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Signal::CanaryTouched { path } => format!("тронут файл-приманка {}", short(path)),
            Signal::UnexpectedHighEntropy { path, entropy } => {
                format!(
                    "{} выглядит зашифрованным (энтропия {:.2})",
                    short(path),
                    entropy
                )
            }
            Signal::BrokenHeader { path } => {
                format!("у {} испорчен заголовок формата", short(path))
            }
            Signal::SuspiciousRename { from, to } => format!("{} → {}", short(from), short(to)),
            Signal::RansomNote { path } => {
                format!("создана записка с требованием выкупа {}", short(path))
            }
            Signal::Burst { files, window_secs } => format!("{files} файлов за {window_secs} с"),
            Signal::ShadowCopyDeletion { command } => format!("удаление теневых копий: {command}"),
        }
    }

    pub fn is_critical(&self) -> bool {
        matches!(
            self,
            Signal::CanaryTouched { .. } | Signal::ShadowCopyDeletion { .. }
        )
    }
}

pub fn short(p: &std::path::Path) -> String {
    p.file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.display().to_string())
}

/// Файл, задетый процессом во время инцидента.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TouchedFile {
    /// Исходный путь (до переименования).
    pub original: PathBuf,
    /// Путь после переименования, если было.
    pub renamed_to: Option<PathBuf>,
    pub modified: bool,
    pub deleted: bool,
    pub first_touch: DateTime<Local>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    /// Подозрительно: процесс заморожен, уведомление.
    Suspicious,
    /// Критично: приманка/теневые копии, окно поверх всех.
    Critical,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncidentState {
    /// Процесс заморожен, ждём решения пользователя.
    AwaitingDecision,
    /// Обнаружено, но заморозить нельзя (нет PID, системный процесс, режим обучения).
    DetectedOnly,
    Killed,
    Allowed,
    /// Процесс завершился сам до решения.
    Exited,
}

impl IncidentState {
    pub fn label(&self) -> &'static str {
        match self {
            IncidentState::AwaitingDecision => "ожидает решения",
            IncidentState::DetectedOnly => "только обнаружено",
            IncidentState::Killed => "процесс завершён",
            IncidentState::Allowed => "разрешено",
            IncidentState::Exited => "процесс завершился сам",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Incident {
    pub id: i64,
    pub pid: Option<Pid>,
    pub process_name: String,
    pub exe_path: Option<PathBuf>,
    /// None — подпись не проверялась или проверка невозможна.
    pub signed: Option<bool>,
    pub severity: Severity,
    pub state: IncidentState,
    pub score: u32,
    pub reasons: Vec<String>,
    pub files: Vec<TouchedFile>,
    pub started: DateTime<Local>,
    /// Когда процесс будет завершён автоматически (только для AwaitingDecision).
    pub deadline: Option<DateTime<Local>>,
    pub restored_files: u32,
}

impl Incident {
    pub fn files_summary(&self) -> String {
        format!(
            "{} {}",
            self.files.len(),
            plural(self.files.len() as u64, "файл", "файла", "файлов")
        )
    }
}

pub fn plural(n: u64, one: &'static str, few: &'static str, many: &'static str) -> &'static str {
    let n10 = n % 10;
    let n100 = n % 100;
    if n10 == 1 && n100 != 11 {
        one
    } else if (2..=4).contains(&n10) && !(12..=14).contains(&n100) {
        few
    } else {
        many
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Level {
    Info,
    Ok,
    Warning,
    Threat,
}

/// Строка журнала.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogEntry {
    pub time: DateTime<Local>,
    pub level: Level,
    pub process: Option<String>,
    pub message: String,
    pub incident_id: Option<i64>,
}

/// Строка таблицы «Процессы, работающие с файлами».
#[derive(Clone, Debug, Default)]
pub struct ProcessRow {
    pub pid: Option<Pid>,
    pub name: String,
    pub files_per_min: u32,
    pub avg_entropy: Option<f64>,
    pub score: u32,
    pub whitelisted: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MonitorMode {
    /// ETW: видим, какой процесс что делает.
    Full,
    /// Только ReadDirectoryChangesW: без привязки к процессам (нет прав администратора).
    Limited,
    Starting,
}

#[derive(Clone, Debug, Default)]
pub struct BackupStatus {
    pub running: bool,
    pub last_run: Option<DateTime<Local>>,
    pub files: u64,
    pub bytes: u64,
    pub last_error: Option<String>,
}

/// Состояние, которое движок публикует для интерфейса.
#[derive(Clone, Debug)]
pub struct UiState {
    pub mode: MonitorMode,
    pub mode_note: Option<String>,
    pub paused_until: Option<DateTime<Local>>,
    pub learning_mode: bool,
    pub processes: Vec<ProcessRow>,
    pub log: VecDeque<LogEntry>,
    pub incidents: Vec<Incident>,
    pub protected_count: usize,
    pub canaries_total: usize,
    pub canaries_ok: usize,
    pub events_today: u64,
    pub threats_stopped: u64,
    pub backup: BackupStatus,
    pub is_admin: bool,
}

impl Default for UiState {
    fn default() -> Self {
        Self {
            mode: MonitorMode::Starting,
            mode_note: None,
            paused_until: None,
            learning_mode: false,
            processes: Vec::new(),
            log: VecDeque::new(),
            incidents: Vec::new(),
            protected_count: 0,
            canaries_total: 0,
            canaries_ok: 0,
            events_today: 0,
            threats_stopped: 0,
            backup: BackupStatus::default(),
            is_admin: false,
        }
    }
}

impl UiState {
    pub const LOG_LIMIT: usize = 1000;

    pub fn push_log(&mut self, e: LogEntry) {
        self.log.push_front(e);
        while self.log.len() > Self::LOG_LIMIT {
            self.log.pop_back();
        }
    }

    pub fn pending_incident(&self) -> Option<&Incident> {
        self.incidents
            .iter()
            .find(|i| i.state == IncidentState::AwaitingDecision)
    }

    pub fn last_incident(&self) -> Option<&Incident> {
        self.incidents.iter().max_by_key(|i| i.started)
    }
}

/// Команды от интерфейса движку.
#[derive(Clone, Debug)]
pub enum Command {
    Kill {
        incident: i64,
        restore: bool,
    },
    Allow {
        incident: i64,
        add_to_whitelist: bool,
    },
    Restore {
        incident: i64,
    },
    PauseFor(std::time::Duration),
    Resume,
    ApplyConfig(Box<crate::config::Config>),
    BackupNow,
    VerifyCanaries,
    Shutdown,
}

/// Уведомления от движка интерфейсу (кроме общего состояния).
#[derive(Clone, Debug)]
pub enum Notice {
    IncidentOpened { id: i64, severity: Severity },
    IncidentClosed { id: i64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn russian_plural() {
        assert_eq!(plural(1, "файл", "файла", "файлов"), "файл");
        assert_eq!(plural(3, "файл", "файла", "файлов"), "файла");
        assert_eq!(plural(11, "файл", "файла", "файлов"), "файлов");
        assert_eq!(plural(21, "файл", "файла", "файлов"), "файл");
        assert_eq!(plural(40, "файл", "файла", "файлов"), "файлов");
    }
}
