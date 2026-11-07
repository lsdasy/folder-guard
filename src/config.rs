//! Настройки программы. Хранятся в TOML-файле в папке профиля пользователя
//! (на Windows: %APPDATA%\FolderGuard\config\config.toml).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Config {
    /// Папки, за которыми следим (рекурсивно).
    pub protected_folders: Vec<PathBuf>,
    /// Имена подпапок, которые не анализируем (target, node_modules, .git...).
    pub excluded_dir_names: Vec<String>,
    /// Процессы, которым разрешено массово менять файлы.
    pub whitelist: Vec<WhitelistEntry>,

    /// Раскладывать файлы-приманки в защищённые папки.
    pub canaries_enabled: bool,
    /// Делать приманки скрытыми (атрибут Hidden).
    pub canaries_hidden: bool,

    /// С этого балла процесс замораживается и показывается уведомление.
    pub suspend_score: u32,
    /// С этого балла — критическая тревога (окно поверх всех).
    pub critical_score: u32,
    /// Сколько файловых операций за окно `burst_window_secs` считается «всплеском».
    pub burst_files: u32,
    pub burst_window_secs: u64,
    /// Через сколько секунд замороженный процесс будет завершён, если пользователь не ответил.
    pub auto_kill_secs: u64,

    /// Режим обучения: только записываем в журнал, ничего не блокируем.
    pub learning_mode: bool,
    /// Показывать всплывающие уведомления Windows.
    pub notifications: bool,
    /// Использовать для уведомлений идентификатор PowerShell (если свои уведомления не появляются).
    pub notifications_compat: bool,

    pub backup: BackupConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WhitelistEntry {
    /// Имя exe-файла, например `7zFM.exe` (без учёта регистра).
    pub name: String,
    /// Если задан полный путь, совпадать должен и он.
    #[serde(default)]
    pub path: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct BackupConfig {
    pub enabled: bool,
    pub interval_minutes: u64,
    pub max_file_mb: u64,
    pub keep_versions: u32,
    /// Своя папка для копий (по умолчанию — в локальных данных программы).
    pub dir: Option<PathBuf>,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_minutes: 30,
            max_file_mb: 50,
            keep_versions: 3,
            dir: None,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protected_folders: default_protected_folders(),
            excluded_dir_names: [
                "target",
                "node_modules",
                ".git",
                "__pycache__",
                ".venv",
                "bin",
                "obj",
                ".idea",
                ".vs",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            whitelist: [
                "code.exe",
                "devenv.exe",
                "cargo.exe",
                "rustc.exe",
                "go.exe",
                "git.exe",
                "7zFM.exe",
                "7zG.exe",
                "7z.exe",
                "WinRAR.exe",
                "OneDrive.exe",
                "Dropbox.exe",
                "MsMpEng.exe",
                "SearchIndexer.exe",
            ]
            .iter()
            .map(|n| WhitelistEntry {
                name: n.to_string(),
                path: None,
            })
            .collect(),
            canaries_enabled: true,
            canaries_hidden: true,
            suspend_score: 50,
            critical_score: 100,
            burst_files: 25,
            burst_window_secs: 10,
            auto_kill_secs: 30,
            learning_mode: false,
            notifications: true,
            notifications_compat: false,
            backup: BackupConfig::default(),
        }
    }
}

fn default_protected_folders() -> Vec<PathBuf> {
    let Some(dirs) = directories::UserDirs::new() else {
        return Vec::new();
    };
    [dirs.document_dir(), dirs.desktop_dir(), dirs.picture_dir()]
        .into_iter()
        .flatten()
        .map(Path::to_path_buf)
        .collect()
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            let cfg = Self::default();
            cfg.save(path)?;
            return Ok(cfg);
        }
        let text =
            std::fs::read_to_string(path).with_context(|| format!("чтение {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("разбор {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = toml::to_string_pretty(self)?;
        // Пишем во временный файл и переименовываем — чтобы не получить полузаписанный конфиг.
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn is_whitelisted(&self, name: &str, exe: Option<&Path>) -> bool {
        self.whitelist.iter().any(|w| {
            if !w.name.eq_ignore_ascii_case(name) {
                return false;
            }
            match (&w.path, exe) {
                (None, _) => true,
                (Some(p), Some(e)) => paths_equal(p, e),
                (Some(_), None) => false,
            }
        })
    }

    pub fn is_protected(&self, path: &Path) -> bool {
        self.protected_folders
            .iter()
            .any(|f| path_starts_with(path, f))
    }

    pub fn is_excluded(&self, path: &Path) -> bool {
        path.components().any(|c| {
            let s = c.as_os_str().to_string_lossy();
            self.excluded_dir_names
                .iter()
                .any(|e| e.eq_ignore_ascii_case(&s))
        })
    }
}

/// Сравнение путей без учёта регистра (Windows) и разделителей.
pub fn paths_equal(a: &Path, b: &Path) -> bool {
    normalize(a) == normalize(b)
}

pub fn path_starts_with(path: &Path, prefix: &Path) -> bool {
    let p = normalize(path);
    let pre = normalize(prefix);
    p == pre || p.starts_with(&(pre.trim_end_matches('/').to_string() + "/"))
}

fn normalize(p: &Path) -> String {
    let s = p.to_string_lossy().replace('\\', "/");
    if cfg!(windows) { s.to_lowercase() } else { s }
}

/// Папки программы: конфиг, журнал, резервные копии, карантин.
#[derive(Clone, Debug)]
pub struct AppDirs {
    pub config_file: PathBuf,
    pub data_dir: PathBuf,
    pub journal_db: PathBuf,
    pub default_backup_dir: PathBuf,
    pub quarantine_dir: PathBuf,
}

impl AppDirs {
    pub fn new() -> Result<Self> {
        let pd = directories::ProjectDirs::from("", "", "FolderGuard")
            .context("не удалось определить папку профиля")?;
        let data_dir = pd.data_local_dir().to_path_buf();
        Ok(Self {
            config_file: pd.config_dir().join("config.toml"),
            journal_db: data_dir.join("journal.db"),
            default_backup_dir: data_dir.join("backups"),
            quarantine_dir: data_dir.join("quarantine"),
            data_dir,
        })
    }

    /// Для тестов и запуска «в песочнице»: всё внутри одной папки.
    pub fn in_dir(root: &Path) -> Self {
        Self {
            config_file: root.join("config.toml"),
            journal_db: root.join("journal.db"),
            default_backup_dir: root.join("backups"),
            quarantine_dir: root.join("quarantine"),
            data_dir: root.to_path_buf(),
        }
    }

    pub fn backup_dir(&self, cfg: &Config) -> PathBuf {
        cfg.backup
            .dir
            .clone()
            .unwrap_or_else(|| self.default_backup_dir.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitelist_by_name_and_path() {
        let mut cfg = Config::default();
        cfg.whitelist = vec![
            WhitelistEntry {
                name: "7zFM.exe".into(),
                path: None,
            },
            WhitelistEntry {
                name: "tool.exe".into(),
                path: Some(PathBuf::from("/opt/tool.exe")),
            },
        ];
        assert!(cfg.is_whitelisted("7zfm.EXE", None));
        assert!(cfg.is_whitelisted("tool.exe", Some(Path::new("/opt/tool.exe"))));
        assert!(!cfg.is_whitelisted("tool.exe", Some(Path::new("/tmp/tool.exe"))));
        assert!(!cfg.is_whitelisted("setup.exe", None));
    }

    #[test]
    fn protected_and_excluded() {
        let mut cfg = Config::default();
        cfg.protected_folders = vec![PathBuf::from("/home/u/docs")];
        assert!(cfg.is_protected(Path::new("/home/u/docs/a.txt")));
        assert!(!cfg.is_protected(Path::new("/home/u/docs2/a.txt")));
        assert!(cfg.is_excluded(Path::new("/home/u/docs/proj/target/debug/x")));
        assert!(!cfg.is_excluded(Path::new("/home/u/docs/proj/src/x")));
    }

    #[test]
    fn roundtrip_toml() {
        let dir = std::env::temp_dir().join(format!("fg-cfg-{}", std::process::id()));
        let file = dir.join("c.toml");
        let cfg = Config::default();
        cfg.save(&file).unwrap();
        assert_eq!(Config::load(&file).unwrap(), cfg);
        let _ = std::fs::remove_dir_all(dir);
    }
}
