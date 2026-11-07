//! Всё, что зависит от операционной системы: управление процессами,
//! цифровые подписи, уведомления, атрибуты файлов, автозапуск.
//!
//! Основная цель — Windows (`windows.rs`). На других системах (`other.rs`)
//! есть упрощённые реализации, чтобы ядро и интерфейс можно было запускать
//! и тестировать где угодно.

use std::path::PathBuf;

use crate::model::Pid;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use self::windows::*;

#[cfg(not(windows))]
mod other;
#[cfg(not(windows))]
pub use self::other::*;

/// Что пользователь нажал в уведомлении.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToastAction {
    Kill,
    Allow,
    Details,
}

impl ToastAction {
    pub fn as_arg(self) -> &'static str {
        match self {
            ToastAction::Kill => "kill",
            ToastAction::Allow => "allow",
            ToastAction::Details => "details",
        }
    }

    pub fn from_arg(s: &str) -> Option<Self> {
        match s {
            "kill" => Some(ToastAction::Kill),
            "allow" => Some(ToastAction::Allow),
            "details" => Some(ToastAction::Details),
            _ => None,
        }
    }
}

pub struct ToastRequest {
    pub title: String,
    pub body: String,
    pub footer: Option<String>,
    pub with_buttons: bool,
    pub compat_app_id: bool,
}

pub type ToastCallback = Box<dyn Fn(Option<ToastAction>) + Send + 'static>;

/// Системные процессы, которые нельзя замораживать или завершать —
/// иначе зависнет рабочий стол или вся система. По ним — только предупреждение.
pub fn is_critical_process(name: &str) -> bool {
    const CRITICAL: [&str; 14] = [
        "system",
        "registry",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "winlogon.exe",
        "services.exe",
        "lsass.exe",
        "svchost.exe",
        "dwm.exe",
        "explorer.exe",
        "fontdrvhost.exe",
        "sihost.exe",
        "memory compression",
    ];
    CRITICAL.iter().any(|c| c.eq_ignore_ascii_case(name))
}

/// Имя процесса и путь к его exe (через sysinfo: работает на всех системах).
pub fn process_info(pid: Pid) -> (String, Option<PathBuf>) {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
    let spid = sysinfo::Pid::from_u32(pid);
    let from_sysinfo = System::new().ok().and_then(|mut sys| {
        sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[spid]),
            true,
            ProcessRefreshKind::nothing().with_exe(UpdateKind::Always),
        );
        sys.process(spid).map(|p| {
            (
                p.name().to_string_lossy().into_owned(),
                p.exe().map(|e| e.to_path_buf()),
            )
        })
    });
    let exe = process_exe(pid).or_else(|| from_sysinfo.as_ref().and_then(|(_, e)| e.clone()));
    let name = exe
        .as_ref()
        .and_then(|e| e.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .or_else(|| from_sysinfo.map(|(n, _)| n))
        .unwrap_or_else(|| format!("PID {pid}"));
    (name, exe)
}

/// Командная строка процесса (нужна, чтобы распознать `vssadmin delete shadows`).
pub fn process_cmdline(pid: Pid) -> Option<String> {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
    let mut sys = System::new().ok()?;
    let spid = sysinfo::Pid::from_u32(pid);
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[spid]),
        true,
        ProcessRefreshKind::nothing().with_cmd(UpdateKind::Always),
    );
    let p = sys.process(spid)?;
    let cmd: Vec<String> = p
        .cmd()
        .iter()
        .map(|s| s.to_string_lossy().into_owned())
        .collect();
    (!cmd.is_empty()).then(|| cmd.join(" "))
}

pub fn process_alive(pid: Pid) -> bool {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
    let Ok(mut sys) = System::new() else {
        return false;
    };
    let spid = sysinfo::Pid::from_u32(pid);
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[spid]),
        true,
        ProcessRefreshKind::nothing(),
    );
    sys.process(spid).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_processes() {
        assert!(is_critical_process("Explorer.EXE"));
        assert!(is_critical_process("lsass.exe"));
        assert!(!is_critical_process("setup.exe"));
    }

    #[test]
    fn own_process_info() {
        let (name, _) = process_info(std::process::id());
        assert!(!name.is_empty());
        assert!(process_alive(std::process::id()));
    }
}
