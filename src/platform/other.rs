//! Реализации для не-Windows систем (для разработки и тестов).
//! Заморозка/завершение работают через сигналы POSIX, остальное — заглушки.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use super::{ToastCallback, ToastRequest};
use crate::model::Pid;

pub fn set_hidden(_path: &Path) {}
pub fn clear_readonly_hidden(_path: &Path) {}

pub fn is_admin() -> bool {
    false
}

#[cfg(unix)]
fn signal(pid: Pid, sig: &str) -> Result<()> {
    let ok = std::process::Command::new("kill")
        .arg(format!("-{sig}"))
        .arg(pid.to_string())
        .status()?
        .success();
    if !ok {
        bail!("kill -{sig} {pid} не удался");
    }
    Ok(())
}

#[cfg(not(unix))]
fn signal(_pid: Pid, _sig: &str) -> Result<()> {
    bail!("не поддерживается на этой системе")
}

pub fn suspend(pid: Pid) -> Result<()> {
    signal(pid, "STOP")
}

pub fn resume(pid: Pid) -> Result<()> {
    signal(pid, "CONT")
}

pub fn kill(pid: Pid) -> Result<()> {
    signal(pid, "KILL")
}

pub fn process_exe(_pid: Pid) -> Option<PathBuf> {
    None
}

pub fn is_signed(_exe: &Path) -> Option<bool> {
    None
}

pub fn register_toast_app() {}

pub fn show_toast(req: ToastRequest, _on_action: ToastCallback) {
    log::info!("[уведомление] {} — {}", req.title, req.body);
}

pub fn restart_elevated() -> Result<()> {
    bail!("запуск с правами администратора поддерживается только в Windows")
}

pub fn autostart_enabled() -> bool {
    false
}

pub fn set_autostart(_enabled: bool) -> Result<()> {
    bail!("автозапуск поддерживается только в Windows")
}

/// Шрифт интерфейса: на Linux используем встроенный в egui.
pub fn ui_font() -> Option<Vec<u8>> {
    None
}

pub fn ui_font_bold() -> Option<Vec<u8>> {
    None
}
