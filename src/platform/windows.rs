//! Реализация для Windows через WinAPI (крейт `windows`).

use std::ffi::{OsStr, c_void};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND};
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    WinVerifyTrust,
};
use windows::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL, FILE_FLAGS_AND_ATTRIBUTES, GetFileAttributesW,
    SetFileAttributesW,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE, QueryFullProcessImageNameW, TerminateProcess,
};
use windows::Win32::UI::Shell::{IsUserAnAdmin, ShellExecuteW};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::core::{PCWSTR, PWSTR, w};

use super::{ToastAction, ToastCallback, ToastRequest};
use crate::model::Pid;

/// Идентификатор приложения для уведомлений Windows.
pub const APP_USER_MODEL_ID: &str = "FolderGuard.Monitor";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const TASK_NAME: &str = "FolderGuard";

// Недокументированные, но давно стабильные функции ntdll для заморозки всего процесса целиком.
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtSuspendProcess(process: *mut c_void) -> i32;
    fn NtResumeProcess(process: *mut c_void) -> i32;
}

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// Открытый дескриптор процесса, который сам закрывается.
struct ProcessHandle(HANDLE);

impl ProcessHandle {
    fn open(pid: Pid, access: PROCESS_ACCESS_RIGHTS) -> Result<Self> {
        let h = unsafe { OpenProcess(access, false, pid)? };
        Ok(Self(h))
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

pub fn suspend(pid: Pid) -> Result<()> {
    let h = ProcessHandle::open(pid, PROCESS_SUSPEND_RESUME)?;
    let status = unsafe { NtSuspendProcess(h.0.0) };
    if status < 0 {
        bail!("NtSuspendProcess вернул 0x{status:08X}");
    }
    Ok(())
}

pub fn resume(pid: Pid) -> Result<()> {
    let h = ProcessHandle::open(pid, PROCESS_SUSPEND_RESUME)?;
    let status = unsafe { NtResumeProcess(h.0.0) };
    if status < 0 {
        bail!("NtResumeProcess вернул 0x{status:08X}");
    }
    Ok(())
}

pub fn kill(pid: Pid) -> Result<()> {
    let h = ProcessHandle::open(pid, PROCESS_TERMINATE)?;
    unsafe { TerminateProcess(h.0, 1)? };
    Ok(())
}

pub fn process_exe(pid: Pid) -> Option<PathBuf> {
    let h = ProcessHandle::open(pid, PROCESS_QUERY_LIMITED_INFORMATION).ok()?;
    let mut buf = vec![0u16; 32_768];
    let mut len = buf.len() as u32;
    unsafe {
        QueryFullProcessImageNameW(h.0, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len)
            .ok()?
    };
    Some(PathBuf::from(String::from_utf16_lossy(
        &buf[..len as usize],
    )))
}

/// Есть ли у файла действительная цифровая подпись (Authenticode).
/// Каталожные подписи (большинство системных exe) этой проверкой не видны,
/// поэтому для них может вернуться `false` — это лишь дополнительная информация.
pub fn is_signed(exe: &Path) -> Option<bool> {
    let path = wide(exe.as_os_str());
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(path.as_ptr()),
        ..Default::default()
    };
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let status = unsafe {
        WinVerifyTrust(
            HWND(std::ptr::null_mut()),
            &mut action,
            &mut data as *mut _ as *mut c_void,
        )
    };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        WinVerifyTrust(
            HWND(std::ptr::null_mut()),
            &mut action,
            &mut data as *mut _ as *mut c_void,
        )
    };
    Some(status == 0)
}

pub fn set_hidden(path: &Path) {
    let p = wide(path.as_os_str());
    unsafe {
        let attrs = GetFileAttributesW(PCWSTR(p.as_ptr()));
        if attrs != u32::MAX {
            let _ = SetFileAttributesW(
                PCWSTR(p.as_ptr()),
                FILE_FLAGS_AND_ATTRIBUTES(attrs | FILE_ATTRIBUTE_HIDDEN.0),
            );
        }
    }
}

pub fn clear_readonly_hidden(path: &Path) {
    let p = wide(path.as_os_str());
    unsafe {
        let _ = SetFileAttributesW(PCWSTR(p.as_ptr()), FILE_ATTRIBUTE_NORMAL);
    }
}

pub fn is_admin() -> bool {
    unsafe { IsUserAnAdmin().as_bool() }
}

/// Регистрирует идентификатор приложения, чтобы уведомления шли от имени «Folder Guard».
pub fn register_toast_app() {
    use winreg::RegKey;
    use winreg::enums::HKEY_CURRENT_USER;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    match hkcu.create_subkey(format!(
        r"Software\Classes\AppUserModelId\{APP_USER_MODEL_ID}"
    )) {
        Ok((key, _)) => {
            let _ = key.set_value("DisplayName", &"Folder Guard");
            let _ = key.set_value("ShowInSettings", &1u32);
        }
        Err(e) => log::warn!("не удалось зарегистрировать уведомления: {e}"),
    }
}

pub fn show_toast(req: ToastRequest, on_action: ToastCallback) {
    use tauri_winrt_notification::{Duration, Scenario, Toast};
    let app_id = if req.compat_app_id {
        Toast::POWERSHELL_APP_ID
    } else {
        APP_USER_MODEL_ID
    };
    let mut toast = Toast::new(app_id)
        .title(&req.title)
        .text1(&req.body)
        .duration(Duration::Long);
    if let Some(f) = &req.footer {
        toast = toast.text2(f);
    }
    if req.with_buttons {
        toast = toast
            .scenario(Scenario::Reminder)
            .add_button("Убить", ToastAction::Kill.as_arg())
            .add_button("Разрешить", ToastAction::Allow.as_arg())
            .add_button("Подробнее", ToastAction::Details.as_arg());
    }
    let toast = toast.on_activated(move |arg| {
        // Клик по самому уведомлению (без кнопки) приходит без аргумента — открываем подробности.
        on_action(Some(
            arg.as_deref()
                .and_then(ToastAction::from_arg)
                .unwrap_or(ToastAction::Details),
        ));
        Ok(())
    });
    if let Err(e) = toast.show() {
        log::warn!("уведомление не показано: {e:?}");
    }
}

/// Перезапуск программы с правами администратора (появится окно UAC).
pub fn restart_elevated() -> Result<()> {
    let exe = std::env::current_exe()?;
    let exe_w = wide(exe.as_os_str());
    let r = unsafe {
        ShellExecuteW(
            None,
            w!("runas"),
            PCWSTR(exe_w.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    // Значения <= 32 означают ошибку (в том числе отказ в окне UAC).
    if (r.0 as isize) <= 32 {
        bail!("перезапуск отменён или не удался (код {})", r.0 as isize);
    }
    std::process::exit(0);
}

/// Автозапуск через Планировщик заданий: программе нужны права администратора,
/// а ключ реестра Run их не даёт.
pub fn autostart_enabled() -> bool {
    std::process::Command::new("schtasks")
        .args(["/Query", "/TN", TASK_NAME])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn set_autostart(enabled: bool) -> Result<()> {
    let mut cmd = std::process::Command::new("schtasks");
    cmd.creation_flags(CREATE_NO_WINDOW);
    if enabled {
        let exe = std::env::current_exe()?;
        let tr = format!("\"{}\" --minimized", exe.display());
        cmd.args([
            "/Create", "/TN", TASK_NAME, "/TR", &tr, "/SC", "ONLOGON", "/RL", "HIGHEST", "/F",
        ]);
    } else {
        cmd.args(["/Delete", "/TN", TASK_NAME, "/F"]);
    }
    let out = cmd.output()?;
    if !out.status.success() {
        bail!("schtasks: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

/// Segoe UI — системный шрифт Windows 11, как на макетах.
pub fn ui_font() -> Option<Vec<u8>> {
    std::fs::read(r"C:\Windows\Fonts\segoeui.ttf").ok()
}

pub fn ui_font_bold() -> Option<Vec<u8>> {
    std::fs::read(r"C:\Windows\Fonts\seguisb.ttf").ok()
}
