// В релизной сборке под Windows не показываем чёрное окно консоли.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
// Часть кода используется только в Windows (ETW, уведомления, трей).
#![cfg_attr(not(windows), allow(dead_code))]
#![cfg_attr(test, allow(clippy::field_reassign_with_default))]

mod analysis;
mod backup;
mod canary;
mod config;
mod engine;
mod icon;
mod journal;
mod model;
mod monitor;
mod platform;
mod scoring;
#[cfg(windows)]
mod tray;
mod ui;

use anyhow::Result;

use crate::config::{AppDirs, Config};

struct Args {
    minimized: bool,
    headless: bool,
    data_dir: Option<std::path::PathBuf>,
    protect: Vec<std::path::PathBuf>,
    page: Option<String>,
}

fn parse_args() -> Args {
    let mut a = Args {
        minimized: false,
        headless: false,
        data_dir: None,
        protect: Vec::new(),
        page: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--minimized" => a.minimized = true,
            "--headless" => a.headless = true,
            "--data-dir" => a.data_dir = it.next().map(Into::into),
            "--protect" => a.protect.extend(it.next().map(Into::into)),
            "--page" => a.page = it.next(),
            "--version" | "-V" => {
                println!("folder-guard {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--help" | "-h" => {
                println!(
                    "folder-guard [--minimized] [--headless] [--data-dir ПАПКА] [--protect ПАПКА]...\n\
                     --minimized  запуск свёрнутым в трей\n\
                     --headless   без интерфейса, события в консоль (для отладки)\n\
                     --data-dir   хранить настройки, журнал и копии в этой папке\n\
                     --protect    защищать эту папку (вместо папок из настроек)\n\
                     --page       открыть раздел: overview, journal, folders, whitelist, backups, settings"
                );
                std::process::exit(0);
            }
            other => eprintln!("неизвестный аргумент: {other}"),
        }
    }
    a
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = parse_args();
    let dirs = match &args.data_dir {
        Some(d) => AppDirs::in_dir(d),
        None => AppDirs::new()?,
    };
    let mut cfg = Config::load(&dirs.config_file).unwrap_or_else(|e| {
        log::error!("настройки повреждены, используются стандартные: {e:#}");
        Config::default()
    });
    if !args.protect.is_empty() {
        cfg.protected_folders = args
            .protect
            .iter()
            .map(|p| std::fs::canonicalize(p).unwrap_or_else(|_| p.clone()))
            .collect();
    }

    let (handle, engine_thread) = engine::spawn(cfg, dirs)?;

    if args.headless {
        log::info!("работаю без интерфейса; Ctrl+C — выход");
        engine_thread.join().ok();
        return Ok(());
    }

    let result = ui::run(handle.clone(), args.minimized, args.page.as_deref());
    handle.send(model::Command::Shutdown);
    engine_thread.join().ok();
    result
}
