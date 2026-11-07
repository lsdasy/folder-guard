//! Источники событий о файлах и процессах.

use std::path::PathBuf;

use crossbeam_channel::Sender;

use crate::model::{MonitorMode, RawEvent};

#[cfg(windows)]
pub mod etw;
pub mod watcher;

/// Запущенные источники. Остановка — просто `drop`.
pub struct Monitors {
    _watcher: Option<watcher::FolderWatcher>,
    #[cfg(windows)]
    _etw: Option<etw::EtwMonitor>,
    pub mode: MonitorMode,
    pub note: Option<String>,
}

impl Monitors {
    pub fn start(folders: &[PathBuf], tx: Sender<RawEvent>, want_full: bool) -> Self {
        let watcher = match watcher::FolderWatcher::start(folders, tx.clone()) {
            Ok(w) => Some(w),
            Err(e) => {
                log::error!("наблюдение за папками не запустилось: {e:#}");
                None
            }
        };

        #[cfg(windows)]
        {
            let mut note = None;
            let etw = if want_full {
                match etw::EtwMonitor::start(folders, tx) {
                    Ok(m) => Some(m),
                    Err(e) => {
                        note = Some(format!("ETW недоступен: {e:#}"));
                        None
                    }
                }
            } else {
                note = Some("нет прав администратора".into());
                None
            };
            let mode = if etw.is_some() {
                MonitorMode::Full
            } else {
                MonitorMode::Limited
            };
            Self {
                _watcher: watcher,
                _etw: etw,
                mode,
                note,
            }
        }

        #[cfg(not(windows))]
        {
            let _ = (want_full, tx);
            Self {
                _watcher: watcher,
                mode: MonitorMode::Limited,
                note: Some("ETW есть только в Windows".into()),
            }
        }
    }
}
