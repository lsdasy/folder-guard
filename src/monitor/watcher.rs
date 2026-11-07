//! Наблюдение за папками через `notify` (на Windows — ReadDirectoryChangesW).
//! Работает без прав администратора, но не сообщает, какой процесс изменил файл.
//! В полном режиме используется только для того, чтобы узнать новое имя при переименовании.

use std::path::PathBuf;
use std::time::Instant;

use anyhow::Result;
use crossbeam_channel::Sender;
use notify::event::{ModifyKind, RenameMode};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::Mutex;

use crate::model::{EventSource, FileOp, RawEvent};

pub struct FolderWatcher {
    _watcher: RecommendedWatcher,
}

impl FolderWatcher {
    pub fn start(folders: &[PathBuf], tx: Sender<RawEvent>) -> Result<Self> {
        // Последнее «переименовано ИЗ» — ждём парное «переименовано В».
        let pending_from: Mutex<Option<PathBuf>> = Mutex::new(None);
        let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| {
            let Ok(ev) = res else { return };
            for raw in translate(ev, &pending_from) {
                let _ = tx.send(raw);
            }
        })?;
        for f in folders {
            if f.exists()
                && let Err(e) = watcher.watch(f, RecursiveMode::Recursive)
            {
                log::warn!("не удалось наблюдать {}: {e}", f.display());
            }
        }
        Ok(Self { _watcher: watcher })
    }
}

fn file_event(path: PathBuf, op: FileOp) -> RawEvent {
    RawEvent::File {
        pid: None,
        path,
        op,
        at: Instant::now(),
        source: EventSource::Watcher,
    }
}

fn translate(ev: Event, pending_from: &Mutex<Option<PathBuf>>) -> Vec<RawEvent> {
    let mut out = Vec::new();
    let mut paths = ev.paths.into_iter();
    match ev.kind {
        EventKind::Create(_) => out.extend(paths.map(|p| file_event(p, FileOp::Create))),
        EventKind::Remove(_) => out.extend(paths.map(|p| file_event(p, FileOp::Delete))),
        EventKind::Modify(ModifyKind::Name(RenameMode::Both)) => {
            if let (Some(from), Some(to)) = (paths.next(), paths.next()) {
                out.push(file_event(from, FileOp::Rename { to: Some(to) }));
            }
        }
        EventKind::Modify(ModifyKind::Name(RenameMode::From)) => {
            *pending_from.lock() = paths.next();
        }
        EventKind::Modify(ModifyKind::Name(RenameMode::To)) => {
            if let Some(to) = paths.next() {
                match pending_from.lock().take() {
                    Some(from) => out.push(file_event(from, FileOp::Rename { to: Some(to) })),
                    // Файл переместили к нам снаружи — считаем созданием.
                    None => out.push(file_event(to, FileOp::Create)),
                }
            }
        }
        EventKind::Modify(ModifyKind::Metadata(_)) => {}
        EventKind::Modify(_) => out.extend(paths.map(|p| file_event(p, FileOp::Write))),
        _ => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use notify::event::CreateKind;

    #[test]
    fn rename_pairs_are_joined() {
        let pending = Mutex::new(None);
        let from = Event::new(EventKind::Modify(ModifyKind::Name(RenameMode::From)))
            .add_path("/d/a.docx".into());
        let to = Event::new(EventKind::Modify(ModifyKind::Name(RenameMode::To)))
            .add_path("/d/a.docx.locked".into());
        assert!(translate(from, &pending).is_empty());
        let out = translate(to, &pending);
        match &out[0] {
            RawEvent::File {
                path,
                op: FileOp::Rename { to: Some(t) },
                ..
            } => {
                assert_eq!(path, &PathBuf::from("/d/a.docx"));
                assert_eq!(t, &PathBuf::from("/d/a.docx.locked"));
            }
            other => panic!("{other:?}"),
        }
        let c = Event::new(EventKind::Create(CreateKind::File)).add_path("/d/n.txt".into());
        assert!(matches!(
            translate(c, &pending)[0],
            RawEvent::File {
                op: FileOp::Create,
                ..
            }
        ));
    }
}
