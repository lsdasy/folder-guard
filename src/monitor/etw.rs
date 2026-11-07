//! Наблюдение через ETW (Event Tracing for Windows).
//!
//! Провайдер `Microsoft-Windows-Kernel-File` сообщает о каждом открытии, записи,
//! переименовании и удалении файла вместе с PID процесса. Провайдер
//! `Microsoft-Windows-Kernel-Process` — о запуске процессов (чтобы поймать
//! `vssadmin delete shadows`). Требуются права администратора.
//!
//! Схема работы с файлами:
//! 1. `Create` (id 12) / `CreateNewFile` (id 30) — запоминаем FileObject → (путь, PID).
//! 2. `Write` (id 16) — помечаем FileObject как изменённый.
//! 3. `Cleanup` (id 13) / `Close` (id 14) — если в файл писали, отправляем событие Write.
//! 4. `SetInformation` (id 17) с классом переименования/удаления — событие Rename/Delete.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Result, anyhow};
use crossbeam_channel::Sender;
use ferrisetw::EventRecord;
use ferrisetw::parser::{Parser, Pointer};
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{UserTrace, stop_trace_by_name};
use parking_lot::Mutex;
use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
use windows::core::PCWSTR;

use crate::model::{EventSource, FileOp, Pid, RawEvent};

const TRACE_NAME: &str = "FolderGuardTrace";
const KERNEL_FILE: &str = "EDD08927-9CC4-4E65-B970-C2560FB5C289";
const KERNEL_PROCESS: &str = "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716";

// Ключевые слова провайдера Kernel-File.
const KW_FILENAME: u64 = 0x10;
const KW_FILEIO: u64 = 0x20;
const KW_CREATE: u64 = 0x80;
const KW_WRITE: u64 = 0x200;
const KW_CREATE_NEW_FILE: u64 = 0x1000;
const KW_PROCESS: u64 = 0x10;

// Классы FILE_INFORMATION_CLASS для SetInformation.
const FILE_RENAME_INFORMATION: u32 = 10;
const FILE_DISPOSITION_INFORMATION: u32 = 13;
const FILE_DISPOSITION_INFORMATION_EX: u32 = 64;
const FILE_RENAME_INFORMATION_EX: u32 = 65;

const MAX_TRACKED_OBJECTS: usize = 200_000;

pub struct EtwMonitor {
    _trace: UserTrace,
}

struct OpenFile {
    path: PathBuf,
    opener: Pid,
    writer: Option<Pid>,
}

/// Таблица «\Device\HarddiskVolume3» → «C:».
struct DeviceMap(Vec<(String, String)>);

impl DeviceMap {
    fn load() -> Self {
        let mut map = Vec::new();
        for letter in b'A'..=b'Z' {
            let drive = format!("{}:", letter as char);
            let drive_w: Vec<u16> = drive.encode_utf16().chain(std::iter::once(0)).collect();
            let mut buf = vec![0u16; 1024];
            let n = unsafe { QueryDosDeviceW(PCWSTR(drive_w.as_ptr()), Some(&mut buf)) };
            if n == 0 {
                continue;
            }
            let end = buf.iter().position(|&c| c == 0).unwrap_or(n as usize);
            let device = String::from_utf16_lossy(&buf[..end]);
            map.push((device.to_lowercase(), drive));
        }
        // Длинные префиксы проверяем первыми (\Device\HarddiskVolume10 раньше \Device\HarddiskVolume1).
        map.sort_by_key(|e| std::cmp::Reverse(e.0.len()));
        Self(map)
    }

    fn to_dos(&self, nt_path: &str) -> Option<String> {
        let lower = nt_path.to_lowercase();
        self.0.iter().find_map(|(dev, drive)| {
            lower
                .strip_prefix(dev.as_str())
                .filter(|rest| rest.starts_with('\\'))
                .map(|_| format!("{drive}{}", &nt_path[dev.len()..]))
        })
    }
}

struct State {
    files: HashMap<usize, OpenFile>,
    parse_errors: u32,
}

impl EtwMonitor {
    pub fn start(protected: &[PathBuf], tx: Sender<RawEvent>) -> Result<Self> {
        // Сессия могла остаться от прошлого запуска, если программа упала.
        let _ = stop_trace_by_name(TRACE_NAME);

        let devices = Arc::new(DeviceMap::load());
        let prefixes: Arc<Vec<String>> = Arc::new(
            protected
                .iter()
                .map(|p| {
                    p.to_string_lossy()
                        .to_lowercase()
                        .trim_end_matches('\\')
                        .to_string()
                        + "\\"
                })
                .collect(),
        );
        let state = Arc::new(Mutex::new(State {
            files: HashMap::new(),
            parse_errors: 0,
        }));
        let own_pid = std::process::id();

        let file_tx = tx.clone();
        let file_cb = move |record: &EventRecord, locator: &SchemaLocator| {
            let pid = record.process_id();
            if pid == own_pid {
                return;
            }
            let Ok(schema) = locator.event_schema(record) else {
                return;
            };
            let parser = Parser::create(record, &schema);
            let fo = || parser.try_parse::<Pointer>("FileObject").map(|p| *p);
            let mut st = state.lock();
            match record.event_id() {
                12 | 30 => {
                    let (Ok(fo), Ok(nt_name)) = (fo(), parser.try_parse::<String>("FileName"))
                    else {
                        st.parse_errors += 1;
                        return;
                    };
                    let Some(dos) = devices.to_dos(&nt_name) else {
                        return;
                    };
                    let lower = dos.to_lowercase();
                    if !prefixes.iter().any(|p| lower.starts_with(p.as_str())) {
                        return;
                    }
                    let path = PathBuf::from(dos);
                    if record.event_id() == 30 {
                        let _ = file_tx.send(RawEvent::File {
                            pid: Some(pid),
                            path: path.clone(),
                            op: FileOp::Create,
                            at: Instant::now(),
                            source: EventSource::Etw,
                        });
                    }
                    if st.files.len() < MAX_TRACKED_OBJECTS {
                        st.files.insert(
                            fo,
                            OpenFile {
                                path,
                                opener: pid,
                                writer: None,
                            },
                        );
                    }
                }
                16 => {
                    if let Ok(fo) = fo()
                        && let Some(f) = st.files.get_mut(&fo)
                    {
                        // Отложенную запись выполняет System (PID 4) — тогда виноват тот, кто открыл файл.
                        f.writer = Some(if pid <= 4 { f.opener } else { pid });
                    }
                }
                13 | 14 => {
                    if let Ok(fo) = fo()
                        && let Some(f) = st.files.remove(&fo)
                        && let Some(writer) = f.writer
                    {
                        let _ = file_tx.send(RawEvent::File {
                            pid: Some(writer),
                            path: f.path,
                            op: FileOp::Write,
                            at: Instant::now(),
                            source: EventSource::Etw,
                        });
                    }
                }
                17 => {
                    let (Ok(fo), Ok(class)) = (fo(), parser.try_parse::<u32>("InfoClass")) else {
                        return;
                    };
                    let Some(f) = st.files.get(&fo) else { return };
                    let op = match class {
                        FILE_RENAME_INFORMATION | FILE_RENAME_INFORMATION_EX => {
                            FileOp::Rename { to: None }
                        }
                        FILE_DISPOSITION_INFORMATION | FILE_DISPOSITION_INFORMATION_EX => {
                            FileOp::Delete
                        }
                        _ => return,
                    };
                    let actor = if pid <= 4 { f.opener } else { pid };
                    let _ = file_tx.send(RawEvent::File {
                        pid: Some(actor),
                        path: f.path.clone(),
                        op,
                        at: Instant::now(),
                        source: EventSource::Etw,
                    });
                }
                _ => {}
            }
            if st.parse_errors == 50 {
                log::warn!(
                    "ETW: многие события Kernel-File не разбираются — проверьте версию Windows"
                );
                st.parse_errors += 1;
            }
        };

        let proc_tx = tx;
        let proc_cb = move |record: &EventRecord, locator: &SchemaLocator| {
            if record.event_id() != 1 {
                return;
            }
            let Ok(schema) = locator.event_schema(record) else {
                return;
            };
            let parser = Parser::create(record, &schema);
            let (Ok(pid), Ok(parent), Ok(image)) = (
                parser.try_parse::<u32>("ProcessID"),
                parser.try_parse::<u32>("ParentProcessID"),
                parser.try_parse::<String>("ImageName"),
            ) else {
                return;
            };
            let _ = proc_tx.send(RawEvent::ProcessStart {
                pid,
                parent,
                image,
                at: Instant::now(),
            });
        };

        let file_provider = Provider::by_guid(KERNEL_FILE)
            .any(KW_FILENAME | KW_FILEIO | KW_CREATE | KW_WRITE | KW_CREATE_NEW_FILE)
            .add_callback(file_cb)
            .build();
        let process_provider = Provider::by_guid(KERNEL_PROCESS)
            .any(KW_PROCESS)
            .add_callback(proc_cb)
            .build();

        let trace = UserTrace::new()
            .named(TRACE_NAME.to_string())
            .enable(file_provider)
            .enable(process_provider)
            .start_and_process()
            .map_err(|e| anyhow!("не удалось запустить ETW-сессию: {e:?}"))?;
        Ok(Self { _trace: trace })
    }
}
