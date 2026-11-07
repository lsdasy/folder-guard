//! Файлы-приманки. Кладутся в каждую защищённую папку; пользователь их не трогает,
//! поэтому любое изменение — почти наверняка работа шифровальщика.
//!
//! Имена подобраны так, чтобы при обходе папки по алфавиту приманки шли
//! первыми (`!`) и последними (`zz`): шифровальщик наткнётся на них раньше,
//! чем на настоящие документы, или хотя бы до конца обхода.

use std::path::{Path, PathBuf};

use anyhow::Result;

pub const CANARY_NAMES: [&str; 3] = [
    "!000_FolderGuard_важное.docx",
    "!001_FolderGuard_notes.txt",
    "zz_FolderGuard_архив.xlsx",
];

/// Содержимое приманки. Детерминировано, чтобы проверять целостность без хранения хешей.
pub fn canary_content(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    if name.ends_with(".docx") || name.ends_with(".xlsx") {
        // Начало как у настоящего Office-файла (zip), чтобы шифровальщик не пропустил его.
        out.extend_from_slice(b"PK\x03\x04\x14\x00\x06\x00");
    }
    let text = "Folder Guard: это файл-приманка. Не изменяйте, не переименовывайте и не удаляйте его.\n\
                Если вы видите этот файл — защита от шифровальщиков работает.\n";
    while out.len() < 4096 {
        out.extend_from_slice(text.as_bytes());
    }
    out
}

pub fn is_canary_name(path: &Path) -> bool {
    path.file_name()
        .map(|n| n.to_string_lossy())
        .is_some_and(|n| CANARY_NAMES.iter().any(|c| *c == n))
}

#[derive(Debug, Clone, PartialEq)]
pub enum CanaryProblem {
    Missing(PathBuf),
    Modified(PathBuf),
}

#[derive(Debug, Default, Clone)]
pub struct CanaryReport {
    pub total: usize,
    pub ok: usize,
    pub problems: Vec<CanaryProblem>,
}

pub fn canary_paths(folders: &[PathBuf]) -> Vec<PathBuf> {
    folders
        .iter()
        .flat_map(|f| CANARY_NAMES.iter().map(move |n| f.join(n)))
        .collect()
}

/// Создаёт отсутствующие приманки (существующие не трогает).
pub fn ensure(folders: &[PathBuf], hidden: bool) -> Result<usize> {
    let mut created = 0;
    for path in canary_paths(folders) {
        if path.parent().is_some_and(|p| !p.exists()) {
            continue;
        }
        if !path.exists() {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            std::fs::write(&path, canary_content(&name))?;
            if hidden {
                crate::platform::set_hidden(&path);
            }
            created += 1;
        }
    }
    Ok(created)
}

/// Перезаписывает приманку эталонным содержимым (после инцидента).
pub fn repair(path: &Path, hidden: bool) -> Result<()> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if path.exists() {
        crate::platform::clear_readonly_hidden(path);
    }
    std::fs::write(path, canary_content(&name))?;
    if hidden {
        crate::platform::set_hidden(path);
    }
    Ok(())
}

pub fn verify(folders: &[PathBuf]) -> CanaryReport {
    let mut report = CanaryReport::default();
    for path in canary_paths(folders) {
        if path.parent().is_some_and(|p| !p.exists()) {
            continue;
        }
        report.total += 1;
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        match std::fs::read(&path) {
            Ok(data) if data == canary_content(&name) => report.ok += 1,
            Ok(_) => report.problems.push(CanaryProblem::Modified(path)),
            Err(_) => report.problems.push(CanaryProblem::Missing(path)),
        }
    }
    report
}

/// Удаляет приманки из папки (когда её убирают из защищённых).
pub fn remove_from(folder: &Path) {
    for n in CANARY_NAMES {
        let p = folder.join(n);
        if p.exists() {
            crate::platform::clear_readonly_hidden(&p);
            let _ = std::fs::remove_file(p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_verify_detect() {
        let dir = std::env::temp_dir().join(format!("fg-canary-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let folders = vec![dir.clone()];
        assert_eq!(ensure(&folders, false).unwrap(), 3);
        assert_eq!(ensure(&folders, false).unwrap(), 0);
        let r = verify(&folders);
        assert_eq!((r.total, r.ok), (3, 3));

        let victim = dir.join(CANARY_NAMES[1]);
        std::fs::write(&victim, b"encrypted!!!").unwrap();
        std::fs::remove_file(dir.join(CANARY_NAMES[0])).unwrap();
        let r = verify(&folders);
        assert_eq!(r.ok, 1);
        assert!(
            r.problems
                .contains(&CanaryProblem::Modified(victim.clone()))
        );

        repair(&victim, false).unwrap();
        ensure(&folders, false).unwrap();
        assert_eq!(verify(&folders).ok, 3);
        assert!(is_canary_name(&victim));
        assert!(!is_canary_name(Path::new("/x/report.docx")));
        let _ = std::fs::remove_dir_all(dir);
    }
}
