//! Безопасный симулятор шифровальщика для проверки Folder Guard.
//!
//! Работает ТОЛЬКО в папке-песочнице, которую создал сам (в ней лежит файл-метка).
//! Шаги:
//!   ransim init  <папка>   — создать песочницу с тестовыми документами
//!   ransim attack <папка>  — «зашифровать» их: перезаписать случайными байтами,
//!                            переименовать в .locked, оставить записки
//!
//! Запускайте в виртуальной машине или хотя бы на тестовой папке.
//! Никаких настоящих данных утилита не трогает и не умеет трогать.

use std::path::{Path, PathBuf};
use std::time::Duration;

const MARKER: &str = ".folder-guard-sandbox";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (Some(cmd), Some(dir)) = (args.get(1), args.get(2)) else {
        eprintln!("использование: ransim init|attack <папка-песочница> [--delay-ms N]");
        std::process::exit(2);
    };
    let delay = args
        .iter()
        .position(|a| a == "--delay-ms")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(50);
    let dir = PathBuf::from(dir);
    let result = match cmd.as_str() {
        "init" => init(&dir),
        "attack" => attack(&dir, Duration::from_millis(delay)),
        _ => Err("неизвестная команда".to_string()),
    };
    if let Err(e) = result {
        eprintln!("ошибка: {e}");
        std::process::exit(1);
    }
}

fn init(dir: &Path) -> Result<(), String> {
    if dir.exists()
        && std::fs::read_dir(dir)
            .map_err(|e| e.to_string())?
            .next()
            .is_some()
        && !dir.join(MARKER).exists()
    {
        return Err("папка не пуста и не является песочницей — откажусь её использовать".into());
    }
    std::fs::create_dir_all(dir.join("Проекты")).map_err(|e| e.to_string())?;
    std::fs::write(
        dir.join(MARKER),
        "Песочница симулятора Folder Guard. Можно удалить.",
    )
    .map_err(|e| e.to_string())?;
    for i in 1..=30 {
        let sub = if i % 3 == 0 {
            dir.join("Проекты")
        } else {
            dir.to_path_buf()
        };
        let text = format!("Документ {i}. Глава 1. Введение.\n").repeat(200);
        std::fs::write(sub.join(format!("документ_{i:02}.txt")), text)
            .map_err(|e| e.to_string())?;
        let mut docx = b"PK\x03\x04".to_vec();
        docx.extend(format!("word/document.xml {i} ").repeat(300).bytes());
        std::fs::write(sub.join(format!("отчёт_{i:02}.docx")), docx).map_err(|e| e.to_string())?;
    }
    println!("песочница готова: {}", dir.display());
    Ok(())
}

fn attack(dir: &Path, delay: Duration) -> Result<(), String> {
    if !dir.join(MARKER).exists() {
        return Err("это не песочница (нет файла-метки). Сначала: ransim init <папка>".into());
    }
    println!("PID симулятора: {}", std::process::id());
    let mut files: Vec<PathBuf> = walk(dir);
    files.sort(); // как настоящий шифровальщик — по алфавиту, приманки с «!» окажутся первыми
    for (n, f) in files.iter().enumerate() {
        if f.file_name().is_some_and(|n| n == MARKER) {
            continue;
        }
        let len = std::fs::metadata(f).map(|m| m.len()).unwrap_or(0).max(1024) as usize;
        let mut junk = vec![0u8; len];
        rand::fill(&mut junk[..]);
        if std::fs::write(f, &junk).is_err() {
            continue;
        }
        let locked = PathBuf::from(format!("{}.locked", f.display()));
        let _ = std::fs::rename(f, &locked);
        if n % 10 == 0
            && let Some(parent) = f.parent()
        {
            let _ = std::fs::write(
                parent.join("HOW_TO_DECRYPT.txt"),
                "Это учебная записка симулятора Folder Guard.",
            );
        }
        println!("зашифрован {}", f.display());
        std::thread::sleep(delay);
    }
    println!("симуляция завершена");
    Ok(())
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}
