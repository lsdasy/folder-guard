//! Анализ содержимого и имён файлов: энтропия, «магические байты»,
//! подозрительные переименования и записки с требованием выкупа.

use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Сколько байт файла читаем для анализа.
pub const SAMPLE_SIZE: usize = 64 * 1024;

/// Порог, выше которого данные выглядят как шифрованные/сжатые (максимум — 8 бит/байт).
pub const HIGH_ENTROPY: f64 = 7.5;

/// Энтропия Шеннона в битах на байт.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Результат анализа файла после записи.
#[derive(Debug, Clone, PartialEq)]
pub struct ContentReport {
    pub entropy: f64,
    pub size: u64,
    /// Ожидаемая сигнатура для расширения есть, но не совпала.
    pub header_broken: bool,
    /// Для этого типа файлов высокая энтропия ненормальна (текст, исходники...).
    pub unexpected_high_entropy: bool,
}

pub fn analyze_file(path: &Path) -> std::io::Result<ContentReport> {
    let mut f = File::open(path)?;
    let size = f.metadata()?.len();
    let mut buf = vec![0u8; SAMPLE_SIZE.min(size as usize)];
    f.read_exact(&mut buf)?;
    Ok(analyze_bytes(path, &buf, size))
}

pub fn analyze_bytes(path: &Path, data: &[u8], size: u64) -> ContentReport {
    let entropy = shannon_entropy(data);
    let ext = extension_lower(path);
    let header_broken = match expected_magic(&ext) {
        Some(sigs) if !data.is_empty() => !sigs.iter().any(|sig| data.starts_with(sig)),
        _ => false,
    };
    // На маленьких файлах энтропия ненадёжна: 100 случайных байт не дадут 7.5.
    let enough_data = data.len() >= 512;
    let unexpected_high_entropy =
        enough_data && entropy >= HIGH_ENTROPY && is_low_entropy_type(&ext);
    ContentReport {
        entropy,
        size,
        header_broken,
        unexpected_high_entropy,
    }
}

pub fn extension_lower(path: &Path) -> String {
    path.extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default()
}

/// Сигнатуры начала файла для популярных форматов.
pub fn expected_magic(ext: &str) -> Option<&'static [&'static [u8]]> {
    const ZIP: &[&[u8]] = &[b"PK\x03\x04", b"PK\x05\x06"];
    const PDF: &[&[u8]] = &[b"%PDF"];
    const PNG: &[&[u8]] = &[b"\x89PNG\r\n\x1a\n"];
    const JPG: &[&[u8]] = &[b"\xFF\xD8\xFF"];
    const GIF: &[&[u8]] = &[b"GIF87a", b"GIF89a"];
    const OLE: &[&[u8]] = &[b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"];
    const RAR: &[&[u8]] = &[b"Rar!\x1A\x07"];
    const SEVENZ: &[&[u8]] = &[b"7z\xBC\xAF\x27\x1C"];
    const BMP: &[&[u8]] = &[b"BM"];
    const SQLITE: &[&[u8]] = &[b"SQLite format 3\0"];
    const MP3: &[&[u8]] = &[b"ID3", b"\xFF\xFB", b"\xFF\xF3", b"\xFF\xF2"];
    const WEBP_RIFF: &[&[u8]] = &[b"RIFF"];
    Some(match ext {
        "docx" | "xlsx" | "pptx" | "zip" | "odt" | "ods" | "odp" | "jar" | "apk" | "epub" => ZIP,
        "pdf" => PDF,
        "png" => PNG,
        "jpg" | "jpeg" => JPG,
        "gif" => GIF,
        "doc" | "xls" | "ppt" | "msi" => OLE,
        "rar" => RAR,
        "7z" => SEVENZ,
        "bmp" => BMP,
        "sqlite" | "db" | "sqlite3" => SQLITE,
        "mp3" => MP3,
        "wav" | "avi" | "webp" => WEBP_RIFF,
        _ => return None,
    })
}

/// Типы, у которых в норме низкая энтропия (текст).
pub fn is_low_entropy_type(ext: &str) -> bool {
    matches!(
        ext,
        "txt"
            | "md"
            | "csv"
            | "json"
            | "xml"
            | "html"
            | "htm"
            | "css"
            | "js"
            | "ts"
            | "rs"
            | "go"
            | "py"
            | "c"
            | "cpp"
            | "h"
            | "hpp"
            | "cs"
            | "java"
            | "kt"
            | "sql"
            | "log"
            | "ini"
            | "toml"
            | "yaml"
            | "yml"
            | "rtf"
            | "tex"
            | "bat"
            | "ps1"
            | "sh"
            | "svg"
            | "php"
            | "rb"
            | "lua"
    )
}

/// Расширения, которые знает обычный пользователь. Переименование в неизвестное расширение подозрительно.
pub fn is_known_extension(ext: &str) -> bool {
    expected_magic(ext).is_some()
        || is_low_entropy_type(ext)
        || matches!(
            ext,
            "mp4"
                | "mkv"
                | "mov"
                | "webm"
                | "flac"
                | "ogg"
                | "m4a"
                | "psd"
                | "ai"
                | "exe"
                | "dll"
                | "iso"
                | "lnk"
                | "url"
                | "tmp"
                | "bak"
                | "old"
                | "part"
                | "crdownload"
                | "torrent"
                | "ttf"
                | "otf"
                | "woff"
                | "woff2"
                | "ico"
                | "tif"
                | "tiff"
                | "heic"
                | "raw"
                | "cr2"
                | "nef"
                | "dwg"
                | "blend"
                | "obj"
                | "stl"
                | "fbx"
                | "gz"
                | "tar"
                | "xz"
                | "bz2"
                | "zst"
                | "wasm"
                | "dat"
                | "bin"
                | "cfg"
                | "conf"
                | "lock"
        )
}

/// Подозрительное переименование: у файла было знакомое расширение,
/// а стало неизвестное (`отчёт.docx` → `отчёт.docx.locked`, `фото.jpg` → `фото.jpg.k3x9`).
pub fn is_suspicious_rename(from: &Path, to: &Path) -> bool {
    let old_ext = extension_lower(from);
    let new_ext = extension_lower(to);
    if old_ext == new_ext || old_ext.is_empty() || !is_known_extension(&old_ext) {
        return false;
    }
    !is_known_extension(&new_ext)
}

/// Похоже ли имя на записку с требованием выкупа.
pub fn looks_like_ransom_note(path: &Path) -> bool {
    let ext = extension_lower(path);
    if !matches!(ext.as_str(), "txt" | "html" | "htm" | "hta" | "url" | "rtf") {
        return false;
    }
    let name = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let keys = [
        "decrypt",
        "restore",
        "recover",
        "ransom",
        "how_to",
        "how-to",
        "howto",
        "readme_for",
        "unlock",
        "your_files",
        "encrypted",
        "расшифр",
        "восстанов",
    ];
    keys.iter().any(|k| name.contains(k))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn entropy_bounds() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        assert_eq!(shannon_entropy(&[7u8; 1000]), 0.0);
        let all: Vec<u8> = (0..=255u8).cycle().take(256 * 64).collect();
        assert!((shannon_entropy(&all) - 8.0).abs() < 1e-9);
        let text = "Привет, это обычный текст курсовой работы. ".repeat(200);
        assert!(shannon_entropy(text.as_bytes()) < 5.5);
    }

    #[test]
    fn random_data_in_text_file_is_suspicious() {
        let mut data = vec![0u8; 8192];
        rand::fill(&mut data[..]);
        let r = analyze_bytes(Path::new("notes.md"), &data, 8192);
        assert!(r.unexpected_high_entropy);
        let r = analyze_bytes(Path::new("archive.zip"), &data, 8192);
        assert!(
            !r.unexpected_high_entropy,
            "у архивов высокая энтропия — это норма"
        );
        assert!(r.header_broken, "но сигнатура zip должна быть");
    }

    #[test]
    fn magic_bytes() {
        let docx = b"PK\x03\x04restofzip";
        assert!(!analyze_bytes(Path::new("a.docx"), docx, 10).header_broken);
        assert!(analyze_bytes(Path::new("a.docx"), b"\x13\x37garbage", 10).header_broken);
        assert!(!analyze_bytes(Path::new("a.unknownext"), b"\x13\x37", 2).header_broken);
    }

    #[test]
    fn renames() {
        let p = |s: &str| PathBuf::from(s);
        assert!(is_suspicious_rename(
            &p("курсовая.docx"),
            &p("курсовая.docx.locked")
        ));
        assert!(is_suspicious_rename(&p("photo.jpg"), &p("photo.jpg.k3x9z")));
        assert!(!is_suspicious_rename(&p("photo.jpg"), &p("photo2.jpg")));
        assert!(!is_suspicious_rename(&p("draft.tmp"), &p("draft.docx")));
        assert!(!is_suspicious_rename(&p("report.docx"), &p("report.pdf")));
    }

    #[test]
    fn ransom_notes() {
        assert!(looks_like_ransom_note(Path::new("HOW_TO_DECRYPT.txt")));
        assert!(looks_like_ransom_note(Path::new("Restore-My-Files.html")));
        assert!(!looks_like_ransom_note(Path::new("README.md")));
        assert!(!looks_like_ransom_note(Path::new("restore.exe")));
    }
}
