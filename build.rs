//! Встраивает в exe ресурсы Windows: иконку, сведения о версии (вкладка «Подробно»
//! в свойствах файла) и манифест (обычные права, высокий DPI, длинные пути, UTF-8).
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/icon.ico");
    println!("cargo:rerun-if-changed=assets/folder-guard.manifest");
    println!("cargo:rerun-if-env-changed=FG_SKIP_RESOURCES");

    // Скрипт сборки работает на машине сборки, поэтому смотрим на ЦЕЛЕВУЮ систему.
    if std::env::var_os("CARGO_CFG_WINDOWS").is_none()
        || std::env::var_os("FG_SKIP_RESOURCES").is_some()
    {
        return;
    }
    let mut res = winresource::WindowsResource::new();
    res.set_icon("assets/icon.ico")
        .set_manifest_file("assets/folder-guard.manifest")
        .set("ProductName", "Folder Guard")
        .set(
            "FileDescription",
            "Folder Guard — защита папок от шифровальщиков",
        )
        .set("CompanyName", "Folder Guard")
        .set("LegalCopyright", "© 2026 Kir. MIT OR Apache-2.0")
        .set("OriginalFilename", "folder-guard.exe");
    // Только для основной программы: симулятору иконка щита ни к чему.
    if let Err(e) = res.compile_for("folder-guard") {
        panic!("не удалось встроить ресурсы Windows: {e}");
    }
}
