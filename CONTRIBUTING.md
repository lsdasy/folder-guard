# Как помочь проекту

Спасибо за интерес к Folder Guard! Ниже — как собрать проект, проверить изменения и прислать их.

## Окружение

- Windows 10/11, [Rust](https://rustup.rs) 1.95 или новее;
- Visual Studio Build Tools с компонентом «Разработка классических приложений на C++».

Ядро и интерфейс собираются и на Linux: так удобно писать тесты.
Код, зависящий от Windows, лежит в `src/platform/windows.rs`, `src/monitor/etw.rs` и `src/tray.rs`.

## Перед отправкой изменений

```powershell
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
```

То же самое автоматически проверяет CI на Windows и Linux.

Если меняется логика обнаружения, проверьте на симуляторе (лучше в виртуальной машине):

```powershell
cargo build --release
.\target\release\ransim.exe init C:\fg-test
Start-Process .\target\release\folder-guard.exe -Verb RunAs -ArgumentList '--protect','C:\fg-test','--data-dir','C:\fg-test-data'
.\target\release\ransim.exe attack C:\fg-test
```

## Правила

- Одна задача — один pull request. Опишите, что меняется и как вы это проверили.
- Новая логика — с тестами. Для движка есть пример полного цикла в `engine::tests`.
- Комментарии и тексты интерфейса — на русском, как в остальном коде.
- Не добавляйте в репозиторий настоящие образцы вредоносных программ, даже «обезвреженные».
- Уязвимости — не в issues, а по инструкции из [SECURITY.md](SECURITY.md).

## Выпуск новой версии (для сопровождающих)

1. Обновить `version` в `Cargo.toml` и раздел в `CHANGELOG.md`.
2. Закоммитить и поставить тег: `git tag v0.2.0 && git push origin v0.2.0`.
3. GitHub Actions соберёт exe, архив и контрольные суммы и создаст релиз.
   Текст релиза берётся из раздела CHANGELOG.

## Лицензия

Присылая изменения, вы соглашаетесь распространять их на условиях лицензий проекта
(MIT или Apache-2.0 на выбор пользователя).
