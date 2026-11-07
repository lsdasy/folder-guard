//! Иконка в области уведомлений и её меню (как на макете «Меню в трее»).

use anyhow::Result;
use crossbeam_channel::{Receiver, unbounded};
use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

use crate::icon;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrayAction {
    Open,
    Journal,
    Restore,
    CheckCanaries,
    ToggleDnd,
    PauseOrResume,
    Quit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrayStatus {
    Ok,
    Warning,
    Alarm,
}

pub struct Tray {
    icon: TrayIcon,
    header: MenuItem,
    journal: MenuItem,
    pause: MenuItem,
    dnd: CheckMenuItem,
    status: Option<TrayStatus>,
    rx: Receiver<TrayAction>,
}

fn make_icon(status: TrayStatus) -> Result<Icon> {
    let (color, excl) = match status {
        TrayStatus::Ok => (icon::GREEN, false),
        TrayStatus::Warning => (icon::YELLOW, true),
        TrayStatus::Alarm => (icon::RED, true),
    };
    Ok(Icon::from_rgba(icon::shield_rgba(32, color, excl), 32, 32)?)
}

impl Tray {
    /// `wake` вызывается из обработчиков меню, чтобы интерфейс обработал действие даже свёрнутым.
    pub fn new(wake: impl Fn() + Send + Sync + Clone + 'static) -> Result<Self> {
        let header = MenuItem::with_id("header", "Защита активна", false, None);
        let open = MenuItem::with_id("open", "Открыть Folder Guard", true, None);
        let journal = MenuItem::with_id("journal", "Журнал событий", true, None);
        let restore = MenuItem::with_id("restore", "Восстановить файлы…", true, None);
        let canaries = MenuItem::with_id("canaries", "Проверить приманки сейчас", true, None);
        let dnd = CheckMenuItem::with_id("dnd", "Режим «не беспокоить»", true, false, None);
        let pause = MenuItem::with_id("pause", "Приостановить защиту на 15 минут", true, None);
        let quit = MenuItem::with_id("quit", "Выход", true, None);

        let menu = Menu::new();
        menu.append_items(&[
            &header,
            &PredefinedMenuItem::separator(),
            &open,
            &journal,
            &restore,
            &canaries,
            &PredefinedMenuItem::separator(),
            &dnd,
            &pause,
            &quit,
        ])?;

        let icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_menu_on_left_click(false)
            .with_tooltip("Folder Guard — защита активна")
            .with_icon(make_icon(TrayStatus::Ok)?)
            .build()?;

        let (tx, rx) = unbounded();
        let menu_tx = tx.clone();
        let menu_wake = wake.clone();
        MenuEvent::set_event_handler(Some(move |e: MenuEvent| {
            let action = match e.id.0.as_str() {
                "open" => TrayAction::Open,
                "journal" => TrayAction::Journal,
                "restore" => TrayAction::Restore,
                "canaries" => TrayAction::CheckCanaries,
                "dnd" => TrayAction::ToggleDnd,
                "pause" => TrayAction::PauseOrResume,
                "quit" => TrayAction::Quit,
                _ => return,
            };
            let _ = menu_tx.send(action);
            menu_wake();
        }));
        TrayIconEvent::set_event_handler(Some(move |e: TrayIconEvent| {
            let open = matches!(
                e,
                TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } | TrayIconEvent::DoubleClick {
                    button: MouseButton::Left,
                    ..
                }
            );
            if open {
                let _ = tx.send(TrayAction::Open);
                wake();
            }
        }));

        Ok(Self {
            icon,
            header,
            journal,
            pause,
            dnd,
            status: Some(TrayStatus::Ok),
            rx,
        })
    }

    pub fn poll(&self) -> Vec<TrayAction> {
        self.rx.try_iter().collect()
    }

    pub fn update(
        &mut self,
        status: TrayStatus,
        header: &str,
        paused: bool,
        dnd: bool,
        new_events: usize,
    ) {
        if self.status != Some(status) {
            if let Ok(i) = make_icon(status) {
                let _ = self.icon.set_icon(Some(i));
            }
            self.status = Some(status);
        }
        self.header.set_text(header);
        let _ = self
            .icon
            .set_tooltip(Some(format!("Folder Guard — {}", header.to_lowercase())));
        self.pause.set_text(if paused {
            "Возобновить защиту"
        } else {
            "Приостановить защиту на 15 минут"
        });
        self.dnd.set_checked(dnd);
        self.journal.set_text(if new_events > 0 {
            format!("Журнал событий ({new_events} новых)")
        } else {
            "Журнал событий".to_string()
        });
    }
}
