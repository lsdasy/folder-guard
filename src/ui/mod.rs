//! Интерфейс на egui: главное окно с разделами и окно критической тревоги.

mod alert;
mod pages;
pub mod theme;

use std::time::{Duration, Instant};

use egui::{Color32, CornerRadius, Frame, Margin, RichText, Stroke, Vec2};

use crate::config::Config;
use crate::engine::EngineHandle;
use crate::model::{Command, IncidentState, MonitorMode, Notice, Severity};
use theme::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page {
    Overview,
    Journal,
    Folders,
    Whitelist,
    Backups,
    Settings,
}

impl Page {
    const ALL: [Page; 6] = [
        Page::Overview,
        Page::Journal,
        Page::Folders,
        Page::Whitelist,
        Page::Backups,
        Page::Settings,
    ];

    fn title(self) -> &'static str {
        match self {
            Page::Overview => "Обзор",
            Page::Journal => "Журнал событий",
            Page::Folders => "Защищённые папки",
            Page::Whitelist => "Белый список",
            Page::Backups => "Резервные копии",
            Page::Settings => "Настройки",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogFilter {
    All,
    Threats,
    Warnings,
}

pub struct App {
    pub(crate) h: EngineHandle,
    pub(crate) page: Page,
    /// Редактируемая копия настроек; применяется кнопкой «Сохранить».
    pub(crate) draft: Config,
    /// Настройки, какими их видели в прошлый раз (чтобы подхватывать изменения от движка).
    last_config: Config,
    pub(crate) alert: Option<i64>,
    pub(crate) selected_incident: Option<i64>,
    pub(crate) log_filter: LogFilter,
    pub(crate) new_whitelist: String,
    pub(crate) new_excluded: String,
    pub(crate) toast: Option<(String, Instant)>,
    pub(crate) autostart: bool,
    pub(crate) seen_log: usize,
    hidden: bool,
    quitting: bool,
    #[cfg(windows)]
    tray: Option<crate::tray::Tray>,
}

pub fn run(h: EngineHandle, start_minimized: bool, start_page: Option<&str>) -> anyhow::Result<()> {
    let page = match start_page {
        Some("journal") => Page::Journal,
        Some("folders") => Page::Folders,
        Some("whitelist") => Page::Whitelist,
        Some("backups") => Page::Backups,
        Some("settings") => Page::Settings,
        _ => Page::Overview,
    };
    let icon = egui::IconData {
        rgba: crate::icon::shield_rgba(64, crate::icon::GREEN, false),
        width: 64,
        height: 64,
    };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Folder Guard")
            .with_inner_size([1120.0, 720.0])
            .with_min_inner_size([900.0, 560.0])
            .with_icon(icon)
            .with_visible(!start_minimized),
        ..Default::default()
    };
    eframe::run_native(
        "Folder Guard",
        options,
        Box::new(move |cc| {
            theme::setup(&cc.egui_ctx);
            let ctx = cc.egui_ctx.clone();
            *h.repaint.write() = Some(Box::new(move || ctx.request_repaint()));
            let mut app = App::new(h, &cc.egui_ctx, start_minimized);
            app.page = page;
            Ok(Box::new(app))
        }),
    )
    .map_err(|e| anyhow::anyhow!("окно не создано: {e}"))
}

impl App {
    fn new(h: EngineHandle, ctx: &egui::Context, hidden: bool) -> Self {
        let draft = h.config.read().clone();
        #[cfg(windows)]
        let tray = {
            let c = ctx.clone();
            match crate::tray::Tray::new(move || c.request_repaint()) {
                Ok(t) => Some(t),
                Err(e) => {
                    log::error!("значок в трее не создан: {e:#}");
                    None
                }
            }
        };
        #[cfg(not(windows))]
        let _ = ctx;
        let seen_log = h.state.read().log.len();
        Self {
            h,
            page: Page::Overview,
            last_config: draft.clone(),
            draft,
            alert: None,
            selected_incident: None,
            log_filter: LogFilter::All,
            new_whitelist: String::new(),
            new_excluded: String::new(),
            toast: None,
            autostart: crate::platform::autostart_enabled(),
            seen_log,
            hidden,
            quitting: false,
            #[cfg(windows)]
            tray,
        }
    }

    fn has_tray(&self) -> bool {
        #[cfg(windows)]
        {
            self.tray.is_some()
        }
        #[cfg(not(windows))]
        {
            false
        }
    }

    pub(crate) fn send(&self, c: Command) {
        self.h.send(c);
    }

    pub(crate) fn flash(&mut self, msg: impl Into<String>) {
        self.toast = Some((msg.into(), Instant::now()));
    }

    pub(crate) fn config_dirty(&self) -> bool {
        self.draft != *self.h.config.read()
    }

    pub(crate) fn save_config(&mut self) {
        self.send(Command::ApplyConfig(Box::new(self.draft.clone())));
        // Сразу считаем сохранённым, чтобы плашка не мигала до ответа движка.
        *self.h.config.write() = self.draft.clone();
        self.last_config = self.draft.clone();
        self.flash("Настройки сохранены");
    }

    fn show_window(&mut self, ctx: &egui::Context) {
        self.hidden = false;
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }

    fn handle_notices(&mut self, ctx: &egui::Context) {
        while let Ok(n) = self.h.notices.try_recv() {
            match n {
                Notice::IncidentOpened { id, severity } => {
                    // Подозрительное — только уведомление Windows (оно с кнопками).
                    // Критическое или «Подробнее» — окно тревоги поверх всех окон.
                    let open_window = severity == Severity::Critical || !cfg!(windows);
                    if open_window {
                        self.alert = Some(id);
                        self.selected_incident = Some(id);
                        self.show_window(ctx);
                    }
                }
                Notice::IncidentClosed { id } => {
                    if self.alert == Some(id) {
                        self.alert = None;
                    }
                }
            }
        }
    }

    #[cfg(windows)]
    fn handle_tray(&mut self, ctx: &egui::Context) {
        use crate::tray::{TrayAction, TrayStatus};
        let Some(tray) = &self.tray else { return };
        let actions = tray.poll();
        for a in actions {
            match a {
                TrayAction::Open => {
                    self.page = Page::Overview;
                    self.show_window(ctx);
                }
                TrayAction::Journal => {
                    self.page = Page::Journal;
                    self.show_window(ctx);
                }
                TrayAction::Restore => {
                    self.page = Page::Backups;
                    self.show_window(ctx);
                }
                TrayAction::CheckCanaries => self.send(Command::VerifyCanaries),
                TrayAction::ToggleDnd => {
                    let mut cfg = self.h.config.read().clone();
                    cfg.notifications = !cfg.notifications;
                    self.draft.notifications = cfg.notifications;
                    self.send(Command::ApplyConfig(Box::new(cfg.clone())));
                    *self.h.config.write() = cfg;
                }
                TrayAction::PauseOrResume => {
                    if self.h.state.read().paused_until.is_some() {
                        self.send(Command::Resume);
                    } else {
                        self.send(Command::PauseFor(Duration::from_secs(15 * 60)));
                    }
                }
                TrayAction::Quit => {
                    self.quitting = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }
        let st = self.h.state.read();
        let (status, header) = if st.pending_incident().is_some() {
            (TrayStatus::Alarm, "Обнаружена угроза".to_string())
        } else if st.paused_until.is_some() {
            (TrayStatus::Warning, "Защита приостановлена".to_string())
        } else if st.mode != MonitorMode::Full {
            (TrayStatus::Warning, "Ограниченная защита".to_string())
        } else {
            (TrayStatus::Ok, "Защита активна".to_string())
        };
        let paused = st.paused_until.is_some();
        let new_events = st.log.len().saturating_sub(self.seen_log);
        drop(st);
        let dnd = !self.h.config.read().notifications;
        if let Some(tray) = &mut self.tray {
            tray.update(status, &header, paused, dnd, new_events);
        }
    }

    fn sidebar(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        for page in Page::ALL {
            let selected = self.page == page;
            let text = RichText::new(page.title()).size(13.0).color(if selected {
                TEXT
            } else {
                Color32::from_rgb(0xb4, 0xb4, 0xbc)
            });
            let text = if selected { text.family(bold()) } else { text };
            let mut btn = egui::Button::new(text)
                .min_size(Vec2::new(ui.available_width(), 36.0))
                .stroke(Stroke::NONE);
            btn = btn.fill(if selected {
                BUTTON
            } else {
                Color32::TRANSPARENT
            });
            let mut resp = ui.add(btn);
            // Счётчик новых угроз у «Журнала».
            if page == Page::Journal {
                let pending = self
                    .h
                    .state
                    .read()
                    .incidents
                    .iter()
                    .filter(|i| i.state == IncidentState::AwaitingDecision)
                    .count();
                if pending > 0 {
                    let c = egui::pos2(resp.rect.right() - 18.0, resp.rect.center().y);
                    ui.painter().circle_filled(c, 9.0, DANGER_BUTTON);
                    ui.painter().text(
                        c,
                        egui::Align2::CENTER_CENTER,
                        pending.to_string(),
                        egui::FontId::proportional(11.0),
                        Color32::WHITE,
                    );
                }
            }
            if resp.clicked() {
                self.page = page;
                if page == Page::Journal {
                    self.seen_log = self.h.state.read().log.len();
                }
            }
            resp = resp.on_hover_cursor(egui::CursorIcon::PointingHand);
            let _ = resp;
        }
        ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
            ui.add_space(8.0);
            let st = self.h.state.read();
            let mode = match st.mode {
                MonitorMode::Full => "Режим: ETW, админ",
                MonitorMode::Limited => "Режим: ограниченный",
                MonitorMode::Starting => "Режим: запуск…",
            };
            let service = if st.paused_until.is_some() {
                "Защита: на паузе"
            } else {
                "Защита: работает"
            };
            ui.label(caption(format!(
                "Folder Guard {}",
                env!("CARGO_PKG_VERSION")
            )));
            ui.label(caption(mode));
            ui.label(caption(service));
        });
    }
}

impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.handle_notices(ctx);
        #[cfg(windows)]
        self.handle_tray(ctx);

        // Крестик сворачивает в трей, а не закрывает программу.
        if ctx.input(|i| i.viewport().close_requested()) && !self.quitting && self.has_tray() {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            self.hidden = true;
            self.alert = None;
        }
        // Движок мог изменить настройки сам (например, «Разрешить всегда» добавляет в белый список).
        // Если пользователь черновик не трогал — подхватываем изменения.
        let current = self.h.config.read().clone();
        if current != self.last_config {
            if self.draft == self.last_config {
                self.draft = current.clone();
            }
            self.last_config = current;
        }
        if !self.hidden {
            ctx.request_repaint_after(Duration::from_millis(500));
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        egui::Panel::left("sidebar")
            .exact_size(220.0)
            .resizable(false)
            .frame(
                Frame::new()
                    .fill(SIDEBAR)
                    .inner_margin(Margin::symmetric(12, 16))
                    .stroke(Stroke::new(1.0, DIVIDER)),
            )
            .show(ui, |ui| self.sidebar(ui));

        let dirty = self.config_dirty()
            && matches!(
                self.page,
                Page::Folders | Page::Whitelist | Page::Backups | Page::Settings
            );
        if dirty {
            egui::Panel::bottom("savebar")
                .frame(
                    Frame::new()
                        .fill(CARD)
                        .inner_margin(Margin::symmetric(28, 10))
                        .stroke(Stroke::new(1.0, CARD_BORDER)),
                )
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Есть несохранённые изменения").color(WARN_TEXT));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if accent_button(ui, "Сохранить").clicked() {
                                self.save_config();
                            }
                            if button(ui, "Отменить").clicked() {
                                self.draft = self.h.config.read().clone();
                            }
                        });
                    });
                });
        }

        egui::CentralPanel::default()
            .frame(
                Frame::new()
                    .fill(BG)
                    .inner_margin(Margin::symmetric(28, 24)),
            )
            .show(ui, |ui| match self.page {
                Page::Overview => pages::overview(self, ui),
                Page::Journal => pages::journal(self, ui),
                Page::Folders => pages::folders(self, ui),
                Page::Whitelist => pages::whitelist(self, ui),
                Page::Backups => pages::backups(self, ui),
                Page::Settings => pages::settings(self, ui),
            });

        // Всплывающая подсказка внизу («Настройки сохранены»).
        if let Some((msg, at)) = &self.toast {
            if at.elapsed() < Duration::from_secs(3) {
                egui::Area::new(egui::Id::unique("flash"))
                    .anchor(egui::Align2::CENTER_BOTTOM, Vec2::new(110.0, -24.0))
                    .show(&ctx, |ui| {
                        Frame::new()
                            .fill(Color32::from_rgb(0x2b, 0x2b, 0x30))
                            .stroke(Stroke::new(1.0, BUTTON_BORDER))
                            .corner_radius(CornerRadius::same(8))
                            .inner_margin(Margin::symmetric(16, 10))
                            .show(ui, |ui| ui.label(msg.as_str()));
                    });
            } else {
                self.toast = None;
            }
        }

        alert::show(self, &ctx);
    }
}
