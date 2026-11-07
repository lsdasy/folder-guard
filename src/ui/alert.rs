//! Окно критической тревоги поверх всех окон (макет «Критическая тревога»).

use egui::{
    Color32, Frame, Margin, RichText, ScrollArea, ViewportBuilder, ViewportId, WindowLevel,
};

use super::App;
use super::pages::incident_details;
use super::theme::*;
use crate::model::{Command, Incident, IncidentState, Severity};

const ALERT_BG: Color32 = Color32::from_rgb(0x1f, 0x1f, 0x23);

pub fn show(app: &mut App, ctx: &egui::Context) {
    let Some(id) = app.alert else { return };
    let Some(inc) = app
        .h
        .state
        .read()
        .incidents
        .iter()
        .find(|i| i.id == id)
        .cloned()
    else {
        app.alert = None;
        return;
    };
    let icon = egui::IconData {
        rgba: crate::icon::shield_rgba(64, crate::icon::RED, true),
        width: 64,
        height: 64,
    };
    let builder = ViewportBuilder::default()
        .with_title("Folder Guard — тревога")
        .with_inner_size([500.0, 500.0])
        .with_resizable(false)
        .with_window_level(WindowLevel::AlwaysOnTop)
        .with_icon(icon);

    let mut close = false;
    ctx.show_viewport_immediate(ViewportId::from_hash_of("alert"), builder, |ui, _class| {
        if ui.ctx().input(|i| i.viewport().close_requested()) {
            close = true;
        }
        let critical = inc.severity == Severity::Critical;

        // Шапка.
        let head_fill = if critical {
            ALERT_BANNER
        } else {
            Color32::from_rgb(0x33, 0x2a, 0x1a)
        };
        egui::Panel::top("alert-head")
            .frame(
                Frame::new()
                    .fill(head_fill)
                    .inner_margin(Margin::symmetric(20, 18)),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    shield_badge(
                        ui,
                        ALERT_ICON_BG,
                        if critical { DANGER_TEXT } else { WARN },
                        false,
                        40.0,
                    );
                    ui.add_space(6.0);
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new(if critical {
                                "Похоже на шифровальщик"
                            } else {
                                "Подозрительная активность"
                            })
                            .size(16.0)
                            .family(bold()),
                        );
                        ui.add(
                            egui::Label::new(
                                RichText::new(subtitle_for(&inc))
                                    .size(13.0)
                                    .color(ALERT_TEXT),
                            )
                            .truncate(),
                        );
                    });
                });
            });

        // Действия — всегда видны внизу.
        egui::Panel::bottom("alert-actions")
            .frame(Frame::new().fill(ALERT_BG).inner_margin(Margin {
                left: 20,
                right: 20,
                top: 8,
                bottom: 18,
            }))
            .show(ui, |ui| {
                if let (IncidentState::AwaitingDecision, Some(deadline)) = (inc.state, inc.deadline)
                {
                    let left = (deadline - chrono::Local::now()).num_seconds().max(0);
                    ui.label(
                        RichText::new(format!(
                            "Процесс будет завершён через {left} с, если не выбрать действие"
                        ))
                        .size(13.0)
                        .color(WARN_TEXT),
                    );
                    ui.ctx()
                        .request_repaint_after(std::time::Duration::from_millis(250));
                } else {
                    ui.label(
                        RichText::new(format!("Состояние: {}", inc.state.label()))
                            .size(13.0)
                            .color(TEXT_DIM),
                    );
                }
                ui.add_space(10.0);
                let w = ui.available_width() - 16.0;
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 8.0;
                    if inc.state == IncidentState::AwaitingDecision {
                        if danger_button(ui, "Убить и восстановить файлы", w * 0.44).clicked()
                        {
                            app.send(Command::Kill {
                                incident: inc.id,
                                restore: true,
                            });
                            close = true;
                        }
                        if secondary_button(ui, "Разрешить", w * 0.28).clicked() {
                            app.send(Command::Allow {
                                incident: inc.id,
                                add_to_whitelist: false,
                            });
                            close = true;
                        }
                    } else {
                        if danger_button(ui, "Восстановить файлы", w * 0.44).clicked()
                        {
                            app.send(Command::Restore { incident: inc.id });
                            close = true;
                        }
                        if secondary_button(ui, "Закрыть", w * 0.28).clicked() {
                            close = true;
                        }
                    }
                    if secondary_button(ui, "Подробнее", w * 0.28).clicked() {
                        app.page = super::Page::Journal;
                        app.selected_incident = Some(inc.id);
                        close = true;
                    }
                });
            });

        egui::CentralPanel::default()
            .frame(
                Frame::new()
                    .fill(ALERT_BG)
                    .inner_margin(Margin::symmetric(20, 14)),
            )
            .show(ui, |ui| {
                ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| incident_details(ui, &inc, 4, 3));
            });
    });
    if close {
        app.alert = None;
    }
}

fn subtitle_for(inc: &Incident) -> String {
    let what = inc.reasons.first().cloned().unwrap_or_default();
    match inc.state {
        IncidentState::AwaitingDecision => format!("Процесс заморожен: {what}"),
        _ => what,
    }
}
