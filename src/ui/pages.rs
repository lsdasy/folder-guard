//! Разделы главного окна.

use std::path::PathBuf;
use std::time::Duration;

use egui::{Color32, RichText, ScrollArea, Ui, Vec2};

use super::theme::*;
use super::{App, LogFilter, Page};
use crate::config::WhitelistEntry;
use crate::model::{
    Command, Incident, IncidentState, Level, LogEntry, MonitorMode, Severity, plural,
};

/// Ячейка таблицы фиксированной ширины (чтобы колонки совпадали построчно).
fn cell<R>(ui: &mut Ui, width: f32, height: f32, add: impl FnOnce(&mut Ui) -> R) -> R {
    ui.allocate_ui_with_layout(
        Vec2::new(width, height),
        egui::Layout::left_to_right(egui::Align::Center),
        |ui| {
            ui.set_min_width(width);
            add(ui)
        },
    )
    .inner
}

// ------------------------------------------------------------------ Обзор

pub fn overview(app: &mut App, ui: &mut Ui) {
    let st = app.h.state.read().clone();
    status_banner(app, ui, &st);
    ui.add_space(20.0);

    // Четыре счётчика.
    let canaries = if st.canaries_total == 0 {
        "—".to_string()
    } else if st.canaries_ok == st.canaries_total {
        st.canaries_total.to_string()
    } else {
        format!("{} из {}", st.canaries_ok, st.canaries_total)
    };
    let stats = [
        ("Защищённых папок", st.protected_count.to_string(), None),
        (
            "Файлов-приманок",
            canaries,
            (st.canaries_ok < st.canaries_total).then_some(WARN),
        ),
        ("Событий сегодня", group_digits(st.events_today), None),
        ("Угроз остановлено", st.threats_stopped.to_string(), None),
    ];
    let gap = 14.0;
    let w = (ui.available_width() - gap * 3.0) / 4.0;
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = gap;
        for (label, value, color) in stats {
            ui.allocate_ui_with_layout(
                Vec2::new(w, 84.0),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    card()
                        .inner_margin(egui::Margin::symmetric(16, 14))
                        .show(ui, |ui| {
                            ui.set_width(w - 34.0);
                            ui.label(caption(label));
                            ui.add_space(2.0);
                            ui.label(
                                RichText::new(value)
                                    .size(26.0)
                                    .family(bold())
                                    .color(color.unwrap_or(TEXT)),
                            );
                        });
                },
            );
        }
    });
    ui.add_space(20.0);

    // Процессы | события.
    let total = ui.available_width();
    let left = (total - gap) * 1.6 / 2.6;
    let right = total - gap - left;
    let height = ui.available_height().max(260.0);
    ui.horizontal_top(|ui| {
        ui.spacing_mut().item_spacing.x = gap;
        ui.allocate_ui_with_layout(
            Vec2::new(left, height),
            egui::Layout::top_down(egui::Align::Min),
            |ui| processes_card(ui, &st, left, height),
        );
        ui.allocate_ui_with_layout(
            Vec2::new(right, height),
            egui::Layout::top_down(egui::Align::Min),
            |ui| events_card(app, ui, &st, right, height),
        );
    });
}

fn status_banner(app: &mut App, ui: &mut Ui, st: &crate::model::UiState) {
    let pending = st.pending_incident().cloned();
    let (fill, border, icon_bg, fg, ok, title, text): (
        Color32,
        Color32,
        Color32,
        Color32,
        bool,
        String,
        String,
    ) = if let Some(inc) = &pending {
        (
            ALERT_BANNER,
            ALERT_BANNER_BORDER,
            ALERT_ICON_BG,
            DANGER_TEXT,
            false,
            "Обнаружена угроза".into(),
            format!("{} заморожен и ждёт вашего решения.", inc.process_name),
        )
    } else if let Some(until) = st.paused_until {
        (
            WARN_BANNER,
            WARN_BANNER_BORDER,
            WARN_ICON_BG,
            WARN,
            false,
            "Защита приостановлена".into(),
            format!(
                "Защита включится автоматически в {}.",
                until.format("%H:%M")
            ),
        )
    } else if st.mode == MonitorMode::Limited {
        let note = st.mode_note.clone().unwrap_or_default();
        (
            WARN_BANNER,
            WARN_BANNER_BORDER,
            WARN_ICON_BG,
            WARN,
            false,
            "Ограниченная защита".into(),
            format!(
                "Приманки работают, но процесс-виновник не определяется ({note}). Остановить шифровальщик автоматически не получится."
            ),
        )
    } else {
        let last = st
            .last_incident()
            .map(|i| {
                format!(
                    " Последний инцидент — {}, {}.",
                    when(i.started).to_lowercase(),
                    i.state.label()
                )
            })
            .unwrap_or_default();
        let learning = if st.learning_mode {
            " Режим обучения: процессы не останавливаются."
        } else {
            ""
        };
        (
            OK_BANNER,
            OK_BANNER_BORDER,
            OK_ICON_BG,
            ACCENT,
            true,
            "Защита активна".into(),
            format!("Подозрительной активности не обнаружено.{last}{learning}"),
        )
    };
    banner(fill, border).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            shield_badge(ui, icon_bg, fg, ok, 44.0);
            ui.add_space(8.0);
            ui.vertical(|ui| {
                ui.set_width(ui.available_width() - 210.0);
                ui.label(RichText::new(title).size(18.0).family(bold()));
                ui.label(RichText::new(text).size(13.0).color(if ok {
                    OK_BANNER_TEXT
                } else {
                    ALERT_TEXT
                }));
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if let Some(inc) = &pending {
                    if danger_button(ui, "Открыть тревогу", 0.0).clicked() {
                        app.alert = Some(inc.id);
                    }
                } else if st.paused_until.is_some() {
                    if button(ui, "Возобновить защиту").clicked() {
                        app.send(Command::Resume);
                    }
                } else if st.mode == MonitorMode::Limited && !st.is_admin && cfg!(windows) {
                    if button(ui, "Перезапустить от администратора").clicked()
                        && let Err(e) = crate::platform::restart_elevated()
                    {
                        app.flash(format!("{e:#}"));
                    }
                } else if button(ui, "Приостановить защиту").clicked() {
                    app.send(Command::PauseFor(Duration::from_secs(15 * 60)));
                    app.flash("Защита приостановлена на 15 минут");
                }
            });
        });
    });
}

fn processes_card(ui: &mut Ui, st: &crate::model::UiState, width: f32, height: f32) {
    card().show(ui, |ui| {
        ui.set_width(width - 34.0);
        ui.set_min_height(height - 34.0);
        ui.horizontal(|ui| {
            ui.label(heading("Процессы, работающие с файлами"));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(caption("обновляется в реальном времени"))
            });
        });
        ui.add_space(6.0);
        let w = ui.available_width();
        let cols = [w * 0.36, w * 0.17, w * 0.15, w * 0.32];
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            for (i, h) in ["ПРОЦЕСС", "ФАЙЛОВ/МИН", "ЭНТРОПИЯ", "ПОДОЗРИТЕЛЬНОСТЬ"]
                .iter()
                .enumerate()
            {
                cell(ui, cols[i], 16.0, |ui| {
                    ui.label(RichText::new(*h).size(10.5).color(MUTED))
                });
            }
        });
        ScrollArea::vertical()
            .id_salt("procs")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                if st.processes.is_empty() {
                    ui.add_space(24.0);
                    ui.vertical_centered(|ui| {
                        ui.label(
                            RichText::new("Пока никто не трогает защищённые файлы").color(MUTED),
                        )
                    });
                }
                for p in st.processes.iter().take(30) {
                    ui.separator();
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 0.0;
                        cell(ui, cols[0], 22.0, |ui| {
                            let name = if p.whitelisted {
                                format!("{} ✓", p.name)
                            } else {
                                p.name.clone()
                            };
                            ui.label(mono(name)).on_hover_text(
                                p.pid
                                    .map(|x| format!("PID {x}"))
                                    .unwrap_or_else(|| "PID неизвестен".into()),
                            );
                        });
                        cell(ui, cols[1], 22.0, |ui| {
                            ui.label(p.files_per_min.to_string())
                        });
                        cell(ui, cols[2], 22.0, |ui| {
                            ui.label(
                                p.avg_entropy
                                    .map(|e| format!("{e:.1}"))
                                    .unwrap_or_else(|| "—".into()),
                            )
                        });
                        cell(ui, cols[3], 22.0, |ui| {
                            ui.horizontal(|ui| {
                                score_bar(ui, p.score, cols[3] - 44.0);
                                ui.add_space(8.0);
                                let s = if p.score > 100 {
                                    "100+".to_string()
                                } else {
                                    p.score.to_string()
                                };
                                ui.label(RichText::new(s).size(12.0).color(TEXT_DIM));
                            });
                        });
                    });
                }
            });
    });
}

fn level_color(l: Level) -> Color32 {
    match l {
        Level::Threat => DANGER,
        Level::Warning => WARN,
        Level::Ok => ACCENT,
        Level::Info => Color32::from_rgb(0x7a, 0x7a, 0x86),
    }
}

fn events_card(app: &mut App, ui: &mut Ui, st: &crate::model::UiState, width: f32, height: f32) {
    card().show(ui, |ui| {
        ui.set_width(width - 34.0);
        ui.set_min_height(height - 34.0);
        ui.horizontal(|ui| {
            ui.label(heading("Последние события"));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.link(RichText::new("Весь журнал").size(12.0)).clicked() {
                    app.page = Page::Journal;
                    app.seen_log = st.log.len();
                }
            });
        });
        ui.add_space(4.0);
        ScrollArea::vertical()
            .id_salt("events")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for e in st.log.iter().take(40) {
                    ui.separator();
                    event_row(ui, e);
                }
            });
    });
}

fn event_row(ui: &mut Ui, e: &LogEntry) {
    ui.horizontal_top(|ui| {
        dot(ui, level_color(e.level));
        ui.vertical(|ui| {
            ui.add(egui::Label::new(RichText::new(&e.message).size(13.0)).wrap());
            ui.label(caption(when(e.time)));
        });
    });
}

// ------------------------------------------------------------------ Журнал

pub fn journal(app: &mut App, ui: &mut Ui) {
    page_title(
        ui,
        "Журнал событий",
        "Инциденты и всё, что происходило с защитой.",
    );
    let st = app.h.state.read().clone();

    ScrollArea::vertical()
        .id_salt("journal")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.label(heading("Инциденты"));
            ui.add_space(6.0);
            if st.incidents.is_empty() {
                ui.label(RichText::new("Инцидентов не было.").color(MUTED));
            }
            for inc in st.incidents.iter().take(50) {
                incident_card(app, ui, inc);
                ui.add_space(8.0);
            }

            ui.add_space(16.0);
            ui.horizontal(|ui| {
                ui.label(heading("События"));
                ui.add_space(16.0);
                for (f, label) in [
                    (LogFilter::All, "Все"),
                    (LogFilter::Threats, "Угрозы"),
                    (LogFilter::Warnings, "Предупреждения"),
                ] {
                    if ui.selectable_label(app.log_filter == f, label).clicked() {
                        app.log_filter = f;
                    }
                }
            });
            ui.add_space(6.0);
            card().show(ui, |ui| {
                ui.set_width(ui.available_width());
                let filtered = st.log.iter().filter(|e| match app.log_filter {
                    LogFilter::All => true,
                    LogFilter::Threats => e.level == Level::Threat,
                    LogFilter::Warnings => matches!(e.level, Level::Warning | Level::Threat),
                });
                let mut any = false;
                for e in filtered.take(300) {
                    if any {
                        ui.separator();
                    }
                    any = true;
                    ui.horizontal_top(|ui| {
                        dot(ui, level_color(e.level));
                        cell(ui, 130.0, 18.0, |ui| {
                            ui.label(caption(e.time.format("%d.%m %H:%M:%S").to_string()))
                        });
                        cell(ui, 150.0, 18.0, |ui| {
                            ui.label(mono(e.process.clone().unwrap_or_default()))
                        });
                        ui.add(egui::Label::new(RichText::new(&e.message).size(13.0)).wrap());
                    });
                }
                if !any {
                    ui.label(RichText::new("Нет событий").color(MUTED));
                }
            });
        });
}

fn incident_card(app: &mut App, ui: &mut Ui, inc: &Incident) {
    let expanded = app.selected_incident == Some(inc.id);
    let (stripe, label_color) = match (inc.state, inc.severity) {
        (IncidentState::AwaitingDecision, _) => (DANGER, DANGER_TEXT),
        (_, Severity::Critical) => (DANGER, TEXT_DIM),
        _ => (WARN, TEXT_DIM),
    };
    card().show(ui, |ui| {
        ui.set_width(ui.available_width());
        let header = ui.horizontal(|ui| {
            dot(ui, stripe);
            ui.label(RichText::new(format!("#{} {}", inc.id, inc.process_name)).family(bold()));
            ui.label(caption(format!(
                "{} · {} · балл {}",
                when(inc.started),
                inc.files_summary(),
                if inc.score > 100 {
                    "100+".to_string()
                } else {
                    inc.score.to_string()
                }
            )));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(
                    RichText::new(inc.state.label())
                        .size(12.0)
                        .color(label_color),
                );
            });
        });
        if header.response.interact(egui::Sense::click()).clicked() {
            app.selected_incident = if expanded { None } else { Some(inc.id) };
        }
        if let Some(r) = inc.reasons.first() {
            ui.label(RichText::new(r).size(12.5).color(TEXT_DIM));
        }
        if !expanded {
            return;
        }
        ui.add_space(8.0);
        incident_details(ui, inc, 12, 20);
        ui.add_space(10.0);
        ui.horizontal(|ui| match inc.state {
            IncidentState::AwaitingDecision => {
                if danger_button(ui, "Убить и восстановить файлы", 0.0).clicked()
                {
                    app.send(Command::Kill {
                        incident: inc.id,
                        restore: true,
                    });
                }
                if secondary_button(ui, "Разрешить", 0.0).clicked() {
                    app.send(Command::Allow {
                        incident: inc.id,
                        add_to_whitelist: false,
                    });
                }
                if secondary_button(ui, "Разрешить всегда", 0.0)
                    .on_hover_text("Добавить в белый список")
                    .clicked()
                {
                    app.send(Command::Allow {
                        incident: inc.id,
                        add_to_whitelist: true,
                    });
                }
            }
            _ => {
                if button(ui, "Восстановить файлы из копии").clicked() {
                    app.send(Command::Restore { incident: inc.id });
                    app.flash("Восстановление запущено — результат появится в журнале");
                }
            }
        });
    });
}

/// Подробности инцидента (общие для журнала и окна тревоги).
pub fn incident_details(ui: &mut Ui, inc: &Incident, max_files: usize, max_reasons: usize) {
    egui::Grid::new(("inc-grid", inc.id))
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.label(RichText::new("Процесс").color(MUTED));
            ui.label(mono(match inc.pid {
                Some(p) => format!("{} (PID {p})", inc.process_name),
                None => inc.process_name.clone(),
            }));
            ui.end_row();
            ui.label(RichText::new("Путь").color(MUTED));
            ui.add(
                egui::Label::new(mono(
                    inc.exe_path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "неизвестен".into()),
                ))
                .truncate(),
            );
            ui.end_row();
            ui.label(RichText::new("Подпись").color(MUTED));
            match inc.signed {
                Some(true) => ui.label(RichText::new("Есть цифровая подпись").color(ACCENT)),
                Some(false) => ui.label(RichText::new("Нет цифровой подписи").color(DANGER_TEXT)),
                None => ui.label(RichText::new("не проверялась").color(MUTED)),
            };
            ui.end_row();
        });
    if inc.reasons.len() > 1 {
        ui.add_space(6.0);
        for r in inc.reasons.iter().take(max_reasons) {
            ui.add(
                egui::Label::new(RichText::new(format!("• {r}")).size(12.5).color(TEXT_DIM))
                    .truncate(),
            );
        }
        if inc.reasons.len() > max_reasons {
            ui.label(caption(format!(
                "и ещё причин: {}",
                inc.reasons.len() - max_reasons
            )));
        }
    }
    ui.add_space(8.0);
    egui::Frame::new()
        .fill(Color32::from_rgb(0x26, 0x26, 0x2b))
        .stroke(egui::Stroke::new(1.0, Color32::from_rgb(0x33, 0x33, 0x39)))
        .corner_radius(egui::CornerRadius::same(10))
        .inner_margin(egui::Margin::symmetric(12, 10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            let shown = inc.files.len().min(max_files);
            ui.label(caption(if inc.files.len() > shown {
                format!(
                    "Затронуто файлов: {} — показаны первые {shown}",
                    inc.files.len()
                )
            } else {
                format!("Затронуто файлов: {}", inc.files.len())
            }));
            ui.add_space(4.0);
            ui.spacing_mut().interact_size.y = 18.0;
            for f in inc.files.iter().take(shown) {
                ui.horizontal(|ui| {
                    ui.label(mono(crate::model::short(&f.original)).color(TEXT_DIM));
                    match (&f.renamed_to, f.deleted) {
                        (Some(to), _) => {
                            ui.label(RichText::new("→").color(Color32::from_rgb(0x8a, 0x8a, 0x94)));
                            ui.add(
                                egui::Label::new(mono(crate::model::short(to)).color(DANGER_TEXT))
                                    .truncate(),
                            );
                        }
                        (None, true) => {
                            ui.label(RichText::new("удалён").size(12.0).color(DANGER_TEXT));
                        }
                        (None, false) if f.modified => {
                            ui.label(RichText::new("изменён").size(12.0).color(DANGER_TEXT));
                        }
                        _ => {}
                    }
                });
            }
            if inc.restored_files > 0 {
                ui.add_space(4.0);
                ui.label(
                    RichText::new(format!("Восстановлено из копии: {}", inc.restored_files))
                        .size(12.0)
                        .color(ACCENT),
                );
            }
        });
}

// ------------------------------------------------------------------ Папки

pub fn folders(app: &mut App, ui: &mut Ui) {
    page_title(
        ui,
        "Защищённые папки",
        "За этими папками программа следит постоянно, в каждую кладёт файлы-приманки.",
    );
    let st = app.h.state.read().clone();
    ScrollArea::vertical().id_salt("folders").auto_shrink([false, false]).show(ui, |ui| {
        let mut remove = None;
        for (i, f) in app.draft.protected_folders.iter().enumerate() {
            card().show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(RichText::new(f.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| f.display().to_string())).family(bold()));
                        ui.label(caption(f.display().to_string()));
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if button(ui, "Убрать").clicked() {
                            remove = Some(i);
                        }
                        if !f.exists() {
                            ui.label(RichText::new("папка не найдена").size(12.0).color(WARN_TEXT));
                        }
                    });
                });
            });
            ui.add_space(8.0);
        }
        if let Some(i) = remove {
            app.draft.protected_folders.remove(i);
        }
        ui.horizontal(|ui| {
            if accent_button(ui, "Добавить папку…").clicked()
                && let Some(dir) = rfd::FileDialog::new().set_title("Какую папку защищать?").pick_folder()
                    && !app.draft.protected_folders.contains(&dir) {
                        app.draft.protected_folders.push(dir);
                    }
            ui.label(caption(format!("Приманки: {} из {} на месте", st.canaries_ok, st.canaries_total)));
            if ui.link(RichText::new("Проверить сейчас").size(12.0)).clicked() {
                app.send(Command::VerifyCanaries);
            }
        });

        ui.add_space(24.0);
        ui.label(heading("Исключения"));
        ui.label(caption("Подпапки с такими именами не анализируются: там сборщики и менеджеры пакетов массово пишут файлы."));
        ui.add_space(6.0);
        card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            let mut remove = None;
            ui.horizontal_wrapped(|ui| {
                for (i, name) in app.draft.excluded_dir_names.iter().enumerate() {
                    if ui.button(RichText::new(format!("{name}  ✕")).monospace()).on_hover_text("Убрать").clicked() {
                        remove = Some(i);
                    }
                }
            });
            if let Some(i) = remove {
                app.draft.excluded_dir_names.remove(i);
            }
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut app.new_excluded).hint_text("имя папки, например dist").desired_width(240.0));
                if button(ui, "Добавить").clicked() && !app.new_excluded.trim().is_empty() {
                    app.draft.excluded_dir_names.push(app.new_excluded.trim().to_string());
                    app.new_excluded.clear();
                }
            });
        });
    });
}

// ------------------------------------------------------------------ Белый список

pub fn whitelist(app: &mut App, ui: &mut Ui) {
    page_title(
        ui,
        "Белый список",
        "Этим программам разрешено массово менять файлы: их активность записывается, но не блокируется. Приманки трогать нельзя никому.",
    );
    ScrollArea::vertical().id_salt("wl").auto_shrink([false, false]).show(ui, |ui| {
        card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            let mut remove = None;
            for (i, w) in app.draft.whitelist.iter().enumerate() {
                if i > 0 {
                    ui.separator();
                }
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(mono(&w.name));
                        ui.label(caption(match &w.path {
                            Some(p) => p.display().to_string(),
                            None => "любое расположение".to_string(),
                        }));
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if button(ui, "Убрать").clicked() {
                            remove = Some(i);
                        }
                    });
                });
            }
            if app.draft.whitelist.is_empty() {
                ui.label(RichText::new("Список пуст").color(MUTED));
            }
            if let Some(i) = remove {
                app.draft.whitelist.remove(i);
            }
        });
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut app.new_whitelist).hint_text("имя процесса, например blender.exe").desired_width(280.0));
            if button(ui, "Добавить по имени").clicked() && !app.new_whitelist.trim().is_empty() {
                app.draft.whitelist.push(WhitelistEntry { name: app.new_whitelist.trim().to_string(), path: None });
                app.new_whitelist.clear();
            }
            if button(ui, "Выбрать программу…").clicked()
                && let Some(exe) = rfd::FileDialog::new().add_filter("Программа", &["exe"]).pick_file() {
                    let name = exe.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                    app.draft.whitelist.push(WhitelistEntry { name, path: Some(exe) });
                }
        });
        ui.add_space(6.0);
        ui.label(caption("Совет: запись с полным путём надёжнее — злоумышленник может назвать свой файл «7zFM.exe», но не сможет подменить его в Program Files без прав администратора."));
    });
}

// ------------------------------------------------------------------ Копии

pub fn backups(app: &mut App, ui: &mut Ui) {
    page_title(
        ui,
        "Резервные копии",
        "Изменившиеся файлы защищённых папок периодически копируются в отдельное хранилище. Файлы, похожие на зашифрованные, в копии не попадают.",
    );
    let st = app.h.state.read().clone();
    ScrollArea::vertical().id_salt("backups").auto_shrink([false, false]).show(ui, |ui| {
        card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    if st.backup.running {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label(RichText::new("Идёт копирование…").family(bold()));
                        });
                    } else {
                        ui.label(RichText::new(match st.backup.last_run {
                            Some(t) => format!("Последняя копия: {}", when(t).to_lowercase()),
                            None => "Копий в этом сеансе ещё не было".into(),
                        }).family(bold()));
                    }
                    ui.label(caption(format!(
                        "В хранилище {} {}, {}",
                        st.backup.files,
                        plural(st.backup.files, "файл", "файла", "файлов"),
                        format_bytes(st.backup.bytes)
                    )));
                    if let Some(e) = &st.backup.last_error {
                        ui.label(RichText::new(e).size(12.0).color(DANGER_TEXT));
                    }
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add_enabled_ui(!st.backup.running, |ui| {
                        if accent_button(ui, "Создать копию сейчас").clicked() {
                            app.send(Command::BackupNow);
                        }
                    });
                });
            });
        });
        ui.add_space(16.0);
        ui.label(heading("Параметры"));
        ui.add_space(6.0);
        card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            let b = &mut app.draft.backup;
            ui.checkbox(&mut b.enabled, "Делать резервные копии автоматически");
            ui.add_enabled_ui(b.enabled, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Каждые");
                    ui.add(egui::DragValue::new(&mut b.interval_minutes).range(5..=1440).suffix(" мин"));
                    ui.add_space(16.0);
                    ui.label("Хранить версий");
                    ui.add(egui::DragValue::new(&mut b.keep_versions).range(1..=20));
                    ui.add_space(16.0);
                    ui.label("Файлы до");
                    ui.add(egui::DragValue::new(&mut b.max_file_mb).range(1..=2048).suffix(" МБ"));
                });
            });
            ui.horizontal(|ui| {
                let dir = app.h.dirs.backup_dir(&app.draft);
                ui.label(caption(format!("Хранилище: {}", dir.display())));
                if ui.link(RichText::new("Изменить…").size(12.0)).clicked()
                    && let Some(d) = rfd::FileDialog::new().pick_folder() {
                        app.draft.backup.dir = Some(d);
                    }
            });
            ui.label(caption("Лучше держать хранилище на другом диске. Шифровальщик, запущенный от администратора, может добраться и до него — копия на внешнем диске надёжнее."));
        });
        ui.add_space(16.0);
        ui.label(heading("Восстановление после инцидентов"));
        ui.add_space(6.0);
        let incidents: Vec<Incident> = st.incidents.iter().filter(|i| !i.files.is_empty()).take(20).cloned().collect();
        if incidents.is_empty() {
            ui.label(RichText::new("Восстанавливать нечего.").color(MUTED));
        }
        for inc in incidents {
            card().show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(RichText::new(format!("#{} {}", inc.id, inc.process_name)).family(bold()));
                        ui.label(caption(format!("{} · {} · восстановлено {}", when(inc.started), inc.files_summary(), inc.restored_files)));
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let enabled = inc.state != IncidentState::AwaitingDecision;
                        ui.add_enabled_ui(enabled, |ui| {
                            if button(ui, "Восстановить файлы").on_disabled_hover_text("Сначала примите решение по процессу").clicked() {
                                app.send(Command::Restore { incident: inc.id });
                                app.flash("Восстановление запущено");
                            }
                        });
                    });
                });
            });
            ui.add_space(8.0);
        }
    });
}

// ------------------------------------------------------------------ Настройки

pub fn settings(app: &mut App, ui: &mut Ui) {
    page_title(ui, "Настройки", "");
    let st = app.h.state.read().clone();
    ScrollArea::vertical().id_salt("settings").auto_shrink([false, false]).show(ui, |ui| {
        ui.label(heading("Чувствительность"));
        ui.add_space(6.0);
        card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            let d = &mut app.draft;
            egui::Grid::new("sens").num_columns(2).spacing([24.0, 10.0]).show(ui, |ui| {
                ui.label("Заморозить процесс с балла");
                ui.add(egui::Slider::new(&mut d.suspend_score, 20..=200));
                ui.end_row();
                ui.label("Критическая тревога с балла");
                ui.add(egui::Slider::new(&mut d.critical_score, d.suspend_score..=300));
                ui.end_row();
                ui.label("Всплеск: файлов");
                ui.add(egui::Slider::new(&mut d.burst_files, 5..=200));
                ui.end_row();
                ui.label("...за секунд");
                ui.add(egui::Slider::new(&mut d.burst_window_secs, 2..=60));
                ui.end_row();
                ui.label("Завершить без ответа через");
                ui.add(egui::Slider::new(&mut d.auto_kill_secs, 10..=300).suffix(" с"));
                ui.end_row();
            });
            ui.add_space(4.0);
            ui.label(caption("Баллы: приманка и удаление теневых копий — 100, всплеск — 30, записки о выкупе — 25, испорченный заголовок и «шифрованное» содержимое — 15, подозрительное переименование — 10. Учитывается последняя минута."));
        });
        ui.add_space(16.0);
        ui.label(heading("Поведение"));
        ui.add_space(6.0);
        card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            let d = &mut app.draft;
            ui.checkbox(&mut d.learning_mode, "Режим обучения — только записывать в журнал, ничего не блокировать");
            ui.checkbox(&mut d.canaries_enabled, "Раскладывать файлы-приманки");
            ui.add_enabled(d.canaries_enabled, egui::Checkbox::new(&mut d.canaries_hidden, "Делать приманки скрытыми"));
            ui.checkbox(&mut d.notifications, "Показывать уведомления Windows");
            ui.add_enabled(d.notifications, egui::Checkbox::new(&mut d.notifications_compat, "Совместимый режим уведомлений (если они не появляются)"));
        });
        ui.add_space(16.0);
        ui.label(heading("Система"));
        ui.add_space(6.0);
        card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label("Права администратора:");
                if st.is_admin {
                    ui.label(RichText::new("есть").color(ACCENT));
                } else {
                    ui.label(RichText::new("нет — процессы не определяются").color(WARN_TEXT));
                    if cfg!(windows) && button(ui, "Перезапустить от администратора").clicked()
                        && let Err(e) = crate::platform::restart_elevated() {
                            app.flash(format!("{e:#}"));
                        }
                }
            });
            if let Some(note) = &st.mode_note {
                ui.label(caption(note));
            }
            if cfg!(windows) {
                let mut auto = app.autostart;
                if ui.checkbox(&mut auto, "Запускать при входе в Windows (через Планировщик заданий)").changed() {
                    match crate::platform::set_autostart(auto) {
                        Ok(()) => app.autostart = auto,
                        Err(e) => app.flash(format!("Не получилось: {e:#}")),
                    }
                }
            }
            ui.add_space(4.0);
            let data: PathBuf = app.h.dirs.data_dir.clone();
            ui.label(caption(format!("Данные программы: {}", data.display())));
            ui.label(caption(format!("Настройки: {}", app.h.dirs.config_file.display())));
        });
    });
}
