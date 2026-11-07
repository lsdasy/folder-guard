//! Цвета, шрифты и общие элементы интерфейса — по макетам.

use egui::{
    Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Frame, Margin, RichText,
    Stroke, TextStyle, Ui, Vec2,
};

pub const BG: Color32 = Color32::from_rgb(0x1c, 0x1c, 0x1f);
pub const SIDEBAR: Color32 = Color32::from_rgb(0x19, 0x19, 0x1c);
pub const CARD: Color32 = Color32::from_rgb(0x24, 0x24, 0x28);
pub const CARD_BORDER: Color32 = Color32::from_rgb(0x2f, 0x2f, 0x35);
pub const DIVIDER: Color32 = Color32::from_rgb(0x2c, 0x2c, 0x31);
pub const BUTTON: Color32 = Color32::from_rgb(0x2a, 0x2a, 0x30);
pub const BUTTON_HOVER: Color32 = Color32::from_rgb(0x34, 0x34, 0x3b);
pub const BUTTON_BORDER: Color32 = Color32::from_rgb(0x3a, 0x3a, 0x42);
pub const TEXT: Color32 = Color32::from_rgb(0xed, 0xed, 0xf0);
pub const TEXT_DIM: Color32 = Color32::from_rgb(0xc4, 0xc4, 0xcc);
pub const MUTED: Color32 = Color32::from_rgb(0xa1, 0xa1, 0xaa);
pub const TRACK: Color32 = Color32::from_rgb(0x33, 0x33, 0x3a);

pub const ACCENT: Color32 = Color32::from_rgb(0x3e, 0xcf, 0x8e);
pub const WARN: Color32 = Color32::from_rgb(0xf5, 0xb5, 0x44);
pub const WARN_TEXT: Color32 = Color32::from_rgb(0xf5, 0xc7, 0x7a);
pub const DANGER: Color32 = Color32::from_rgb(0xf9, 0x73, 0x62);
pub const DANGER_TEXT: Color32 = Color32::from_rgb(0xff, 0x9a, 0x8a);
pub const DANGER_BUTTON: Color32 = Color32::from_rgb(0xe2, 0x51, 0x3f);
pub const BLUE: Color32 = Color32::from_rgb(0x7c, 0xc4, 0xff);

pub const OK_BANNER: Color32 = Color32::from_rgb(0x1f, 0x2a, 0x24);
pub const OK_BANNER_BORDER: Color32 = Color32::from_rgb(0x2f, 0x4a, 0x3b);
pub const OK_BANNER_TEXT: Color32 = Color32::from_rgb(0xb4, 0xc4, 0xba);
pub const OK_ICON_BG: Color32 = Color32::from_rgb(0x24, 0x39, 0x2d);
pub const WARN_BANNER: Color32 = Color32::from_rgb(0x2c, 0x26, 0x1a);
pub const WARN_BANNER_BORDER: Color32 = Color32::from_rgb(0x4d, 0x40, 0x22);
pub const WARN_ICON_BG: Color32 = Color32::from_rgb(0x3d, 0x33, 0x1c);
pub const ALERT_BANNER: Color32 = Color32::from_rgb(0x3a, 0x1f, 0x1b);
pub const ALERT_BANNER_BORDER: Color32 = Color32::from_rgb(0x5a, 0x2e, 0x28);
pub const ALERT_ICON_BG: Color32 = Color32::from_rgb(0x5a, 0x2a, 0x24);
pub const ALERT_TEXT: Color32 = Color32::from_rgb(0xf0, 0xc4, 0xbc);

pub fn bold() -> FontFamily {
    FontFamily::Name("bold".into())
}

pub fn setup(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    let mut proportional = fonts
        .families
        .get(&FontFamily::Proportional)
        .cloned()
        .unwrap_or_default();
    let mut bold_family = proportional.clone();

    if let Some(data) = crate::platform::ui_font() {
        fonts
            .font_data
            .insert("ui".into(), FontData::from_owned(data).into());
        proportional.insert(0, "ui".into());
        bold_family.insert(0, "ui".into());
    }
    if let Some(data) = crate::platform::ui_font_bold() {
        fonts
            .font_data
            .insert("ui-bold".into(), FontData::from_owned(data).into());
        bold_family.insert(0, "ui-bold".into());
    }
    for mono in [
        r"C:\Windows\Fonts\CascadiaMono.ttf",
        r"C:\Windows\Fonts\consola.ttf",
    ] {
        if let Ok(data) = std::fs::read(mono) {
            fonts
                .font_data
                .insert("mono".into(), FontData::from_owned(data).into());
            if let Some(m) = fonts.families.get_mut(&FontFamily::Monospace) {
                m.insert(0, "mono".into());
            }
            break;
        }
    }
    fonts
        .families
        .insert(FontFamily::Proportional, proportional);
    fonts.families.insert(bold(), bold_family);
    ctx.set_fonts(fonts);

    ctx.set_theme(egui::Theme::Dark);
    ctx.style_mut_of(egui::Theme::Dark, |style| {
        style.text_styles = [
            (TextStyle::Small, FontId::proportional(11.5)),
            (TextStyle::Body, FontId::proportional(13.5)),
            (TextStyle::Button, FontId::proportional(13.5)),
            (TextStyle::Heading, FontId::new(18.0, bold())),
            (TextStyle::Monospace, FontId::monospace(12.5)),
        ]
        .into();
        style.spacing.item_spacing = Vec2::new(8.0, 6.0);
        style.spacing.button_padding = Vec2::new(14.0, 7.0);
        style.spacing.interact_size.y = 30.0;
        let v = &mut style.visuals;
        v.dark_mode = true;
        v.panel_fill = BG;
        v.window_fill = CARD;
        v.extreme_bg_color = Color32::from_rgb(0x16, 0x16, 0x19);
        v.faint_bg_color = CARD;
        v.override_text_color = Some(TEXT);
        v.selection.bg_fill = Color32::from_rgb(0x2e, 0x5e, 0x48);
        v.selection.stroke = Stroke::new(1.0, ACCENT);
        v.hyperlink_color = BLUE;
        let r = CornerRadius::same(8);
        for w in [
            &mut v.widgets.inactive,
            &mut v.widgets.hovered,
            &mut v.widgets.active,
            &mut v.widgets.open,
        ] {
            w.corner_radius = r;
        }
        v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, CARD_BORDER);
        v.widgets.inactive.bg_fill = BUTTON;
        v.widgets.inactive.weak_bg_fill = BUTTON;
        v.widgets.inactive.bg_stroke = Stroke::new(1.0, BUTTON_BORDER);
        v.widgets.hovered.bg_fill = BUTTON_HOVER;
        v.widgets.hovered.weak_bg_fill = BUTTON_HOVER;
        v.widgets.hovered.bg_stroke = Stroke::new(1.0, Color32::from_rgb(0x4a, 0x4a, 0x54));
        v.widgets.active.bg_fill = Color32::from_rgb(0x3d, 0x3d, 0x45);
        v.widgets.active.weak_bg_fill = Color32::from_rgb(0x3d, 0x3d, 0x45);
        v.window_corner_radius = CornerRadius::same(12);
    });
}

/// Карточка как на макете: тёмная подложка, тонкая рамка, скругление 12.
pub fn card() -> Frame {
    Frame::new()
        .fill(CARD)
        .stroke(Stroke::new(1.0, CARD_BORDER))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::same(16))
}

pub fn banner(fill: Color32, border: Color32) -> Frame {
    Frame::new()
        .fill(fill)
        .stroke(Stroke::new(1.0, border))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::symmetric(20, 16))
}

pub fn heading(text: &str) -> RichText {
    RichText::new(text).family(bold()).size(14.0)
}

pub fn page_title(ui: &mut Ui, title: &str, subtitle: &str) {
    ui.label(RichText::new(title).family(bold()).size(22.0));
    if !subtitle.is_empty() {
        ui.label(RichText::new(subtitle).color(MUTED));
    }
    ui.add_space(12.0);
}

pub fn caption(text: impl Into<String>) -> RichText {
    RichText::new(text.into()).size(11.5).color(MUTED)
}

pub fn mono(text: impl Into<String>) -> RichText {
    RichText::new(text.into()).monospace()
}

/// Обычная кнопка в стиле макетов.
pub fn button(ui: &mut Ui, text: &str) -> egui::Response {
    ui.add(egui::Button::new(RichText::new(text).size(13.0)).min_size(Vec2::new(0.0, 34.0)))
}

/// Красная кнопка основного действия («Убить»).
pub fn danger_button(ui: &mut Ui, text: &str, width: f32) -> egui::Response {
    ui.add(
        egui::Button::new(
            RichText::new(text)
                .family(bold())
                .size(13.0)
                .color(Color32::WHITE),
        )
        .fill(DANGER_BUTTON)
        .stroke(Stroke::NONE)
        .min_size(Vec2::new(width, 40.0)),
    )
}

pub fn secondary_button(ui: &mut Ui, text: &str, width: f32) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(text).size(13.0))
            .fill(Color32::from_rgb(0x33, 0x33, 0x3a))
            .stroke(Stroke::NONE)
            .min_size(Vec2::new(width, 40.0)),
    )
}

pub fn accent_button(ui: &mut Ui, text: &str) -> egui::Response {
    ui.add(
        egui::Button::new(
            RichText::new(text)
                .family(bold())
                .size(13.0)
                .color(Color32::from_rgb(0x0f, 0x24, 0x1a)),
        )
        .fill(ACCENT)
        .stroke(Stroke::NONE)
        .min_size(Vec2::new(0.0, 34.0)),
    )
}

/// Цветная точка уровня события.
pub fn dot(ui: &mut Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(8.0, 18.0), egui::Sense::hover());
    ui.painter()
        .circle_filled(egui::pos2(rect.center().x, rect.top() + 8.0), 4.0, color);
}

/// Полоса подозрительности (0..100).
pub fn score_bar(ui: &mut Ui, score: u32, width: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 18.0), egui::Sense::hover());
    let bar = egui::Rect::from_min_size(
        egui::pos2(rect.left(), rect.center().y - 3.0),
        Vec2::new(width, 6.0),
    );
    let p = ui.painter();
    p.rect_filled(bar, CornerRadius::same(3), TRACK);
    let frac = (score as f32 / 100.0).clamp(0.0, 1.0);
    if frac > 0.0 {
        let mut fill = bar;
        fill.set_width((width * frac).max(4.0));
        p.rect_filled(fill, CornerRadius::same(3), score_color(score));
    }
}

pub fn score_color(score: u32) -> Color32 {
    if score >= 50 {
        DANGER
    } else if score >= 20 {
        WARN
    } else {
        ACCENT
    }
}

/// Щит-иконка в круге (как в баннере статуса).
pub fn shield_badge(ui: &mut Ui, bg: Color32, fg: Color32, ok: bool, size: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), egui::Sense::hover());
    let p = ui.painter();
    p.circle_filled(rect.center(), size / 2.0, bg);
    let s = size / 44.0 * 1.05;
    let c = rect.center();
    let pt = |x: f32, y: f32| egui::pos2(c.x + (x - 12.0) * s, c.y + (y - 12.0) * s);
    let stroke = Stroke::new(2.0, fg);
    // Контур щита из макета: M12 3 l8 3 v6 c0 5-3.5 8-8 9 c-4.5-1-8-4-8-9 V6 l8-3z
    let mut outline = vec![pt(12.0, 3.0), pt(20.0, 6.0), pt(20.0, 12.0)];
    for i in 1..=8 {
        let t = i as f32 / 8.0;
        outline.push(pt(
            20.0 - 8.0 * t.powf(1.4),
            12.0 + 9.0 * (t * std::f32::consts::FRAC_PI_2).sin(),
        ));
    }
    for i in 1..=8 {
        let t = i as f32 / 8.0;
        outline.push(pt(12.0 - 8.0 * t.powf(0.7), 21.0 - 9.0 * t.powf(1.6)));
    }
    outline.push(pt(4.0, 6.0));
    outline.push(pt(12.0, 3.0));
    p.add(egui::Shape::line(outline, stroke));
    if ok {
        p.add(egui::Shape::line(
            vec![pt(8.5, 12.0), pt(11.0, 14.5), pt(15.5, 9.5)],
            stroke,
        ));
    } else {
        p.line_segment([pt(12.0, 8.0), pt(12.0, 13.0)], stroke);
        p.circle_filled(pt(12.0, 16.0), 1.3, fg);
    }
}

pub fn format_bytes(b: u64) -> String {
    const UNITS: [&str; 5] = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{b} {}", UNITS[0])
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

/// «1 284» — разряды через пробел, как на макете.
pub fn group_digits(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push('\u{202F}');
        }
        out.push(ch);
    }
    out
}

pub fn when(t: chrono::DateTime<chrono::Local>) -> String {
    let today = chrono::Local::now().date_naive();
    let d = t.date_naive();
    if d == today {
        format!("Сегодня, {}", t.format("%H:%M"))
    } else if Some(d) == today.pred_opt() {
        format!("Вчера, {}", t.format("%H:%M"))
    } else {
        t.format("%d.%m.%Y, %H:%M").to_string()
    }
}
