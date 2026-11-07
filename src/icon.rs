//! Иконка-щит (как на макетах), рисуется программно — без файлов картинок.

pub const GREEN: [u8; 3] = [0x3e, 0xcf, 0x8e];
pub const YELLOW: [u8; 3] = [0xf5, 0xb5, 0x44];
pub const RED: [u8; 3] = [0xf9, 0x73, 0x62];

/// Щит с галочкой (ok) или восклицательным знаком (!), RGBA `size`×`size`.
pub fn shield_rgba(size: u32, color: [u8; 3], exclamation: bool) -> Vec<u8> {
    const SS: u32 = 4; // сглаживание: 4×4 подвыборки на пиксель
    let mut out = vec![0u8; (size * size * 4) as usize];
    for py in 0..size {
        for px in 0..size {
            let (mut fill, mut mark) = (0u32, 0u32);
            for sy in 0..SS {
                for sx in 0..SS {
                    // Координаты в системе 24×24, как у SVG на макете.
                    let x = (px as f32 + (sx as f32 + 0.5) / SS as f32) / size as f32 * 24.0;
                    let y = (py as f32 + (sy as f32 + 0.5) / SS as f32) / size as f32 * 24.0;
                    if inside_shield(x, y) {
                        fill += 1;
                        let on_mark = if exclamation {
                            on_exclamation(x, y)
                        } else {
                            on_check(x, y)
                        };
                        if on_mark {
                            mark += 1;
                        }
                    }
                }
            }
            let total = (SS * SS) as f32;
            let a = fill as f32 / total;
            let m = if fill > 0 {
                mark as f32 / fill as f32
            } else {
                0.0
            };
            let i = ((py * size + px) * 4) as usize;
            for c in 0..3 {
                out[i + c] = (color[c] as f32 * (1.0 - m) + 255.0 * m) as u8;
            }
            out[i + 3] = (a * 255.0) as u8;
        }
    }
    out
}

fn inside_shield(x: f32, y: f32) -> bool {
    let dx = (x - 12.0).abs();
    if !(3.0..=21.5).contains(&y) {
        return false;
    }
    let half = if y < 6.0 {
        9.0 * (y - 3.0) / 3.0
    } else if y <= 12.0 {
        9.0
    } else {
        let t = ((y - 12.0) / 9.5).min(1.0);
        9.0 * (1.0 - t * t).max(0.0).sqrt()
    };
    dx <= half
}

fn dist_to_segment(px: f32, py: f32, (ax, ay): (f32, f32), (bx, by): (f32, f32)) -> f32 {
    let (vx, vy) = (bx - ax, by - ay);
    let t = (((px - ax) * vx + (py - ay) * vy) / (vx * vx + vy * vy)).clamp(0.0, 1.0);
    let (cx, cy) = (ax + t * vx, ay + t * vy);
    ((px - cx).powi(2) + (py - cy).powi(2)).sqrt()
}

fn on_check(x: f32, y: f32) -> bool {
    dist_to_segment(x, y, (8.0, 12.0), (11.0, 15.0)) < 1.3
        || dist_to_segment(x, y, (11.0, 15.0), (16.0, 9.0)) < 1.3
}

fn on_exclamation(x: f32, y: f32) -> bool {
    dist_to_segment(x, y, (12.0, 7.5), (12.0, 13.0)) < 1.4
        || ((x - 12.0).powi(2) + (y - 16.5).powi(2)).sqrt() < 1.5
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icon_has_shape() {
        let px = shield_rgba(32, GREEN, false);
        assert_eq!(px.len(), 32 * 32 * 4);
        let alpha = |x: u32, y: u32| px[((y * 32 + x) * 4 + 3) as usize];
        assert_eq!(alpha(0, 0), 0, "угол прозрачный");
        assert_eq!(alpha(16, 14), 255, "центр залит");
    }
}
