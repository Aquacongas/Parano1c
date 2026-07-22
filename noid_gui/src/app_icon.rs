// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use iced::window;

const SIZE: u32 = 64;
const SAMPLES: u32 = 4;
const BACKGROUND: [f32; 3] = [31.0, 33.0, 43.0];
const ACCENT: [f32; 3] = [52.0, 224.0, 111.0];

pub fn icon() -> window::Icon {
    let mut rgba = Vec::with_capacity((SIZE * SIZE * 4) as usize);

    for y in 0..SIZE {
        for x in 0..SIZE {
            let mut background_samples = 0;
            let mut mark_samples = 0;

            for sample_y in 0..SAMPLES {
                for sample_x in 0..SAMPLES {
                    let px = x as f32 + (sample_x as f32 + 0.5) / SAMPLES as f32;
                    let py = y as f32 + (sample_y as f32 + 0.5) / SAMPLES as f32;

                    if inside_rounded_square(px, py) {
                        background_samples += 1;

                        let radius = ((px - 32.0).powi(2) + (py - 32.0).powi(2)).sqrt();
                        let ring = (radius - 23.5).abs() <= 2.5;
                        let digit = distance_to_segment(px, py, 25.0, 29.0, 32.0, 22.0) <= 3.0
                            || distance_to_segment(px, py, 32.0, 22.0, 32.0, 44.0) <= 3.0;

                        if ring || digit {
                            mark_samples += 1;
                        }
                    }
                }
            }

            let sample_count = (SAMPLES * SAMPLES) as f32;
            let alpha = background_samples as f32 / sample_count;
            let mark = mark_samples as f32 / sample_count;

            for channel in 0..3 {
                let color = BACKGROUND[channel] * (1.0 - mark) + ACCENT[channel] * mark;
                rgba.push(color.round() as u8);
            }
            rgba.push((alpha * 255.0).round() as u8);
        }
    }

    window::icon::from_rgba(rgba, SIZE, SIZE).expect("generated application icon is valid")
}

fn inside_rounded_square(x: f32, y: f32) -> bool {
    let nearest_x = x.clamp(12.0, 52.0);
    let nearest_y = y.clamp(12.0, 52.0);
    (x - nearest_x).powi(2) + (y - nearest_y).powi(2) <= 12.0_f32.powi(2)
}

fn distance_to_segment(
    px: f32,
    py: f32,
    start_x: f32,
    start_y: f32,
    end_x: f32,
    end_y: f32,
) -> f32 {
    let dx = end_x - start_x;
    let dy = end_y - start_y;
    let length_squared = dx * dx + dy * dy;
    let projection = (((px - start_x) * dx + (py - start_y) * dy) / length_squared).clamp(0.0, 1.0);
    let closest_x = start_x + projection * dx;
    let closest_y = start_y + projection * dy;

    ((px - closest_x).powi(2) + (py - closest_y).powi(2)).sqrt()
}
