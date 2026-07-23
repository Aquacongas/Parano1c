// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use iced::border::Radius;
use iced::widget::canvas;
use iced::{Color, Point, Rectangle, Renderer, Size, Theme, Vector};

use crate::app::Message;
use crate::theme;

const DESIGN_WIDTH: f32 = 320.0;
const DESIGN_HEIGHT: f32 = 190.0;
const CYCLE_SECONDS: f32 = 1.22;
const IMPACT_PHASE: f32 = 0.58;
const SPARK_END_PHASE: f32 = 0.88;
const HAMMER_HEAD_ROTATION: f32 = 0.864;

#[derive(Debug, Clone, Copy)]
pub struct ProofForge {
    elapsed_seconds: f32,
}

impl ProofForge {
    pub fn new(elapsed_seconds: f32) -> Self {
        Self {
            elapsed_seconds: elapsed_seconds.max(0.0),
        }
    }
}

impl canvas::Program<Message> for ProofForge {
    type State = ();

    fn draw(
        &self,
        _state: &Self::State,
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: iced::mouse::Cursor,
    ) -> Vec<canvas::Geometry> {
        let mut frame = canvas::Frame::new(renderer, bounds.size());
        let scale = (bounds.width / DESIGN_WIDTH)
            .min(bounds.height / DESIGN_HEIGHT)
            .max(0.01);
        let origin = Vector::new(
            (bounds.width - DESIGN_WIDTH * scale) * 0.5,
            (bounds.height - DESIGN_HEIGHT * scale) * 0.5,
        );
        let motion = forge_motion(self.elapsed_seconds);

        frame.with_save(|frame| {
            frame.translate(origin);
            frame.scale(scale);

            draw_forge_field(frame, self.elapsed_seconds, motion.impact);
            draw_impact_glow(frame, motion);
            draw_anvil(frame, motion.impact);

            if motion.swing_progress > 0.0 && motion.swing_progress < 1.0 {
                for (offset, opacity) in [(0.09, 0.08), (0.16, 0.045)] {
                    draw_hammer(
                        frame,
                        motion.hammer_angle + offset,
                        opacity * motion.swing_progress,
                        0.0,
                    );
                }
            }

            draw_hammer(frame, motion.hammer_angle, 1.0, motion.impact);
            draw_sparks(frame, motion.spark_progress);
        });

        vec![frame.into_geometry()]
    }
}

#[derive(Debug, Clone, Copy)]
struct ForgeMotion {
    hammer_angle: f32,
    impact: f32,
    spark_progress: Option<f32>,
    swing_progress: f32,
}

fn forge_motion(elapsed_seconds: f32) -> ForgeMotion {
    let phase = (elapsed_seconds / CYCLE_SECONDS).rem_euclid(1.0);
    let (hammer_angle, swing_progress) = if phase < 0.25 {
        let progress = smoothstep(phase / 0.25);
        (lerp(0.72, 0.78, progress), 0.0)
    } else if phase < IMPACT_PHASE {
        let progress = (phase - 0.25) / (IMPACT_PHASE - 0.25);
        (lerp(0.78, -0.025, progress * progress * progress), progress)
    } else if phase < 0.70 {
        let progress = smoothstep((phase - IMPACT_PHASE) / (0.70 - IMPACT_PHASE));
        (lerp(-0.025, 0.16, progress), 0.0)
    } else {
        let progress = smoothstep((phase - 0.70) / 0.30);
        (lerp(0.16, 0.72, progress), 0.0)
    };
    let impact = if (IMPACT_PHASE..0.76).contains(&phase) {
        1.0 - smoothstep((phase - IMPACT_PHASE) / (0.76 - IMPACT_PHASE))
    } else {
        0.0
    };
    let spark_progress = (IMPACT_PHASE..SPARK_END_PHASE)
        .contains(&phase)
        .then(|| (phase - IMPACT_PHASE) / (SPARK_END_PHASE - IMPACT_PHASE));

    ForgeMotion {
        hammer_angle,
        impact,
        spark_progress,
        swing_progress,
    }
}

fn draw_forge_field(frame: &mut canvas::Frame, elapsed_seconds: f32, impact: f32) {
    let pulse = 0.5 + 0.5 * (elapsed_seconds * 2.1).sin();

    for y in [36.0, 72.0, 108.0, 144.0] {
        let line = canvas::Path::line(Point::new(42.0, y), Point::new(278.0, y));
        frame.stroke(
            &line,
            canvas::Stroke::default()
                .with_width(1.0)
                .with_color(with_alpha(theme::CYAN, 0.025 + pulse * 0.018)),
        );
    }
    for x in [80.0, 120.0, 160.0, 200.0, 240.0] {
        let line = canvas::Path::line(Point::new(x, 24.0), Point::new(x, 172.0));
        frame.stroke(
            &line,
            canvas::Stroke::default()
                .with_width(1.0)
                .with_color(with_alpha(theme::PROOF, 0.022 + pulse * 0.014)),
        );
    }

    for (radius, alpha) in [(61.0, 0.055), (78.0, 0.032)] {
        let ring = canvas::Path::circle(Point::new(160.0, 109.0), radius + impact * 3.0);
        frame.stroke(
            &ring,
            canvas::Stroke::default()
                .with_width(1.0)
                .with_color(with_alpha(theme::PROOF, alpha + impact * 0.10)),
        );
    }

    for (start, end, color) in [
        (
            Point::new(72.0, 160.0),
            Point::new(117.0, 160.0),
            theme::CYAN,
        ),
        (
            Point::new(203.0, 160.0),
            Point::new(248.0, 160.0),
            theme::CYAN,
        ),
        (
            Point::new(92.0, 169.0),
            Point::new(126.0, 169.0),
            theme::PROOF,
        ),
        (
            Point::new(194.0, 169.0),
            Point::new(228.0, 169.0),
            theme::PROOF,
        ),
    ] {
        let rail = canvas::Path::line(start, end);
        frame.stroke(
            &rail,
            canvas::Stroke::default()
                .with_width(1.0)
                .with_color(with_alpha(color, 0.20 + impact * 0.28)),
        );
    }

    let ground = canvas::Path::rounded_rectangle(
        Point::new(103.0, 177.0),
        Size::new(114.0, 5.0),
        Radius::from(2.5),
    );
    frame.fill(&ground, Color::from_rgba8(5, 7, 13, 0.42));
}

fn draw_impact_glow(frame: &mut canvas::Frame, motion: ForgeMotion) {
    if motion.impact <= 0.0 {
        return;
    }

    let point = Point::new(160.0, 108.0);
    for (radius, alpha) in [(29.0, 0.05), (18.0, 0.11), (9.0, 0.28)] {
        let glow = canvas::Path::circle(point, radius * (1.0 + (1.0 - motion.impact) * 0.25));
        frame.fill(&glow, with_alpha(theme::PROOF, alpha * motion.impact));
    }
    let core = canvas::Path::circle(point, 3.5 + motion.impact * 2.0);
    frame.fill(&core, with_alpha(theme::TEXT, 0.82 * motion.impact));
}

fn draw_anvil(frame: &mut canvas::Frame, impact: f32) {
    let silhouette = anvil_silhouette();

    frame.with_save(|frame| {
        frame.translate(Vector::new(0.0, 4.0));
        frame.fill(&silhouette, Color::from_rgba8(5, 7, 13, 0.46));
    });
    frame.fill(&silhouette, theme::SURFACE_HIGH);
    frame.stroke(
        &silhouette,
        canvas::Stroke::default()
            .with_width(1.25)
            .with_color(with_alpha(theme::CYAN, 0.34 + impact * 0.48)),
    );

    let top_face = canvas::Path::new(|path| {
        path.move_to(Point::new(77.0, 124.0));
        path.line_to(Point::new(112.0, 116.0));
        path.line_to(Point::new(191.0, 116.0));
        path.line_to(Point::new(199.0, 121.0));
        path.line_to(Point::new(231.0, 121.0));
        path.line_to(Point::new(220.0, 128.0));
        path.line_to(Point::new(100.0, 128.0));
        path.close();
    });
    frame.fill(&top_face, with_alpha(theme::MUTED, 0.24 + impact * 0.16));

    let center_facet = canvas::Path::new(|path| {
        path.move_to(Point::new(137.0, 134.0));
        path.line_to(Point::new(184.0, 134.0));
        path.line_to(Point::new(178.0, 157.0));
        path.line_to(Point::new(142.0, 157.0));
        path.close();
    });
    frame.fill(&center_facet, Color::from_rgba8(31, 34, 45, 0.76));

    let base_edge = canvas::Path::line(Point::new(112.0, 175.0), Point::new(207.0, 175.0));
    frame.stroke(
        &base_edge,
        canvas::Stroke::default()
            .with_width(1.5)
            .with_color(with_alpha(theme::PROOF, 0.44 + impact * 0.36)),
    );

    let ingot = canvas::Path::rounded_rectangle(
        Point::new(138.0, 108.0),
        Size::new(47.0, 7.0),
        Radius::from(2.0),
    );
    frame.fill(
        &ingot,
        if impact > 0.0 {
            with_alpha(theme::TEXT, 0.72 + impact * 0.28)
        } else {
            with_alpha(theme::PROOF, 0.88)
        },
    );
    frame.stroke(
        &ingot,
        canvas::Stroke::default()
            .with_width(1.0)
            .with_color(with_alpha(theme::ACCENT, 0.58 + impact * 0.42)),
    );

    for index in 1..6 {
        let x = 138.0 + index as f32 * 47.0 / 6.0;
        let seam = canvas::Path::line(Point::new(x, 109.0), Point::new(x, 114.0));
        frame.stroke(
            &seam,
            canvas::Stroke::default()
                .with_width(0.75)
                .with_color(with_alpha(theme::INK, 0.56)),
        );
    }
}

fn anvil_silhouette() -> canvas::Path {
    canvas::Path::new(|path| {
        path.move_to(Point::new(77.0, 124.0));
        path.line_to(Point::new(112.0, 116.0));
        path.line_to(Point::new(191.0, 116.0));
        path.line_to(Point::new(199.0, 121.0));
        path.line_to(Point::new(231.0, 121.0));
        path.line_to(Point::new(231.0, 128.0));
        path.line_to(Point::new(193.0, 131.0));
        path.line_to(Point::new(181.0, 140.0));
        path.line_to(Point::new(178.0, 157.0));
        path.line_to(Point::new(198.0, 166.0));
        path.line_to(Point::new(208.0, 176.0));
        path.line_to(Point::new(111.0, 176.0));
        path.line_to(Point::new(121.0, 166.0));
        path.line_to(Point::new(142.0, 157.0));
        path.line_to(Point::new(139.0, 140.0));
        path.line_to(Point::new(128.0, 131.0));
        path.line_to(Point::new(99.0, 128.0));
        path.close();
    })
}

fn draw_hammer(frame: &mut canvas::Frame, angle: f32, opacity: f32, impact: f32) {
    frame.with_save(|frame| {
        frame.translate(Vector::new(231.0, 31.0 + impact * 1.2));
        frame.rotate(angle);

        let handle_shadow = canvas::Path::line(Point::new(-3.0, 4.0), Point::new(-66.0, 57.0));
        frame.stroke(
            &handle_shadow,
            canvas::Stroke::default()
                .with_width(12.0)
                .with_color(Color::from_rgba8(5, 7, 13, 0.34 * opacity)),
        );
        let handle = canvas::Path::line(Point::new(-4.0, 1.0), Point::new(-66.0, 54.0));
        frame.stroke(
            &handle,
            canvas::Stroke::default()
                .with_width(9.0)
                .with_color(with_alpha(theme::MUTED, 0.86 * opacity)),
        );
        frame.stroke(
            &handle,
            canvas::Stroke::default()
                .with_width(2.0)
                .with_color(with_alpha(theme::PROOF, (0.72 + impact * 0.28) * opacity)),
        );

        frame.with_save(|frame| {
            frame.translate(Vector::new(-72.0, 57.5));
            frame.rotate(HAMMER_HEAD_ROTATION);

            let head_shadow = hammer_head(Vector::new(2.0, 3.0));
            frame.fill(&head_shadow, Color::from_rgba8(5, 7, 13, 0.38 * opacity));
            let head = hammer_head(Vector::new(0.0, 0.0));
            frame.fill(&head, with_alpha(theme::SURFACE_HIGH, opacity));
            frame.stroke(
                &head,
                canvas::Stroke::default()
                    .with_width(1.4)
                    .with_color(with_alpha(theme::CYAN, (0.42 + impact * 0.58) * opacity)),
            );

            let face = canvas::Path::new(|path| {
                path.move_to(Point::new(-23.0, -9.0));
                path.line_to(Point::new(-18.0, -13.0));
                path.line_to(Point::new(-18.0, 13.0));
                path.line_to(Point::new(-23.0, 9.0));
                path.close();
            });
            frame.fill(
                &face,
                with_alpha(theme::TEXT, (0.25 + impact * 0.55) * opacity),
            );

            let highlight = canvas::Path::line(Point::new(-14.0, -10.0), Point::new(14.0, -10.0));
            frame.stroke(
                &highlight,
                canvas::Stroke::default()
                    .with_width(1.0)
                    .with_color(with_alpha(theme::TEXT, 0.46 * opacity)),
            );
        });
    });
}

fn hammer_head(offset: Vector) -> canvas::Path {
    canvas::Path::new(|path| {
        path.move_to(Point::new(-23.0 + offset.x, -9.0 + offset.y));
        path.line_to(Point::new(-18.0 + offset.x, -13.0 + offset.y));
        path.line_to(Point::new(13.0 + offset.x, -13.0 + offset.y));
        path.line_to(Point::new(22.0 + offset.x, -7.0 + offset.y));
        path.line_to(Point::new(22.0 + offset.x, 7.0 + offset.y));
        path.line_to(Point::new(14.0 + offset.x, 13.0 + offset.y));
        path.line_to(Point::new(-18.0 + offset.x, 13.0 + offset.y));
        path.line_to(Point::new(-23.0 + offset.x, 9.0 + offset.y));
        path.close();
    })
}

fn draw_sparks(frame: &mut canvas::Frame, progress: Option<f32>) {
    let Some(progress) = progress else {
        return;
    };
    let origin = Point::new(160.0, 108.0);
    let fade = (1.0 - progress).powi(2);

    let shockwave = canvas::Path::circle(origin, 7.0 + 40.0 * progress);
    frame.stroke(
        &shockwave,
        canvas::Stroke::default()
            .with_width(1.2)
            .with_color(with_alpha(theme::CYAN, 0.34 * fade)),
    );

    for index in 0..15 {
        let angle = (196.0 + index as f32 * 10.9).to_radians();
        let speed = 30.0 + ((index * 23) % 41) as f32;
        let distance = speed * progress;
        let gravity = 31.0 * progress * progress;
        let point = Point::new(
            origin.x + angle.cos() * distance,
            origin.y + angle.sin() * distance + gravity,
        );
        let previous = Point::new(
            origin.x + angle.cos() * (distance - 7.0).max(0.0),
            origin.y + angle.sin() * (distance - 7.0).max(0.0) + gravity * 0.78,
        );
        let color = match index % 3 {
            0 => theme::PROOF,
            1 => theme::CYAN,
            _ => theme::ACCENT,
        };
        let trail = canvas::Path::line(previous, point);
        frame.stroke(
            &trail,
            canvas::Stroke::default()
                .with_width(if index % 5 == 0 { 2.0 } else { 1.2 })
                .with_color(with_alpha(color, fade * 0.92)),
        );
        let spark = canvas::Path::circle(point, if index % 5 == 0 { 1.8 } else { 1.1 });
        frame.fill(&spark, with_alpha(color, fade));
    }
}

fn smoothstep(value: f32) -> f32 {
    let value = value.clamp(0.0, 1.0);
    value * value * (3.0 - 2.0 * value)
}

fn lerp(start: f32, end: f32, amount: f32) -> f32 {
    start + (end - start) * amount
}

fn with_alpha(color: Color, alpha: f32) -> Color {
    Color {
        a: color.a * alpha.clamp(0.0, 1.0),
        ..color
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forge_cycle_has_a_raised_hammer_a_strike_and_a_recovery() {
        let raised = forge_motion(0.0);
        let strike = forge_motion(CYCLE_SECONDS * IMPACT_PHASE);
        let recovery = forge_motion(CYCLE_SECONDS * 0.78);
        let repeated = forge_motion(CYCLE_SECONDS);

        assert!(raised.hammer_angle > 0.70);
        assert!(strike.hammer_angle.abs() < 0.03);
        assert_eq!(strike.impact, 1.0);
        assert!(strike.spark_progress.is_some());
        assert!(recovery.hammer_angle > strike.hammer_angle);
        assert!((repeated.hammer_angle - raised.hammer_angle).abs() < f32::EPSILON);
    }

    #[test]
    fn hammer_head_is_perpendicular_to_the_handle() {
        let handle_axis = 53.0_f32.atan2(-62.0);
        let angle = (handle_axis - HAMMER_HEAD_ROTATION).abs();

        assert!((angle - std::f32::consts::FRAC_PI_2).abs() < 0.01);
    }
}
