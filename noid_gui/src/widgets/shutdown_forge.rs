// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use iced::border::Radius;
use iced::widget::{canvas, text};
use iced::{alignment, Color, Point, Rectangle, Renderer, Size, Theme, Vector};

use crate::app::Message;
use crate::theme;

const DESIGN_WIDTH: f32 = 700.0;
const DESIGN_HEIGHT: f32 = 500.0;
const SCENE_CYCLE_SECONDS: f32 = 9.2;
const STRIKE_CYCLE_SECONDS: f32 = 1.18;
const RAISED_ANGLE: f32 = 4.02;
const STRIKE_ANGLE: f32 = 3.30;
const REBOUND_ANGLE: f32 = 3.48;

#[derive(Debug, Clone, Copy)]
pub struct ShutdownForge {
    elapsed_seconds: f32,
}

impl ShutdownForge {
    pub fn new(elapsed_seconds: f32) -> Self {
        Self {
            elapsed_seconds: elapsed_seconds.max(0.0),
        }
    }
}

impl canvas::Program<Message> for ShutdownForge {
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
            .clamp(0.01, 0.90);
        let origin = Vector::new(
            (bounds.width - DESIGN_WIDTH * scale) * 0.5,
            (bounds.height - DESIGN_HEIGHT * scale) * 0.5,
        );
        let state = scene_state(self.elapsed_seconds);

        frame.with_save(|frame| {
            frame.translate(origin);
            frame.scale(scale);

            draw_stage_field(frame, state);
            draw_anvil(frame, state);
            draw_operator(frame, state);
            draw_impact(frame, state);
            draw_shutdown_copy(frame, self.elapsed_seconds);
        });

        vec![frame.into_geometry()]
    }
}

#[derive(Debug, Clone, Copy)]
struct SceneState {
    attention: f32,
    wave: f32,
    hammer_angle: f32,
    hammer_drop: f32,
    impact: f32,
    spark_progress: Option<f32>,
    cycle_time: f32,
}

fn scene_state(elapsed_seconds: f32) -> SceneState {
    let cycle_time = elapsed_seconds.rem_euclid(SCENE_CYCLE_SECONDS);
    let mut attention = 0.0;
    let mut wave = 0.0;
    let mut forge_time = cycle_time;

    if (4.35..4.90).contains(&cycle_time) {
        attention = smoothstep((cycle_time - 4.35) / 0.55);
        forge_time = 4.35;
    } else if (4.90..6.35).contains(&cycle_time) {
        attention = 1.0;
        wave = (cycle_time - 4.90) / 1.45;
        forge_time = 4.35;
    } else if (6.35..6.90).contains(&cycle_time) {
        attention = 1.0 - smoothstep((cycle_time - 6.35) / 0.55);
        forge_time = 4.35;
    } else if cycle_time >= 6.90 {
        forge_time = cycle_time - 2.55;
    }

    let strike_phase = (forge_time / STRIKE_CYCLE_SECONDS).rem_euclid(1.0);
    let (mut hammer_angle, mut hammer_drop) = if strike_phase < 0.25 {
        (
            lerp(
                RAISED_ANGLE,
                RAISED_ANGLE + 0.012,
                smoothstep(strike_phase / 0.25),
            ),
            0.0,
        )
    } else if strike_phase < 0.59 {
        let progress = (strike_phase - 0.25) / 0.34;
        let strike = progress * progress * progress;
        (lerp(RAISED_ANGLE + 0.012, STRIKE_ANGLE, strike), strike)
    } else if strike_phase < 0.72 {
        let progress = smoothstep((strike_phase - 0.59) / 0.13);
        (
            lerp(STRIKE_ANGLE, REBOUND_ANGLE, progress),
            lerp(1.0, 0.84, progress),
        )
    } else {
        let progress = smoothstep((strike_phase - 0.72) / 0.28);
        (
            lerp(REBOUND_ANGLE, RAISED_ANGLE, progress),
            lerp(0.84, 0.0, progress),
        )
    };

    let mut impact = if (0.59..0.77).contains(&strike_phase) {
        1.0 - smoothstep((strike_phase - 0.59) / 0.18)
    } else {
        0.0
    };
    let mut spark_progress = (0.59..0.90)
        .contains(&strike_phase)
        .then(|| (strike_phase - 0.59) / 0.31);

    hammer_angle = lerp(hammer_angle, STRIKE_ANGLE, attention);
    hammer_drop = lerp(hammer_drop, 1.0, attention);
    impact *= 1.0 - attention;
    if attention > 0.05 {
        spark_progress = None;
    }

    SceneState {
        attention,
        wave,
        hammer_angle,
        hammer_drop,
        impact,
        spark_progress,
        cycle_time,
    }
}

fn draw_stage_field(frame: &mut canvas::Frame, state: SceneState) {
    let pulse = 0.5 + 0.5 * (state.cycle_time * 2.1).sin();

    for (radius, alpha) in [(154.0, 0.012), (116.0, 0.020), (76.0, 0.028)] {
        let glow = canvas::Path::circle(Point::new(350.0, 224.0), radius);
        frame.fill(&glow, with_alpha(theme::PROOF, alpha));
    }

    for y in (78..=330).step_by(42) {
        draw_line(
            frame,
            Point::new(88.0, y as f32),
            Point::new(612.0, y as f32),
            with_alpha(theme::CYAN, 0.035),
            1.0,
        );
    }
    for x in (110..=590).step_by(60) {
        draw_line(
            frame,
            Point::new(x as f32, 58.0),
            Point::new(x as f32, 340.0),
            with_alpha(theme::PROOF, 0.028),
            1.0,
        );
    }

    for (radius, alpha, color) in [
        (94.0 + pulse * 3.0, 0.075, theme::PROOF),
        (126.0 + pulse * 2.0, 0.035, theme::CYAN),
    ] {
        let ring = canvas::Path::circle(Point::new(350.0, 224.0), radius);
        frame.stroke(
            &ring,
            canvas::Stroke::default()
                .with_width(1.0)
                .with_color(with_alpha(color, alpha)),
        );
    }
}

fn draw_anvil(frame: &mut canvas::Frame, state: SceneState) {
    const SILHOUETTE: [Point; 16] = [
        Point::new(237.0, 250.0),
        Point::new(285.0, 239.0),
        Point::new(388.0, 239.0),
        Point::new(399.0, 246.0),
        Point::new(441.0, 246.0),
        Point::new(441.0, 257.0),
        Point::new(393.0, 261.0),
        Point::new(379.0, 272.0),
        Point::new(375.0, 302.0),
        Point::new(401.0, 314.0),
        Point::new(414.0, 328.0),
        Point::new(280.0, 328.0),
        Point::new(293.0, 314.0),
        Point::new(320.0, 302.0),
        Point::new(316.0, 272.0),
        Point::new(267.0, 257.0),
    ];
    let silhouette = polygon(&SILHOUETTE);

    frame.with_save(|frame| {
        frame.translate(Vector::new(0.0, 5.0));
        frame.fill(&silhouette, Color::from_rgba8(5, 7, 13, 0.55));
    });
    frame.fill(&silhouette, theme::SURFACE_HIGH);
    frame.stroke(
        &silhouette,
        canvas::Stroke::default()
            .with_width(1.3)
            .with_color(with_alpha(theme::CYAN, 0.42 + state.impact * 0.48)),
    );

    let top_face = polygon(&[
        Point::new(237.0, 250.0),
        Point::new(285.0, 239.0),
        Point::new(388.0, 239.0),
        Point::new(399.0, 246.0),
        Point::new(441.0, 246.0),
        Point::new(425.0, 257.0),
        Point::new(267.0, 257.0),
    ]);
    frame.fill(
        &top_face,
        with_alpha(theme::MUTED, 0.24 + state.impact * 0.18),
    );

    let center_facet = polygon(&[
        Point::new(315.0, 268.0),
        Point::new(380.0, 268.0),
        Point::new(373.0, 302.0),
        Point::new(323.0, 302.0),
    ]);
    frame.fill(&center_facet, Color::from_rgba8(31, 34, 45, 0.78));

    draw_line(
        frame,
        Point::new(280.0, 328.0),
        Point::new(414.0, 328.0),
        with_alpha(theme::PROOF, 0.48 + state.impact * 0.34),
        1.8,
    );

    let ingot = canvas::Path::rounded_rectangle(
        Point::new(324.0, 229.0),
        Size::new(58.0, 9.0),
        Radius::from(2.0),
    );
    frame.fill(
        &ingot,
        if state.impact > 0.0 {
            with_alpha(theme::TEXT, 0.76 + state.impact * 0.24)
        } else {
            with_alpha(theme::PROOF, 0.90)
        },
    );
    frame.stroke(
        &ingot,
        canvas::Stroke::default()
            .with_width(1.0)
            .with_color(with_alpha(theme::PROOF, 0.62 + state.impact * 0.38)),
    );
    for index in 1..7 {
        let x = 324.0 + index as f32 * 58.0 / 7.0;
        draw_line(
            frame,
            Point::new(x, 230.0),
            Point::new(x, 237.0),
            with_alpha(theme::INK, 0.58),
            0.8,
        );
    }
}

#[derive(Debug, Clone, Copy)]
struct HammerRig {
    main_shoulder: Point,
    support_shoulder: Point,
    main_elbow: Point,
    support_elbow: Point,
    main_grip: Point,
    base_grip: Point,
    head: Point,
    angle: f32,
}

fn hammer_rig(state: SceneState) -> HammerRig {
    let main_shoulder = Point::new(459.0, 174.0);
    let support_shoulder = Point::new(511.0, 174.0);
    let axis = Vector::new(state.hammer_angle.cos(), state.hammer_angle.sin());
    let base_grip = Point::new(
        lerp(451.0, 442.0, state.hammer_drop),
        lerp(179.0, 241.0, state.hammer_drop),
    );
    let main_grip = base_grip + axis * 20.0;
    let head = base_grip + axis * 72.0;
    let main_elbow = elbow_between(main_shoulder, main_grip, -9.0);
    let support_elbow = elbow_between(support_shoulder, base_grip, -10.0);

    HammerRig {
        main_shoulder,
        support_shoulder,
        main_elbow,
        support_elbow,
        main_grip,
        base_grip,
        head,
        angle: state.hammer_angle,
    }
}

fn elbow_between(shoulder: Point, hand: Point, bend: f32) -> Point {
    let delta = hand - shoulder;
    let length = delta.x.hypot(delta.y).max(1.0);
    let normal = Vector::new(-delta.y / length, delta.x / length);
    Point::new(
        (shoulder.x + hand.x) * 0.5 + normal.x * bend,
        (shoulder.y + hand.y) * 0.5 + normal.y * bend,
    )
}

fn draw_operator(frame: &mut canvas::Frame, state: SceneState) {
    let body_x = 486.0;
    let head_x = lerp(479.0, 486.0, state.attention);
    let shoulder_y = 174.0;

    stroke_limb(
        frame,
        &[
            Point::new(body_x, 158.0),
            Point::new(body_x, 220.0),
            Point::new(body_x, 259.0),
        ],
        theme::MUTED,
        with_alpha(theme::PROOF, 0.78),
        6.0,
    );
    stroke_limb(
        frame,
        &[Point::new(body_x, 259.0), Point::new(455.0, 327.0)],
        theme::MUTED,
        with_alpha(theme::CYAN, 0.72),
        6.0,
    );
    stroke_limb(
        frame,
        &[Point::new(body_x, 259.0), Point::new(520.0, 327.0)],
        theme::MUTED,
        with_alpha(theme::CYAN, 0.72),
        6.0,
    );
    draw_line(
        frame,
        Point::new(443.0, 328.0),
        Point::new(465.0, 328.0),
        with_alpha(theme::TEXT, 0.62),
        4.0,
    );
    draw_line(
        frame,
        Point::new(510.0, 328.0),
        Point::new(532.0, 328.0),
        with_alpha(theme::TEXT, 0.62),
        4.0,
    );

    let rig = hammer_rig(state);
    stroke_limb(
        frame,
        &[rig.main_shoulder, rig.main_elbow, rig.main_grip],
        theme::MUTED,
        with_alpha(theme::PROOF, 0.86),
        5.5,
    );

    let wave_amount = smoothstep(state.attention);
    let wave_swing = (state.wave * std::f32::consts::PI * 6.0).sin();
    let wave_elbow = Point::new(518.0, 150.0);
    let wave_hand = Point::new(535.0 + wave_swing * 11.0, 107.0 + wave_swing.abs() * 3.0);
    let support_elbow = point_lerp(rig.support_elbow, wave_elbow, wave_amount);
    let support_hand = point_lerp(rig.base_grip, wave_hand, wave_amount);
    stroke_limb(
        frame,
        &[rig.support_shoulder, support_elbow, support_hand],
        theme::MUTED,
        with_alpha(theme::ACCENT, 0.84),
        5.5,
    );

    draw_hammer(frame, rig, state);

    for (point, color) in [
        (Point::new(body_x, 259.0), theme::CYAN),
        (rig.main_shoulder, theme::PROOF),
        (rig.main_elbow, theme::PROOF),
        (rig.main_grip, theme::PROOF),
        (support_elbow, theme::ACCENT),
        (support_hand, theme::ACCENT),
    ] {
        draw_joint(frame, point, color);
    }

    draw_coin_head(
        frame,
        Point::new(head_x, 124.0),
        state.attention,
        state.cycle_time,
    );

    let shoulder_marker = canvas::Path::circle(Point::new(511.0, shoulder_y), 3.0);
    frame.fill(&shoulder_marker, with_alpha(theme::ACCENT, 0.34));
}

fn draw_coin_head(frame: &mut canvas::Frame, center: Point, attention: f32, cycle_time: f32) {
    let radius_x = lerp(18.0, 23.0, attention);
    let radius_y = 23.0;

    for (radius, alpha) in [(35.0, 0.025), (29.0, 0.055)] {
        let halo = canvas::Path::circle(center, radius);
        frame.fill(&halo, with_alpha(theme::PROOF, alpha + attention * 0.025));
    }

    draw_ellipse(
        frame,
        center,
        Vector::new(radius_x + 2.0, radius_y + 2.0),
        Color::from_rgba8(5, 7, 13, 0.58),
        None,
    );
    draw_ellipse(
        frame,
        center,
        Vector::new(radius_x, radius_y),
        theme::SURFACE_ALT,
        Some((
            if attention > 0.5 {
                theme::ACCENT
            } else {
                theme::CYAN
            },
            1.5,
        )),
    );
    draw_ellipse(
        frame,
        center,
        Vector::new((radius_x - 7.0).max(8.0), radius_y - 7.0),
        Color::TRANSPARENT,
        Some((with_alpha(theme::PROOF, 0.46 + attention * 0.22), 1.0)),
    );

    frame.fill_text(canvas::Text {
        content: "1".into(),
        position: Point::new(center.x, center.y + 0.5),
        color: theme::TEXT,
        size: iced::Pixels(if attention > 0.6 { 20.0 } else { 18.0 }),
        font: theme::BRAND_FONT,
        align_x: text::Alignment::Center,
        align_y: alignment::Vertical::Center,
        ..canvas::Text::default()
    });

    if attention > 0.35 {
        let blink = if (cycle_time * 7.0).sin() > 0.985 {
            0.2
        } else {
            1.0
        };
        for offset in [-7.0, 7.0] {
            let eye = canvas::Path::circle(Point::new(center.x + offset, center.y - 3.0), 1.35);
            frame.fill(&eye, with_alpha(theme::PROOF, attention * blink));
        }
    }
}

fn draw_hammer(frame: &mut canvas::Frame, rig: HammerRig, state: SceneState) {
    draw_line(
        frame,
        rig.base_grip + Vector::new(2.0, 3.0),
        rig.head + Vector::new(2.0, 3.0),
        Color::from_rgba8(5, 7, 13, 0.52),
        13.0,
    );
    draw_line(frame, rig.base_grip, rig.head, theme::MUTED, 9.0);
    draw_line(
        frame,
        rig.base_grip,
        rig.head,
        with_alpha(theme::PROOF, 0.82),
        2.0,
    );

    frame.with_save(|frame| {
        frame.translate(Vector::new(rig.head.x, rig.head.y));
        frame.rotate(rig.angle + std::f32::consts::FRAC_PI_2);

        let head = polygon(&[
            Point::new(-25.0, -10.0),
            Point::new(-19.0, -14.0),
            Point::new(15.0, -14.0),
            Point::new(25.0, -8.0),
            Point::new(25.0, 8.0),
            Point::new(16.0, 14.0),
            Point::new(-19.0, 14.0),
            Point::new(-25.0, 10.0),
        ]);
        frame.with_save(|frame| {
            frame.translate(Vector::new(2.0, 3.0));
            frame.fill(&head, Color::from_rgba8(5, 7, 13, 0.38));
        });
        frame.fill(&head, theme::SURFACE_HIGH);
        frame.stroke(
            &head,
            canvas::Stroke::default()
                .with_width(1.5)
                .with_color(with_alpha(theme::CYAN, 0.48 + state.impact * 0.52)),
        );

        let face = polygon(&[
            Point::new(-25.0, -10.0),
            Point::new(-19.0, -14.0),
            Point::new(-19.0, 14.0),
            Point::new(-25.0, 10.0),
        ]);
        frame.fill(&face, with_alpha(theme::TEXT, 0.26 + state.impact * 0.56));
        draw_line(
            frame,
            Point::new(-15.0, -11.0),
            Point::new(15.0, -11.0),
            with_alpha(theme::TEXT, 0.50),
            1.0,
        );
    });
}

fn draw_impact(frame: &mut canvas::Frame, state: SceneState) {
    let Some(progress) = state.spark_progress else {
        return;
    };
    let fade = (1.0 - progress).powi(2);
    let origin = Point::new(370.0, 230.0);
    let shockwave = canvas::Path::circle(origin, 8.0 + progress * 46.0);
    frame.stroke(
        &shockwave,
        canvas::Stroke::default()
            .with_width(1.2)
            .with_color(with_alpha(theme::CYAN, 0.38 * fade)),
    );

    for index in 0..18 {
        let angle = (194.0 + index as f32 * 9.7).to_radians();
        let speed = 36.0 + ((index * 29) % 54) as f32;
        let distance = speed * progress;
        let gravity = 38.0 * progress * progress;
        let point = Point::new(
            origin.x + angle.cos() * distance,
            origin.y + angle.sin() * distance + gravity,
        );
        let previous_distance = (distance - 9.0).max(0.0);
        let previous = Point::new(
            origin.x + angle.cos() * previous_distance,
            origin.y + angle.sin() * previous_distance + gravity * 0.78,
        );
        let color = match index % 3 {
            0 => theme::PROOF,
            1 => theme::CYAN,
            _ => theme::ACCENT,
        };
        draw_line(
            frame,
            previous,
            point,
            with_alpha(color, fade * 0.96),
            if index % 6 == 0 { 2.2 } else { 1.3 },
        );
        let spark = canvas::Path::circle(point, if index % 6 == 0 { 2.0 } else { 1.1 });
        frame.fill(&spark, with_alpha(color, fade));
    }
}

fn draw_shutdown_copy(frame: &mut canvas::Frame, elapsed_seconds: f32) {
    centered_text(
        frame,
        "CLOSING WALLET SAFELY",
        405.0,
        18.0,
        theme::TEXT,
        theme::BRAND_FONT,
    );
    centered_text(
        frame,
        "Finishing the current proof step",
        432.0,
        11.0,
        theme::MUTED,
        iced::Font::MONOSPACE,
    );
    centered_text(
        frame,
        "THE WALLET WILL CLOSE AUTOMATICALLY",
        455.0,
        9.0,
        theme::DIM,
        iced::Font::MONOSPACE,
    );

    for index in 0..3 {
        let pulse = 0.24 + 0.76 * (elapsed_seconds * 3.1 - index as f32 * 0.75).sin().max(0.0);
        let dot = canvas::Path::circle(Point::new(350.0 + (index as f32 - 1.0) * 13.0, 478.0), 2.2);
        frame.fill(
            &dot,
            with_alpha(
                if index == 1 {
                    theme::PROOF
                } else {
                    theme::CYAN
                },
                pulse,
            ),
        );
    }
}

fn centered_text(
    frame: &mut canvas::Frame,
    content: &str,
    y: f32,
    size: f32,
    color: Color,
    font: iced::Font,
) {
    frame.fill_text(canvas::Text {
        content: content.into(),
        position: Point::new(DESIGN_WIDTH * 0.5, y),
        color,
        size: iced::Pixels(size),
        font,
        align_x: text::Alignment::Center,
        align_y: alignment::Vertical::Center,
        ..canvas::Text::default()
    });
}

fn stroke_limb(
    frame: &mut canvas::Frame,
    points: &[Point],
    main: Color,
    accent: Color,
    width: f32,
) {
    let path = polyline(points);
    let rounded = canvas::Stroke::default()
        .with_line_cap(canvas::LineCap::Round)
        .with_line_join(canvas::LineJoin::Round);
    frame.stroke(
        &path,
        rounded
            .with_width(width + 5.0)
            .with_color(Color::from_rgba8(5, 7, 13, 0.60)),
    );
    frame.stroke(&path, rounded.with_width(width).with_color(main));
    frame.stroke(&path, rounded.with_width(1.4).with_color(accent));
}

fn draw_joint(frame: &mut canvas::Frame, point: Point, color: Color) {
    let joint = canvas::Path::circle(point, 4.2);
    frame.fill(&joint, theme::SURFACE_HIGH);
    frame.stroke(
        &joint,
        canvas::Stroke::default()
            .with_width(1.1)
            .with_color(with_alpha(color, 0.75)),
    );
}

fn draw_line(frame: &mut canvas::Frame, from: Point, to: Point, color: Color, width: f32) {
    let line = canvas::Path::line(from, to);
    frame.stroke(
        &line,
        canvas::Stroke::default()
            .with_width(width)
            .with_line_cap(canvas::LineCap::Round)
            .with_color(color),
    );
}

fn draw_ellipse(
    frame: &mut canvas::Frame,
    center: Point,
    radii: Vector,
    fill: Color,
    stroke: Option<(Color, f32)>,
) {
    frame.with_save(|frame| {
        frame.translate(Vector::new(center.x, center.y));
        frame.scale_nonuniform(Vector::new(radii.x / radii.y.max(0.01), 1.0));
        let ellipse = canvas::Path::circle(Point::ORIGIN, radii.y);
        if fill.a > 0.0 {
            frame.fill(&ellipse, fill);
        }
        if let Some((color, width)) = stroke {
            frame.stroke(
                &ellipse,
                canvas::Stroke::default()
                    .with_width(width)
                    .with_color(color),
            );
        }
    });
}

fn polygon(points: &[Point]) -> canvas::Path {
    canvas::Path::new(|path| {
        if let Some(first) = points.first().copied() {
            path.move_to(first);
            for point in points.iter().skip(1).copied() {
                path.line_to(point);
            }
            path.close();
        }
    })
}

fn polyline(points: &[Point]) -> canvas::Path {
    canvas::Path::new(|path| {
        if let Some(first) = points.first().copied() {
            path.move_to(first);
            for point in points.iter().skip(1).copied() {
                path.line_to(point);
            }
        }
    })
}

fn point_lerp(start: Point, end: Point, amount: f32) -> Point {
    Point::new(lerp(start.x, end.x, amount), lerp(start.y, end.y, amount))
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
    fn forge_cycle_has_a_real_windup_and_strike_arc() {
        let raised = scene_state(0.0);
        let strike = scene_state(STRIKE_CYCLE_SECONDS * 0.59);
        let raised_rig = hammer_rig(raised);
        let strike_rig = hammer_rig(strike);

        assert!(raised.hammer_angle - strike.hammer_angle > 0.65);
        assert!(raised_rig.head.y < raised_rig.base_grip.y);
        assert!((strike_rig.head.x - 370.0).abs() < 3.0);
        assert!((strike_rig.head.y - 230.0).abs() < 3.0);
        assert_eq!(strike.impact, 1.0);
    }

    #[test]
    fn attention_phase_rests_the_hammer_and_suppresses_sparks() {
        let waving = scene_state(5.42);

        assert_eq!(waving.attention, 1.0);
        assert!(waving.wave > 0.0);
        assert!((waving.hammer_angle - STRIKE_ANGLE).abs() < f32::EPSILON);
        assert!((waving.hammer_drop - 1.0).abs() < f32::EPSILON);
        assert!(waving.spark_progress.is_none());
    }
}
