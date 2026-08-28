// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use iced::widget::canvas;
use iced::{Color, Point, Rectangle, Renderer, Theme};

use crate::app::Message;
use crate::theme;

/// Static ambient geometry shared by every wallet screen.
///
/// The backdrop intentionally has no clock or subscription. It is redrawn only
/// when the GUI redraws and does not add work to the node.
#[derive(Debug, Clone, Copy, Default)]
pub struct InterfaceBackdrop;

impl canvas::Program<Message> for InterfaceBackdrop {
    type State = canvas::Cache;

    fn draw(
        &self,
        state: &Self::State,
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: iced::mouse::Cursor,
    ) -> Vec<canvas::Geometry> {
        vec![state.draw(renderer, bounds.size(), |frame| {
            draw_grid(frame, bounds);
            draw_ambient_rings(frame, bounds);
        })]
    }
}

fn draw_grid(frame: &mut canvas::Frame, bounds: Rectangle) {
    let spacing = if bounds.width < 1_000.0 { 54.0 } else { 64.0 };
    let grid_left = (bounds.width * 0.035).floor();
    let grid_right = bounds.width - grid_left;
    let grid_top = 40.0;
    let grid_bottom = bounds.height - 32.0;

    let mut x = grid_left;
    while x <= grid_right {
        let line = canvas::Path::line(Point::new(x, grid_top), Point::new(x, grid_bottom));
        frame.stroke(
            &line,
            canvas::Stroke::default()
                .with_width(1.0)
                .with_color(Color::from_rgba8(206, 88, 214, 0.105)),
        );
        x += spacing;
    }

    let mut y = grid_top;
    while y <= grid_bottom {
        let line = canvas::Path::line(Point::new(grid_left, y), Point::new(grid_right, y));
        frame.stroke(
            &line,
            canvas::Stroke::default()
                .with_width(1.0)
                .with_color(Color::from_rgba8(103, 215, 246, 0.115)),
        );
        y += spacing;
    }
}

fn draw_ambient_rings(frame: &mut canvas::Frame, bounds: Rectangle) {
    let short_side = bounds.width.min(bounds.height);
    let left_center = Point::new(bounds.width * 0.18, bounds.height * 0.61);
    let right_center = Point::new(bounds.width * 0.84, bounds.height * 0.34);

    draw_ring_family(
        frame,
        left_center,
        short_side * 0.15,
        [theme::PROOF, theme::CYAN, theme::ACCENT],
        [0.17, 0.10, 0.052],
    );
    draw_ring_family(
        frame,
        right_center,
        short_side * 0.12,
        [theme::CYAN, theme::ACCENT, theme::PROOF],
        [0.13, 0.072, 0.038],
    );

    draw_soft_glow(frame, left_center, short_side * 0.31, theme::PROOF, 0.072);
    draw_soft_glow(frame, right_center, short_side * 0.25, theme::CYAN, 0.052);
}

fn draw_ring_family(
    frame: &mut canvas::Frame,
    center: Point,
    base_radius: f32,
    colors: [Color; 3],
    alphas: [f32; 3],
) {
    for (index, (color, alpha)) in colors.into_iter().zip(alphas).enumerate() {
        let radius = base_radius * (1.0 + index as f32 * 0.43);
        let ring = canvas::Path::circle(center, radius);
        frame.stroke(
            &ring,
            canvas::Stroke::default()
                .with_width(1.0)
                .with_color(Color { a: alpha, ..color }),
        );
    }
}

fn draw_soft_glow(frame: &mut canvas::Frame, center: Point, radius: f32, color: Color, alpha: f32) {
    for layer in (1..=10).rev() {
        let progress = layer as f32 / 10.0;
        let glow = canvas::Path::circle(center, radius * progress);
        frame.fill(
            &glow,
            Color {
                a: alpha * (1.0 - progress).powi(2) * 0.48,
                ..color
            },
        );
    }
}
