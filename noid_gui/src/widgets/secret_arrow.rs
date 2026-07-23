// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use iced::widget::canvas;
use iced::{Point, Rectangle, Renderer, Theme};

use crate::app::Message;
use crate::theme;

#[derive(Debug, Clone, Copy, Default)]
pub struct SecretArrow;

impl canvas::Program<Message> for SecretArrow {
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
        let center_y = bounds.height * 0.5;
        let tip_x = bounds.width - 1.0;
        let head = 5.0_f32.min(bounds.width * 0.25);
        let shaft = canvas::Path::line(Point::new(1.0, center_y), Point::new(tip_x, center_y));
        frame.stroke(
            &shaft,
            canvas::Stroke::default()
                .with_width(1.25)
                .with_color(theme::PROOF),
        );
        let arrowhead = canvas::Path::new(|path| {
            path.move_to(Point::new(tip_x - head, center_y - head * 0.62));
            path.line_to(Point::new(tip_x, center_y));
            path.line_to(Point::new(tip_x - head, center_y + head * 0.62));
        });
        frame.stroke(
            &arrowhead,
            canvas::Stroke::default()
                .with_width(1.25)
                .with_color(theme::PROOF),
        );
        vec![frame.into_geometry()]
    }
}
