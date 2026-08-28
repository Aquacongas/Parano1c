// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use iced::widget::canvas;
use iced::{Color, Point, Rectangle, Renderer, Size, Theme};

use crate::app::Message;
use crate::theme;

#[derive(Debug, Clone, Copy)]
pub struct PhotoScanner {
    progress: f32,
    active: bool,
}

impl PhotoScanner {
    pub fn new(progress: f32, active: bool) -> Self {
        Self {
            progress: progress.clamp(0.0, 1.0),
            active,
        }
    }
}

#[derive(Debug, Default)]
pub struct PhotoScannerState {
    background: canvas::Cache,
}

impl canvas::Program<Message> for PhotoScanner {
    type State = PhotoScannerState;

    fn draw(
        &self,
        state: &Self::State,
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: iced::mouse::Cursor,
    ) -> Vec<canvas::Geometry> {
        let background = state.background.draw(renderer, bounds.size(), |frame| {
            draw_background(frame, bounds.size());
        });

        if !self.active || bounds.width < 4.0 || bounds.height < 5.0 {
            return vec![background];
        }

        let mut frame = canvas::Frame::new(renderer, bounds.size());
        let y = 8.0 + (bounds.height - 16.0).max(0.0) * self.progress;
        for (half_height, alpha) in [(24.0, 0.025), (12.0, 0.045), (5.0, 0.075)] {
            let top = (y - half_height).max(0.0);
            let bottom = (y + half_height).min(bounds.height);
            let band = canvas::Path::rectangle(
                Point::new(0.0, top),
                Size::new(bounds.width, bottom - top),
            );
            frame.fill(&band, Color::from_rgba8(103, 215, 246, alpha));
        }

        for (offset, width, alpha) in [
            (-4.0, 5.0, 0.06),
            (4.0, 5.0, 0.06),
            (-1.5, 3.0, 0.13),
            (1.5, 3.0, 0.13),
        ] {
            let glow = canvas::Path::line(
                Point::new(0.0, (y + offset).clamp(0.0, bounds.height)),
                Point::new(bounds.width, (y + offset).clamp(0.0, bounds.height)),
            );
            frame.stroke(
                &glow,
                canvas::Stroke::default()
                    .with_width(width)
                    .with_color(Color::from_rgba8(103, 215, 246, alpha)),
            );
        }
        let core = canvas::Path::line(Point::new(0.0, y), Point::new(bounds.width, y));
        frame.stroke(
            &core,
            canvas::Stroke::default()
                .with_width(1.25)
                .with_color(theme::CYAN),
        );

        for index in 0..14 {
            let x = ((index * 47 + 19) % 193) as f32 / 193.0 * bounds.width;
            let offset = (((index * 29 + 7) % 17) as f32 - 8.0) * 1.25;
            let size = if index % 5 == 0 { 2.5 } else { 1.5 };
            let pixel = canvas::Path::rectangle(
                Point::new(x, (y + offset).clamp(1.0, bounds.height - size - 1.0)),
                Size::new(size, size),
            );
            frame.fill(
                &pixel,
                if index % 3 == 0 {
                    theme::PROOF
                } else {
                    theme::ACCENT
                },
            );
        }

        vec![background, frame.into_geometry()]
    }
}

fn draw_background(frame: &mut canvas::Frame, size: Size) {
    for column in 1..12 {
        let x = size.width * column as f32 / 12.0;
        let path = canvas::Path::line(Point::new(x, 0.0), Point::new(x, size.height));
        frame.stroke(
            &path,
            canvas::Stroke::default()
                .with_width(1.0)
                .with_color(Color::from_rgba8(103, 215, 246, 0.055)),
        );
    }
    for row in 1..8 {
        let y = size.height * row as f32 / 8.0;
        let path = canvas::Path::line(Point::new(0.0, y), Point::new(size.width, y));
        frame.stroke(
            &path,
            canvas::Stroke::default()
                .with_width(1.0)
                .with_color(Color::from_rgba8(103, 215, 246, 0.045)),
        );
    }

    let corner = 18.0_f32.min(size.width * 0.1).min(size.height * 0.1);
    for (start, middle, end) in [
        (
            Point::new(1.0, corner),
            Point::new(1.0, 1.0),
            Point::new(corner, 1.0),
        ),
        (
            Point::new(size.width - corner, 1.0),
            Point::new(size.width - 1.0, 1.0),
            Point::new(size.width - 1.0, corner),
        ),
        (
            Point::new(1.0, size.height - corner),
            Point::new(1.0, size.height - 1.0),
            Point::new(corner, size.height - 1.0),
        ),
        (
            Point::new(size.width - corner, size.height - 1.0),
            Point::new(size.width - 1.0, size.height - 1.0),
            Point::new(size.width - 1.0, size.height - corner),
        ),
    ] {
        let path = canvas::Path::new(|builder| {
            builder.move_to(start);
            builder.line_to(middle);
            builder.line_to(end);
        });
        frame.stroke(
            &path,
            canvas::Stroke::default()
                .with_width(1.5)
                .with_color(Color::from_rgba8(103, 215, 246, 0.72)),
        );
    }
}
