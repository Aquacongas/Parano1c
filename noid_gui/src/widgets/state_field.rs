// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use iced::border::Radius;
use iced::mouse;
use iced::widget::canvas;
use iced::{Color, Point, Rectangle, Renderer, Size, Theme};

use crate::app::Message;
use crate::model::{SegmentSnapshot, UtxoSnapshot};
use crate::theme;

const ATLAS_COLUMNS: usize = 16;
const ATLAS_ROWS: usize = 16;

#[derive(Debug, Clone)]
pub struct StateField {
    segments: Vec<SegmentSnapshot>,
    owner_counts: [u16; ATLAS_COLUMNS * ATLAS_ROWS],
    selected_segment: Option<u8>,
}

impl StateField {
    pub fn new(
        segments: &[SegmentSnapshot],
        utxos: &[UtxoSnapshot],
        selected_segment: Option<u8>,
    ) -> Self {
        let mut owner_counts = [0u16; ATLAS_COLUMNS * ATLAS_ROWS];
        for utxo in utxos {
            owner_counts[utxo.segment as usize] =
                owner_counts[utxo.segment as usize].saturating_add(1);
        }

        Self {
            segments: segments.to_vec(),
            owner_counts,
            selected_segment,
        }
    }

    fn segment_at(&self, bounds: Rectangle, cursor: mouse::Cursor) -> Option<usize> {
        let position = cursor.position_in(bounds)?;
        let geometry = AtlasGeometry::new(bounds);
        let relative_x = position.x - geometry.origin.x;
        let relative_y = position.y - geometry.origin.y;
        if relative_x < 0.0 || relative_y < 0.0 {
            return None;
        }

        let column = (relative_x / geometry.stride_x()).floor() as usize;
        let row = (relative_y / geometry.stride_y()).floor() as usize;
        if column >= ATLAS_COLUMNS || row >= ATLAS_ROWS {
            return None;
        }

        if relative_x - column as f32 * geometry.stride_x() > geometry.cell.width
            || relative_y - row as f32 * geometry.stride_y() > geometry.cell.height
        {
            return None;
        }

        let index = row * ATLAS_COLUMNS + column;
        self.segments.get(index).map(|_| index)
    }
}

impl canvas::Program<Message> for StateField {
    type State = ();

    fn update(
        &self,
        _state: &mut Self::State,
        event: &canvas::Event,
        bounds: Rectangle,
        cursor: mouse::Cursor,
    ) -> Option<canvas::Action<Message>> {
        if matches!(
            event,
            canvas::Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Left))
        ) {
            let index = self.segment_at(bounds, cursor)?;
            if self
                .segments
                .get(index)
                .is_some_and(|segment| segment.owned)
            {
                return Some(
                    canvas::Action::publish(Message::SelectSegment(index as u8)).and_capture(),
                );
            }
        }

        None
    }

    fn draw(
        &self,
        _state: &Self::State,
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        cursor: mouse::Cursor,
    ) -> Vec<canvas::Geometry> {
        let mut frame = canvas::Frame::new(renderer, bounds.size());
        let geometry = AtlasGeometry::new(bounds);
        let hovered = self.segment_at(bounds, cursor);

        for (index, segment) in self
            .segments
            .iter()
            .take(ATLAS_COLUMNS * ATLAS_ROWS)
            .enumerate()
        {
            let (top_left, size) = geometry.cell(index);
            let radius = (size.width.min(size.height) * 0.12).clamp(1.0, 2.5);
            let path = canvas::Path::rounded_rectangle(top_left, size, Radius::from(radius));

            frame.fill(&path, density_color(segment.occupancy));

            if segment.owned {
                frame.fill(&path, Color::from_rgba8(206, 88, 214, 0.90));
                frame.stroke(
                    &path,
                    canvas::Stroke::default()
                        .with_width(if hovered == Some(index) { 2.0 } else { 1.0 })
                        .with_color(if hovered == Some(index) {
                            theme::TEXT
                        } else {
                            Color::from_rgba8(246, 247, 250, 0.45)
                        }),
                );

                let count = self.owner_counts[index];
                if count > 1 && size.height >= 12.0 {
                    frame.fill_text(canvas::Text {
                        content: count.to_string(),
                        position: Point::new(
                            top_left.x + (size.width * 0.34).max(3.0),
                            top_left.y + (size.height * 0.10).max(1.0),
                        ),
                        color: theme::INK,
                        size: iced::Pixels((size.height * 0.56).clamp(8.0, 12.0)),
                        font: theme::BRAND_FONT,
                        ..canvas::Text::default()
                    });
                }
            }

            if self.selected_segment == Some(index as u8) {
                frame.fill(&path, theme::TEXT);

                let inset = (size.width.min(size.height) * 0.26).clamp(3.0, 6.0);
                let marker_size = Size::new(
                    (size.width - inset * 2.0).max(3.0),
                    (size.height - inset * 2.0).max(3.0),
                );
                let marker = canvas::Path::rounded_rectangle(
                    Point::new(top_left.x + inset, top_left.y + inset),
                    marker_size,
                    Radius::from(1.0),
                );
                frame.fill(&marker, theme::PROOF);

                frame.stroke(
                    &path,
                    canvas::Stroke::default()
                        .with_width(3.0)
                        .with_color(theme::CYAN),
                );

                let halo = canvas::Path::rounded_rectangle(
                    Point::new(top_left.x - 2.0, top_left.y - 2.0),
                    Size::new(size.width + 4.0, size.height + 4.0),
                    Radius::from(radius + 2.0),
                );
                frame.stroke(
                    &halo,
                    canvas::Stroke::default()
                        .with_width(1.0)
                        .with_color(Color::from_rgba8(103, 215, 246, 0.62)),
                );
            }
        }

        vec![frame.into_geometry()]
    }

    fn mouse_interaction(
        &self,
        _state: &Self::State,
        bounds: Rectangle,
        cursor: mouse::Cursor,
    ) -> mouse::Interaction {
        self.segment_at(bounds, cursor)
            .and_then(|index| self.segments.get(index))
            .filter(|segment| segment.owned)
            .map(|_| mouse::Interaction::Pointer)
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Copy)]
struct AtlasGeometry {
    origin: Point,
    cell: Size,
    gap: f32,
}

impl AtlasGeometry {
    fn new(bounds: Rectangle) -> Self {
        let padding = if bounds.width < 500.0 { 10.0 } else { 12.0 };
        let gap = if bounds.width < 500.0 { 2.5 } else { 3.0 };
        let usable_width = (bounds.width - padding * 2.0).max(64.0);
        let usable_height = (bounds.height - padding * 2.0).max(64.0);
        let cell = Size::new(
            ((usable_width - gap * (ATLAS_COLUMNS - 1) as f32) / ATLAS_COLUMNS as f32).max(2.0),
            ((usable_height - gap * (ATLAS_ROWS - 1) as f32) / ATLAS_ROWS as f32).max(2.0),
        );

        Self {
            origin: Point::new(padding, padding),
            cell,
            gap,
        }
    }

    fn stride_x(self) -> f32 {
        self.cell.width + self.gap
    }

    fn stride_y(self) -> f32 {
        self.cell.height + self.gap
    }

    fn cell(self, index: usize) -> (Point, Size) {
        let column = (index % ATLAS_COLUMNS) as f32;
        let row = (index / ATLAS_COLUMNS) as f32;
        (
            Point::new(
                self.origin.x + column * self.stride_x(),
                self.origin.y + row * self.stride_y(),
            ),
            self.cell,
        )
    }
}

fn density_color(occupancy: f32) -> Color {
    let strength = occupancy.clamp(0.0, 1.0).sqrt();
    if strength <= 0.02 {
        return Color::from_rgb8(28, 31, 42);
    }

    Color::from_rgb(
        0.10 + strength * 0.10,
        0.16 + strength * 0.38,
        0.22 + strength * 0.46,
    )
}
