// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use std::cell::Cell;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use iced::border::Radius;
use iced::mouse;
use iced::widget::canvas;
use iced::{Color, Point, Rectangle, Renderer, Size, Theme};

use crate::app::Message;
use crate::model::{SegmentSnapshot, UtxoSnapshot};
use crate::theme;

const ATLAS_COLUMNS: usize = 16;
const ATLAS_ROWS: usize = 16;
const ATLAS_GROUP: usize = 4;

#[derive(Debug, Clone)]
pub struct StateField {
    segments: Vec<SegmentSnapshot>,
    owner_counts: [u32; ATLAS_COLUMNS * ATLAS_ROWS],
    selected_segment: Option<u8>,
    filtered_segment: Option<u8>,
}

#[derive(Debug, Default)]
pub struct StateFieldState {
    geometry: canvas::Cache,
    fingerprint: Cell<u64>,
    hovered_segment: Cell<Option<usize>>,
}

impl StateField {
    pub fn new(
        segments: &[SegmentSnapshot],
        utxos: &[UtxoSnapshot],
        selected_segment: Option<u8>,
        filtered_segment: Option<u8>,
    ) -> Self {
        let mut owner_counts = [0u32; ATLAS_COLUMNS * ATLAS_ROWS];
        for utxo in utxos {
            owner_counts[utxo.segment as usize] =
                owner_counts[utxo.segment as usize].saturating_add(1);
        }

        Self {
            segments: segments.to_vec(),
            owner_counts,
            selected_segment,
            filtered_segment,
        }
    }

    fn segment_at(&self, bounds: Rectangle, cursor: mouse::Cursor) -> Option<usize> {
        let position = cursor.position_in(bounds)?;
        let geometry = AtlasGeometry::new(bounds);
        let index = geometry.index_at(position)?;
        self.segments.get(index).map(|_| index)
    }

    fn interactive_segment_at(&self, bounds: Rectangle, cursor: mouse::Cursor) -> Option<usize> {
        self.segment_at(bounds, cursor)
            .filter(|index| self.segments[*index].owned)
    }

    fn visual_fingerprint(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.selected_segment.hash(&mut hasher);
        self.filtered_segment.hash(&mut hasher);
        self.owner_counts.hash(&mut hasher);
        self.segments.len().hash(&mut hasher);
        for segment in &self.segments {
            segment.occupancy.to_bits().hash(&mut hasher);
            segment.owned.hash(&mut hasher);
        }
        hasher.finish()
    }
}

impl canvas::Program<Message> for StateField {
    type State = StateFieldState;

    fn update(
        &self,
        state: &mut Self::State,
        event: &canvas::Event,
        bounds: Rectangle,
        cursor: mouse::Cursor,
    ) -> Option<canvas::Action<Message>> {
        if matches!(
            event,
            canvas::Event::Mouse(
                mouse::Event::CursorEntered
                    | mouse::Event::CursorLeft
                    | mouse::Event::CursorMoved { .. }
            )
        ) {
            let hovered = self.interactive_segment_at(bounds, cursor);
            if state.hovered_segment.replace(hovered) != hovered {
                return Some(canvas::Action::request_redraw());
            }
        }

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
        state: &Self::State,
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        cursor: mouse::Cursor,
    ) -> Vec<canvas::Geometry> {
        let fingerprint = self.visual_fingerprint();
        if state.fingerprint.replace(fingerprint) != fingerprint {
            state.geometry.clear();
        }
        let hovered = self.interactive_segment_at(bounds, cursor);
        state.hovered_segment.set(hovered);
        let base = state.geometry.draw(renderer, bounds.size(), |frame| {
            let geometry = AtlasGeometry::new(bounds);
            let (atlas_origin, atlas_size) = geometry.atlas_bounds();
            let backdrop = canvas::Path::rounded_rectangle(
                Point::new(atlas_origin.x - 8.0, atlas_origin.y - 8.0),
                Size::new(atlas_size.width + 16.0, atlas_size.height + 16.0),
                Radius::from(7.0),
            );
            frame.fill(&backdrop, Color::from_rgba8(8, 11, 19, 0.68));
            frame.stroke(
                &backdrop,
                canvas::Stroke::default()
                    .with_width(1.0)
                    .with_color(Color::from_rgba8(103, 215, 246, 0.14)),
            );

            for group_row in 0..ATLAS_ROWS / ATLAS_GROUP {
                for group_column in 0..ATLAS_COLUMNS / ATLAS_GROUP {
                    let (top_left, size) = geometry.group(group_column, group_row);
                    let group = canvas::Path::rounded_rectangle(
                        Point::new(top_left.x - 2.0, top_left.y - 2.0),
                        Size::new(size.width + 4.0, size.height + 4.0),
                        Radius::from(4.0),
                    );
                    frame.stroke(
                        &group,
                        canvas::Stroke::default()
                            .with_width(1.0)
                            .with_color(Color::from_rgba8(214, 224, 255, 0.10)),
                    );
                }
            }

            for (index, segment) in self
                .segments
                .iter()
                .take(ATLAS_COLUMNS * ATLAS_ROWS)
                .enumerate()
            {
                let (top_left, size) = geometry.cell(index);
                let radius = (size.width.min(size.height) * 0.12).clamp(1.0, 2.5);
                let path = canvas::Path::rounded_rectangle(top_left, size, Radius::from(radius));
                let strength = segment.occupancy.clamp(0.0, 1.0).sqrt();

                frame.fill(&path, density_color(segment.occupancy));
                frame.stroke(
                    &path,
                    canvas::Stroke::default()
                        .with_width(0.75)
                        .with_color(Color::from_rgba8(214, 224, 255, 0.13)),
                );

                if strength > 0.02 {
                    let inset = 1.5;
                    let signal_width = ((size.width - inset * 2.0) * strength).max(1.0);
                    let signal = canvas::Path::rounded_rectangle(
                        Point::new(top_left.x + inset, top_left.y + size.height - inset - 1.2),
                        Size::new(signal_width, 1.2),
                        Radius::from(0.6),
                    );
                    frame.fill(
                        &signal,
                        Color::from_rgba8(103, 215, 246, 0.30 + strength * 0.42),
                    );
                }

                if segment.owned {
                    frame.stroke(
                        &path,
                        canvas::Stroke::default()
                            .with_width(1.35)
                            .with_color(Color::from_rgba8(206, 88, 214, 0.92)),
                    );

                    let count = self.owner_counts[index];
                    if count > 1 && size.height >= 12.0 {
                        let label = count.to_string();
                        frame.fill_text(canvas::Text {
                            content: label.clone(),
                            position: Point::new(
                                top_left.x + size.width * 0.5
                                    - label.len() as f32 * size.height * 0.15,
                                top_left.y + size.height * 0.08,
                            ),
                            color: theme::TEXT,
                            size: iced::Pixels((size.height * 0.58).clamp(7.0, 10.0)),
                            font: theme::BRAND_FONT,
                            ..canvas::Text::default()
                        });
                    } else {
                        let marker = canvas::Path::circle(
                            Point::new(
                                top_left.x + size.width - 2.5,
                                top_left.y + size.height * 0.25,
                            ),
                            1.35,
                        );
                        frame.fill(&marker, theme::PROOF);
                    }
                }

                if self.filtered_segment == Some(index as u8) {
                    frame.fill(&path, Color::from_rgba8(206, 88, 214, 0.14));
                    let halo = canvas::Path::rounded_rectangle(
                        Point::new(top_left.x - 2.5, top_left.y - 2.5),
                        Size::new(size.width + 5.0, size.height + 5.0),
                        Radius::from(radius + 2.5),
                    );
                    frame.stroke(
                        &halo,
                        canvas::Stroke::default()
                            .with_width(2.0)
                            .with_color(Color::from_rgba8(206, 88, 214, 0.78)),
                    );
                }

                if self.selected_segment == Some(index as u8) {
                    // Keep the density signal and owned-UTXO count visible. The
                    // former pale marker looked like a covered or corrupt cell.
                    frame.fill(&path, Color::from_rgba8(103, 215, 246, 0.10));
                    frame.stroke(
                        &path,
                        canvas::Stroke::default()
                            .with_width(2.2)
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
                            .with_width(1.2)
                            .with_color(Color::from_rgba8(103, 215, 246, 0.48)),
                    );
                }
            }
        });

        let mut overlay = canvas::Frame::new(renderer, bounds.size());
        if let Some(index) = hovered.filter(|index| self.selected_segment != Some(*index as u8)) {
            let geometry = AtlasGeometry::new(bounds);
            let (top_left, size) = geometry.cell(index);
            let radius = (size.width.min(size.height) * 0.12).clamp(1.0, 2.5);
            let path = canvas::Path::rounded_rectangle(top_left, size, Radius::from(radius));
            overlay.fill(&path, Color::from_rgba8(103, 215, 246, 0.055));
            overlay.stroke(
                &path,
                canvas::Stroke::default()
                    .with_width(if self.segments[index].owned { 2.2 } else { 1.5 })
                    .with_color(Color::from_rgba8(103, 215, 246, 0.72)),
            );
        }

        vec![base, overlay.into_geometry()]
    }

    fn mouse_interaction(
        &self,
        _state: &Self::State,
        bounds: Rectangle,
        cursor: mouse::Cursor,
    ) -> mouse::Interaction {
        self.interactive_segment_at(bounds, cursor)
            .map(|_| mouse::Interaction::Pointer)
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Copy)]
struct AtlasGeometry {
    origin: Point,
    cell: Size,
    gap: f32,
    group_gap: f32,
    atlas_size: Size,
}

impl AtlasGeometry {
    fn new(bounds: Rectangle) -> Self {
        let padding = if bounds.width < 500.0 { 14.0 } else { 18.0 };
        let gap = if bounds.width < 500.0 { 1.8 } else { 2.2 };
        let group_gap = if bounds.width < 500.0 { 2.8 } else { 3.5 };
        let usable_width = (bounds.width - padding * 2.0).max(64.0);
        let usable_height = (bounds.height - padding * 2.0).max(64.0);
        let ordinary_gaps = gap * (ATLAS_COLUMNS - 1) as f32;
        let group_gaps = group_gap * (ATLAS_COLUMNS / ATLAS_GROUP - 1) as f32;
        let max_cell_width =
            ((usable_width - ordinary_gaps - group_gaps) / ATLAS_COLUMNS as f32).max(2.0);
        let max_cell_height =
            ((usable_height - ordinary_gaps - group_gaps) / ATLAS_ROWS as f32).max(2.0);
        let cell = Size::new(max_cell_width, max_cell_height);
        let atlas_size = Size::new(
            cell.width * ATLAS_COLUMNS as f32 + ordinary_gaps + group_gaps,
            cell.height * ATLAS_ROWS as f32 + ordinary_gaps + group_gaps,
        );

        Self {
            origin: Point::new(
                ((bounds.width - atlas_size.width) * 0.5).max(padding),
                ((bounds.height - atlas_size.height) * 0.5).max(padding),
            ),
            cell,
            gap,
            group_gap,
            atlas_size,
        }
    }

    fn atlas_bounds(self) -> (Point, Size) {
        (self.origin, self.atlas_size)
    }

    fn offset(self, position: usize, cell_extent: f32) -> f32 {
        position as f32 * (cell_extent + self.gap)
            + (position / ATLAS_GROUP) as f32 * self.group_gap
    }

    fn cell(self, index: usize) -> (Point, Size) {
        let column = index % ATLAS_COLUMNS;
        let row = index / ATLAS_COLUMNS;
        (
            Point::new(
                self.origin.x + self.offset(column, self.cell.width),
                self.origin.y + self.offset(row, self.cell.height),
            ),
            self.cell,
        )
    }

    fn group(self, column: usize, row: usize) -> (Point, Size) {
        let first = row * ATLAS_GROUP * ATLAS_COLUMNS + column * ATLAS_GROUP;
        let (top_left, _) = self.cell(first);
        let width = self.cell.width * ATLAS_GROUP as f32 + self.gap * (ATLAS_GROUP - 1) as f32;
        let height = self.cell.height * ATLAS_GROUP as f32 + self.gap * (ATLAS_GROUP - 1) as f32;
        (top_left, Size::new(width, height))
    }

    fn index_at(self, position: Point) -> Option<usize> {
        let column = self.axis_at(position.x - self.origin.x, self.cell.width)?;
        let row = self.axis_at(position.y - self.origin.y, self.cell.height)?;
        Some(row * ATLAS_COLUMNS + column)
    }

    fn axis_at(self, position: f32, cell_extent: f32) -> Option<usize> {
        if position < 0.0 {
            return None;
        }

        (0..ATLAS_COLUMNS).find(|index| {
            let start = self.offset(*index, cell_extent);
            position >= start && position <= start + cell_extent
        })
    }
}

fn density_color(occupancy: f32) -> Color {
    let strength = occupancy.clamp(0.0, 1.0).sqrt();
    if strength <= 0.02 {
        return Color::from_rgb8(23, 27, 38);
    }

    Color::from_rgb(
        0.10 + strength * 0.10,
        0.16 + strength * 0.38,
        0.22 + strength * 0.46,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atlas_hit_testing_round_trips_every_segment() {
        let geometry = AtlasGeometry::new(Rectangle {
            x: 0.0,
            y: 0.0,
            width: 440.0,
            height: 250.0,
        });

        for index in 0..ATLAS_COLUMNS * ATLAS_ROWS {
            let (top_left, size) = geometry.cell(index);
            let center = Point::new(
                top_left.x + size.width * 0.5,
                top_left.y + size.height * 0.5,
            );
            assert_eq!(geometry.index_at(center), Some(index));
        }
    }

    #[test]
    fn hover_redraws_only_for_interactive_owned_segments() {
        let bounds = Rectangle {
            x: 0.0,
            y: 0.0,
            width: 440.0,
            height: 250.0,
        };
        let geometry = AtlasGeometry::new(bounds);
        let mut segments = vec![
            SegmentSnapshot {
                occupancy: 0.0,
                live_count: 0,
                capacity: 1,
                owned: false,
            };
            ATLAS_COLUMNS * ATLAS_ROWS
        ];
        segments[17].owned = true;
        segments[17].live_count = 1;
        let field = StateField::new(&segments, &[], None, None);
        let mut state = StateFieldState::default();
        let center = |index| {
            let (top_left, size) = geometry.cell(index);
            Point::new(
                top_left.x + size.width * 0.5,
                top_left.y + size.height * 0.5,
            )
        };
        let moved = |position| canvas::Event::Mouse(mouse::Event::CursorMoved { position });

        let empty = center(0);
        assert!(<StateField as canvas::Program<Message>>::update(
            &field,
            &mut state,
            &moved(empty),
            bounds,
            mouse::Cursor::Available(empty),
        )
        .is_none());

        let owned = center(17);
        assert!(<StateField as canvas::Program<Message>>::update(
            &field,
            &mut state,
            &moved(owned),
            bounds,
            mouse::Cursor::Available(owned),
        )
        .is_some());
        assert!(<StateField as canvas::Program<Message>>::update(
            &field,
            &mut state,
            &moved(owned),
            bounds,
            mouse::Cursor::Available(owned),
        )
        .is_none());
        assert!(<StateField as canvas::Program<Message>>::update(
            &field,
            &mut state,
            &moved(empty),
            bounds,
            mouse::Cursor::Available(empty),
        )
        .is_some());
    }

    #[test]
    fn atlas_expands_to_the_available_panel_area() {
        let bounds = Rectangle {
            x: 0.0,
            y: 0.0,
            width: 900.0,
            height: 300.0,
        };
        let geometry = AtlasGeometry::new(bounds);
        let (_, atlas_size) = geometry.atlas_bounds();

        assert!(atlas_size.width >= bounds.width - 40.0);
        assert!(atlas_size.height >= bounds.height - 40.0);
    }

    #[test]
    fn visual_fingerprint_invalidates_cached_state_changes() {
        let mut segments = vec![
            SegmentSnapshot {
                occupancy: 0.0,
                live_count: 0,
                capacity: 1,
                owned: false,
            };
            ATLAS_COLUMNS * ATLAS_ROWS
        ];
        let mut field = StateField::new(&segments, &[], None, None);
        let empty = field.visual_fingerprint();

        segments[17].occupancy = 0.42;
        field = StateField::new(&segments, &[], None, None);
        let occupied = field.visual_fingerprint();
        assert_ne!(empty, occupied);

        field.selected_segment = Some(17);
        assert_ne!(occupied, field.visual_fingerprint());
    }
}
