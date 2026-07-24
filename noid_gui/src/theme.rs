// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use iced::border::Radius;
use iced::widget::{
    button as button_widget, container, scrollable as scrollable_widget,
    text_editor as editor_widget, text_input as input_widget,
};
use iced::{font, theme::Palette, Background, Border, Color, Font, Shadow, Theme, Vector};

pub const BACKGROUND: Color = Color::from_rgb8(35, 37, 49);
pub const SURFACE: Color = Color::from_rgb8(39, 42, 56);
pub const SURFACE_ALT: Color = Color::from_rgb8(47, 50, 66);
pub const SURFACE_HIGH: Color = Color::from_rgb8(59, 64, 81);
pub const LINE: Color = Color::from_rgba8(214, 224, 255, 0.14);
pub const LINE_STRONG: Color = Color::from_rgba8(224, 232, 255, 0.25);
pub const TEXT: Color = Color::from_rgb8(246, 247, 250);
pub const MUTED: Color = Color::from_rgb8(195, 198, 211);
pub const DIM: Color = Color::from_rgb8(132, 135, 153);
pub const ACCENT: Color = Color::from_rgb8(52, 224, 111);
pub const CYAN: Color = Color::from_rgb8(103, 215, 246);
pub const PROOF: Color = Color::from_rgb8(206, 88, 214);
pub const WARNING: Color = Color::from_rgb8(231, 218, 61);
pub const ADVISORY: Color = Color::from_rgb8(255, 176, 74);
pub const DANGER: Color = Color::from_rgb8(255, 107, 119);
pub const INK: Color = Color::from_rgb8(31, 33, 43);
pub const TECH_FONT: Font = Font {
    family: font::Family::Name("Noto Sans Mono"),
    weight: font::Weight::Normal,
    stretch: font::Stretch::Normal,
    style: font::Style::Normal,
};
pub const BRAND_FONT: Font = Font {
    family: font::Family::Name("Noto Sans"),
    weight: font::Weight::Bold,
    stretch: font::Stretch::Normal,
    style: font::Style::Normal,
};
pub const SYMBOL_FONT: Font = Font {
    family: font::Family::Name("Noto Sans Symbols"),
    weight: font::Weight::Bold,
    stretch: font::Stretch::Normal,
    style: font::Style::Normal,
};

fn soft_shadow() -> Shadow {
    Shadow {
        color: Color::from_rgba8(5, 7, 13, 0.20),
        offset: Vector::new(0.0, 2.0),
        blur_radius: 6.0,
    }
}

pub fn paranoid_theme() -> Theme {
    Theme::custom(
        "ParanO(1)d System",
        Palette {
            background: BACKGROUND,
            text: TEXT,
            primary: ACCENT,
            success: ACCENT,
            warning: WARNING,
            danger: DANGER,
        },
    )
}

pub fn root(_: &Theme) -> container::Style {
    container::Style::default()
        .background(BACKGROUND)
        .color(TEXT)
}

pub fn surface(_: &Theme) -> container::Style {
    container::Style {
        text_color: Some(TEXT),
        background: Some(Background::Color(SURFACE)),
        border: Border {
            color: LINE,
            width: 1.0,
            radius: Radius::from(8.0),
        },
        shadow: soft_shadow(),
        snap: true,
    }
}

pub fn surface_alt(_: &Theme) -> container::Style {
    container::Style {
        text_color: Some(TEXT),
        background: Some(Background::Color(SURFACE_ALT)),
        border: Border {
            color: LINE,
            width: 1.0,
            radius: Radius::from(6.0),
        },
        shadow: Shadow::default(),
        snap: true,
    }
}

pub fn node_log_panel(_: &Theme) -> container::Style {
    container::Style {
        text_color: Some(TEXT),
        background: Some(Background::Color(SURFACE)),
        border: Border {
            color: Color { a: 0.42, ..CYAN },
            width: 1.0,
            radius: Radius::from(8.0),
        },
        shadow: soft_shadow(),
        snap: true,
    }
}

pub fn top_bar(_: &Theme) -> container::Style {
    container::Style {
        text_color: Some(TEXT),
        background: Some(Background::Color(Color::from_rgb8(31, 34, 45))),
        border: Border {
            color: LINE_STRONG,
            width: 1.0,
            radius: Radius::from(10.0),
        },
        shadow: soft_shadow(),
        snap: true,
    }
}

pub fn command_bar(_: &Theme) -> container::Style {
    container::Style {
        text_color: Some(TEXT),
        background: Some(Background::Color(Color::from_rgb8(31, 34, 45))),
        border: Border {
            color: LINE_STRONG,
            width: 1.0,
            radius: Radius::from(8.0),
        },
        shadow: soft_shadow(),
        snap: true,
    }
}

pub fn status_panel(_: &Theme) -> container::Style {
    container::Style {
        text_color: Some(TEXT),
        background: Some(Background::Color(Color::from_rgb8(31, 34, 45))),
        border: Border {
            color: Color::from_rgba8(103, 215, 246, 0.18),
            width: 1.0,
            radius: Radius::from(8.0),
        },
        shadow: Shadow::default(),
        snap: true,
    }
}

pub fn secret_visual(_: &Theme) -> container::Style {
    container::Style {
        text_color: Some(TEXT),
        background: Some(Background::Color(Color::from_rgb8(28, 31, 41))),
        border: Border {
            color: Color::from_rgba8(206, 88, 214, 0.32),
            width: 1.0,
            radius: Radius::from(8.0),
        },
        shadow: soft_shadow(),
        snap: true,
    }
}

pub fn secret_key_token(_: &Theme) -> container::Style {
    container::Style {
        text_color: Some(TEXT),
        background: Some(Background::Color(Color::from_rgb8(34, 38, 49))),
        border: Border {
            color: Color::from_rgba8(52, 224, 111, 0.58),
            width: 1.0,
            radius: Radius::from(10.0),
        },
        shadow: Shadow {
            color: Color::from_rgba8(3, 5, 10, 0.48),
            offset: Vector::new(0.0, 5.0),
            blur_radius: 13.0,
        },
        snap: true,
    }
}

pub fn secret_address_token(depth: u8) -> container::Style {
    let lift = 3.0 - f32::from(depth).min(2.0) * 0.7;
    container::Style {
        text_color: Some(TEXT),
        background: Some(Background::Color(Color::from_rgb8(
            48 + depth.min(2) * 2,
            51 + depth.min(2) * 2,
            68 + depth.min(2) * 2,
        ))),
        border: Border {
            color: Color::from_rgba8(103, 215, 246, 0.28),
            width: 1.0,
            radius: Radius::from(5.0),
        },
        shadow: Shadow {
            color: Color::from_rgba8(3, 5, 10, 0.42),
            offset: Vector::new(0.0, lift),
            blur_radius: 6.0,
        },
        snap: true,
    }
}

pub fn photo_frame(_: &Theme) -> container::Style {
    container::Style {
        text_color: Some(TEXT),
        background: Some(Background::Color(Color::from_rgb8(22, 25, 34))),
        border: Border {
            color: Color::from_rgba8(103, 215, 246, 0.42),
            width: 1.0,
            radius: Radius::from(6.0),
        },
        shadow: Shadow::default(),
        snap: true,
    }
}

pub fn status_capsule(_: &Theme) -> container::Style {
    container::Style {
        text_color: Some(TEXT),
        background: Some(Background::Color(SURFACE)),
        border: Border {
            color: LINE,
            width: 1.0,
            radius: Radius::from(6.0),
        },
        shadow: Shadow::default(),
        snap: true,
    }
}

pub fn state_scale_tick(active: bool) -> impl Fn(&Theme) -> container::Style {
    move |_| {
        container::Style::default().background(if active {
            ACCENT
        } else {
            Color::from_rgba8(214, 224, 255, 0.12)
        })
    }
}

fn title_style(background: Color) -> container::Style {
    container::Style {
        text_color: Some(INK),
        background: Some(Background::Color(background)),
        border: Border {
            color: Color::TRANSPARENT,
            width: 0.0,
            radius: Radius::from(4.0),
        },
        shadow: Shadow::default(),
        snap: true,
    }
}

pub fn title_bar_cyan(_: &Theme) -> container::Style {
    title_style(CYAN)
}

pub fn title_bar_proof(_: &Theme) -> container::Style {
    title_style(PROOF)
}

pub fn title_bar_accent(_: &Theme) -> container::Style {
    title_style(ACCENT)
}

pub fn table_header(_: &Theme) -> container::Style {
    container::Style {
        border: Border {
            radius: Radius::from(3.0),
            ..Border::default()
        },
        ..title_style(ACCENT)
    }
}

pub fn utxo_table_header(_: &Theme) -> container::Style {
    container::Style {
        text_color: Some(MUTED),
        background: Some(Background::Color(SURFACE_ALT)),
        border: Border {
            color: Color { a: 0.50, ..CYAN },
            width: 1.0,
            radius: Radius::from(3.0),
        },
        shadow: Shadow::default(),
        snap: true,
    }
}

pub fn scope_table_header(_: &Theme) -> container::Style {
    container::Style {
        text_color: Some(MUTED),
        background: Some(Background::Color(SURFACE_ALT)),
        border: Border {
            color: Color::from_rgba8(206, 88, 214, 0.34),
            width: 1.0,
            radius: Radius::from(3.0),
        },
        shadow: Shadow::default(),
        snap: true,
    }
}

pub fn table_row(alternate: bool) -> impl Fn(&Theme) -> container::Style {
    move |_| {
        container::Style::default()
            .background(if alternate { SURFACE_ALT } else { SURFACE })
            .color(TEXT)
    }
}

pub fn transaction_row(alternate: bool, status: button_widget::Status) -> button_widget::Style {
    let hovered = matches!(
        status,
        button_widget::Status::Hovered | button_widget::Status::Pressed
    );
    button_widget::Style {
        background: Some(Background::Color(if hovered {
            SURFACE_HIGH
        } else if alternate {
            SURFACE_ALT
        } else {
            SURFACE
        })),
        text_color: TEXT,
        border: Border {
            color: if hovered {
                LINE_STRONG
            } else {
                Color::TRANSPARENT
            },
            width: if hovered { 1.0 } else { 0.0 },
            radius: Radius::from(2.0),
        },
        shadow: Shadow::default(),
        snap: true,
    }
}

pub fn utxo_row(
    alternate: bool,
    selected: bool,
    status: button_widget::Status,
) -> button_widget::Style {
    let hovered = matches!(
        status,
        button_widget::Status::Hovered | button_widget::Status::Pressed
    );
    let background = if selected {
        Color::from_rgba8(206, 88, 214, if hovered { 0.19 } else { 0.12 })
    } else if hovered {
        SURFACE_HIGH
    } else if alternate {
        SURFACE_ALT
    } else {
        SURFACE
    };

    button_widget::Style {
        background: Some(Background::Color(background)),
        text_color: TEXT,
        border: Border {
            color: if selected { PROOF } else { Color::TRANSPARENT },
            width: if selected { 1.0 } else { 0.0 },
            radius: Radius::from(2.0),
        },
        shadow: Shadow::default(),
        snap: true,
    }
}

pub fn divider(_: &Theme) -> container::Style {
    container::Style::default().background(LINE)
}

pub fn scrollable(theme: &Theme, status: scrollable_widget::Status) -> scrollable_widget::Style {
    let mut style = scrollable_widget::default(theme, status);
    let active = matches!(
        status,
        scrollable_widget::Status::Hovered {
            is_vertical_scrollbar_hovered: true,
            ..
        } | scrollable_widget::Status::Dragged {
            is_vertical_scrollbar_dragged: true,
            ..
        }
    );

    style.vertical_rail.background = Some(Background::Color(Color::from_rgba8(
        103,
        215,
        246,
        if active { 0.10 } else { 0.05 },
    )));
    style.vertical_rail.border = Border {
        color: Color::TRANSPARENT,
        width: 0.0,
        radius: Radius::from(99.0),
    };
    style.vertical_rail.scroller.background = Background::Color(Color {
        a: if active { 0.92 } else { 0.48 },
        ..CYAN
    });
    style.vertical_rail.scroller.border = Border {
        color: Color::TRANSPARENT,
        width: 0.0,
        radius: Radius::from(99.0),
    };
    style
}

pub fn status_dot(color: Color) -> impl Fn(&Theme) -> container::Style {
    move |_| {
        container::Style::default()
            .background(color)
            .border(Border {
                color,
                width: 0.0,
                radius: Radius::from(99.0),
            })
    }
}

pub fn advisory_badge(pulse: f32) -> impl Fn(&Theme) -> container::Style {
    move |_| {
        let pulse = pulse.clamp(0.0, 1.0);
        container::Style {
            text_color: Some(ADVISORY),
            background: Some(Background::Color(Color {
                a: 0.10 + 0.12 * pulse,
                ..ADVISORY
            })),
            border: Border {
                color: Color {
                    a: 0.55 + 0.35 * pulse,
                    ..ADVISORY
                },
                width: 1.0 + 0.5 * pulse,
                radius: Radius::from(99.0),
            },
            shadow: Shadow::default(),
            snap: true,
        }
    }
}

pub fn advisory_card(_: &Theme) -> container::Style {
    container::Style {
        text_color: Some(TEXT),
        background: Some(Background::Color(Color::from_rgb8(31, 34, 45))),
        border: Border {
            color: Color {
                a: 0.68,
                ..ADVISORY
            },
            width: 1.0,
            radius: Radius::from(8.0),
        },
        shadow: soft_shadow(),
        snap: true,
    }
}

pub fn overlay(_: &Theme) -> container::Style {
    container::Style::default().background(Color::from_rgba8(12, 13, 19, 0.78))
}

pub fn proof_forge_overlay(_: &Theme) -> container::Style {
    container::Style {
        text_color: Some(TEXT),
        background: Some(Background::Color(Color::from_rgba8(18, 20, 29, 0.97))),
        border: Border {
            color: Color::from_rgba8(206, 88, 214, 0.42),
            width: 1.0,
            radius: Radius::from(8.0),
        },
        shadow: Shadow {
            color: Color::from_rgba8(206, 88, 214, 0.16),
            offset: Vector::new(0.0, 0.0),
            blur_radius: 14.0,
        },
        snap: true,
    }
}

pub fn shutdown_forge_overlay(_: &Theme) -> container::Style {
    container::Style {
        text_color: Some(TEXT),
        background: Some(Background::Color(Color::from_rgba8(12, 13, 19, 0.94))),
        border: Border {
            color: Color::from_rgba8(206, 88, 214, 0.34),
            width: 1.0,
            radius: Radius::from(0.0),
        },
        shadow: Shadow::default(),
        snap: true,
    }
}

pub fn key_cap(color: Color) -> impl Fn(&Theme) -> container::Style {
    move |_| container::Style {
        text_color: Some(INK),
        background: Some(Background::Color(color)),
        border: Border {
            color: Color::from_rgba8(228, 250, 255, 0.28),
            width: 1.0,
            radius: Radius::from(3.0),
        },
        shadow: Shadow::default(),
        snap: true,
    }
}

pub fn text_input(_: &Theme, status: input_widget::Status) -> input_widget::Style {
    let focused = matches!(status, input_widget::Status::Focused { .. });
    let hovered = matches!(status, input_widget::Status::Hovered);

    input_widget::Style {
        background: Background::Color(SURFACE),
        border: Border {
            color: if focused {
                CYAN
            } else if hovered {
                LINE_STRONG
            } else {
                LINE
            },
            width: 1.0,
            radius: Radius::from(6.0),
        },
        icon: MUTED,
        placeholder: DIM,
        value: TEXT,
        selection: Color::from_rgba8(103, 215, 246, 0.28),
    }
}

pub fn scope_search_input(_: &Theme, status: input_widget::Status) -> input_widget::Style {
    let focused = matches!(status, input_widget::Status::Focused { .. });
    let hovered = matches!(status, input_widget::Status::Hovered);

    input_widget::Style {
        background: Background::Color(SURFACE),
        border: Border {
            color: Color {
                a: if focused {
                    1.0
                } else if hovered {
                    0.82
                } else {
                    0.64
                },
                ..ACCENT
            },
            width: if focused { 2.0 } else { 1.5 },
            radius: Radius::from(6.0),
        },
        icon: ACCENT,
        placeholder: MUTED,
        value: TEXT,
        selection: Color::from_rgba8(52, 224, 111, 0.28),
    }
}

pub fn text_editor(_: &Theme, status: editor_widget::Status) -> editor_widget::Style {
    let focused = matches!(status, editor_widget::Status::Focused { .. });
    let hovered = matches!(status, editor_widget::Status::Hovered);

    editor_widget::Style {
        background: Background::Color(SURFACE),
        border: Border {
            color: if focused {
                CYAN
            } else if hovered {
                LINE_STRONG
            } else {
                LINE
            },
            width: 1.0,
            radius: Radius::from(6.0),
        },
        placeholder: DIM,
        value: TEXT,
        selection: Color::from_rgba8(103, 215, 246, 0.28),
    }
}

pub fn node_log_editor(_: &Theme, status: editor_widget::Status) -> editor_widget::Style {
    let focused = matches!(status, editor_widget::Status::Focused { .. });
    let hovered = matches!(status, editor_widget::Status::Hovered);

    editor_widget::Style {
        background: Background::Color(Color::from_rgb8(18, 20, 27)),
        border: Border {
            color: if focused {
                ACCENT
            } else if hovered {
                Color { a: 0.72, ..CYAN }
            } else {
                Color { a: 0.34, ..CYAN }
            },
            width: if focused { 1.5 } else { 1.0 },
            radius: Radius::from(5.0),
        },
        placeholder: DIM,
        value: Color::from_rgb8(196, 228, 207),
        selection: Color::from_rgba8(103, 215, 246, 0.32),
    }
}

pub fn selectable_address(_: &Theme, _: input_widget::Status) -> input_widget::Style {
    input_widget::Style {
        background: Background::Color(Color::TRANSPARENT),
        border: Border::default(),
        icon: MUTED,
        placeholder: DIM,
        value: TEXT,
        selection: Color::from_rgba8(103, 215, 246, 0.34),
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ButtonKind {
    Primary,
    Secondary,
    Ghost,
    Command,
    CommandActive,
}

pub fn button(kind: ButtonKind, status: button_widget::Status) -> button_widget::Style {
    if matches!(status, button_widget::Status::Disabled) {
        return button_widget::Style {
            background: Some(Background::Color(SURFACE)),
            text_color: DIM,
            border: Border {
                color: LINE,
                width: 1.0,
                radius: Radius::from(6.0),
            },
            shadow: Shadow::default(),
            snap: true,
        };
    }

    let hovered = matches!(
        status,
        button_widget::Status::Hovered | button_widget::Status::Pressed
    );
    let pressed = matches!(status, button_widget::Status::Pressed);

    match kind {
        ButtonKind::Primary => button_widget::Style {
            background: Some(Background::Color(if pressed {
                Color::from_rgb8(45, 189, 113)
            } else if hovered {
                Color::from_rgb8(82, 238, 137)
            } else {
                ACCENT
            })),
            text_color: INK,
            border: Border {
                color: Color::from_rgba8(190, 255, 213, 0.32),
                width: 1.0,
                radius: Radius::from(6.0),
            },
            shadow: Shadow::default(),
            snap: true,
        },
        ButtonKind::Secondary => button_widget::Style {
            background: Some(Background::Color(if pressed {
                Color::from_rgb8(51, 55, 70)
            } else if hovered {
                SURFACE_HIGH
            } else {
                SURFACE_ALT
            })),
            text_color: TEXT,
            border: Border {
                color: if hovered { LINE_STRONG } else { LINE },
                width: 1.0,
                radius: Radius::from(6.0),
            },
            shadow: Shadow::default(),
            snap: true,
        },
        ButtonKind::Ghost => button_widget::Style {
            background: Some(Background::Color(if hovered {
                SURFACE_HIGH
            } else {
                Color::TRANSPARENT
            })),
            text_color: if hovered { TEXT } else { MUTED },
            border: Border {
                color: if hovered { LINE } else { Color::TRANSPARENT },
                width: 1.0,
                radius: Radius::from(5.0),
            },
            ..button_widget::Style::default()
        },
        ButtonKind::Command => button_widget::Style {
            background: Some(Background::Color(if pressed {
                Color::from_rgba8(103, 215, 246, 0.22)
            } else if hovered {
                Color::from_rgba8(103, 215, 246, 0.12)
            } else {
                Color::TRANSPARENT
            })),
            text_color: TEXT,
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: Radius::from(5.0),
            },
            shadow: Shadow::default(),
            snap: true,
        },
        ButtonKind::CommandActive => button_widget::Style {
            background: Some(Background::Color(if pressed {
                Color::from_rgba8(103, 215, 246, 0.24)
            } else if hovered {
                Color::from_rgba8(103, 215, 246, 0.20)
            } else {
                Color::from_rgba8(103, 215, 246, 0.13)
            })),
            text_color: CYAN,
            border: Border {
                color: Color::from_rgba8(103, 215, 246, 0.30),
                width: 1.0,
                radius: Radius::from(5.0),
            },
            shadow: Shadow::default(),
            snap: true,
        },
    }
}

pub fn consolidation_button(pulse: f32, status: button_widget::Status) -> button_widget::Style {
    if matches!(status, button_widget::Status::Disabled) {
        return button(ButtonKind::Secondary, status);
    }

    let pulse = pulse.clamp(0.0, 1.0);
    let hovered = matches!(
        status,
        button_widget::Status::Hovered | button_widget::Status::Pressed
    );
    let pressed = matches!(status, button_widget::Status::Pressed);

    button_widget::Style {
        background: Some(Background::Color(if pressed {
            Color {
                a: 0.24,
                ..ADVISORY
            }
        } else if hovered {
            Color {
                a: 0.18,
                ..ADVISORY
            }
        } else {
            Color {
                a: 0.06 + 0.08 * pulse,
                ..ADVISORY
            }
        })),
        text_color: ADVISORY,
        border: Border {
            color: Color {
                a: if hovered { 0.95 } else { 0.48 + 0.42 * pulse },
                ..ADVISORY
            },
            width: 1.0 + 0.5 * pulse,
            radius: Radius::from(6.0),
        },
        shadow: Shadow::default(),
        snap: true,
    }
}
