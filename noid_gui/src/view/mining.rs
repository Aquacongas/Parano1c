// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

#[cfg(feature = "dev-genesis")]
use iced::widget::checkbox;
use iced::widget::{button, column, container, row, scrollable, text};
use iced::{Alignment, Element, Length, Padding};

use crate::app::{App, BackendState, Message};
use crate::theme::{self, ButtonKind};

pub fn view(app: &App, compact: bool) -> Element<'_, Message> {
    let page_title = container(
        row![
            container(text("MINING").size(13))
                .padding([6, 9])
                .style(theme::title_bar_proof),
            iced::widget::Space::new().width(Length::Fill),
            text("PROOF-NATIVE BLOCK PRODUCTION")
                .size(11)
                .color(theme::DIM),
        ]
        .align_y(Alignment::Center),
    )
    .style(theme::surface_alt);

    let controls = if compact {
        column![miner_status(app), miner_controls(app)].spacing(10)
    } else {
        column![row![
            miner_status(app).width(Length::FillPortion(7)),
            miner_controls(app).width(Length::FillPortion(5)),
        ]
        .spacing(10),]
    };

    let mut page = column![page_title, controls].spacing(10);
    if let Some(error) = &app.backend_error {
        page = page.push(
            container(
                column![
                    text("NODE ERROR").size(11).color(theme::DANGER),
                    text(error).size(12).color(theme::MUTED),
                ]
                .spacing(5),
            )
            .padding([10, 12])
            .width(Length::Fill)
            .style(theme::surface),
        );
    }

    container(scrollable(container(page).padding(Padding::ZERO.right(10))))
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(12)
        .into()
}

fn miner_status(app: &App) -> iced::widget::Container<'_, Message> {
    let address = app.snapshot.active_address();
    let (status, status_color) = if app.node_action_in_flight {
        ("RESTARTING NODE", theme::WARNING)
    } else if app.snapshot.mining.enabled {
        ("MINING", theme::ACCENT)
    } else {
        ("STOPPED", theme::DIM)
    };
    let connection = match app.backend_state {
        BackendState::Online => "LOCAL NODE ONLINE",
        BackendState::Starting => "LOCAL NODE STARTING",
        BackendState::Offline => "LOCAL NODE OFFLINE",
        BackendState::Mock => "DESIGN PREVIEW",
    };

    container(
        column![
            container(
                row![
                    text("INTERNAL MINER").size(12).color(theme::PROOF),
                    iced::widget::Space::new().width(Length::Fill),
                    text(format!("[{status}]")).size(12).color(status_color),
                ]
                .align_y(Alignment::Center),
            )
            .padding([7, 10])
            .style(theme::surface_alt),
            container(
                column![
                    detail(
                        "PAYOUT",
                        format!("[{}] {}", address.key_index, address.label)
                    ),
                    text(&address.address)
                        .size(14)
                        .color(theme::TEXT)
                        .wrapping(text::Wrapping::WordOrGlyph),
                    divider(),
                    row![
                        detail("BACKEND", app.snapshot.network.backend.clone()),
                        iced::widget::Space::new().width(Length::Fill),
                        detail(
                            "THREADS",
                            format!(
                                "{}/{}",
                                app.snapshot.mining.selected_threads,
                                app.snapshot.mining.available_threads
                            ),
                        ),
                    ]
                    .spacing(12),
                    row![
                        detail("TARGET", "15 s".into()),
                        iced::widget::Space::new().width(Length::Fill),
                        text(connection).size(10).color(theme::DIM),
                    ]
                    .align_y(Alignment::Center),
                ]
                .spacing(10),
            )
            .padding([14, 16]),
        ]
        .spacing(0),
    )
    .width(Length::Fill)
    .style(theme::surface)
}

fn miner_controls(app: &App) -> iced::widget::Container<'_, Message> {
    let can_edit_threads = !app.snapshot.mining.enabled && !app.node_action_in_flight;
    let mut decrement = button(text("−").size(18))
        .padding([7, 12])
        .style(|_, status| theme::button(ButtonKind::Secondary, status));
    let mut increment = button(text("+").size(18))
        .padding([7, 12])
        .style(|_, status| theme::button(ButtonKind::Secondary, status));
    if can_edit_threads && app.snapshot.mining.selected_threads > 1 {
        decrement = decrement.on_press(Message::AdjustMiningThreads(-1));
    }
    if can_edit_threads
        && app.snapshot.mining.selected_threads < app.snapshot.mining.available_threads
    {
        increment = increment.on_press(Message::AdjustMiningThreads(1));
    }

    let thread_control = row![
        decrement,
        container(
            column![
                text(app.snapshot.mining.selected_threads.to_string())
                    .size(24)
                    .color(if can_edit_threads {
                        theme::TEXT
                    } else {
                        theme::DIM
                    }),
                text("CPU THREADS").size(9).color(theme::DIM),
            ]
            .spacing(2)
            .align_x(Alignment::Center),
        )
        .width(Length::Fill)
        .align_x(Alignment::Center),
        increment,
    ]
    .spacing(8)
    .align_y(Alignment::Center);

    let genesis_control: Element<'_, Message> = {
        #[cfg(feature = "dev-genesis")]
        {
            let allowed = !app.snapshot.mining.enabled
                && !app.node_action_in_flight
                && app.snapshot.network.height == 0;
            let mut control = checkbox(app.genesis_enabled)
                .label("Genesis node")
                .size(18)
                .text_size(12)
                .spacing(9);
            if allowed {
                control = control.on_toggle(Message::ToggleGenesis);
            }
            column![
                control,
                text("Start a new local chain from an empty development state.")
                    .size(10)
                    .color(if allowed { theme::MUTED } else { theme::DIM }),
                text("TEMPORARY DEVELOPMENT CONTROL")
                    .size(9)
                    .color(theme::WARNING),
            ]
            .spacing(5)
            .into()
        }
        #[cfg(not(feature = "dev-genesis"))]
        {
            column![
                text("NETWORK READINESS").size(10).color(theme::DIM),
                text("Mining begins only after the local node is synchronized.")
                    .size(11)
                    .color(theme::MUTED),
            ]
            .spacing(5)
            .into()
        }
    };

    let mining_enabled = app.snapshot.mining.enabled;
    let label = if app.node_action_in_flight {
        "RESTARTING…"
    } else if mining_enabled {
        "STOP MINING"
    } else {
        "START MINING"
    };
    let mut toggle = button(
        container(text(label).size(13))
            .width(Length::Fill)
            .align_x(Alignment::Center),
    )
    .width(Length::Fill)
    .padding([11, 14])
    .style(move |_, status| {
        theme::button(
            if mining_enabled {
                ButtonKind::Secondary
            } else {
                ButtonKind::Primary
            },
            status,
        )
    });
    if !app.node_action_in_flight && app.backend_state != BackendState::Offline {
        toggle = toggle.on_press(Message::SetMining(!mining_enabled));
    }

    container(
        column![
            container(text("MINER CONTROL").size(12).color(theme::CYAN)).padding([7, 10]),
            container(column![thread_control, divider(), genesis_control, toggle].spacing(12),)
                .padding([14, 16]),
        ]
        .spacing(0),
    )
    .width(Length::Fill)
    .style(theme::surface)
}

fn detail(label: &'static str, value: String) -> Element<'static, Message> {
    row![
        text(label).size(10).color(theme::DIM),
        text(format!("[{value}]")).size(11).color(theme::CYAN),
    ]
    .spacing(6)
    .align_y(Alignment::Center)
    .into()
}

fn divider() -> Element<'static, Message> {
    container(iced::widget::Space::new())
        .width(Length::Fill)
        .height(1)
        .style(theme::divider)
        .into()
}
