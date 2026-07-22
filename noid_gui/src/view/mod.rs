// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

mod mining;
mod present;

use iced::widget::{button, column, container, responsive, row, scrollable, stack, text};
use iced::{Alignment, Element, Length, Padding};

use crate::app::{Action, App, Message};
use crate::model::Section;
use crate::theme::{self, ButtonKind};

pub fn root(app: &App) -> Element<'_, Message> {
    let body = responsive(|size| application(app, size.width < 1_040.0));

    container(body)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(theme::root)
        .into()
}

fn application(app: &App, compact: bool) -> Element<'_, Message> {
    let page = match app.section {
        Section::Present => present::view(app, compact),
        Section::Mine => mining::view(app, compact),
        Section::Settings => settings(app, compact),
        Section::Proofs | Section::Node => section_placeholder(app.section),
    };

    let mut layers = vec![page];
    layers.extend(present::wallet_overlays(app, compact));
    let content = stack(layers).width(Length::Fill).height(Length::Fill);

    let workspace = column![system_status(app, compact), content]
        .width(Length::Fill)
        .height(Length::Fill);

    let top = container(header(app, compact)).padding(Padding::ZERO.top(10).right(12).left(12));
    let bottom = container(command_bar(app)).padding(Padding::ZERO.right(12).bottom(10).left(12));

    column![top, workspace, bottom]
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

fn system_status(app: &App, compact: bool) -> Element<'_, Message> {
    container(present::system_meters(app, compact))
        .padding(Padding::ZERO.top(12).right(12).left(12))
        .width(Length::Fill)
        .into()
}

fn header(app: &App, _compact: bool) -> Element<'_, Message> {
    let network = &app.snapshot.network;
    let sync_status = match app.backend_state {
        crate::app::BackendState::Starting => ("STARTING", theme::WARNING),
        crate::app::BackendState::Offline => ("OFFLINE", theme::DANGER),
        crate::app::BackendState::Mock => ("PREVIEW", theme::WARNING),
        crate::app::BackendState::Online if network.synced => ("SYNCED", theme::ACCENT),
        crate::app::BackendState::Online => ("SYNCING", theme::WARNING),
    };
    let mining_status = if app.node_action_in_flight {
        ("SWITCHING", theme::WARNING)
    } else if app.snapshot.mining.enabled {
        ("MINING ON", theme::ACCENT)
    } else {
        ("MINING OFF", theme::DIM)
    };

    let wordmark = row![
        text("Paran")
            .size(19)
            .font(theme::BRAND_FONT)
            .color(theme::TEXT),
        text("O(1)")
            .size(19)
            .font(theme::BRAND_FONT)
            .color(theme::ACCENT),
        text("d")
            .size(19)
            .font(theme::BRAND_FONT)
            .color(theme::TEXT),
    ]
    .spacing(0);
    let brand = container(wordmark).padding(Padding::ZERO.top(4));

    let network_status = container(
        row![
            live_status(sync_status.0, sync_status.1),
            separator(),
            status_value("PEERS", network.peers.to_string()),
            separator(),
            status_value("HEIGHT", crate::model::grouped(network.height)),
        ]
        .spacing(10)
        .align_y(Alignment::Center),
    )
    .padding([7, 12])
    .style(theme::status_capsule);

    let mining_status = container(
        row![
            status_value("BACKEND", network.backend.clone()),
            separator(),
            live_status(mining_status.0, mining_status.1),
        ]
        .spacing(10)
        .align_y(Alignment::Center),
    )
    .padding([7, 12])
    .style(theme::status_capsule);

    container(
        row![
            brand,
            iced::widget::Space::new().width(Length::Fill),
            network_status,
            mining_status,
        ]
        .spacing(8),
    )
    .height(56)
    .padding([0, 18])
    .align_y(Alignment::Center)
    .width(Length::Fill)
    .style(theme::top_bar)
    .into()
}

fn live_status(label: &'static str, color: iced::Color) -> Element<'static, Message> {
    row![
        container(iced::widget::Space::new())
            .width(9)
            .height(9)
            .style(theme::status_dot(color)),
        container(text(label).size(13).color(color)).padding(Padding::ZERO.top(1)),
    ]
    .spacing(8)
    .align_y(Alignment::Center)
    .into()
}

fn status_value(label: &'static str, value: String) -> Element<'static, Message> {
    row![
        text(label).size(11).color(theme::DIM),
        text(value).size(13).color(theme::TEXT),
    ]
    .spacing(6)
    .align_y(Alignment::Center)
    .into()
}

fn separator() -> Element<'static, Message> {
    container(iced::widget::Space::new())
        .width(1)
        .height(22)
        .style(theme::divider)
        .into()
}

fn command_bar(app: &App) -> Element<'static, Message> {
    let addresses_active = app.address_picker_open;
    let send_active = app.action == Some(Action::Send);
    let main_active = app.section == Section::Present && !addresses_active && !send_active;

    let commands = row![
        command(
            "F1",
            "Main",
            Message::Navigate(Section::Present),
            main_active,
        ),
        command(
            "F2",
            "Addresses",
            Message::ToggleAddressPicker,
            addresses_active,
        ),
        command("F3", "Send", Message::OpenAction(Action::Send), send_active,),
        command(
            "F4",
            "Proofs",
            Message::Navigate(Section::Proofs),
            app.section == Section::Proofs,
        ),
        command(
            "F5",
            "Mining",
            Message::Navigate(Section::Mine),
            app.section == Section::Mine,
        ),
        command(
            "F6",
            "Node",
            Message::Navigate(Section::Node),
            app.section == Section::Node,
        ),
        command(
            "F7",
            "Settings",
            Message::Navigate(Section::Settings),
            app.section == Section::Settings,
        ),
        command("F10", "Quit", Message::Exit, false),
    ]
    .spacing(4)
    .height(32)
    .width(Length::Fill)
    .align_y(Alignment::Center);

    container(commands)
        .width(Length::Fill)
        .height(40)
        .padding(4)
        .style(theme::command_bar)
        .into()
}

fn command(
    key: &'static str,
    label: &'static str,
    message: Message,
    active: bool,
) -> Element<'static, Message> {
    button(
        row![
            container(text(key).size(14).color(theme::INK))
                .height(Length::Fill)
                .padding([5, 3])
                .style(theme::key_cap(if active {
                    theme::ACCENT
                } else {
                    theme::CYAN
                })),
            container(
                text(label)
                    .size(14)
                    .color(if active { theme::CYAN } else { theme::TEXT })
            )
            .height(Length::Fill)
            .padding([5, 4]),
        ]
        .spacing(0)
        .height(Length::Fill)
        .align_y(Alignment::Center),
    )
    .height(Length::Fill)
    .width(Length::FillPortion(1))
    .padding(0)
    .on_press(message)
    .style(move |_, status| {
        theme::button(
            if active {
                ButtonKind::CommandActive
            } else {
                ButtonKind::Command
            },
            status,
        )
    })
    .into()
}

fn section_placeholder(section: Section) -> Element<'static, Message> {
    let title = format!("{} / NATIVE SURFACE", section.label().to_uppercase());
    container(
        column![
            container(text(title).size(13))
                .padding([6, 9])
                .style(theme::title_bar),
            text("The first design pass is focused on MAIN.")
                .size(17)
                .color(theme::MUTED),
            button(text("Return to main").size(14))
                .on_press(Message::Navigate(Section::Present))
                .padding([9, 14])
                .style(|_, status| theme::button(ButtonKind::Secondary, status)),
        ]
        .spacing(18),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .padding(24)
    .into()
}

fn settings(app: &App, compact: bool) -> Element<'_, Message> {
    let page_title = container(
        row![
            container(text("SETTINGS").size(13))
                .padding([6, 9])
                .style(theme::title_bar_cyan),
            iced::widget::Space::new().width(Length::Fill),
            text("LOCAL CONFIGURATION").size(11).color(theme::DIM),
        ]
        .align_y(Alignment::Center),
    )
    .style(theme::surface_alt);

    let owner_secret = owner_secret_group();
    let node = settings_group(
        "NODE",
        theme::CYAN,
        vec![
            setting_row(
                "DATA DIRECTORY",
                "State, wallet metadata and receipts",
                "SYSTEM DEFAULT",
            ),
            setting_row("LOG LEVEL", "Local diagnostic output", "INFO"),
        ],
    );
    let network = settings_group(
        "NETWORK",
        theme::ACCENT,
        vec![
            setting_row("PEER DISCOVERY", "Find independent peers", "AUTO"),
            setting_row("INBOUND", "Accept incoming peer links", "ON"),
        ],
    );
    let mining = settings_group(
        "MINING",
        theme::PROOF,
        vec![
            setting_row(
                "THREADS",
                "CPU workers used while mining",
                &format!(
                    "{} / {}",
                    app.snapshot.mining.selected_threads, app.snapshot.mining.available_threads
                ),
            ),
            setting_row("START ON LAUNCH", "Mining remains opt-in", "OFF"),
        ],
    );
    let interface = settings_group(
        "INTERFACE",
        theme::WARNING,
        vec![
            setting_row("UI SCALE", "Follow the operating system", "SYSTEM"),
            setting_row("NOTIFICATIONS", "Blocks, payments and node health", "ON"),
        ],
    );

    let groups: Element<'_, Message> = if compact {
        column![node, network, mining, interface].spacing(10).into()
    } else {
        column![
            row![node, network].spacing(10),
            row![mining, interface].spacing(10),
        ]
        .spacing(10)
        .into()
    };

    let settings = column![
        owner_secret,
        groups,
        text("SETTINGS ARE STORED ONLY ON THIS DEVICE")
            .size(10)
            .color(theme::DIM),
    ]
    .spacing(10);

    let settings = container(settings)
        .width(Length::Fill)
        .padding(Padding::ZERO.right(10));

    container(column![page_title, scrollable(settings).style(theme::scrollable)].spacing(10))
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(12)
        .into()
}

fn owner_secret_group() -> iced::widget::Container<'static, Message> {
    let title = row![
        text("OWNER SECRET").size(12).color(theme::PROOF),
        iced::widget::Space::new().width(Length::Fill),
        text("LOCAL KEYSTORE").size(10).color(theme::ACCENT),
    ]
    .align_y(Alignment::Center);

    let details = row![
        column![
            text("SPENDING AUTHORITY").size(12).color(theme::TEXT),
            text("Derives every address and authorizes every spend")
                .size(10)
                .color(theme::DIM),
        ]
        .spacing(3),
        iced::widget::Space::new().width(Length::Fill),
        column![
            text("SOURCE").size(10).color(theme::DIM),
            text("GENERATED SECRET").size(11).color(theme::TEXT),
        ]
        .spacing(3),
        column![
            text("PROTECTION").size(10).color(theme::DIM),
            text("PASSWORD NOT SET").size(11).color(theme::WARNING),
        ]
        .spacing(3),
    ]
    .spacing(24)
    .align_y(Alignment::Center);

    let actions = row![
        settings_action("IMPORT SECRET"),
        settings_action("EXPORT SECRET"),
        settings_action("SET PASSWORD"),
        iced::widget::Space::new().width(Length::Fill),
        text("THE SECRET IS NEVER SENT TO THE NETWORK")
            .size(10)
            .color(theme::DIM),
    ]
    .spacing(8)
    .align_y(Alignment::Center);

    container(
        column![
            container(title).padding([7, 10]),
            container(details)
                .width(Length::Fill)
                .padding([9, 10])
                .style(theme::surface_alt),
            container(actions).padding([8, 10]),
        ]
        .spacing(1),
    )
    .width(Length::Fill)
    .style(theme::surface)
}

fn settings_action(label: &'static str) -> iced::widget::Button<'static, Message> {
    button(text(label).size(11))
        .on_press(Message::Noop)
        .padding([7, 10])
        .style(|_, status| theme::button(ButtonKind::Secondary, status))
}

fn settings_group(
    title: &'static str,
    color: iced::Color,
    rows: Vec<Element<'static, Message>>,
) -> iced::widget::Container<'static, Message> {
    container(
        column![
            container(text(title).size(12).color(color)).padding([7, 10]),
            column(rows).spacing(1),
        ]
        .spacing(0),
    )
    .width(Length::Fill)
    .style(theme::surface)
}

fn setting_row(
    label: &'static str,
    description: &'static str,
    value: &str,
) -> Element<'static, Message> {
    container(
        row![
            column![
                text(label).size(12).color(theme::TEXT),
                text(description).size(10).color(theme::DIM),
            ]
            .spacing(3),
            iced::widget::Space::new().width(Length::Fill),
            button(text(value.to_string()).size(11))
                .on_press(Message::Noop)
                .width(Length::Fixed(132.0))
                .padding([7, 9])
                .style(|_, status| theme::button(ButtonKind::Secondary, status)),
        ]
        .spacing(10)
        .align_y(Alignment::Center),
    )
    .width(Length::Fill)
    .padding([8, 10])
    .style(theme::surface_alt)
    .into()
}
