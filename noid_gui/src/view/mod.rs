// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

mod explorer;
mod mining;
mod present;
mod proofs;

use iced::widget::{
    button, canvas, column, container, image, opaque, responsive, row, scrollable, stack, text,
    text_editor, text_input, Space,
};
use iced::{Alignment, ContentFit, Element, Length, Padding};

use crate::app::{Action, App, Message, SecretDialog, WalletSetupMode};
use crate::model::{SecretImportMode, Section, SettingsTab};
use crate::theme::{self, ButtonKind};
use crate::widgets::{PhotoScanner, SecretArrow, ShutdownForge};

pub fn root(app: &App) -> Element<'_, Message> {
    let body = responsive(|size| {
        if app.wallet_setup_required {
            wallet_setup(app, size.width < 900.0)
        } else {
            application(app, size.width < 1_040.0)
        }
    });

    let wallet: Element<'_, Message> = container(body)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(theme::root)
        .into();

    if app.shutting_down() {
        stack([wallet, shutdown_forge_overlay(app)])
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    } else {
        wallet
    }
}

fn shutdown_forge_overlay(app: &App) -> Element<'_, Message> {
    let animation = canvas(ShutdownForge::new(app.shutdown_forge_elapsed_seconds()))
        .width(Length::Fill)
        .height(Length::Fill);

    opaque(
        container(animation)
            .width(Length::Fill)
            .height(Length::Fill)
            .style(theme::shutdown_forge_overlay),
    )
}

fn wallet_setup(app: &App, compact: bool) -> Element<'_, Message> {
    let brand = row![
        text("Paran")
            .size(22)
            .font(theme::BRAND_FONT)
            .color(theme::TEXT),
        text("O(1)")
            .size(22)
            .font(theme::BRAND_FONT)
            .color(theme::ACCENT),
        text("d")
            .size(22)
            .font(theme::BRAND_FONT)
            .color(theme::TEXT),
    ]
    .spacing(0);
    let header = container(
        row![
            brand,
            Space::new().width(Length::Fill),
            column![
                text("FIRST RUN").size(10).color(theme::CYAN),
                text("MASTER KEY SETUP").size(11).color(theme::MUTED),
            ]
            .spacing(3)
            .align_x(Alignment::End),
        ]
        .align_y(Alignment::Center),
    )
    .width(Length::Fill)
    .padding([13, 16])
    .style(theme::top_bar);

    let body: Element<'_, Message> = match app.wallet_setup_mode {
        WalletSetupMode::Choose => wallet_setup_choices(app, compact),
        WalletSetupMode::Generate => wallet_setup_generate(app, compact),
        WalletSetupMode::Raw => wallet_setup_raw(app, compact),
        WalletSetupMode::Photo => wallet_setup_photo(app, compact),
    };
    let footer = row![
        text("ONE SECRET · EVERY ADDRESS")
            .size(10)
            .color(theme::PROOF),
        Space::new().width(Length::Fill),
        text("THE KEY IS STORED LOCALLY").size(9).color(theme::DIM),
    ]
    .align_y(Alignment::Center);

    container(
        column![header, body, footer]
            .spacing(12)
            .width(Length::Fill)
            .height(Length::Fill),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .padding(if compact { 14 } else { 24 })
    .into()
}

fn wallet_setup_choices(app: &App, compact: bool) -> Element<'_, Message> {
    let busy = app.secret_action_in_flight;
    let visual = owner_model_visual(compact);
    let generate = setup_source_button(
        "01",
        "GENERATE",
        "Create a new 256-bit key",
        theme::ACCENT,
        WalletSetupMode::Generate,
        busy,
    );
    let raw = setup_source_button(
        "02",
        "IMPORT",
        "Restore from 64 hex characters",
        theme::CYAN,
        WalletSetupMode::Raw,
        busy,
    );
    let photo = setup_source_button(
        "03",
        "USE PHOTO",
        "Derive the same key from pixels",
        theme::PROOF,
        WalletSetupMode::Photo,
        busy,
    );
    let control = container(
        column![
            text("INITIALIZE OWNER").size(16).color(theme::TEXT),
            text("Choose how this device obtains the master key.")
                .size(10)
                .color(theme::MUTED),
            Space::new().height(4),
            generate,
            raw,
            photo,
        ]
        .spacing(9),
    )
    .width(Length::Fill)
    .height(if compact {
        Length::Shrink
    } else {
        Length::Fixed(320.0)
    })
    .padding(16)
    .style(theme::surface);
    let workspace: Element<'_, Message> = if compact {
        column![visual, control].spacing(10).into()
    } else {
        row![
            visual.width(Length::FillPortion(5)),
            control.width(Length::FillPortion(4)),
        ]
        .spacing(10)
        .align_y(Alignment::Start)
        .into()
    };
    let mut content = column![workspace].spacing(10);
    if let Some(error) = &app.settings_error {
        content = content.push(
            container(text(error).size(11).color(theme::DANGER))
                .width(Length::Fill)
                .padding([10, 12])
                .style(theme::surface_alt),
        );
    }
    container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .align_y(Alignment::Center)
        .padding(if compact {
            Padding::ZERO
        } else {
            Padding::ZERO.left(50).right(50)
        })
        .into()
}

fn owner_model_visual(compact: bool) -> iced::widget::Container<'static, Message> {
    let addresses = column![
        text("ADDRESSES").size(10).color(theme::CYAN),
        row![
            address_index("[0]", 0),
            address_index("[1]", 1),
            address_index("[2]", 2),
            text("···").size(13).color(theme::MUTED),
        ]
        .spacing(5)
        .align_y(Alignment::Center),
    ]
    .spacing(9)
    .align_x(Alignment::Center);
    let key = container(
        column![
            text("①")
                .font(theme::SYMBOL_FONT)
                .size(if compact { 42 } else { 50 })
                .color(theme::ACCENT),
            text("256-BIT KEY").size(10).color(theme::CYAN),
        ]
        .spacing(6)
        .align_x(Alignment::Center),
    )
    .width(if compact { 102 } else { 112 })
    .padding([12, 10])
    .align_x(Alignment::Center)
    .style(theme::secret_key_token);
    let map = row![
        key,
        canvas(SecretArrow)
            .width(if compact { 34 } else { 42 })
            .height(18),
        addresses,
    ]
    .spacing(if compact { 12 } else { 18 })
    .align_y(Alignment::Center);

    container(
        column![
            Space::new().height(Length::Fill),
            text("A secret is enough.")
                .size(if compact { 23 } else { 28 })
                .color(theme::TEXT),
            text("No keypair. No signature.")
                .size(if compact { 14 } else { 16 })
                .color(theme::PROOF),
            Space::new().height(if compact { 18 } else { 26 }),
            map,
            Space::new().height(Length::Fill),
        ]
        .spacing(7)
        .width(Length::Fill)
        .align_x(Alignment::Center),
    )
    .width(Length::Fill)
    .height(if compact { 190 } else { 320 })
    .padding(16)
    .align_x(Alignment::Center)
    .style(theme::secret_visual)
}

fn address_index(label: &'static str, depth: u8) -> iced::widget::Container<'static, Message> {
    container(text(label).size(10).color(theme::TEXT))
        .padding([6, 7])
        .style(move |_| theme::secret_address_token(depth))
}

fn setup_source_button(
    number: &'static str,
    title: &'static str,
    detail: &'static str,
    color: iced::Color,
    mode: WalletSetupMode,
    busy: bool,
) -> iced::widget::Button<'static, Message> {
    let mut select = button(
        row![
            text(number).size(10).color(theme::DIM),
            column![
                text(title).size(12).color(color),
                text(detail).size(9).color(theme::MUTED),
            ]
            .spacing(3),
            Space::new().width(Length::Fill),
            text("→").size(15).color(color),
        ]
        .spacing(11)
        .align_y(Alignment::Center),
    )
    .width(Length::Fill)
    .padding([10, 12])
    .style(|_, status| theme::button(ButtonKind::Secondary, status));
    if !busy {
        select = select.on_press(Message::SetWalletSetupMode(mode));
    }
    select
}

fn wallet_setup_generate<'a>(app: &'a App, compact: bool) -> Element<'a, Message> {
    let visual = setup_raw_visual(
        "RANDOM KEY",
        "256 BITS · GENERATED LOCALLY",
        theme::ACCENT,
        compact,
    );
    let mut create = button(text(if app.secret_action_in_flight {
        "CREATING WALLET…"
    } else {
        "CREATE WALLET"
    }))
    .width(Length::Fill)
    .padding([11, 14])
    .style(|_, status| theme::button(ButtonKind::Primary, status));
    if !app.secret_action_in_flight {
        create = create.on_press(Message::ConfirmGenerateSecret);
    }
    let control = column![
        setup_back_header("GENERATE", theme::ACCENT, app.secret_action_in_flight),
        text("A cryptographically random key will be created and stored in the local keystore.")
            .size(12)
            .color(theme::TEXT),
        Space::new().height(Length::Fill),
        create,
    ]
    .spacing(12);
    wallet_setup_workspace(app, compact, visual, control.into())
}

fn wallet_setup_raw<'a>(app: &'a App, compact: bool) -> Element<'a, Message> {
    let visual = setup_raw_visual("IMPORT KEY", "64 HEX CHARACTERS", theme::CYAN, compact);
    let input = text_input(
        "Paste 64-character key",
        app.imported_master_secret.as_str(),
    )
    .on_input(|value| Message::ImportSecretChanged(crate::model::SensitiveString::new(value)))
    .size(12)
    .padding([12, 13])
    .style(theme::text_input);
    let mut import = button(text(if app.secret_action_in_flight {
        "RESTORING WALLET…"
    } else {
        "RESTORE WALLET"
    }))
    .width(Length::Fill)
    .padding([11, 14])
    .style(|_, status| theme::button(ButtonKind::Primary, status));
    if !app.secret_action_in_flight && app.imported_master_secret_valid() {
        import = import.on_press(Message::ConfirmImportSecret);
    }
    let control = column![
        setup_back_header("IMPORT KEY", theme::CYAN, app.secret_action_in_flight),
        text("The key restores the same deterministic address sequence.")
            .size(11)
            .color(theme::MUTED),
        input,
        Space::new().height(Length::Fill),
        import,
    ]
    .spacing(12);
    wallet_setup_workspace(app, compact, visual, control.into())
}

fn wallet_setup_photo<'a>(app: &'a App, compact: bool) -> Element<'a, Message> {
    let visual = if app.secret_photo.is_some() {
        secret_visual(app, compact)
    } else {
        setup_photo_empty(compact)
    };
    let photo_busy = app.secret_action_in_flight || app.photo_scan_active;
    let mut choose = button(text(if app.photo_scan_active {
        "PHOTO LOCKED FOR SCAN"
    } else if app.secret_action_in_flight
        && app.secret_photo.is_some()
        && app.photo_scan_progress >= 1.0
    {
        "PHOTO SELECTED"
    } else if app.secret_action_in_flight {
        "READING PHOTO…"
    } else if app.secret_photo.is_some() {
        "CHOOSE ANOTHER PHOTO"
    } else {
        "CHOOSE PHOTO"
    }))
    .width(Length::Fill)
    .padding([10, 13])
    .style(|_, status| theme::button(ButtonKind::Secondary, status));
    if !photo_busy {
        choose = choose.on_press(Message::ChooseSecretPhoto);
    }
    let mut use_photo = button(text(
        if app.photo_scan_active && app.photo_scan_progress >= 1.0 {
            "KEY READY"
        } else if app.photo_scan_active {
            "SCANNING PIXELS…"
        } else if app.secret_action_in_flight
            && app.secret_photo.is_some()
            && app.photo_scan_progress >= 1.0
        {
            "RESTORING WALLET…"
        } else {
            "USE THIS PHOTO"
        },
    ))
    .width(Length::Fill)
    .padding([11, 14])
    .style(|_, status| theme::button(ButtonKind::Primary, status));
    if !photo_busy && app.secret_photo.is_some() {
        use_photo = use_photo.on_press(Message::ConfirmImportSecret);
    }
    let control = column![
        setup_back_header("PHOTO KEY", theme::PROOF, photo_busy),
        text("The key is derived from decoded pixels. Metadata and the file name are ignored.")
            .size(11)
            .color(theme::TEXT),
        choose,
        text("Keep the private original. Restore from the unchanged file; recompression changes the key.")
            .size(10)
            .color(theme::WARNING),
        Space::new().height(Length::Fill),
        use_photo,
    ]
    .spacing(11);
    wallet_setup_workspace(app, compact, visual, control.into())
}

fn setup_raw_visual<'a>(
    title: &'static str,
    detail: &'static str,
    color: iced::Color,
    compact: bool,
) -> iced::widget::Container<'a, Message> {
    container(
        column![
            text("①").font(theme::SYMBOL_FONT).size(74).color(color),
            text(title).size(14).color(color),
            text(detail).size(10).color(theme::MUTED),
        ]
        .spacing(8)
        .align_x(Alignment::Center),
    )
    .width(Length::Fill)
    .height(if compact { 220 } else { 320 })
    .align_x(Alignment::Center)
    .align_y(Alignment::Center)
    .style(theme::secret_visual)
}

fn setup_photo_empty<'a>(compact: bool) -> iced::widget::Container<'a, Message> {
    container(
        column![
            text("▦").size(72).color(theme::PROOF),
            text("PRIVATE PHOTO").size(14).color(theme::PROOF),
            text("PIXELS → 256-BIT KEY").size(10).color(theme::MUTED),
        ]
        .spacing(8)
        .align_x(Alignment::Center),
    )
    .width(Length::Fill)
    .height(if compact { 220 } else { 320 })
    .align_x(Alignment::Center)
    .align_y(Alignment::Center)
    .style(theme::secret_visual)
}

fn setup_back_header(
    title: &'static str,
    color: iced::Color,
    busy: bool,
) -> Element<'static, Message> {
    let mut back = button(text("← ESC BACK").size(11).color(theme::PROOF))
        .padding([6, 9])
        .style(|_, status| theme::button(ButtonKind::Ghost, status));
    if !busy {
        back = back.on_press(Message::SetWalletSetupMode(WalletSetupMode::Choose));
    }
    row![
        text(title).size(13).color(color),
        Space::new().width(Length::Fill),
        back,
    ]
    .align_y(Alignment::Center)
    .into()
}

fn wallet_setup_workspace<'a>(
    app: &'a App,
    compact: bool,
    visual: iced::widget::Container<'a, Message>,
    control: Element<'a, Message>,
) -> Element<'a, Message> {
    let control = container(control)
        .width(Length::Fill)
        .height(if compact {
            Length::Shrink
        } else {
            Length::Fixed(320.0)
        })
        .padding(16)
        .style(theme::surface);
    let workspace: Element<'_, Message> = if compact {
        column![visual, control].spacing(10).into()
    } else {
        row![
            visual.width(Length::FillPortion(5)),
            control.width(Length::FillPortion(4)),
        ]
        .spacing(10)
        .align_y(Alignment::Start)
        .into()
    };
    let mut body = column![workspace].spacing(10);
    if let Some(error) = &app.settings_error {
        body = body.push(
            container(text(error).size(11).color(theme::DANGER))
                .width(Length::Fill)
                .padding([9, 11])
                .style(theme::surface_alt),
        );
    }
    container(body)
        .width(Length::Fill)
        .height(Length::Fill)
        .align_y(Alignment::Center)
        .padding(if compact {
            Padding::ZERO
        } else {
            Padding::ZERO.left(50).right(50)
        })
        .into()
}

fn application(app: &App, compact: bool) -> Element<'_, Message> {
    let page = match app.section {
        Section::Present => present::view(app, compact),
        Section::Proofs => proofs::view(app, compact),
        Section::Mine => mining::view(app, compact),
        Section::Explorer => explorer::view(app, compact),
        Section::Settings => settings(app, compact),
    };

    let workspace_base = column![system_status(app, compact), page]
        .width(Length::Fill)
        .height(Length::Fill);

    let mut layers: Vec<Element<'_, Message>> = vec![workspace_base.into()];
    layers.extend(present::wallet_overlays(app, compact));
    layers.extend(mining::overlays(app, compact));
    let workspace = stack(layers).width(Length::Fill).height(Length::Fill);

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
        ("SWITCHING".into(), theme::WARNING)
    } else if app.snapshot.mining.enabled && app.snapshot.mining.isolated {
        ("ISOLATED".into(), theme::WARNING)
    } else if app.snapshot.mining.enabled && app.snapshot.mining.ready {
        ("MINING ON".into(), theme::ACCENT)
    } else if app.snapshot.mining.enabled {
        (
            format!(
                "WAITING {}/{}",
                app.snapshot.mining.confirmed_peers, app.snapshot.mining.required_peers
            ),
            theme::WARNING,
        )
    } else {
        ("MINING OFF".into(), theme::DIM)
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

fn live_status(label: impl Into<String>, color: iced::Color) -> Element<'static, Message> {
    let label = label.into();
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

pub(super) fn copy_value_button(value: &str, copied: bool) -> Element<'static, Message> {
    button(
        text(if copied { "✓" } else { "⧉" })
            .size(17)
            .font(theme::SYMBOL_FONT)
            .color(theme::ACCENT),
    )
    .on_press(Message::CopyValue(value.to_owned()))
    .padding([3, 5])
    .style(|_, status| theme::button(ButtonKind::Ghost, status))
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
            "Explorer",
            Message::Navigate(Section::Explorer),
            app.section == Section::Explorer,
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

fn settings(app: &App, compact: bool) -> Element<'_, Message> {
    let tabs = settings_tabs(app);
    let body: Element<'_, Message> = match app.settings_tab {
        SettingsTab::Secret => secret_settings(app, compact),
        SettingsTab::Node => settings_with_controls(app, node_settings_group(app).into()),
        SettingsTab::Network => settings_with_controls(app, network_settings_group(app).into()),
    };
    let mut settings = column![tabs, body].spacing(10);
    if let Some(feedback) = settings_feedback(app) {
        settings = settings.push(feedback);
    }

    container(
        scrollable(container(settings).padding(Padding::ZERO.right(10))).style(theme::scrollable),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .padding(12)
    .into()
}

fn settings_tabs(app: &App) -> Element<'_, Message> {
    row![
        settings_tab("SECRET", SettingsTab::Secret, app),
        settings_tab("NODE", SettingsTab::Node, app),
        settings_tab("NETWORK", SettingsTab::Network, app),
    ]
    .spacing(5)
    .align_y(Alignment::Center)
    .into()
}

fn settings_tab(label: &'static str, tab: SettingsTab, app: &App) -> Element<'static, Message> {
    let active = app.settings_tab == tab;
    button(text(label).size(12))
        .on_press(Message::SetSettingsTab(tab))
        .padding([8, 14])
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

fn secret_settings(app: &App, compact: bool) -> Element<'_, Message> {
    let introduction = container(
        row![
            column![
                text("MASTER SECRET").size(18).color(theme::PROOF),
                text("ONE SECRET · EVERY ADDRESS")
                    .size(12)
                    .color(theme::TEXT),
            ]
            .spacing(5),
            Space::new().width(Length::Fill),
            column![
                text("PROTECTION").size(10).color(theme::DIM),
                text("LOCAL KEYSTORE · OWNER ONLY")
                    .size(12)
                    .color(theme::CYAN),
            ]
            .spacing(5)
            .align_x(Alignment::End),
        ]
        .align_y(Alignment::Center),
    )
    .padding(if compact { 13 } else { 16 })
    .width(Length::Fill)
    .style(theme::surface);

    let visual = secret_visual(app, compact);
    let control = secret_control(app, compact);
    let workspace: Element<'_, Message> = if compact {
        column![visual, control].spacing(10).into()
    } else {
        row![
            visual.width(Length::FillPortion(5)),
            control.width(Length::FillPortion(4)),
        ]
        .spacing(10)
        .align_y(Alignment::Start)
        .into()
    };

    column![introduction, workspace].spacing(10).into()
}

fn secret_visual(app: &App, compact: bool) -> iced::widget::Container<'_, Message> {
    let height = if compact { 220.0 } else { 320.0 };
    let content: Element<'_, Message> = if let Some(photo) = app.secret_photo.as_ref() {
        let scan_percent = ((app.photo_scan_progress * 100.0).floor() as u32).min(100);
        let (status, color) = if app.photo_scan_active && app.photo_scan_progress >= 1.0 {
            ("KEY READY · 100%".into(), theme::ACCENT)
        } else if app.photo_scan_active {
            (format!("SCANNING PIXELS · {scan_percent:02}%"), theme::CYAN)
        } else if app.photo_key_active {
            ("PHOTO KEY ACTIVE".into(), theme::ACCENT)
        } else {
            ("PHOTO KEY READY".into(), theme::PROOF)
        };
        column![
            photo_preview(app, height - 72.0),
            row![
                column![
                    text(status).size(11).color(color),
                    text(format!("KEY ID  {}", photo.key_id))
                        .size(10)
                        .color(theme::TEXT),
                ]
                .spacing(4),
                Space::new().width(Length::Fill),
                column![
                    text(format!("{} × {}", photo.width, photo.height))
                        .size(10)
                        .color(theme::MUTED),
                    text("PREVIEW NOT STORED").size(9).color(theme::DIM),
                ]
                .spacing(4)
                .align_x(Alignment::End),
            ]
            .align_y(Alignment::Center),
        ]
        .spacing(9)
        .into()
    } else {
        container(
            column![
                text("①")
                    .font(theme::SYMBOL_FONT)
                    .size(66)
                    .color(theme::ACCENT),
                text("KEY ACTIVE").size(13).color(theme::CYAN),
                text("ONE KEY · EVERY ADDRESS").size(11).color(theme::TEXT),
                text("No source media is stored.")
                    .size(10)
                    .color(theme::DIM),
            ]
            .spacing(7)
            .align_x(Alignment::Center),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .align_x(Alignment::Center)
        .align_y(Alignment::Center)
        .into()
    };

    container(content)
        .width(Length::Fill)
        .height(height)
        .padding(14)
        .style(theme::secret_visual)
}

fn photo_preview(app: &App, height: f32) -> Element<'_, Message> {
    let photo = app
        .secret_photo
        .as_ref()
        .expect("photo preview requires a prepared photo");
    let preview = photo.preview.clone();
    let source_width = photo.width.max(1) as f32;
    let source_height = photo.height.max(1) as f32;
    let scan_progress = app.photo_scan_progress;
    let scan_active = app.photo_scan_active;
    responsive(move |available| {
        let scale = (available.width / source_width)
            .min(available.height / source_height)
            .max(0.01);
        let rendered_width = (source_width * scale).max(1.0);
        let rendered_height = (source_height * scale).max(1.0);
        let picture = image(preview.clone())
            .content_fit(ContentFit::Fill)
            .width(rendered_width)
            .height(rendered_height);
        let scanner = canvas(PhotoScanner::new(scan_progress, scan_active))
            .width(rendered_width)
            .height(rendered_height);
        container(
            container(stack![picture, scanner])
                .width(rendered_width)
                .height(rendered_height)
                .style(theme::photo_frame),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .align_x(Alignment::Center)
        .align_y(Alignment::Center)
        .into()
    })
    .width(Length::Fill)
    .height(height)
    .into()
}

fn secret_control(app: &App, compact: bool) -> iced::widget::Container<'_, Message> {
    let busy = app.settings_applying || app.secret_action_in_flight || app.photo_scan_active;
    let content: Element<'_, Message> = match app.secret_dialog {
        None => secret_control_home(busy),
        Some(SecretDialog::Export) => secret_export_control(app, busy, compact),
        Some(SecretDialog::Import) => match app.secret_import_mode {
            SecretImportMode::Raw => secret_raw_import_control(app, busy),
            SecretImportMode::Photo => secret_photo_import_control(app, busy),
        },
        Some(SecretDialog::Generate) => secret_generate_control(busy),
    };
    container(content)
        .width(Length::Fill)
        .height(if compact {
            Length::Shrink
        } else {
            Length::Fixed(320.0)
        })
        .padding(14)
        .style(theme::surface)
}

fn secret_control_home(busy: bool) -> Element<'static, Message> {
    let mut raw = secret_control_button("IMPORT KEY", busy);
    let mut photo = secret_control_button("USE PHOTO", busy);
    let mut export = secret_control_button("EXPORT KEY", busy);
    let mut generate = secret_control_button("GENERATE NEW", busy);
    if !busy {
        raw = raw.on_press(Message::BeginImportSecret);
        photo = photo.on_press(Message::BeginPhotoSecret);
        export = export.on_press(Message::BeginExportSecret);
        generate = generate.on_press(Message::BeginGenerateSecret);
    }
    column![
        text("KEY CONTROL").size(12).color(theme::PROOF),
        text("The keystore always contains one 256-bit key.")
            .size(10)
            .color(theme::MUTED),
        Space::new().height(3),
        raw,
        photo,
        export,
        generate,
    ]
    .spacing(8)
    .into()
}

fn secret_control_button(
    label: &'static str,
    busy: bool,
) -> iced::widget::Button<'static, Message> {
    button(text(if busy { "WORKING…" } else { label }).size(11))
        .width(Length::Fill)
        .padding([10, 13])
        .style(|_, status| theme::button(ButtonKind::Secondary, status))
}

fn secret_back_button(busy: bool) -> iced::widget::Button<'static, Message> {
    let mut back = button(text("← ESC BACK").size(11).color(theme::PROOF))
        .padding([6, 9])
        .style(|_, status| theme::button(ButtonKind::Ghost, status));
    if !busy {
        back = back.on_press(Message::CloseSecretDialog);
    }
    back
}

fn secret_control_header(
    title: &'static str,
    color: iced::Color,
    busy: bool,
) -> Element<'static, Message> {
    row![
        text(title).size(12).color(color),
        Space::new().width(Length::Fill),
        secret_back_button(busy),
    ]
    .align_y(Alignment::Center)
    .into()
}

fn secret_export_control(app: &App, busy: bool, compact: bool) -> Element<'_, Message> {
    let secret: Element<'_, Message> = if app.exported_master_secret.is_empty() {
        container(
            text("Reading local master secret…")
                .size(if compact { 10 } else { 11 })
                .color(theme::MUTED),
        )
        .width(Length::Fill)
        .padding([12, 13])
        .style(theme::surface_alt)
        .into()
    } else {
        text_input("", app.exported_master_secret.as_str())
            .on_input(|_| Message::Noop)
            .size(if compact { 10 } else { 11 })
            .padding([12, 13])
            .style(theme::text_input)
            .into()
    };
    let mut copy = button(text(if app.exported_master_secret.is_empty() {
        "WAIT"
    } else if app.master_secret_copied {
        "COPIED ✓"
    } else {
        "COPY KEY"
    }))
    .width(Length::Fill)
    .padding([10, 13])
    .style(|_, status| theme::button(ButtonKind::Primary, status));
    if !app.exported_master_secret.is_empty() {
        copy = copy.on_press(Message::CopyExportedSecret);
    }
    column![
        secret_control_header("EXPORT KEY", theme::PROOF, busy),
        secret,
        text("Anyone with this key controls every derived address.")
            .size(10)
            .color(theme::WARNING),
        Space::new().height(Length::Fill),
        copy,
    ]
    .spacing(10)
    .into()
}

fn secret_raw_import_control(app: &App, busy: bool) -> Element<'_, Message> {
    let input = text_input(
        "Paste 64-character key",
        app.imported_master_secret.as_str(),
    )
    .on_input(|value| Message::ImportSecretChanged(crate::model::SensitiveString::new(value)))
    .size(12)
    .padding([11, 12])
    .style(theme::text_input);
    let mut confirm = button(text(if busy {
        "IMPORTING WALLET…"
    } else {
        "USE KEY"
    }))
    .width(Length::Fill)
    .padding([10, 13])
    .style(|_, status| theme::button(ButtonKind::Primary, status));
    if !busy && app.imported_master_secret_valid() {
        confirm = confirm.on_press(Message::ConfirmImportSecret);
    }
    column![
        secret_control_header("IMPORT KEY", theme::CYAN, busy),
        replacement_warning(),
        input,
        Space::new().height(Length::Fill),
        confirm,
    ]
    .spacing(10)
    .into()
}

fn secret_photo_import_control(app: &App, busy: bool) -> Element<'_, Message> {
    let mut choose = button(text(if app.photo_scan_active {
        "PHOTO LOCKED FOR SCAN"
    } else if busy && app.secret_photo.is_some() && app.photo_scan_progress >= 1.0 {
        "PHOTO SELECTED"
    } else if busy {
        "READING PHOTO…"
    } else if app.secret_photo.is_some() {
        "CHOOSE ANOTHER PHOTO"
    } else {
        "CHOOSE PHOTO"
    }))
    .width(Length::Fill)
    .padding([9, 13])
    .style(|_, status| theme::button(ButtonKind::Secondary, status));
    if !busy {
        choose = choose.on_press(Message::ChooseSecretPhoto);
    }
    let detail: Element<'_, Message> = if let Some(photo) = app.secret_photo.as_ref() {
        column![
            text(&photo.name).size(11).color(theme::TEXT),
            text(format!(
                "{} × {} · {} · METADATA IGNORED",
                photo.width,
                photo.height,
                format_file_size(photo.size)
            ))
            .size(9)
            .color(theme::CYAN),
            text(format!("KEY ID  {}", photo.key_id))
                .size(10)
                .color(theme::PROOF),
        ]
        .spacing(4)
        .into()
    } else {
        text("JPEG · PNG · WEBP · GIF · BMP · TIFF")
            .size(10)
            .color(theme::DIM)
            .into()
    };
    let mut confirm = button(text(
        if app.photo_scan_active && app.photo_scan_progress >= 1.0 {
            "KEY READY"
        } else if app.photo_scan_active {
            "SCANNING PIXELS…"
        } else if busy && app.secret_photo.is_some() && app.photo_scan_progress >= 1.0 {
            "IMPORTING WALLET…"
        } else {
            "USE THIS PHOTO"
        },
    ))
    .width(Length::Fill)
    .padding([10, 13])
    .style(|_, status| theme::button(ButtonKind::Primary, status));
    if !busy && app.secret_photo.is_some() {
        confirm = confirm.on_press(Message::ConfirmImportSecret);
    }
    column![
        secret_control_header("PHOTO KEY", theme::PROOF, busy),
        replacement_warning(),
        choose,
        detail,
        text("Keep the private original. Changed pixels create a different wallet.")
            .size(9)
            .color(theme::WARNING),
        Space::new().height(Length::Fill),
        confirm,
    ]
    .spacing(9)
    .into()
}

fn secret_generate_control(busy: bool) -> Element<'static, Message> {
    let mut generate = button(text(if busy {
        "GENERATING & RESTARTING…"
    } else {
        "GENERATE NEW KEY"
    }))
    .width(Length::Fill)
    .padding([10, 13])
    .style(|_, status| theme::button(ButtonKind::Primary, status));
    if !busy {
        generate = generate.on_press(Message::ConfirmGenerateSecret);
    }
    column![
        secret_control_header("GENERATE NEW", theme::ACCENT, busy),
        replacement_warning(),
        text("A fresh random 256-bit key will replace every local address.")
            .size(11)
            .color(theme::TEXT),
        Space::new().height(Length::Fill),
        generate,
    ]
    .spacing(10)
    .into()
}

fn settings_with_controls<'a>(
    app: &'a App,
    settings: Element<'a, Message>,
) -> Element<'a, Message> {
    let busy = app.settings_applying || app.secret_action_in_flight;
    let mut apply = button(text(if app.settings_applying {
        "APPLYING…"
    } else {
        "APPLY & RESTART"
    }))
    .padding([9, 13])
    .style(|_, status| theme::button(ButtonKind::Primary, status));
    if app.settings_dirty() && !busy {
        apply = apply.on_press(Message::ApplySettings);
    }
    let mut reset = button(text("RESET").size(11))
        .padding([9, 13])
        .style(|_, status| theme::button(ButtonKind::Secondary, status));
    if app.settings_dirty() && !busy {
        reset = reset.on_press(Message::ResetSettings);
    }
    column![
        settings,
        row![
            apply,
            reset,
            Space::new().width(Length::Fill),
            text("CHANGES RESTART THE LOCAL NODE")
                .size(10)
                .color(theme::DIM),
        ]
        .spacing(8)
        .align_y(Alignment::Center),
    ]
    .spacing(10)
    .into()
}

fn settings_feedback(app: &App) -> Option<Element<'_, Message>> {
    app.settings_error
        .as_ref()
        .map(|error| {
            container(text(error).size(11).color(theme::DANGER))
                .width(Length::Fill)
                .padding([9, 11])
                .style(theme::surface_alt)
                .into()
        })
        .or_else(|| {
            app.settings_notice.as_ref().map(|notice| {
                container(text(notice).size(11).color(theme::ACCENT))
                    .width(Length::Fill)
                    .padding([9, 11])
                    .style(theme::surface_alt)
                    .into()
            })
        })
}

fn node_settings_group(app: &App) -> iced::widget::Container<'_, Message> {
    let data_dir = text_input("Node data directory", &app.settings_data_dir)
        .on_input(Message::SettingsDataDirectoryChanged)
        .size(11)
        .padding([8, 10])
        .style(theme::text_input);
    let choose = button(text("CHOOSE").size(10))
        .on_press(Message::ChooseDataDirectory)
        .padding([9, 10])
        .style(|_, status| theme::button(ButtonKind::Secondary, status));

    let mut levels = row![].spacing(5).width(Length::Fill);
    for level in crate::model::LogLevel::ALL {
        let active = app.settings_log_level == level;
        let mut select = button(text(level.label()).size(10).color(if active {
            theme::INK
        } else {
            theme::TEXT
        }))
        .width(Length::Fill)
        .padding([7, 5])
        .style(move |_, status| {
            theme::button(
                if active {
                    ButtonKind::Primary
                } else {
                    ButtonKind::Secondary
                },
                status,
            )
        });
        if !app.settings_applying {
            select = select.on_press(Message::SetSettingsLogLevel(level));
        }
        levels = levels.push(select);
    }

    settings_panel(
        "NODE",
        theme::CYAN,
        column![
            settings_field(
                "DATA DIRECTORY",
                "Live state, wallet records and matrix cache",
                row![data_dir, choose].spacing(6).into(),
            ),
            settings_field(
                "LOG LEVEL",
                "Written locally to paranoid-node.log",
                levels.into(),
            ),
        ]
        .spacing(1)
        .into(),
    )
}

fn network_settings_group(app: &App) -> iced::widget::Container<'_, Message> {
    let listen = text_input("0.0.0.0:9400", &app.settings_p2p_listen)
        .on_input(Message::SettingsP2pListenChanged)
        .size(11)
        .padding([8, 10])
        .style(theme::text_input);
    let seeds = text_editor(&app.settings_seeds)
        .placeholder("One seed peer per line")
        .on_action(Message::EditSettingsSeeds)
        .size(11)
        .padding([8, 10])
        .height(76)
        .wrapping(iced::widget::text::Wrapping::None)
        .style(theme::text_editor);
    settings_panel(
        "NETWORK",
        theme::ACCENT,
        column![
            settings_field(
                "P2P LISTEN",
                "Address used for inbound peer connections",
                listen.into(),
            ),
            settings_field(
                "CUSTOM SEEDS",
                "Optional bootstrap peers · DNS seeds and local discovery remain automatic",
                seeds.into(),
            ),
        ]
        .spacing(1)
        .into(),
    )
}

fn settings_panel<'a>(
    title: &'static str,
    color: iced::Color,
    content: Element<'a, Message>,
) -> iced::widget::Container<'a, Message> {
    container(
        column![
            container(text(title).size(12).color(color)).padding([7, 10]),
            content,
        ]
        .spacing(0),
    )
    .width(Length::Fill)
    .style(theme::surface)
}

fn settings_field<'a>(
    label: &'static str,
    description: &'static str,
    control: Element<'a, Message>,
) -> Element<'a, Message> {
    container(
        column![
            row![
                text(label).size(11).color(theme::TEXT),
                Space::new().width(Length::Fill),
                text(description).size(9).color(theme::DIM),
            ]
            .spacing(8)
            .align_y(Alignment::Center),
            control,
        ]
        .spacing(6),
    )
    .width(Length::Fill)
    .padding([8, 10])
    .style(theme::surface_alt)
    .into()
}

fn replacement_warning() -> iced::widget::Container<'static, Message> {
    container(
        column![
            text("IMPORTANT").size(10).color(theme::WARNING),
            text("The current master secret cannot be recovered after replacement. Export it first if you need to keep it.")
                .size(11)
                .color(theme::TEXT),
        ]
        .spacing(4),
    )
    .width(Length::Fill)
    .padding([10, 12])
    .style(theme::surface_alt)
}

fn format_file_size(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    let bytes = bytes as f64;
    if bytes >= GIB {
        format!("{:.2} GiB", bytes / GIB)
    } else if bytes >= MIB {
        format!("{:.2} MiB", bytes / MIB)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes / KIB)
    } else {
        format!("{} B", bytes as u64)
    }
}
