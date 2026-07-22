// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use iced::widget::{
    button, column, container, mouse_area, opaque, pin, responsive, row, scrollable, stack, text,
    text_input,
};
use iced::{Alignment, Element, Length, Padding};

use crate::app::{Action, App, Message};
use crate::model::{
    format_micronoid, grouped, AddressSnapshot, UtxoSnapshot, WALLET_CONSOLIDATION_INPUT_LIMIT,
};
use crate::theme::{self, ButtonKind};
use crate::widgets::StateField;

const DESKTOP_METER_CELLS: usize = 34;
const COMPACT_METER_CELLS: usize = 16;
const PROGRESS_METER_CELLS: usize = 24;
const PREVIEW_FEE_BASE_MICRONOID: u64 = 5_000;
const PREVIEW_FEE_PER_INPUT_MICRONOID: u64 = 100;
const PREVIEW_FEE_PER_OUTPUT_MICRONOID: u64 = 700;

pub fn view(app: &App, compact: bool) -> Element<'_, Message> {
    let page = if compact {
        compact_page(app)
    } else {
        desktop_page(app)
    };

    let mut layers: Vec<Element<'_, Message>> = vec![page];
    if app.consolidation_hint_open && app.consolidation_recommended() {
        layers.push(consolidation_hint(compact));
    }

    stack(layers)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

pub(super) fn wallet_overlays(app: &App, compact: bool) -> Vec<Element<'_, Message>> {
    let mut layers = Vec::new();
    if app.address_picker_open {
        layers.push(address_picker(app, compact));
    }
    if let Some(action) = app.action {
        layers.push(action_sheet(app, action, compact));
    }
    if app.editing_address.is_some() {
        layers.push(address_label_editor(app));
    }
    layers
}

fn desktop_page(app: &App) -> Element<'_, Message> {
    container(
        column![
            active_owner(app, false),
            row![
                utxo_table(app).width(Length::FillPortion(13)),
                state_panel(app).width(Length::FillPortion(8)),
            ]
            .spacing(10)
            .height(Length::Fill),
        ]
        .spacing(10),
    )
    .padding(Padding::new(12.0).top(10))
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}

fn compact_page(app: &App) -> Element<'_, Message> {
    let content = column![
        active_owner(app, true),
        utxo_table(app).height(390),
        state_panel(app).height(430),
    ]
    .spacing(10)
    .padding(10);

    scrollable(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

pub fn system_meters(app: &App, compact: bool) -> Element<'_, Message> {
    let network = &app.snapshot.network;
    let state_capacity = network.slot_capacity();
    let state_ratio = network.active_slots as f32 / state_capacity.max(1) as f32;
    let mempool_tx_ratio =
        network.mempool_transactions as f32 / network.mempool_capacity_transactions.max(1) as f32;
    let mempool_byte_ratio =
        network.mempool_bytes as f32 / network.mempool_capacity_bytes.max(1) as f32;
    let mempool_ratio = mempool_tx_ratio.max(mempool_byte_ratio);
    let miner_ratio = app.snapshot.mining.selected_threads as f32
        / app.snapshot.mining.available_threads.max(1) as f32;
    let memory_ratio = network.memory_used_bytes as f32 / network.memory_total_bytes.max(1) as f32;
    let meter_cells = if compact {
        COMPACT_METER_CELLS
    } else {
        DESKTOP_METER_CELLS
    };
    let meter_label_width = if compact { 90.0 } else { 110.0 };
    let state_color = if state_ratio >= 0.75 {
        theme::WARNING
    } else {
        theme::ACCENT
    };
    let mempool_color = if mempool_ratio >= 0.90 {
        theme::DANGER
    } else if mempool_ratio >= 0.70 {
        theme::WARNING
    } else {
        theme::CYAN
    };

    let meters: Element<'_, Message> = row![
        column![
            state_scale(network.log_slots, compact),
            terminal_meter(
                "State use".into(),
                state_ratio,
                state_color,
                format!("{:.1}%", state_ratio.clamp(0.0, 1.0) * 100.0),
                meter_cells,
                meter_label_width,
                false,
            ),
            terminal_meter(
                "Mempool".into(),
                mempool_ratio,
                mempool_color,
                format!("{:.1}%", mempool_ratio.clamp(0.0, 1.0) * 100.0),
                meter_cells,
                meter_label_width,
                false,
            ),
        ]
        .spacing(3)
        .width(Length::FillPortion(if compact { 5 } else { 1 })),
        column![
            terminal_meter(
                "CPU".into(),
                network.cpu_load,
                theme::ACCENT,
                format!("{:.1}%", network.cpu_load.clamp(0.0, 1.0) * 100.0),
                meter_cells,
                meter_label_width,
                false,
            ),
            terminal_meter(
                "Memory".into(),
                memory_ratio,
                theme::WARNING,
                format!("{:.1}%", memory_ratio.clamp(0.0, 1.0) * 100.0),
                meter_cells,
                meter_label_width,
                false,
            ),
            terminal_meter(
                "Mining TH".into(),
                miner_ratio,
                if app.snapshot.mining.enabled {
                    theme::ACCENT
                } else {
                    theme::DIM
                },
                format!(
                    "{}/{}",
                    app.snapshot.mining.selected_threads, app.snapshot.mining.available_threads,
                ),
                meter_cells,
                meter_label_width,
                !app.snapshot.mining.enabled,
            ),
        ]
        .spacing(3)
        .width(Length::FillPortion(if compact { 4 } else { 1 })),
    ]
    .spacing(if compact { 10 } else { 18 })
    .width(Length::Fill)
    .into();

    let network_status: Element<'_, Message> = column![
        telemetry_value(
            "Last block",
            if network.height == 0 {
                "genesis".into()
            } else {
                format!("{}s ago", network.last_block_age_seconds)
            },
            theme::ACCENT,
        ),
        telemetry_value(
            "Avg time",
            format!("{:.1}s", network.average_block_time_ms as f64 / 1_000.0),
            theme::ACCENT,
        ),
        telemetry_value(
            "Difficulty",
            format!("{:.2}×", network.difficulty),
            theme::WARNING,
        ),
    ]
    .spacing(7)
    .width(Length::Fill)
    .into();

    let dashboard: Element<'_, Message> = if compact {
        row![
            container(meters).width(Length::FillPortion(11)),
            container(network_status).width(Length::FillPortion(4)),
        ]
        .spacing(12)
        .align_y(Alignment::Center)
        .width(Length::Fill)
        .into()
    } else {
        row![
            container(meters).width(Length::FillPortion(4)),
            container(network_status).width(Length::FillPortion(1)),
        ]
        .spacing(26)
        .align_y(Alignment::Center)
        .width(Length::Fill)
        .into()
    };

    container(dashboard)
        .padding([10, 12])
        .width(Length::Fill)
        .style(theme::status_panel)
        .into()
}

fn terminal_meter(
    label: String,
    ratio: f32,
    color: iced::Color,
    value: String,
    meter_cells: usize,
    label_width: f32,
    disabled: bool,
) -> Element<'static, Message> {
    let active = (ratio.clamp(0.0, 1.0) * meter_cells as f32).ceil() as usize;
    let mut cells = row![].spacing(0);
    for index in 0..meter_cells {
        cells = cells.push(
            text(if index < active { "|" } else { " " })
                .size(17)
                .color(color)
                .width(5),
        );
    }
    let label_color = if disabled { theme::DIM } else { theme::CYAN };
    let bracket_color = theme::DIM;
    let value_color = if disabled { theme::DIM } else { theme::MUTED };

    row![
        text(label)
            .size(15)
            .color(label_color)
            .wrapping(text::Wrapping::None)
            .width(label_width),
        text("[").size(17).color(bracket_color),
        cells,
        iced::widget::Space::new().width(Length::Fill),
        text(value).size(14).color(value_color),
        text("]").size(17).color(bracket_color),
    ]
    .spacing(2)
    .align_y(Alignment::Center)
    .width(Length::FillPortion(1))
    .into()
}

fn state_scale(current: u32, compact: bool) -> Element<'static, Message> {
    let badge_width = if compact { 20.0 } else { 25.0 };
    let label_width = if compact { 90.0 } else { 110.0 };
    let mut levels = row![].align_y(Alignment::Center).width(Length::Fill);

    for log_slots in 24..=32 {
        let active = log_slots == current;
        levels = levels.push(
            container(
                column![
                    text(log_slots.to_string())
                        .size(if compact { 11 } else { 13 })
                        .color(if active { theme::ACCENT } else { theme::DIM }),
                    container(iced::widget::Space::new())
                        .width(Length::Fill)
                        .height(if active { 3 } else { 1 })
                        .style(theme::state_scale_tick(active)),
                ]
                .spacing(2)
                .align_x(Alignment::Center),
            )
            .width(badge_width)
            .height(23)
            .align_x(Alignment::Center)
            .align_y(Alignment::Center),
        );

        if log_slots < 32 {
            levels = levels.push(iced::widget::Space::new().width(Length::Fill));
        }
    }

    row![
        text("State lvl")
            .size(15)
            .color(theme::CYAN)
            .wrapping(text::Wrapping::None)
            .width(label_width),
        levels,
    ]
    .spacing(4)
    .align_y(Alignment::Center)
    .width(Length::Fill)
    .into()
}

fn telemetry_value(
    label: &'static str,
    value: String,
    color: iced::Color,
) -> Element<'static, Message> {
    container(
        row![
            text(label)
                .size(14)
                .color(theme::CYAN)
                .wrapping(text::Wrapping::None),
            text(format!("[{value}]"))
                .size(14)
                .color(color)
                .wrapping(text::Wrapping::None),
        ]
        .spacing(6)
        .align_y(Alignment::Center),
    )
    .width(Length::Fill)
    .into()
}

fn progress_meter(
    label: &'static str,
    ratio: f32,
    color: iced::Color,
    value: String,
) -> Element<'static, Message> {
    let active = (ratio.clamp(0.0, 1.0) * PROGRESS_METER_CELLS as f32).ceil() as usize;
    let mut cells = row![].spacing(2).width(Length::Fill);
    for index in 0..PROGRESS_METER_CELLS {
        cells = cells.push(
            container(iced::widget::Space::new())
                .width(Length::FillPortion(1))
                .height(13)
                .style(theme::meter_cell(color, index < active)),
        );
    }

    row![
        text(label).size(14).color(color).width(86),
        cells,
        text(value)
            .size(13)
            .color(theme::TEXT)
            .width(Length::Fixed(330.0)),
    ]
    .spacing(12)
    .align_y(Alignment::Center)
    .into()
}

fn active_owner(app: &App, compact: bool) -> Element<'_, Message> {
    let address = app.snapshot.active_address();
    let owner_tab = container(text("ACTIVE ADDRESS").size(13))
        .padding([6, 9])
        .style(theme::title_bar_proof);

    let title = row![owner_tab, iced::widget::Space::new().width(Length::Fill)]
        .spacing(8)
        .align_y(Alignment::Center);

    let address_line = container(
        row![
            container(
                text(format!("[{}] {}", address.key_index, address.label))
                    .size(12)
                    .color(theme::PROOF)
                    .wrapping(text::Wrapping::None)
            )
            .padding(Padding::ZERO.top(2)),
            container(iced::widget::Space::new())
                .width(1)
                .height(18)
                .style(theme::divider),
            mouse_area(
                text_input("", &address.address)
                    .size(if compact { 14 } else { 15 })
                    .line_height(1.0)
                    .padding(0)
                    .width(Length::Fixed(if compact { 448.0 } else { 480.0 }))
                    .style(theme::selectable_address)
            )
            .on_right_press(Message::CopyAddress(address.key_index))
            .interaction(iced::mouse::Interaction::Text),
            copy_address_button(
                address.key_index,
                app.copied_address == Some(address.key_index),
            ),
            button(text("SWITCH").size(12))
                .on_press(Message::ToggleAddressPicker)
                .padding([6, 12])
                .style(|_, status| theme::button(ButtonKind::Secondary, status)),
            iced::widget::Space::new().width(Length::Fill),
        ]
        .spacing(8)
        .align_y(Alignment::Center),
    )
    .padding([7, 12])
    .width(Length::Fill);

    let balance_size = if compact { 25.0 } else { 28.0 };
    let metric_label_size = if compact { 10.0 } else { 11.0 };
    let metric_value_size = if compact { 16.0 } else { 18.0 };
    let balance_metric = container(
        column![
            text("NOID BALANCE")
                .size(metric_label_size)
                .color(theme::DIM),
            row![
                text(address.balance()).size(balance_size),
                container(
                    text("①")
                        .size(balance_size)
                        .line_height(1.0)
                        .font(theme::SYMBOL_FONT)
                        .color(theme::ACCENT)
                )
                .padding(Padding::ZERO.bottom(3)),
            ]
            .spacing(7)
            .align_y(Alignment::Center),
        ]
        .spacing(4),
    )
    .width(Length::Shrink);

    let metrics = row![
        balance_metric,
        account_separator(),
        spendable_stat(
            if compact {
                "SPENDABLE"
            } else {
                "SPENDABLE OUTPUTS"
            },
            address.spendable_utxo_count().to_string(),
            metric_label_size,
            metric_value_size,
            app.consolidation_recommended(),
            app.consolidation_pulse(),
        ),
        account_separator(),
        amount_stat(
            "PENDING",
            address.pending_outbound(),
            if address.pending_outbound_micronoid == 0 {
                theme::DIM
            } else {
                theme::WARNING
            },
            metric_label_size,
            metric_value_size,
        ),
        account_separator(),
        amount_stat(
            "INCOMING",
            address.incoming(),
            if address.incoming_micronoid == 0 {
                theme::DIM
            } else {
                theme::ACCENT
            },
            metric_label_size,
            metric_value_size,
        ),
    ]
    .spacing(if compact { 6 } else { 14 })
    .align_y(Alignment::Center)
    .width(Length::Shrink);

    let pulse = app.consolidation_pulse();
    let consolidate = button(text("CONSOLIDATE").size(if compact { 11 } else { 12 }))
        .padding([9, if compact { 10 } else { 13 }]);
    let consolidate = if app.consolidation_recommended() {
        consolidate.style(move |_, status| theme::consolidation_button(pulse, status))
    } else {
        consolidate.style(|_, status| theme::button(ButtonKind::Secondary, status))
    };
    let consolidate = if address.spendable_utxo_count() >= 2 {
        consolidate.on_press(Message::OpenAction(Action::Consolidate))
    } else {
        consolidate
    };
    let actions = row![
        consolidate,
        button(text("SEND").size(13))
            .on_press(Message::OpenAction(Action::Send))
            .padding([9, if compact { 15 } else { 18 }])
            .style(|_, status| theme::button(ButtonKind::Primary, status)),
    ]
    .spacing(8)
    .align_y(Alignment::Center);

    let summary: Element<'_, Message> = row![
        metrics,
        iced::widget::Space::new().width(Length::Fill),
        actions
    ]
    .spacing(if compact { 12 } else { 20 })
    .align_y(Alignment::Center)
    .into();

    container(
        column![
            container(title).style(theme::surface_alt),
            address_line,
            container(iced::widget::Space::new())
                .width(Length::Fill)
                .height(1)
                .style(theme::divider),
            container(summary).padding([10, 12])
        ]
        .spacing(0),
    )
    .width(Length::Fill)
    .style(theme::surface)
    .into()
}

fn copy_address_button(key_index: u32, copied: bool) -> Element<'static, Message> {
    button(
        text(if copied { "✓" } else { "⧉" })
            .size(17)
            .font(theme::SYMBOL_FONT)
            .color(theme::ACCENT),
    )
    .on_press(Message::CopyAddress(key_index))
    .padding([3, 5])
    .style(|_, status| theme::button(ButtonKind::Ghost, status))
    .into()
}

fn spendable_stat(
    label: &'static str,
    value: String,
    label_size: f32,
    value_size: f32,
    recommended: bool,
    pulse: f32,
) -> Element<'static, Message> {
    let mut value_row = row![text(value).size(value_size).color(theme::TEXT)]
        .spacing(7)
        .align_y(Alignment::Center);

    if recommended {
        let badge = container(text("i").size(12).color(theme::ADVISORY))
            .width(19)
            .height(19)
            .align_x(Alignment::Center)
            .align_y(Alignment::Center)
            .style(theme::advisory_badge(pulse));
        value_row = value_row.push(
            mouse_area(badge)
                .on_enter(Message::EnterConsolidationBadge)
                .on_exit(Message::LeaveConsolidationBadge)
                .on_press(Message::OpenAction(Action::Consolidate))
                .interaction(iced::mouse::Interaction::Help),
        );
    }

    container(
        column![
            text(label)
                .size(label_size)
                .color(theme::DIM)
                .wrapping(text::Wrapping::None),
            value_row,
        ]
        .spacing(5),
    )
    .width(Length::Shrink)
    .into()
}

fn consolidation_hint(compact: bool) -> Element<'static, Message> {
    responsive(move |size| {
        let card_width = if compact { 350.0 } else { 390.0 };
        let x = (size.width * if compact { 0.20 } else { 0.24 })
            .clamp(12.0, (size.width - card_width - 12.0).max(12.0));

        let card = container(
            column![
                text("CONSOLIDATION RECOMMENDED")
                    .size(11)
                    .color(theme::ADVISORY),
                text(
                    "Please consolidate up to 64 UTXOs into one state slot to support the network and speed up wallet operations."
                )
                .size(12)
                .color(theme::MUTED)
                .width(Length::Fill),
                button(text("CONSOLIDATE").size(11))
                    .on_press(Message::OpenAction(Action::Consolidate))
                    .padding([7, 12])
                    .style(|_, status| theme::consolidation_button(1.0, status)),
            ]
            .spacing(9),
        )
        .width(card_width)
        .padding(12)
        .style(theme::advisory_card);

        pin(opaque(
            mouse_area(card)
                .on_enter(Message::EnterConsolidationCard)
                .on_exit(Message::LeaveConsolidationCard),
        ))
        .x(x)
        .y(108)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    })
    .into()
}

fn amount_stat(
    label: &'static str,
    value: String,
    color: iced::Color,
    label_size: f32,
    value_size: f32,
) -> Element<'static, Message> {
    container(
        column![
            text(label).size(label_size).color(theme::DIM),
            row![
                text(value).size(value_size).color(color),
                text("①")
                    .size(value_size)
                    .line_height(1.0)
                    .font(theme::SYMBOL_FONT)
                    .color(color),
            ]
            .spacing(5)
            .align_y(Alignment::Center),
        ]
        .spacing(5),
    )
    .width(Length::Shrink)
    .into()
}

fn account_separator() -> Element<'static, Message> {
    container(iced::widget::Space::new())
        .width(1)
        .height(42)
        .style(theme::divider)
        .into()
}

fn utxo_table(app: &App) -> container::Container<'_, Message> {
    let address = app.snapshot.active_address();
    let title = row![
        container(text("ACTIVE UTXO SET").size(13))
            .padding([6, 9])
            .style(theme::title_bar_cyan),
        iced::widget::Space::new().width(Length::Fill),
        container(text(format!("{} OUTPUTS", address.utxo_count)).size(11))
            .padding(Padding::ZERO.right(9)),
    ]
    .align_y(Alignment::Center);

    let header = table_columns("SLOT", "VALUE / NOID", "CREATION ID", "SEGMENT", "STATE");
    let mut rows = column![].spacing(0);
    for (index, utxo) in app.snapshot.utxos.iter().enumerate() {
        rows = rows.push(utxo_row(
            utxo,
            index % 2 == 1,
            app.selected_utxo_slot == Some(utxo.slot_index),
        ));
    }

    let output_status = row![
        state_metric("OWNED", address.utxo_count.to_string(), theme::CYAN),
        state_metric(
            "SPENDABLE",
            address.spendable_utxo_count().to_string(),
            theme::ACCENT,
        ),
        state_metric(
            "RESERVED",
            address.reserved_utxo_count.to_string(),
            if address.reserved_utxo_count == 0 {
                theme::DIM
            } else {
                theme::WARNING
            },
        ),
    ]
    .spacing(12)
    .align_y(Alignment::Center);

    container(
        column![
            container(title).style(theme::surface_alt),
            header,
            scrollable(rows)
                .direction(iced::widget::scrollable::Direction::Vertical(
                    iced::widget::scrollable::Scrollbar::new()
                        .width(8)
                        .scroller_width(4)
                        .margin(2),
                ))
                .height(Length::Fill)
                .style(theme::scrollable),
            container(output_status).padding([7, 9]),
        ]
        .spacing(0),
    )
    .height(Length::Fill)
    .style(theme::surface)
}

fn table_columns(
    slot: &'static str,
    value: &'static str,
    creation: &'static str,
    segment: &'static str,
    state: &'static str,
) -> Element<'static, Message> {
    container(
        row![
            table_cell(slot.to_string(), 3, theme::INK),
            table_cell(value.to_string(), 5, theme::INK),
            table_cell(creation.to_string(), 5, theme::INK),
            table_cell(segment.to_string(), 3, theme::INK),
            table_cell(state.to_string(), 4, theme::INK),
        ]
        .align_y(Alignment::Center),
    )
    .padding([7, 9])
    .style(theme::table_header)
    .into()
}

fn utxo_row(utxo: &UtxoSnapshot, alternate: bool, selected: bool) -> Element<'_, Message> {
    button(
        row![
            table_cell(grouped(utxo.slot_index as u64), 3, theme::CYAN),
            table_cell(utxo.value(), 5, theme::TEXT),
            table_cell(grouped(utxo.creation_id), 5, theme::MUTED),
            table_cell(format!("{:03}", utxo.segment), 3, theme::PROOF),
            table_cell(
                if utxo.reserved {
                    "RESERVED".to_string()
                } else {
                    "SPENDABLE".to_string()
                },
                4,
                if utxo.reserved {
                    theme::WARNING
                } else {
                    theme::ACCENT
                },
            ),
        ]
        .align_y(Alignment::Center),
    )
    .on_press(Message::SelectUtxo(utxo.slot_index))
    .width(Length::Fill)
    .padding([8, 9])
    .style(move |_, status| theme::utxo_row(alternate, selected, status))
    .into()
}

fn table_cell(value: String, portion: u16, color: iced::Color) -> Element<'static, Message> {
    text(value)
        .size(14)
        .color(color)
        .width(Length::FillPortion(portion))
        .into()
}

fn state_panel(app: &App) -> container::Container<'_, Message> {
    let selected_utxo = app.selected_utxo_slot.and_then(|slot| {
        app.snapshot
            .utxos
            .iter()
            .find(|utxo| utxo.slot_index == slot)
    });
    let selected_segment = selected_utxo.map(|utxo| utxo.segment);
    let field = iced::widget::canvas(StateField::new(
        &app.snapshot.segments,
        &app.snapshot.utxos,
        selected_segment,
    ))
    .width(Length::Fill)
    .height(Length::Fill);

    let selection: Element<'_, Message> = if let Some(utxo) = selected_utxo {
        let state = if utxo.reserved {
            ("RESERVED", theme::WARNING)
        } else {
            ("SPENDABLE", theme::ACCENT)
        };

        column![
            row![
                text("SELECTED OUTPUT").size(11).color(theme::PROOF),
                iced::widget::Space::new().width(Length::Fill),
                state_detail("SLOT", grouped(utxo.slot_index as u64), theme::CYAN),
                state_detail("SEG", format!("{:03}", utxo.segment), theme::PROOF),
                text(state.0).size(11).color(state.1),
            ]
            .spacing(8)
            .align_y(Alignment::Center),
            row![
                text(utxo.value()).size(16).color(theme::TEXT),
                text("①")
                    .size(16)
                    .line_height(1.0)
                    .font(theme::SYMBOL_FONT)
                    .color(theme::ACCENT),
                iced::widget::Space::new().width(Length::Fill),
                state_detail("CREATED", grouped(utxo.creation_id), theme::MUTED),
            ]
            .spacing(6)
            .align_y(Alignment::Center),
        ]
        .spacing(4)
        .into()
    } else {
        row![
            text("NO OUTPUT SELECTED").size(11).color(theme::DIM),
            iced::widget::Space::new().width(Length::Fill),
            text("SELECT A MAGENTA CELL").size(10).color(theme::MUTED),
        ]
        .into()
    };

    let atlas_legend = row![
        legend_item(theme::CYAN, "STATE OCCUPANCY"),
        legend_item(theme::PROOF, "ACTIVE ADDRESS"),
        legend_item(theme::TEXT, "SELECTED"),
    ]
    .spacing(13)
    .align_y(Alignment::Center);

    let terminal_status = if app.snapshot.network.terminal_verified {
        ("VERIFIED", theme::ACCENT)
    } else {
        ("UNVERIFIED", theme::WARNING)
    };

    container(
        column![
            container(
                row![
                    container(text("LIVE STATE").size(13))
                        .padding([6, 9])
                        .style(theme::title_bar_proof),
                    iced::widget::Space::new().width(Length::Fill),
                    container(
                        row![
                            text(format!("[{}]", terminal_status.0))
                                .size(10)
                                .color(terminal_status.1),
                            text("ROOT").size(9).color(theme::DIM),
                            text(format!(
                                "[{}]",
                                short_digest(&app.snapshot.network.state_root)
                            ))
                            .size(10)
                            .color(theme::PROOF),
                        ]
                        .spacing(7)
                        .align_y(Alignment::Center)
                    )
                    .padding(Padding::ZERO.right(9)),
                ]
                .align_y(Alignment::Center)
            )
            .style(theme::surface_alt),
            field,
            container(column![selection, atlas_legend].spacing(7)).padding([8, 10]),
        ]
        .spacing(0),
    )
    .height(Length::Fill)
    .style(theme::surface)
}

fn state_detail(
    label: &'static str,
    value: String,
    color: iced::Color,
) -> Element<'static, Message> {
    row![
        text(label).size(10).color(theme::DIM),
        text(format!("[{value}]")).size(11).color(color),
    ]
    .spacing(4)
    .align_y(Alignment::Center)
    .into()
}

fn short_digest(digest: &str) -> String {
    if digest.len() <= 17 {
        return digest.to_string();
    }

    format!("{}…{}", &digest[..5], &digest[digest.len() - 5..])
}

fn state_metric(
    label: &'static str,
    value: String,
    color: iced::Color,
) -> Element<'static, Message> {
    row![
        text(label).size(10).color(theme::DIM),
        text(format!("[{value}]")).size(11).color(color),
    ]
    .spacing(4)
    .align_y(Alignment::Center)
    .into()
}

fn legend_item(color: iced::Color, label: &'static str) -> Element<'static, Message> {
    row![
        text("■").size(11).color(color),
        text(label).size(10).color(theme::MUTED),
    ]
    .spacing(5)
    .align_y(Alignment::Center)
    .into()
}

fn address_picker(app: &App, compact: bool) -> Element<'_, Message> {
    let title = row![
        text("ADDRESS BOOK").size(13),
        iced::widget::Space::new().width(Length::Fill),
        button(text("ESC CLOSE").size(12))
            .on_press(Message::ToggleAddressPicker)
            .padding([6, 9])
            .style(|_, status| theme::button(ButtonKind::Ghost, status)),
    ]
    .spacing(8)
    .align_y(Alignment::Center);

    let header = container(
        row![
            row![
                table_cell("IDX".into(), 2, theme::INK),
                table_cell("LABEL".into(), 5, theme::INK),
                table_cell("ADDRESS".into(), 12, theme::INK),
                table_cell("STATUS".into(), 5, theme::INK),
            ]
            .width(Length::Fill)
            .align_y(Alignment::Center),
            text("ACTIONS")
                .size(14)
                .color(theme::INK)
                .width(Length::Fixed(150.0)),
        ]
        .spacing(8)
        .align_y(Alignment::Center),
    )
    .padding([7, 9])
    .style(theme::table_header);

    let mut rows = column![].spacing(0);

    for (index, address) in app.snapshot.addresses.iter().enumerate() {
        let is_active = address.key_index == app.snapshot.active_address().key_index;
        rows = rows.push(address_row(app, address, is_active, index % 2 == 1));
    }

    let card = container(
        column![
            container(title)
                .padding([6, 9])
                .style(theme::title_bar_proof),
            header,
            scrollable(rows)
                .direction(iced::widget::scrollable::Direction::Vertical(
                    iced::widget::scrollable::Scrollbar::new()
                        .width(8)
                        .scroller_width(4)
                        .margin(2),
                ))
                .height(Length::Fill)
                .style(theme::scrollable),
            container(
                row![button(text("NEW ADDRESS").size(13))
                    .on_press(Message::CreateAddress)
                    .padding([10, 14])
                    .style(|_, status| theme::button(ButtonKind::Primary, status)),]
                .align_y(Alignment::Center)
            )
            .padding(12),
            container(
                text("LABELS ARE LOCAL · ADDRESSES CANNOT BE DELETED")
                    .size(11)
                    .color(theme::DIM)
            )
            .padding([8, 12]),
        ]
        .spacing(0),
    )
    .width(if compact {
        Length::Fill
    } else {
        Length::Fixed(900.0)
    })
    .height(Length::Fill)
    .style(theme::surface_alt);

    container(card)
        .width(Length::Fill)
        .height(Length::Fill)
        .align_x(Alignment::Center)
        .align_y(Alignment::Center)
        .padding(Padding::from(if compact { [8, 12] } else { [24, 24] }))
        .style(theme::overlay)
        .into()
}

fn address_row<'a>(
    app: &App,
    address: &'a AddressSnapshot,
    active: bool,
    alternate: bool,
) -> Element<'a, Message> {
    let status = if active { "ACTIVE" } else { "GENERATED" };
    let details = row![
        table_cell(address.key_index.to_string(), 2, theme::CYAN),
        table_cell(address.label.clone(), 5, theme::TEXT),
        row![
            text(address.short_address()).size(14).color(theme::MUTED),
            copy_address_button(
                address.key_index,
                app.copied_address == Some(address.key_index),
            ),
        ]
        .spacing(5)
        .align_y(Alignment::Center)
        .width(Length::FillPortion(12)),
        table_cell(
            status.to_string(),
            5,
            if active { theme::ACCENT } else { theme::DIM },
        ),
    ]
    .width(Length::Fill)
    .align_y(Alignment::Center);

    let activate = if active {
        button(text("ACTIVE").size(11))
            .on_press(Message::Noop)
            .style(|_, status| theme::button(ButtonKind::Primary, status))
    } else {
        button(text("USE").size(11))
            .on_press(Message::SelectAddress(address.key_index))
            .style(|_, status| theme::button(ButtonKind::Secondary, status))
    };

    container(
        row![
            details,
            button(text("EDIT").size(11))
                .width(Length::Fixed(68.0))
                .on_press(Message::BeginEditAddress(address.key_index))
                .style(|_, status| theme::button(ButtonKind::Secondary, status)),
            activate.width(Length::Fixed(76.0)),
        ]
        .spacing(6)
        .align_y(Alignment::Center),
    )
    .width(Length::Fill)
    .padding([5, 9])
    .style(theme::table_row(alternate))
    .into()
}

fn address_label_editor(app: &App) -> Element<'_, Message> {
    let key_index = app.editing_address.unwrap_or_default();
    let card = container(
        column![
            container(
                row![
                    text(format!("EDIT ADDRESS [{key_index}]")).size(13),
                    iced::widget::Space::new().width(Length::Fill),
                    button(text("ESC CANCEL").size(12))
                        .on_press(Message::CancelAddressLabel)
                        .padding([6, 9])
                        .style(|_, status| theme::button(ButtonKind::Ghost, status)),
                ]
                .align_y(Alignment::Center)
            )
            .padding([6, 9])
            .style(theme::title_bar_proof),
            container(
                column![
                    text("LOCAL LABEL").size(11).color(theme::DIM),
                    text_input("Address label", &app.edit_label)
                        .on_input(Message::EditAddressLabel)
                        .on_submit(Message::SaveAddressLabel)
                        .size(14)
                        .padding([10, 12])
                        .style(theme::text_input),
                    row![
                        text("The label is stored only on this device.")
                            .size(11)
                            .color(theme::DIM),
                        iced::widget::Space::new().width(Length::Fill),
                        button(text("CANCEL").size(12))
                            .on_press(Message::CancelAddressLabel)
                            .padding([8, 12])
                            .style(|_, status| theme::button(ButtonKind::Secondary, status)),
                        button(text("SAVE").size(12))
                            .on_press(Message::SaveAddressLabel)
                            .padding([8, 16])
                            .style(|_, status| theme::button(ButtonKind::Primary, status)),
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center),
                ]
                .spacing(12)
            )
            .padding(16),
        ]
        .spacing(0),
    )
    .width(Length::Fixed(520.0))
    .style(theme::surface_alt);

    container(card)
        .width(Length::Fill)
        .height(Length::Fill)
        .align_x(Alignment::Center)
        .align_y(Alignment::Center)
        .padding(24)
        .style(theme::overlay)
        .into()
}

struct ConsolidationPreview {
    input_count: usize,
    input_value_micronoid: u64,
    fee_micronoid: u64,
    output_value_micronoid: u64,
    untouched_count: usize,
    remaining_count: usize,
    balance_after_micronoid: u64,
    freed_slots: usize,
}

fn consolidation_preview(app: &App) -> ConsolidationPreview {
    let address = app.snapshot.active_address();
    let mut spendable = app
        .snapshot
        .utxos
        .iter()
        .filter(|utxo| !utxo.reserved)
        .collect::<Vec<_>>();
    spendable.sort_by_key(|utxo| (utxo.value_micronoid, utxo.slot_index));

    let input_count = spendable.len().min(WALLET_CONSOLIDATION_INPUT_LIMIT);
    let input_value_micronoid = spendable
        .into_iter()
        .take(input_count)
        .fold(0u64, |sum, utxo| sum.saturating_add(utxo.value_micronoid));

    // Design preview only. The connected backend will provide the exact quote,
    // including the live relay floor, before confirmation.
    let fee_micronoid = PREVIEW_FEE_BASE_MICRONOID
        .saturating_add(PREVIEW_FEE_PER_INPUT_MICRONOID.saturating_mul(input_count as u64))
        .saturating_add(PREVIEW_FEE_PER_OUTPUT_MICRONOID);
    let untouched_count = address.spendable_utxo_count().saturating_sub(input_count);

    ConsolidationPreview {
        input_count,
        input_value_micronoid,
        fee_micronoid,
        output_value_micronoid: input_value_micronoid.saturating_sub(fee_micronoid),
        untouched_count,
        remaining_count: untouched_count + usize::from(input_count > 0),
        balance_after_micronoid: address.balance_micronoid.saturating_sub(fee_micronoid),
        freed_slots: input_count.saturating_sub(1),
    }
}

fn action_sheet(app: &App, action: Action, compact: bool) -> Element<'_, Message> {
    let address = app.snapshot.active_address();
    let consolidation = consolidation_preview(app);

    let (label, content): (String, Element<'_, Message>) = match action {
        Action::Send => (
            "PROVE & SEND".into(),
            column![
                form_line("RECIPIENT", "o1…", compact),
                form_line("AMOUNT", "0.000000 NOID", compact),
                form_line("FEE", "AUTO", compact),
                progress_meter("WITNESS", 1.0, theme::ACCENT, "READY".into()),
                progress_meter("ZK PROOF", 0.0, theme::PROOF, "WAITING".into()),
                text("The spending witness remains inside this node.")
                    .size(12)
                    .color(theme::DIM),
            ]
            .spacing(if compact { 7 } else { 12 })
            .into(),
        ),
        Action::Consolidate => (
            format!("CONSOLIDATE · [{}] {}", address.key_index, address.label),
            column![
                form_line(
                    "INPUTS",
                    format!(
                        "{} smallest of {} · {} NOID",
                        consolidation.input_count,
                        address.spendable_utxo_count(),
                        format_micronoid(consolidation.input_value_micronoid)
                    ),
                    compact,
                ),
                form_line(
                    "NETWORK FEE",
                    format!("{} NOID", format_micronoid(consolidation.fee_micronoid)),
                    compact,
                ),
                form_line(
                    "NEW OUTPUT",
                    format!(
                        "1 · {} NOID",
                        format_micronoid(consolidation.output_value_micronoid)
                    ),
                    compact,
                ),
                form_line(
                    "STATE",
                    format!(
                        "{} → {} outputs · {} slots freed",
                        address.spendable_utxo_count(),
                        consolidation.remaining_count,
                        consolidation.freed_slots,
                    ),
                    compact,
                ),
                container(
                    column![
                        text("TOTAL BALANCE").size(10).color(theme::DIM),
                        row![
                            text(address.balance()).size(16).color(theme::TEXT),
                            text("①")
                                .size(16)
                                .line_height(1.0)
                                .font(theme::SYMBOL_FONT)
                                .color(theme::ACCENT),
                            text("→").size(14).color(theme::DIM),
                            text(format_micronoid(consolidation.balance_after_micronoid))
                                .size(16)
                                .color(theme::TEXT),
                            text("①")
                                .size(16)
                                .line_height(1.0)
                                .font(theme::SYMBOL_FONT)
                                .color(theme::ACCENT),
                        ]
                        .spacing(6)
                        .align_y(Alignment::Center),
                        text("Only the network fee changes the balance.")
                            .size(12)
                            .color(theme::MUTED),
                        text(format!(
                            "{} outputs remain untouched.",
                            consolidation.untouched_count,
                        ))
                        .size(12)
                        .color(theme::MUTED),
                    ]
                    .spacing(if compact { 4 } else { 6 })
                )
                .padding(if compact { [9, 11] } else { [12, 14] })
                .width(Length::Fill)
                .style(theme::surface),
                row![
                    iced::widget::Space::new().width(Length::Fill),
                    button(text("CANCEL").size(12))
                        .on_press(Message::CloseAction)
                        .padding(if compact { [7, 12] } else { [9, 14] })
                        .style(|_, status| theme::button(ButtonKind::Secondary, status)),
                    button(text("CONSOLIDATE").size(12))
                        .on_press(Message::CloseAction)
                        .padding(if compact { [7, 14] } else { [9, 16] })
                        .style(|_, status| theme::button(ButtonKind::Primary, status)),
                ]
                .spacing(8)
                .align_y(Alignment::Center),
            ]
            .spacing(if compact { 7 } else { 12 })
            .into(),
        ),
    };

    let card = container(
        column![
            container(
                row![
                    text(label).size(13),
                    iced::widget::Space::new().width(Length::Fill),
                    button(text("ESC CLOSE").size(12))
                        .on_press(Message::CloseAction)
                        .padding([6, 9])
                        .style(|_, status| theme::button(ButtonKind::Ghost, status)),
                ]
                .align_y(Alignment::Center)
            )
            .padding([6, 9])
            .style(theme::title_bar_proof),
            container(content).padding(if compact { 12 } else { 18 }),
        ]
        .spacing(0),
    )
    .width(Length::Fixed(680.0))
    .style(theme::surface_alt);

    container(card)
        .width(Length::Fill)
        .height(Length::Fill)
        .align_x(Alignment::Center)
        .align_y(Alignment::Center)
        .padding(Padding::from(if compact { [8, 12] } else { [24, 18] }))
        .style(theme::overlay)
        .into()
}

fn form_line(
    label: &'static str,
    value: impl Into<String>,
    compact: bool,
) -> Element<'static, Message> {
    container(
        row![
            text(label).size(12).color(theme::CYAN).width(120),
            text(value.into()).size(13).color(theme::TEXT),
        ]
        .align_y(Alignment::Center),
    )
    .padding(if compact { [7, 10] } else { [10, 12] })
    .width(Length::Fill)
    .style(theme::surface)
    .into()
}
