// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use iced::widget::{
    button, column, container, mouse_area, opaque, pin, responsive, row, scrollable, stack, text,
    text_input,
};
use iced::{Alignment, Element, Length, Padding};

use crate::app::{Action, AddressOperation, App, Message};
use crate::backend::{ConsolidationPlan, ConsolidationSubmission, PaymentSubmission};
use crate::model::{
    format_creation_origin, format_micronoid, grouped, AddressSnapshot, UtxoSnapshot,
};
use crate::theme::{self, ButtonKind};
use crate::widgets::StateField;

use super::copy_value_button;

const DESKTOP_METER_CELLS: usize = 34;
const COMPACT_METER_CELLS: usize = 16;

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
                "STATE USE".into(),
                state_ratio,
                state_color,
                format!("{:.1}%", state_ratio.clamp(0.0, 1.0) * 100.0),
                meter_cells,
                meter_label_width,
                false,
            ),
            terminal_meter(
                "MEMPOOL".into(),
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
                "MEMORY".into(),
                memory_ratio,
                theme::WARNING,
                format!("{:.1}%", memory_ratio.clamp(0.0, 1.0) * 100.0),
                meter_cells,
                meter_label_width,
                false,
            ),
            terminal_meter(
                "MINING TH".into(),
                miner_ratio,
                if app.snapshot.mining.enabled && app.snapshot.mining.ready {
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
                !(app.snapshot.mining.enabled && app.snapshot.mining.ready),
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
            "LAST BLOCK",
            if network.height == 0 {
                "genesis".into()
            } else {
                format!("{}s ago", network.last_block_age_seconds)
            },
            theme::ACCENT,
        ),
        telemetry_value(
            "AVG TIME",
            format!("{:.1}s", network.average_block_time_ms as f64 / 1_000.0),
            theme::ACCENT,
        ),
        telemetry_value(
            "DIFFICULTY",
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
            .size(12)
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
        text("STATE LVL")
            .size(12)
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
                .size(12)
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

fn active_owner(app: &App, compact: bool) -> Element<'_, Message> {
    let address = app.snapshot.active_address();
    let address_field_width = if compact { 516.0 } else { 552.0 };
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
                    .width(Length::Fixed(address_field_width))
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

    let header = table_columns("SLOT", "VALUE / NOID", "ORIGIN", "SEGMENT", "STATE");
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
            table_cell(format_creation_origin(utxo.creation_id), 5, theme::MUTED),
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
                state_detail(
                    "ORIGIN",
                    format_creation_origin(utxo.creation_id),
                    theme::MUTED,
                ),
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
    let busy = app.address_operation.is_some();
    let mut close = button(text("ESC CLOSE").size(12))
        .padding([6, 9])
        .style(|_, status| theme::button(ButtonKind::Ghost, status));
    if !busy {
        close = close.on_press(Message::ToggleAddressPicker);
    }
    let title = row![
        text("ADDRESS BOOK").size(13),
        iced::widget::Space::new().width(Length::Fill),
        close,
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

    let mut new_address = button(
        text(if app.address_operation == Some(AddressOperation::Create) {
            "CREATING..."
        } else {
            "NEW ADDRESS"
        })
        .size(13),
    )
    .padding([10, 14])
    .style(|_, status| theme::button(ButtonKind::Primary, status));
    if !busy {
        new_address = new_address.on_press(Message::CreateAddress);
    }

    let mut controls =
        column![container(row![new_address].align_y(Alignment::Center)).padding(12),].spacing(0);
    if let Some(error) = &app.address_error {
        controls = controls.push(
            container(text(error).size(11).color(theme::DANGER))
                .width(Length::Fill)
                .padding([9, 12])
                .style(theme::surface),
        );
    }
    controls = controls.push(
        container(
            text("LABELS ARE LOCAL · ADDRESSES CANNOT BE DELETED")
                .size(11)
                .color(theme::DIM),
        )
        .padding([8, 12]),
    );

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
            controls,
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
    let activating = app.address_operation == Some(AddressOperation::Activate(address.key_index));
    let busy = app.address_operation.is_some();
    let status = if active {
        "ACTIVE"
    } else if activating {
        "SWITCHING"
    } else {
        "GENERATED"
    };
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
            if active {
                theme::ACCENT
            } else if activating {
                theme::PROOF
            } else {
                theme::DIM
            },
        ),
    ]
    .width(Length::Fill)
    .align_y(Alignment::Center);

    let activate = if active {
        button(text("ACTIVE").size(11))
            .on_press(Message::Noop)
            .style(|_, status| theme::button(ButtonKind::Primary, status))
    } else {
        let mut button = button(text(if activating { "USING..." } else { "USE" }).size(11))
            .style(|_, status| theme::button(ButtonKind::Secondary, status));
        if !busy {
            button = button.on_press(Message::SelectAddress(address.key_index));
        }
        button
    };

    let mut edit = button(text("EDIT").size(11))
        .width(Length::Fixed(68.0))
        .style(|_, status| theme::button(ButtonKind::Secondary, status));
    if !busy {
        edit = edit.on_press(Message::BeginEditAddress(address.key_index));
    }

    container(
        row![details, edit, activate.width(Length::Fixed(76.0)),]
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

fn action_sheet(app: &App, action: Action, compact: bool) -> Element<'_, Message> {
    let address = app.snapshot.active_address();

    let (label, content): (String, Element<'_, Message>) = match action {
        Action::Send => (
            format!("SEND · [{}] {}", address.key_index, address.label),
            send_form(app, compact),
        ),
        Action::Consolidate => (
            format!("CONSOLIDATE · [{}] {}", address.key_index, address.label),
            consolidation_form(app, compact),
        ),
    };

    let mut close = button(text("ESC CLOSE").size(12))
        .padding([6, 9])
        .style(|_, status| theme::button(ButtonKind::Ghost, status));
    if !app.wallet_action_in_flight() {
        close = close.on_press(Message::CloseAction);
    }

    let card = container(
        column![
            container(
                row![
                    text(label).size(13),
                    iced::widget::Space::new().width(Length::Fill),
                    close,
                ]
                .align_y(Alignment::Center)
            )
            .padding([6, 9])
            .style(theme::title_bar_proof),
            container(content).padding(if compact { 12 } else { 18 }),
        ]
        .spacing(0),
    )
    .width(Length::Fill)
    .max_width(680)
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

fn consolidation_form(app: &App, compact: bool) -> Element<'_, Message> {
    if let Some(result) = app.consolidation_result.as_ref() {
        return consolidation_success(app, result, compact);
    }

    let Some(plan) = app.consolidation_plan.as_ref() else {
        let (title, detail, color) = if app.consolidation_plan_in_flight {
            (
                "CALCULATING TRANSACTION",
                "Checking available outputs and the network fee…",
                theme::WARNING,
            )
        } else {
            (
                "CANNOT CONSOLIDATE",
                app.consolidation_error
                    .as_deref()
                    .unwrap_or("The wallet could not calculate the transaction."),
                theme::DANGER,
            )
        };
        let mut close = button(text("CANCEL").size(12))
            .padding(if compact { [9, 13] } else { [10, 15] })
            .style(|_, status| theme::button(ButtonKind::Secondary, status));
        if !app.wallet_action_in_flight() {
            close = close.on_press(Message::CloseAction);
        }
        let mut retry = button(text("TRY AGAIN").size(12))
            .padding(if compact { [9, 13] } else { [10, 17] })
            .style(|_, status| theme::button(ButtonKind::Primary, status));
        if !app.wallet_action_in_flight() {
            retry = retry.on_press(Message::OpenAction(Action::Consolidate));
        }
        return column![
            container(
                column![
                    text(title).size(12).color(color),
                    text(detail).size(11).color(theme::TEXT),
                ]
                .spacing(6),
            )
            .padding(if compact { 12 } else { 16 })
            .width(Length::Fill)
            .style(theme::surface),
            row![iced::widget::Space::new().width(Length::Fill), close, retry,]
                .spacing(8)
                .align_y(Alignment::Center),
        ]
        .spacing(if compact { 9 } else { 12 })
        .into();
    };

    consolidation_confirmation(app, plan, compact)
}

fn consolidation_confirmation<'a>(
    app: &'a App,
    plan: &'a ConsolidationPlan,
    compact: bool,
) -> Element<'a, Message> {
    let original_count = plan.input_count.saturating_add(plan.untouched_count);
    let proof_label = if app.consolidation_in_flight {
        "BUILDING"
    } else {
        "READY"
    };
    let proof_color = if app.consolidation_in_flight {
        theme::WARNING
    } else {
        theme::PROOF
    };
    let feedback: Element<'_, Message> = if let Some(error) = app.consolidation_error.as_ref() {
        container(
            column![
                text("TRANSACTION NOT SENT").size(11).color(theme::DANGER),
                text(error).size(11).color(theme::TEXT),
            ]
            .spacing(5),
        )
        .padding(if compact { 10 } else { 12 })
        .width(Length::Fill)
        .style(theme::surface)
        .into()
    } else {
        container(
            text("Calculated from the current wallet state. Your secret stays on this device.")
                .size(11)
                .color(theme::DIM),
        )
        .padding([5, 2])
        .width(Length::Fill)
        .into()
    };

    let mut cancel = button(text("CANCEL").size(12))
        .padding(if compact { [9, 13] } else { [10, 15] })
        .style(|_, status| theme::button(ButtonKind::Secondary, status));
    if !app.wallet_action_in_flight() {
        cancel = cancel.on_press(Message::CloseAction);
    }
    let mut submit = button(
        text(if app.consolidation_in_flight {
            "BUILDING PROOF…"
        } else {
            "PROVE & CONSOLIDATE"
        })
        .size(12),
    )
    .padding(if compact { [9, 13] } else { [10, 17] })
    .style(|_, status| theme::button(ButtonKind::Primary, status));
    if !app.wallet_action_in_flight()
        && matches!(
            app.backend_state,
            crate::app::BackendState::Online | crate::app::BackendState::Mock
        )
    {
        submit = submit.on_press(Message::SubmitConsolidation);
    }

    column![
        form_line(
            "INPUTS",
            format!(
                "{} smallest of {} · {} NOID",
                plan.input_count,
                original_count,
                format_micronoid(plan.input_value_micronoid)
            ),
            compact,
        ),
        form_line(
            "NETWORK FEE",
            format!("{} NOID", format_micronoid(plan.fee_micronoid)),
            compact,
        ),
        form_line(
            "NEW OUTPUT",
            format!("1 · {} NOID", format_micronoid(plan.output_value_micronoid)),
            compact,
        ),
        form_line(
            "STATE",
            format!(
                "{} → {} outputs · {} slots freed",
                original_count, plan.remaining_count, plan.freed_slots,
            ),
            compact,
        ),
        container(
            column![
                text("TOTAL BALANCE").size(10).color(theme::DIM),
                row![
                    text(format_micronoid(plan.balance_before_micronoid))
                        .size(16)
                        .color(theme::TEXT),
                    text("①")
                        .size(16)
                        .line_height(1.0)
                        .font(theme::SYMBOL_FONT)
                        .color(theme::ACCENT),
                    text("→").size(14).color(theme::DIM),
                    text(format_micronoid(plan.balance_after_micronoid))
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
                    "{} output{} remain{} untouched.",
                    plan.untouched_count,
                    if plan.untouched_count == 1 { "" } else { "s" },
                    if plan.untouched_count == 1 { "s" } else { "" },
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
            send_status("SPENDING SECRET", "LOCAL", theme::ACCENT),
            send_status("PROOF", proof_label, proof_color),
        ]
        .spacing(8),
        feedback,
        row![
            iced::widget::Space::new().width(Length::Fill),
            cancel,
            submit,
        ]
        .spacing(8)
        .align_y(Alignment::Center),
    ]
    .spacing(if compact { 7 } else { 10 })
    .into()
}

fn consolidation_success<'a>(
    app: &'a App,
    result: &'a ConsolidationSubmission,
    compact: bool,
) -> Element<'a, Message> {
    let txid = row![
        text("TXID")
            .size(10)
            .color(theme::CYAN)
            .width(if compact { 54 } else { 70 }),
        text_input("", &result.txid)
            .on_input(|_| Message::Noop)
            .size(12)
            .padding([8, 10])
            .width(Length::Fill)
            .style(theme::text_input),
        copy_value_button(
            &result.txid,
            app.copied_value.as_deref() == Some(result.txid.as_str()),
        ),
    ]
    .spacing(8)
    .align_y(Alignment::Center);
    let metrics = row![
        send_result_metric("INPUTS", result.input_count.to_string()),
        send_result_metric("OUTPUTS", result.output_count.to_string()),
        send_result_metric(
            "FEE",
            format!("{} ①", format_micronoid(result.fee_micronoid)),
        ),
        send_result_metric("FREED", result.freed_slots.to_string()),
    ]
    .spacing(7);
    let close = button(text("CLOSE").size(12))
        .on_press(Message::CloseAction)
        .padding(if compact { [9, 13] } else { [10, 15] })
        .style(|_, status| theme::button(ButtonKind::Secondary, status));

    column![
        row![
            text("CONSOLIDATION SENT").size(12).color(theme::ACCENT),
            iced::widget::Space::new().width(Length::Fill),
            text("PENDING CONFIRMATION").size(10).color(theme::WARNING),
        ]
        .align_y(Alignment::Center),
        container(txid)
            .padding([7, 9])
            .width(Length::Fill)
            .style(theme::surface),
        metrics,
        form_line(
            "NEW OUTPUT",
            format!("{} NOID", format_micronoid(result.output_value_micronoid)),
            compact,
        ),
        form_line(
            "INPUT VALUE",
            format!(
                "{} NOID selected",
                format_micronoid(result.input_value_micronoid),
            ),
            compact,
        ),
        text("Broadcasting to the network...")
            .size(11)
            .color(theme::DIM),
        row![iced::widget::Space::new().width(Length::Fill), close,].align_y(Alignment::Center),
    ]
    .spacing(if compact { 7 } else { 10 })
    .into()
}

fn send_form(app: &App, compact: bool) -> Element<'_, Message> {
    if let Some(result) = app.send_result.as_ref() {
        return send_success(app, result, compact);
    }
    let address = app.snapshot.active_address();
    let spendable = address
        .balance_micronoid
        .saturating_sub(address.pending_outbound_micronoid);
    let recipient = send_input_line(
        "RECIPIENT",
        "Paste an o1 address",
        &app.send_recipient,
        Message::SendRecipientChanged,
        compact,
        app.send_in_flight,
    );
    let amount = send_input_line(
        "AMOUNT / NOID",
        "0.000000",
        &app.send_amount,
        Message::SendAmountChanged,
        compact,
        app.send_in_flight,
    );

    let proof_label = if app.send_in_flight {
        "BUILDING"
    } else {
        "READY"
    };
    let proof_color = if app.send_in_flight {
        theme::WARNING
    } else {
        theme::PROOF
    };
    let status: Element<'_, Message> = row![
        send_status("SPENDING SECRET", "LOCAL", theme::ACCENT),
        send_status("PROOF", proof_label, proof_color),
    ]
    .spacing(8)
    .into();

    let feedback: Element<'_, Message> = if let Some(error) = app.send_error.as_ref() {
        container(
            column![
                text("TRANSACTION NOT SENT").size(11).color(theme::DANGER),
                text(error).size(11).color(theme::TEXT),
            ]
            .spacing(5),
        )
        .padding(if compact { 10 } else { 12 })
        .width(Length::Fill)
        .style(theme::surface)
        .into()
    } else {
        container(
            text("Your secret stays on this device. Only the transaction is sent.")
                .size(11)
                .color(theme::DIM),
        )
        .padding([5, 2])
        .width(Length::Fill)
        .into()
    };

    let mut cancel = button(text("CANCEL").size(12))
        .padding(if compact { [9, 13] } else { [10, 15] })
        .width(if compact {
            Length::Fill
        } else {
            Length::Shrink
        })
        .style(|_, status| theme::button(ButtonKind::Secondary, status));
    if !app.send_in_flight {
        cancel = cancel.on_press(Message::CloseAction);
    }
    let mut submit = button(
        text(if app.send_in_flight {
            "BUILDING PROOF…"
        } else {
            "PROVE & SEND"
        })
        .size(12),
    )
    .padding(if compact { [9, 13] } else { [10, 17] })
    .width(if compact {
        Length::Fill
    } else {
        Length::Shrink
    })
    .style(|_, status| theme::button(ButtonKind::Primary, status));
    if !app.send_in_flight
        && matches!(
            app.backend_state,
            crate::app::BackendState::Online | crate::app::BackendState::Mock
        )
    {
        submit = submit.on_press(Message::SubmitSend);
    }
    let controls = row![
        if compact {
            iced::widget::Space::new().width(Length::Shrink)
        } else {
            iced::widget::Space::new().width(Length::Fill)
        },
        cancel,
        submit,
    ]
    .spacing(8)
    .align_y(Alignment::Center);

    column![
        form_line(
            "FROM",
            format!(
                "[{}] {} · {} ① spendable",
                address.key_index,
                address.label,
                format_micronoid(spendable)
            ),
            compact,
        ),
        recipient,
        amount,
        form_line(
            "NETWORK FEE",
            "AUTOMATIC · calculated by the wallet",
            compact
        ),
        status,
        feedback,
        controls,
    ]
    .spacing(if compact { 7 } else { 10 })
    .into()
}

fn send_success<'a>(
    app: &'a App,
    result: &'a PaymentSubmission,
    compact: bool,
) -> Element<'a, Message> {
    let recipient = row![
        text("TO")
            .size(10)
            .color(theme::CYAN)
            .width(if compact { 54 } else { 70 }),
        text_input("", &result.recipient)
            .on_input(|_| Message::Noop)
            .size(12)
            .padding([8, 10])
            .width(Length::Fill)
            .style(theme::text_input),
        copy_value_button(
            &result.recipient,
            app.copied_value.as_deref() == Some(result.recipient.as_str()),
        ),
    ]
    .spacing(8)
    .align_y(Alignment::Center);
    let txid = row![
        text("TXID")
            .size(10)
            .color(theme::CYAN)
            .width(if compact { 54 } else { 70 }),
        text_input("", &result.txid)
            .on_input(|_| Message::Noop)
            .size(12)
            .padding([8, 10])
            .width(Length::Fill)
            .style(theme::text_input),
        copy_value_button(
            &result.txid,
            app.copied_value.as_deref() == Some(result.txid.as_str()),
        ),
    ]
    .spacing(8)
    .align_y(Alignment::Center);
    let metrics = row![
        send_result_metric(
            "AMOUNT",
            format!("{} ①", format_micronoid(result.amount_micronoid)),
        ),
        send_result_metric(
            "FEE",
            format!("{} ①", format_micronoid(result.fee_micronoid)),
        ),
        send_result_metric("INPUTS", result.input_count.to_string()),
        send_result_metric("OUTPUTS", result.output_count.to_string()),
    ]
    .spacing(7);

    let close = button(text("CLOSE").size(12))
        .on_press(Message::CloseAction)
        .padding(if compact { [9, 13] } else { [10, 15] })
        .width(if compact {
            Length::Fill
        } else {
            Length::Shrink
        })
        .style(|_, status| theme::button(ButtonKind::Secondary, status));
    let another = button(text("SEND ANOTHER").size(12))
        .on_press(Message::ResetSend)
        .padding(if compact { [9, 13] } else { [10, 17] })
        .width(if compact {
            Length::Fill
        } else {
            Length::Shrink
        })
        .style(|_, status| theme::button(ButtonKind::Primary, status));

    column![
        row![
            text("TRANSACTION SENT").size(12).color(theme::ACCENT),
            iced::widget::Space::new().width(Length::Fill),
            text("PENDING CONFIRMATION").size(10).color(theme::WARNING),
        ]
        .align_y(Alignment::Center),
        container(recipient)
            .padding([7, 9])
            .width(Length::Fill)
            .style(theme::surface),
        container(txid)
            .padding([7, 9])
            .width(Length::Fill)
            .style(theme::surface),
        metrics,
        text("Broadcasting to the network...")
            .size(11)
            .color(theme::DIM),
        row![
            if compact {
                iced::widget::Space::new().width(Length::Shrink)
            } else {
                iced::widget::Space::new().width(Length::Fill)
            },
            close,
            another,
        ]
        .spacing(8)
        .align_y(Alignment::Center),
    ]
    .spacing(if compact { 7 } else { 10 })
    .into()
}

fn send_result_metric(label: &'static str, value: String) -> Element<'static, Message> {
    container(
        column![
            text(label).size(9).color(theme::DIM),
            text(value).size(11).color(theme::TEXT),
        ]
        .spacing(3),
    )
    .padding([8, 10])
    .width(Length::Fill)
    .style(theme::surface)
    .into()
}

fn send_input_line<'a>(
    label: &'static str,
    placeholder: &'static str,
    value: &'a str,
    on_input: fn(String) -> Message,
    compact: bool,
    disabled: bool,
) -> Element<'a, Message> {
    let mut input = text_input(placeholder, value)
        .size(13)
        .padding([9, 10])
        .width(Length::Fill)
        .style(theme::text_input);
    if !disabled {
        input = input.on_input(on_input).on_submit(Message::SubmitSend);
    }
    let content: Element<'a, Message> = row![
        text(label)
            .size(if compact { 10 } else { 11 })
            .color(theme::CYAN)
            .width(if compact { 110 } else { 120 }),
        input
    ]
    .spacing(if compact { 8 } else { 10 })
    .align_y(Alignment::Center)
    .into();
    container(content)
        .padding(if compact { [8, 10] } else { [9, 12] })
        .width(Length::Fill)
        .style(theme::surface)
        .into()
}

fn send_status(
    label: &'static str,
    value: &'static str,
    color: iced::Color,
) -> Element<'static, Message> {
    container(
        row![
            text(label).size(10).color(theme::DIM),
            iced::widget::Space::new().width(Length::Fill),
            text(value).size(11).color(color),
        ]
        .align_y(Alignment::Center),
    )
    .padding([8, 10])
    .width(Length::Fill)
    .style(theme::surface)
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
