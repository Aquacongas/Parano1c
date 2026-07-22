// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use std::time::Duration;

use iced::{Element, Subscription, Task};

use crate::backend::{Backend, BackendSnapshot, NodeMode};
use crate::model::{AppSnapshot, Section, WALLET_CONSOLIDATION_INPUT_LIMIT};
use crate::view;

#[derive(Debug)]
pub struct App {
    pub snapshot: AppSnapshot,
    pub section: Section,
    pub backend_state: BackendState,
    pub backend_error: Option<String>,
    pub node_action_in_flight: bool,
    pub genesis_enabled: bool,
    pub address_picker_open: bool,
    pub action: Option<Action>,
    pub copied_address: Option<u32>,
    pub editing_address: Option<u32>,
    pub edit_label: String,
    pub selected_utxo_slot: Option<u32>,
    pub consolidation_hint_open: bool,
    consolidation_badge_hovered: bool,
    consolidation_card_hovered: bool,
    consolidation_hint_close_ticks: u8,
    consolidation_pulse_phase: f32,
    backend: Backend,
    refresh_in_flight: bool,
    ensure_in_flight: bool,
    consecutive_refresh_failures: u8,
    shutting_down: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendState {
    Mock,
    Starting,
    Online,
    Offline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Send,
    Consolidate,
}

#[derive(Debug, Clone)]
pub enum Message {
    Navigate(Section),
    ToggleAddressPicker,
    SelectAddress(u32),
    CreateAddress,
    OpenAction(Action),
    CloseAction,
    CopyAddress(u32),
    SelectUtxo(u32),
    SelectSegment(u8),
    BeginEditAddress(u32),
    EditAddressLabel(String),
    SaveAddressLabel,
    CancelAddressLabel,
    EnterConsolidationBadge,
    LeaveConsolidationBadge,
    EnterConsolidationCard,
    LeaveConsolidationCard,
    PulseConsolidationHint,
    EnsureNodeFinished(Result<(), String>),
    RefreshTick,
    SnapshotLoaded(Result<Box<BackendSnapshot>, String>),
    AddressActionFinished(Result<(), String>),
    #[cfg(feature = "dev-genesis")]
    ToggleGenesis(bool),
    AdjustMiningThreads(i8),
    SetMining(bool),
    NodeRestarted(Result<(), String>),
    Noop,
    Exit,
    ExitReady,
}

impl App {
    pub fn new() -> (Self, Task<Message>) {
        let backend = Backend::from_env();
        let mock = backend.is_mock();
        let snapshot = if mock {
            AppSnapshot::design_preview()
        } else {
            AppSnapshot::offline(backend.available_threads())
        };
        let selected_utxo_slot = snapshot.utxos.first().map(|utxo| utxo.slot_index);

        let app = Self {
            snapshot,
            section: Section::Present,
            backend_state: if mock {
                BackendState::Mock
            } else {
                BackendState::Starting
            },
            backend_error: None,
            node_action_in_flight: false,
            genesis_enabled: false,
            address_picker_open: false,
            action: None,
            copied_address: None,
            editing_address: None,
            edit_label: String::new(),
            selected_utxo_slot,
            consolidation_hint_open: false,
            consolidation_badge_hovered: false,
            consolidation_card_hovered: false,
            consolidation_hint_close_ticks: 0,
            consolidation_pulse_phase: 0.0,
            backend: backend.clone(),
            refresh_in_flight: false,
            ensure_in_flight: !mock,
            consecutive_refresh_failures: 0,
            shutting_down: false,
        };
        let task = if mock {
            Task::none()
        } else {
            Task::perform(
                async move { backend.ensure_running().await },
                Message::EnsureNodeFinished,
            )
        };
        (app, task)
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Navigate(section) => {
                self.section = section;
                self.address_picker_open = false;
                self.action = None;
                self.editing_address = None;
                self.close_consolidation_hint();
            }
            Message::ToggleAddressPicker => {
                self.address_picker_open = !self.address_picker_open;
                if self.address_picker_open {
                    self.action = None;
                }
                self.editing_address = None;
                self.close_consolidation_hint();
            }
            Message::SelectAddress(key_index) => {
                self.address_picker_open = false;
                self.copied_address = None;
                self.selected_utxo_slot = None;
                self.close_consolidation_hint();
                if self.backend.is_mock() {
                    self.snapshot.activate_address(key_index);
                } else {
                    let backend = self.backend.clone();
                    return Task::perform(
                        async move { backend.set_active_address(key_index).await },
                        Message::AddressActionFinished,
                    );
                }
            }
            Message::CreateAddress => {
                self.address_picker_open = false;
                self.copied_address = None;
                self.selected_utxo_slot = None;
                self.close_consolidation_hint();
                if self.backend.is_mock() {
                    self.snapshot.create_preview_address();
                } else {
                    let backend = self.backend.clone();
                    return Task::perform(
                        async move { backend.create_address().await },
                        Message::AddressActionFinished,
                    );
                }
            }
            Message::OpenAction(action) => {
                self.action = Some(action);
                self.address_picker_open = false;
                self.close_consolidation_hint();
            }
            Message::CloseAction => self.action = None,
            Message::CopyAddress(key_index) => {
                if let Some(address) = self
                    .snapshot
                    .addresses
                    .iter()
                    .find(|address| address.key_index == key_index)
                {
                    self.copied_address = Some(key_index);
                    return iced::clipboard::write(address.address.clone());
                }
            }
            Message::SelectUtxo(slot_index) => {
                if self
                    .snapshot
                    .utxos
                    .iter()
                    .any(|utxo| utxo.slot_index == slot_index)
                {
                    self.selected_utxo_slot = Some(slot_index);
                }
            }
            Message::SelectSegment(segment) => {
                let matches = self
                    .snapshot
                    .utxos
                    .iter()
                    .filter(|utxo| utxo.segment == segment)
                    .map(|utxo| utxo.slot_index)
                    .collect::<Vec<_>>();
                self.selected_utxo_slot = if matches.is_empty() {
                    None
                } else if let Some(current) = self.selected_utxo_slot {
                    let next = matches
                        .iter()
                        .position(|slot| *slot == current)
                        .map(|position| (position + 1) % matches.len())
                        .unwrap_or(0);
                    Some(matches[next])
                } else {
                    Some(matches[0])
                };
            }
            Message::BeginEditAddress(key_index) => {
                if let Some(address) = self
                    .snapshot
                    .addresses
                    .iter()
                    .find(|address| address.key_index == key_index)
                {
                    self.editing_address = Some(key_index);
                    self.edit_label = address.label.clone();
                }
            }
            Message::EditAddressLabel(label) => self.edit_label = label,
            Message::SaveAddressLabel => {
                if let Some(key_index) = self.editing_address {
                    self.snapshot.rename_address(key_index, &self.edit_label);
                }
                self.editing_address = None;
                self.edit_label.clear();
            }
            Message::CancelAddressLabel => {
                self.editing_address = None;
                self.edit_label.clear();
            }
            Message::EnterConsolidationBadge => {
                if self.consolidation_recommended() {
                    self.consolidation_hint_open = true;
                    self.consolidation_badge_hovered = true;
                    self.consolidation_hint_close_ticks = 0;
                }
            }
            Message::LeaveConsolidationBadge => {
                self.consolidation_badge_hovered = false;
                if !self.consolidation_card_hovered {
                    self.consolidation_hint_close_ticks = 4;
                }
            }
            Message::EnterConsolidationCard => {
                self.consolidation_hint_open = true;
                self.consolidation_card_hovered = true;
                self.consolidation_hint_close_ticks = 0;
            }
            Message::LeaveConsolidationCard => {
                self.consolidation_card_hovered = false;
                if !self.consolidation_badge_hovered {
                    self.consolidation_hint_close_ticks = 4;
                }
            }
            Message::PulseConsolidationHint => {
                self.consolidation_pulse_phase =
                    (self.consolidation_pulse_phase + 0.15) % std::f32::consts::TAU;

                if !self.consolidation_badge_hovered
                    && !self.consolidation_card_hovered
                    && self.consolidation_hint_close_ticks > 0
                {
                    self.consolidation_hint_close_ticks -= 1;
                    if self.consolidation_hint_close_ticks == 0 {
                        self.consolidation_hint_open = false;
                    }
                }
            }
            Message::EnsureNodeFinished(result) => {
                self.ensure_in_flight = false;
                match result {
                    Ok(()) => {
                        self.backend_state = BackendState::Online;
                        self.backend_error = None;
                        return self.refresh_snapshot();
                    }
                    Err(error) => {
                        self.backend_state = BackendState::Offline;
                        self.backend_error = Some(error);
                    }
                }
            }
            Message::RefreshTick => {
                if !self.backend.is_mock()
                    && !self.refresh_in_flight
                    && !self.ensure_in_flight
                    && !self.node_action_in_flight
                    && !self.shutting_down
                {
                    return self.refresh_snapshot();
                }
            }
            Message::SnapshotLoaded(result) => {
                self.refresh_in_flight = false;
                match result {
                    Ok(live) => {
                        let mut live = *live;
                        live.snapshot.preserve_local_labels_from(&self.snapshot);
                        let selected_still_exists = self.selected_utxo_slot.is_some_and(|slot| {
                            live.snapshot
                                .utxos
                                .iter()
                                .any(|utxo| utxo.slot_index == slot)
                        });
                        self.snapshot = live.snapshot;
                        if !selected_still_exists {
                            self.selected_utxo_slot =
                                self.snapshot.utxos.first().map(|utxo| utxo.slot_index);
                        }
                        self.backend_state = BackendState::Online;
                        self.backend_error = None;
                        self.consecutive_refresh_failures = 0;
                    }
                    Err(error) => {
                        self.backend_state = BackendState::Offline;
                        self.backend_error = Some(error);
                        self.consecutive_refresh_failures =
                            self.consecutive_refresh_failures.saturating_add(1);
                        if self.consecutive_refresh_failures >= 3 {
                            self.ensure_in_flight = true;
                            let backend = self.backend.clone();
                            return Task::perform(
                                async move { backend.ensure_running().await },
                                Message::EnsureNodeFinished,
                            );
                        }
                    }
                }
            }
            Message::AddressActionFinished(result) => match result {
                Ok(()) => return self.refresh_snapshot(),
                Err(error) => self.backend_error = Some(error),
            },
            #[cfg(feature = "dev-genesis")]
            Message::ToggleGenesis(enabled) => {
                if self.snapshot.network.height == 0 && !self.snapshot.mining.enabled {
                    self.genesis_enabled = enabled;
                }
            }
            Message::AdjustMiningThreads(delta) => {
                if !self.snapshot.mining.enabled && !self.node_action_in_flight {
                    let available = self.snapshot.mining.available_threads.max(1);
                    let selected = self.snapshot.mining.selected_threads.max(1);
                    let next = if delta.is_negative() {
                        selected.saturating_sub(delta.unsigned_abs() as usize)
                    } else {
                        selected.saturating_add(delta as usize)
                    }
                    .clamp(1, available);
                    self.snapshot.mining.selected_threads = next;
                    self.backend.set_selected_threads(next);
                }
            }
            Message::SetMining(enabled) => {
                if self.node_action_in_flight || self.snapshot.mining.enabled == enabled {
                    return Task::none();
                }
                if self.backend.is_mock() {
                    self.snapshot.mining.enabled = enabled;
                    return Task::none();
                }
                let genesis = enabled
                    && self.genesis_enabled
                    && self.snapshot.network.height == 0
                    && cfg!(feature = "dev-genesis");
                let mode = if enabled {
                    NodeMode::Miner
                } else {
                    NodeMode::Node
                };
                let selected_threads = self.snapshot.mining.selected_threads;
                self.node_action_in_flight = true;
                self.backend_state = BackendState::Starting;
                self.backend_error = None;
                let backend = self.backend.clone();
                return Task::perform(
                    async move { backend.restart(mode, selected_threads, genesis).await },
                    Message::NodeRestarted,
                );
            }
            Message::NodeRestarted(result) => {
                self.node_action_in_flight = false;
                match result {
                    Ok(()) => {
                        self.genesis_enabled = false;
                        self.backend_state = BackendState::Online;
                        return self.refresh_snapshot();
                    }
                    Err(error) => {
                        self.backend_state = BackendState::Offline;
                        self.backend_error = Some(error);
                    }
                }
            }
            Message::Noop => {}
            Message::Exit => {
                if self.shutting_down {
                    return Task::none();
                }
                self.shutting_down = true;
                let backend = self.backend.clone();
                return Task::perform(
                    async move {
                        let _ = backend.shutdown().await;
                    },
                    |_| Message::ExitReady,
                );
            }
            Message::ExitReady => return iced::exit(),
        }

        Task::none()
    }

    pub fn view(&self) -> Element<'_, Message> {
        view::root(self)
    }

    pub fn subscription(&self) -> Subscription<Message> {
        let mut subscriptions = vec![iced::window::close_requests().map(|_| Message::Exit)];
        if !self.backend.is_mock() {
            subscriptions
                .push(iced::time::every(Duration::from_secs(1)).map(|_| Message::RefreshTick));
        }
        if self.section == Section::Present && self.consolidation_recommended() {
            subscriptions.push(
                iced::time::every(Duration::from_millis(80))
                    .map(|_| Message::PulseConsolidationHint),
            );
        }
        Subscription::batch(subscriptions)
    }

    pub fn consolidation_recommended(&self) -> bool {
        self.snapshot.active_address().spendable_utxo_count() >= WALLET_CONSOLIDATION_INPUT_LIMIT
    }

    pub fn consolidation_pulse(&self) -> f32 {
        0.5 + 0.5 * self.consolidation_pulse_phase.sin()
    }

    fn close_consolidation_hint(&mut self) {
        self.consolidation_hint_open = false;
        self.consolidation_badge_hovered = false;
        self.consolidation_card_hovered = false;
        self.consolidation_hint_close_ticks = 0;
    }

    fn refresh_snapshot(&mut self) -> Task<Message> {
        if self.refresh_in_flight {
            return Task::none();
        }
        self.refresh_in_flight = true;
        let backend = self.backend.clone();
        Task::perform(
            async move { backend.snapshot().await.map(Box::new) },
            Message::SnapshotLoaded,
        )
    }
}
