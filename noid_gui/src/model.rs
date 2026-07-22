// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

pub const WALLET_CONSOLIDATION_INPUT_LIMIT: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Present,
    Proofs,
    Mine,
    Node,
    Settings,
}

impl Section {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Present => "Main",
            Self::Proofs => "Proofs",
            Self::Mine => "Mining",
            Self::Node => "Node",
            Self::Settings => "Settings",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppSnapshot {
    pub network: NetworkSnapshot,
    pub addresses: Vec<AddressSnapshot>,
    pub active_address: usize,
    pub segments: Vec<SegmentSnapshot>,
    pub utxos: Vec<UtxoSnapshot>,
    pub mining: MiningSnapshot,
}

#[derive(Debug, Clone)]
pub struct NetworkSnapshot {
    pub height: u64,
    pub peers: usize,
    pub active_slots: u64,
    pub log_slots: u32,
    pub mempool_transactions: usize,
    pub mempool_capacity_transactions: usize,
    pub mempool_bytes: u64,
    pub mempool_capacity_bytes: u64,
    pub cpu_load: f32,
    pub memory_used_bytes: u64,
    pub memory_total_bytes: u64,
    pub last_block_age_seconds: u64,
    pub average_block_time_ms: u64,
    pub difficulty: f64,
    pub backend: String,
    pub synced: bool,
    pub terminal_verified: bool,
    pub state_root: String,
}

impl NetworkSnapshot {
    pub fn slot_capacity(&self) -> u64 {
        1u64.checked_shl(self.log_slots).unwrap_or(u64::MAX)
    }
}

#[derive(Debug, Clone)]
pub struct AddressSnapshot {
    pub key_index: u32,
    pub address: String,
    pub label: String,
    pub balance_micronoid: u64,
    pub utxo_count: usize,
    pub reserved_utxo_count: usize,
    pub pending_outbound_micronoid: u64,
    pub incoming_micronoid: u64,
}

impl AddressSnapshot {
    pub fn balance(&self) -> String {
        format_micronoid(self.balance_micronoid)
    }

    pub fn pending_outbound(&self) -> String {
        format_micronoid(self.pending_outbound_micronoid)
    }

    pub fn incoming(&self) -> String {
        format_micronoid(self.incoming_micronoid)
    }

    pub fn spendable_utxo_count(&self) -> usize {
        self.utxo_count.saturating_sub(self.reserved_utxo_count)
    }

    pub fn short_address(&self) -> String {
        if self.address.len() <= 26 {
            return self.address.clone();
        }

        format!(
            "{}…{}",
            &self.address[..15],
            &self.address[self.address.len() - 9..]
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SegmentSnapshot {
    pub occupancy: f32,
    pub owned: bool,
}

#[derive(Debug, Clone)]
pub struct UtxoSnapshot {
    pub slot_index: u32,
    pub value_micronoid: u64,
    pub creation_id: u64,
    pub segment: u8,
    pub reserved: bool,
}

impl UtxoSnapshot {
    pub fn value(&self) -> String {
        format_micronoid(self.value_micronoid)
    }
}

#[derive(Debug, Clone)]
pub struct MiningSnapshot {
    pub enabled: bool,
    pub selected_threads: usize,
    pub available_threads: usize,
}

impl AppSnapshot {
    pub fn active_address(&self) -> &AddressSnapshot {
        &self.addresses[self.active_address]
    }

    pub fn activate_address(&mut self, key_index: u32) {
        if let Some(position) = self
            .addresses
            .iter()
            .position(|address| address.key_index == key_index)
        {
            self.active_address = position;
        }
    }

    pub fn rename_address(&mut self, key_index: u32, label: &str) {
        let label = label.trim();
        if label.is_empty() {
            return;
        }

        if let Some(address) = self
            .addresses
            .iter_mut()
            .find(|address| address.key_index == key_index)
        {
            address.label = label.to_string();
        }
    }

    pub fn create_preview_address(&mut self) {
        let key_index = self.addresses.len() as u32;
        self.addresses.push(AddressSnapshot {
            key_index,
            address: format!(
                "o1q{:02}n7k4v9s2p8m5x3d6ta0er4wh1yc5j7l9u3g6b2n8k5p4mc",
                key_index
            ),
            label: format!("Address {key_index}"),
            balance_micronoid: 0,
            utxo_count: 0,
            reserved_utxo_count: 0,
            pending_outbound_micronoid: 0,
            incoming_micronoid: 0,
        });
        self.active_address = self.addresses.len() - 1;
        self.utxos.clear();
    }

    pub fn preserve_local_labels_from(&mut self, previous: &Self) {
        for address in &mut self.addresses {
            if let Some(previous_address) = previous
                .addresses
                .iter()
                .find(|candidate| candidate.key_index == address.key_index)
            {
                address.label.clone_from(&previous_address.label);
            }
        }
    }

    pub fn offline(available_threads: usize) -> Self {
        Self {
            network: NetworkSnapshot {
                height: 0,
                peers: 0,
                active_slots: 0,
                log_slots: 24,
                mempool_transactions: 0,
                mempool_capacity_transactions: 1_024,
                mempool_bytes: 0,
                mempool_capacity_bytes: 384 * 1024 * 1024,
                cpu_load: 0.0,
                memory_used_bytes: 0,
                memory_total_bytes: 1,
                last_block_age_seconds: 0,
                average_block_time_ms: 15_000,
                difficulty: 1.0,
                backend: "STARTING".into(),
                synced: false,
                terminal_verified: false,
                state_root: "waiting-for-local-node".into(),
            },
            addresses: vec![AddressSnapshot {
                key_index: 0,
                address: "Local wallet is starting…".into(),
                label: "Main".into(),
                balance_micronoid: 0,
                utxo_count: 0,
                reserved_utxo_count: 0,
                pending_outbound_micronoid: 0,
                incoming_micronoid: 0,
            }],
            active_address: 0,
            segments: vec![
                SegmentSnapshot {
                    occupancy: 0.0,
                    owned: false,
                };
                256
            ],
            utxos: Vec::new(),
            mining: MiningSnapshot {
                enabled: false,
                selected_threads: available_threads,
                available_threads,
            },
        }
    }

    pub fn design_preview() -> Self {
        const PREVIEW_ADDRESS_COUNT: usize = 20;
        const PREVIEW_UTXO_COUNT: usize = 72;
        const PREVIEW_BALANCE_MICRONOID: u64 = 100_000_000_000;

        let segments = (0u32..256)
            .map(|index| {
                let mixed = index.wrapping_mul(0x9E37_79B9).rotate_left(index % 17) ^ 0xA5C3_18D7;
                let raw = ((mixed >> 9) & 0x7f) as f32 / 127.0;
                let occupancy = if raw < 0.16 {
                    0.0
                } else {
                    raw.powf(2.0) * 0.22
                };
                SegmentSnapshot {
                    occupancy: if matches!(index, 28 | 73 | 119 | 164 | 213) {
                        occupancy.max(0.04)
                    } else {
                        occupancy
                    },
                    owned: matches!(index, 28 | 73 | 119 | 164 | 213),
                }
            })
            .collect();

        let owned_segments = [28u8, 73, 119, 164, 213];
        let base_value = PREVIEW_BALANCE_MICRONOID / PREVIEW_UTXO_COUNT as u64;
        let remainder = PREVIEW_BALANCE_MICRONOID % PREVIEW_UTXO_COUNT as u64;
        let utxos = (0..PREVIEW_UTXO_COUNT)
            .map(|index| UtxoSnapshot {
                slot_index: 73 + index as u32 * 73,
                value_micronoid: base_value + u64::from((index as u64) < remainder),
                creation_id: 1_284_088 + index as u64 * 3,
                segment: owned_segments[index % owned_segments.len()],
                reserved: false,
            })
            .collect();

        let mut addresses = vec![
            AddressSnapshot {
                key_index: 0,
                address: "o1q9p2w4t8k3ux7c5n0r6dmzfae9hj2ls4v8y6c3b7n5q2wk0t9xp".into(),
                label: "Main".into(),
                balance_micronoid: PREVIEW_BALANCE_MICRONOID,
                utxo_count: PREVIEW_UTXO_COUNT,
                reserved_utxo_count: 0,
                pending_outbound_micronoid: 100_000_000_000,
                incoming_micronoid: 100_000_000_000,
            },
            AddressSnapshot {
                key_index: 1,
                address: "o1y7m4h2p8vz5k9c3d6ta0er4wn8qx2f5j7l9s3u6g1b4n8kp2mc".into(),
                label: "Savings".into(),
                balance_micronoid: 312_000_000,
                utxo_count: 6,
                reserved_utxo_count: 0,
                pending_outbound_micronoid: 0,
                incoming_micronoid: 0,
            },
            AddressSnapshot {
                key_index: 2,
                address: "o1k3v8s5q2nc7r4m9x6df0wa8h1yt5p3j7u9e2l6b4z8g0cm5nr".into(),
                label: "Shop".into(),
                balance_micronoid: 0,
                utxo_count: 0,
                reserved_utxo_count: 0,
                pending_outbound_micronoid: 0,
                incoming_micronoid: 0,
            },
        ];
        addresses.extend((addresses.len()..PREVIEW_ADDRESS_COUNT).map(|key_index| {
            AddressSnapshot {
                key_index: key_index as u32,
                address: format!("o1q{key_index:02}n7k4v9s2p8m5x3d6ta0er4wh1yc5j7l9u3g6b2n8k5p4mc"),
                label: format!("Address {key_index}"),
                balance_micronoid: 0,
                utxo_count: 0,
                reserved_utxo_count: 0,
                pending_outbound_micronoid: 0,
                incoming_micronoid: 0,
            }
        }));

        Self {
            network: NetworkSnapshot {
                height: 18_420,
                peers: 12,
                active_slots: 1_276_944,
                log_slots: 24,
                mempool_transactions: 7,
                mempool_capacity_transactions: 1_024,
                mempool_bytes: 2_936_832,
                mempool_capacity_bytes: 384 * 1024 * 1024,
                cpu_load: 0.147,
                memory_used_bytes: 12_300_000_000,
                memory_total_bytes: 31_000_000_000,
                last_block_age_seconds: 4,
                average_block_time_ms: 15_200,
                difficulty: 10.60,
                backend: "AVX2".into(),
                synced: true,
                terminal_verified: true,
                state_root: "a94f2c7718d95063e4770b423f5b7211ca60d2ea8cf7c8a4c9f35e7318c21c2e"
                    .into(),
            },
            addresses,
            active_address: 0,
            segments,
            utxos,
            mining: MiningSnapshot {
                enabled: false,
                selected_threads: 12,
                available_threads: 12,
            },
        }
    }
}

pub fn grouped(value: u64) -> String {
    let digits = value.to_string();
    let first = digits.len() % 3;
    let mut output = String::with_capacity(digits.len() + digits.len() / 3);

    for (index, character) in digits.chars().enumerate() {
        if index > 0 && index % 3 == first {
            output.push('\u{2009}');
        }
        output.push(character);
    }

    output
}

pub fn format_micronoid(value: u64) -> String {
    let whole = value / 1_000_000;
    let fractional = value % 1_000_000;
    format!("{whole}.{fractional:06}")
}
