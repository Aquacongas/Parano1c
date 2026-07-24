// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

pub const WALLET_CONSOLIDATION_INPUT_LIMIT: usize = 64;
pub const MINED_BLOCK_PAGE_SIZE: u32 = 8;
pub const EXPLORER_PAGE_SIZE: u32 = 8;
pub const EXPLORER_SLOT_PAGE_SIZE: usize = 8;
pub const RECEIPT_PAGE_SIZE: u32 = 7;
pub const UTXO_PAGE_SIZE: usize = 25;

#[derive(Clone, Default)]
pub struct SensitiveString(zeroize::Zeroizing<String>);

impl SensitiveString {
    pub fn new(value: String) -> Self {
        Self(zeroize::Zeroizing::new(value))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn clear(&mut self) {
        zeroize::Zeroize::zeroize(&mut *self.0);
    }
}

impl std::fmt::Debug for SensitiveString {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SensitiveString(<redacted>)")
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
}

impl LogLevel {
    pub const ALL: [Self; 4] = [Self::Error, Self::Warn, Self::Info, Self::Debug];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warn => "WARN",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeSettingsSnapshot {
    pub data_dir: String,
    pub p2p_listen: String,
    pub custom_seeds: Vec<String>,
    pub log_level: LogLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatrixClass {
    B64,
    B255,
}

impl MatrixClass {
    pub const fn cli_value(self) -> &'static str {
        match self {
            Self::B64 => "b64",
            Self::B255 => "b255",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatrixCacheState {
    Pending,
    Preparing,
    Ready,
    Failed(String),
}

impl MatrixCacheState {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Preparing => "PREPARING",
            Self::Ready => "READY",
            Self::Failed(_) => "FAILED",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofsTab {
    Mine,
    Verify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsTab {
    Secret,
    Node,
    Network,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretImportMode {
    Raw,
    Photo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Present,
    Proofs,
    Mine,
    Explorer,
    Settings,
}

#[derive(Debug, Clone)]
pub struct AppSnapshot {
    pub network: NetworkSnapshot,
    pub addresses: Vec<AddressSnapshot>,
    pub active_address: usize,
    pub segments: Vec<SegmentSnapshot>,
    pub utxos: Vec<UtxoSnapshot>,
    pub mining: MiningSnapshot,
    pub mined_blocks: MinedBlocksSnapshot,
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
    pub live_count: u64,
    pub capacity: u64,
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
    pub ready: bool,
    pub isolated: bool,
    pub confirmed_peers: usize,
    pub required_peers: usize,
    pub selected_threads: usize,
    pub available_threads: usize,
}

#[derive(Debug, Clone)]
pub struct MinedBlocksSnapshot {
    pub page: u32,
    pub total: usize,
    pub total_pages: u32,
    pub blocks: Vec<MinedBlockSnapshot>,
}

#[derive(Debug, Clone)]
pub struct ReceiptsSnapshot {
    pub page: u32,
    pub total: usize,
    pub total_pages: u32,
    pub receipts: Vec<ReceiptSnapshot>,
}

impl ReceiptsSnapshot {
    pub fn empty() -> Self {
        Self {
            page: 1,
            total: 0,
            total_pages: 0,
            receipts: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReceiptSnapshot {
    pub txid: String,
    pub height: u64,
    pub timestamp: u64,
    pub amount_micronoid: u64,
    pub fee_micronoid: u64,
    pub peer_address: Option<String>,
    pub own_address: Option<String>,
    pub own_key_index: Option<u32>,
    pub input_count: usize,
    pub output_count: usize,
    pub receipt_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct ReceiptDetailSnapshot {
    pub receipt_hex: String,
    pub verification: ReceiptVerificationSnapshot,
}

#[derive(Debug, Clone)]
pub struct ReceiptVerificationSnapshot {
    pub merkle_valid: bool,
    pub canonical: bool,
    pub confirmed: bool,
    pub error: Option<String>,
    pub authenticated_summary: Option<ReceiptSummarySnapshot>,
}

#[derive(Debug, Clone)]
pub struct ReceiptSummarySnapshot {
    pub txid: String,
    pub claimed_height: u64,
    pub confirmed_unix: u64,
    pub tx_index: u16,
    pub tx_count: u16,
    pub fee_micronoid: u64,
    pub inputs: Vec<ReceiptInputSnapshot>,
    pub outputs: Vec<ReceiptOutputSnapshot>,
}

#[derive(Debug, Clone)]
pub struct ReceiptInputSnapshot {
    pub slot_index: u32,
    pub owner: String,
}

#[derive(Debug, Clone)]
pub struct ReceiptOutputSnapshot {
    pub slot_index: u32,
    pub amount_micronoid: u64,
    pub owner: String,
}

impl MinedBlocksSnapshot {
    pub fn empty() -> Self {
        Self {
            page: 1,
            total: 0,
            total_pages: 0,
            blocks: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MinedBlockSnapshot {
    pub height: u64,
    pub block_hash: String,
    pub timestamp: u64,
    pub reward_micronoid: u64,
    pub payout_key_index: u32,
    pub confirmations: u64,
    pub full_block_available: bool,
}

impl MinedBlockSnapshot {
    pub fn reward(&self) -> String {
        format_micronoid(self.reward_micronoid)
    }

    pub fn short_hash(&self) -> String {
        if self.block_hash.len() <= 20 {
            return self.block_hash.clone();
        }
        format!(
            "{}…{}",
            &self.block_hash[..11],
            &self.block_hash[self.block_hash.len() - 7..]
        )
    }
}

#[derive(Debug, Clone)]
pub struct BlockDetailsSnapshot {
    pub header: BlockHeaderSnapshot,
    pub retained: Option<RetainedBlockSnapshot>,
}

#[derive(Debug, Clone)]
pub struct BlockHeaderSnapshot {
    pub height: u64,
    pub hash: String,
    pub prev_hash: String,
    pub state_root: String,
    pub tx_root: String,
    pub timestamp: u64,
    pub miner: String,
    pub nonce_hex: String,
    pub difficulty_target: String,
    pub log_slots: u32,
    pub active_slot_count: u64,
    pub alloc_counter: u64,
}

#[derive(Debug, Clone)]
pub struct RetainedBlockSnapshot {
    pub proof_class: String,
    pub logical_transactions: u16,
    pub user_pages: u16,
    pub live_inputs: u16,
    pub live_outputs: u16,
    pub reward_micronoid: u64,
    pub total_fees_micronoid: String,
    pub block_bytes: u64,
    pub history_step_bytes: u64,
    pub bundle_bytes: u64,
    pub transactions: Vec<BlockTransactionSnapshot>,
}

#[derive(Debug, Clone)]
pub struct BlockTransactionSnapshot {
    pub position: u16,
    pub txid: String,
    pub page_count: u16,
    pub live_inputs: u16,
    pub live_outputs: u16,
    pub fee_micronoid: u64,
    pub coinbase: bool,
    pub epoch_anchor: String,
    pub input_owner: Option<String>,
    pub input_sum_micronoid: String,
    pub output_sum_micronoid: String,
    pub page_hashes: Vec<String>,
    pub inputs: Vec<BlockTransactionInputSnapshot>,
    pub outputs: Vec<BlockTransactionOutputSnapshot>,
}

#[derive(Debug, Clone)]
pub struct BlockTransactionInputSnapshot {
    pub page: u16,
    pub lane: u8,
    pub slot_index: u32,
    pub amount_micronoid: u64,
    pub creation_id: u64,
}

#[derive(Debug, Clone)]
pub struct BlockTransactionOutputSnapshot {
    pub page: u16,
    pub lane: u8,
    pub slot_index: u32,
    pub amount_micronoid: u64,
    pub owner: String,
    pub creation_id: u64,
}

#[derive(Debug, Clone)]
pub struct ExplorerSnapshot {
    pub tip_height: u64,
    pub block_page: u32,
    pub block_total_pages: u32,
    pub blocks: Vec<ExplorerBlockSnapshot>,
    pub recent_transactions: RecentTransactionsSnapshot,
}

impl ExplorerSnapshot {
    pub fn empty() -> Self {
        Self {
            tip_height: 0,
            block_page: 1,
            block_total_pages: 0,
            blocks: Vec::new(),
            recent_transactions: RecentTransactionsSnapshot::empty(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExplorerBlockSnapshot {
    pub header: BlockHeaderSnapshot,
    pub confirmations: u64,
    pub full_block_available: bool,
}

#[derive(Debug, Clone)]
pub struct RecentTransactionsSnapshot {
    pub page: u32,
    pub total: usize,
    pub total_pages: u32,
    pub tip_height: u64,
    pub retained_from_height: u64,
    pub transactions: Vec<RecentTransactionSnapshot>,
}

impl RecentTransactionsSnapshot {
    pub fn empty() -> Self {
        Self {
            page: 1,
            total: 0,
            total_pages: 0,
            tip_height: 0,
            retained_from_height: 0,
            transactions: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RecentTransactionSnapshot {
    pub height: u64,
    pub timestamp: u64,
    pub position: u16,
    pub txid: String,
    pub live_inputs: u16,
    pub live_outputs: u16,
    pub fee_micronoid: u64,
    pub coinbase: bool,
    pub address_spent_micronoid: Option<String>,
    pub address_received_micronoid: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ExplorerSlotSnapshot {
    pub slot_index: u32,
    pub value_micronoid: u64,
    pub creation_id: u64,
    pub owner: String,
    pub empty: bool,
}

#[derive(Debug, Clone)]
pub struct ExplorerAddressSnapshot {
    pub address: String,
    pub balance_micronoid: u128,
    pub slots: Vec<ExplorerSlotSnapshot>,
    pub recent_transactions: RecentTransactionsSnapshot,
}

#[derive(Debug, Clone)]
pub enum ExplorerSearchResultSnapshot {
    Address(ExplorerAddressSnapshot),
    Slot(ExplorerSlotSnapshot),
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

    pub fn set_preview_mining_page(&mut self, page: u32) {
        self.mined_blocks = preview_mined_blocks(page);
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
                    live_count: 0,
                    capacity: 1 << 16,
                    owned: false,
                };
                256
            ],
            utxos: Vec::new(),
            mining: MiningSnapshot {
                enabled: false,
                ready: false,
                isolated: false,
                confirmed_peers: 0,
                required_peers: 2,
                selected_threads: available_threads,
                available_threads,
            },
            mined_blocks: MinedBlocksSnapshot::empty(),
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
                let occupancy = if matches!(index, 28 | 73 | 119 | 164 | 213) {
                    occupancy.max(0.04)
                } else {
                    occupancy
                };
                SegmentSnapshot {
                    occupancy,
                    live_count: (occupancy * (1u64 << 16) as f32).round() as u64,
                    capacity: 1 << 16,
                    owned: matches!(index, 28 | 73 | 119 | 164 | 213),
                }
            })
            .collect();

        let owned_segments = [28u8, 73, 119, 164, 213];
        let base_value = PREVIEW_BALANCE_MICRONOID / PREVIEW_UTXO_COUNT as u64;
        let remainder = PREVIEW_BALANCE_MICRONOID % PREVIEW_UTXO_COUNT as u64;
        let utxos = (0..PREVIEW_UTXO_COUNT)
            .rev()
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
                address: "o12p4r8dl49ys3462zrqqys5vz8ll8m93su6lc70wu7rrwg3nn7fgsd7jnnt".into(),
                label: "Main".into(),
                balance_micronoid: PREVIEW_BALANCE_MICRONOID,
                utxo_count: PREVIEW_UTXO_COUNT,
                reserved_utxo_count: 0,
                pending_outbound_micronoid: 100_000_000_000,
                incoming_micronoid: 100_000_000_000,
            },
            AddressSnapshot {
                key_index: 1,
                address: "o17z7pfmh09rjztwga8y9pzpy05ncznl5teqe23a48d0sumjcnrlaszlk2vj".into(),
                label: "Savings".into(),
                balance_micronoid: 312_000_000,
                utxo_count: 6,
                reserved_utxo_count: 0,
                pending_outbound_micronoid: 0,
                incoming_micronoid: 0,
            },
            AddressSnapshot {
                key_index: 2,
                address: "o1ajnpfqtpkpugpwvpgjtkhk432fhd86l6vnvurgzn97hmvpcldpesewn8k6".into(),
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
                address: format!(
                    "o1q{key_index:02}n7k4v9s2p8m5x3d6ta0er4wh1yc5j7l9u3g6b2n8k5p4mc7x9m2qadc"
                ),
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
                ready: false,
                isolated: false,
                confirmed_peers: 12,
                required_peers: 2,
                selected_threads: 12,
                available_threads: 12,
            },
            mined_blocks: preview_mined_blocks(1),
        }
    }
}

fn preview_mined_blocks(page: u32) -> MinedBlocksSnapshot {
    const TOTAL: usize = 23;
    let total_pages = (TOTAL as u32).div_ceil(MINED_BLOCK_PAGE_SIZE);
    let page = page.clamp(1, total_pages);
    let offset = (page - 1) * MINED_BLOCK_PAGE_SIZE;
    let count = MINED_BLOCK_PAGE_SIZE.min(TOTAL as u32 - offset);
    let blocks = (0..count)
        .map(|row| {
            let index = offset + row;
            let height = 18_420 - u64::from(index);
            let confirmations = u64::from(index) + 1;
            MinedBlockSnapshot {
                height,
                block_hash: format!("{:064x}", 0xa94f_2c77_18d9_5063u64.wrapping_add(height)),
                timestamp: 1_784_732_200u64.saturating_sub(u64::from(index) * 15),
                reward_micronoid: 50_000_000,
                payout_key_index: 0,
                confirmations,
                full_block_available: confirmations <= 18,
            }
        })
        .collect();
    MinedBlocksSnapshot {
        page,
        total: TOTAL,
        total_pages,
        blocks,
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

/// Human-readable form of the consensus creation-id namespaces.
///
/// The high bit tags a coinbase output and the remaining bits encode its
/// block height. Ordinary outputs use the monotone output-id namespace.
pub fn format_creation_origin(creation_id: u64) -> String {
    const COINBASE_TAG: u64 = 1 << 63;

    if creation_id & COINBASE_TAG != 0 {
        format!("CB #{}", creation_id & !COINBASE_TAG)
    } else {
        format!("OUT #{creation_id}")
    }
}

pub fn format_micronoid(value: u64) -> String {
    let whole = value / 1_000_000;
    let fractional = value % 1_000_000;
    format!("{whole}.{fractional:06}")
}

#[cfg(test)]
mod tests {
    use super::{format_creation_origin, AppSnapshot, SensitiveString};

    #[test]
    fn formats_creation_id_namespaces_semantically() {
        assert_eq!(format_creation_origin(4), "OUT #4");
        assert_eq!(format_creation_origin((1 << 63) | 1), "CB #1");
    }

    #[test]
    fn sensitive_strings_are_redacted_and_explicitly_cleared() {
        let secret = "11".repeat(32);
        let mut value = SensitiveString::new(secret.clone());

        let debug = format!("{value:?}");
        assert!(!debug.contains(&secret));
        assert_eq!(debug, "SensitiveString(<redacted>)");

        value.clear();
        assert!(value.is_empty());
    }

    #[test]
    fn preview_address_creation_does_not_change_the_active_owner() {
        let mut snapshot = AppSnapshot::design_preview();
        let active_index = snapshot.active_address;
        let active_key_index = snapshot.active_address().key_index;
        let utxo_slots = snapshot
            .utxos
            .iter()
            .map(|utxo| utxo.slot_index)
            .collect::<Vec<_>>();
        let address_count = snapshot.addresses.len();

        snapshot.create_preview_address();

        assert_eq!(snapshot.addresses.len(), address_count + 1);
        assert_eq!(snapshot.active_address, active_index);
        assert_eq!(snapshot.active_address().key_index, active_key_index);
        assert_eq!(
            snapshot
                .utxos
                .iter()
                .map(|utxo| utxo.slot_index)
                .collect::<Vec<_>>(),
            utxo_slots
        );
    }

    #[test]
    fn preview_addresses_match_the_canonical_display_width() {
        let snapshot = AppSnapshot::design_preview();
        assert!(snapshot
            .addresses
            .iter()
            .all(|address| address.address.chars().count() == 60));
    }
}
