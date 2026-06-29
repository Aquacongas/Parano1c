// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.
//! JSON-RPC trait definition (generated server + client traits via proc macro).

use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;

use crate::types::{
    AddressInfo, BlockHeaderInfo, BlockTemplateResponse, ChainInfo, FeeEstimate, MempoolInfo,
    MiningInfo, ReceiptVerifyResult, SlotInfo, StateInfo, TxInfo, WalletAddressInfo, WalletBalance,
    WalletConsolidatePlan, WalletHistoryEntry, WalletScanResult, WalletSendPlan, WalletSendResult,
    WalletStatus, WalletUtxoInfo,
};

#[rpc(server, namespace = "paranoid")]
pub trait ParanoidApi {
    // =========================================================================
    // Chain
    // =========================================================================

    /// Current tip height.
    #[method(name = "blockCount")]
    async fn block_count(&self) -> RpcResult<u64>;

    /// Chain tip summary: height, hash, difficulty, active UTXOs.
    #[method(name = "getChainInfo")]
    async fn get_chain_info(&self) -> RpcResult<ChainInfo>;

    /// H_BLOCK hash of the block at `height` (hex, no 0x prefix).
    /// Stored forever. Returns null if height > tip.
    #[method(name = "getBlockHash")]
    async fn get_block_hash(&self, height: u64) -> RpcResult<Option<String>>;

    /// Decoded block header at `height`. All fields as typed values.
    /// Stored forever.
    #[method(name = "getBlockHeader")]
    async fn get_block_header(&self, height: u64) -> RpcResult<Option<BlockHeaderInfo>>;

    /// Raw 212-byte block header hex at `height` (for developers).
    #[method(name = "getHeaderByHeight")]
    async fn get_header_by_height(&self, height: u64) -> RpcResult<Option<String>>;

    /// Raw 212-byte block header hex by H_BLOCK hash.
    #[method(name = "getHeaderByHash")]
    async fn get_header_by_hash(&self, hash: String) -> RpcResult<Option<String>>;

    /// Current constant-size history proof envelope, if the local finalized cache is ready.
    /// Snapshot authority remains fail-closed until the trustless verifier is active.
    #[method(name = "getHistoryProof")]
    async fn get_history_proof(&self) -> RpcResult<Option<String>>;

    /// UTXO slot contents by index.
    #[method(name = "getSlot")]
    async fn get_slot(&self, slot_index: u32) -> RpcResult<SlotInfo>;

    /// All live UTXO slots owned by `address` (bech32m).
    /// Uses the persistent owner index — O(1) lookup.
    #[method(name = "getSlotsByOwner")]
    async fn get_slots_by_owner(&self, address: String) -> RpcResult<Vec<SlotInfo>>;

    /// Total live UTXO count.
    #[method(name = "getActiveSlotCount")]
    async fn get_active_slot_count(&self) -> RpcResult<u64>;

    /// Full state dimensions: capacity, fill %, bytes on disk, expansion headroom.
    #[method(name = "getStateInfo")]
    async fn get_state_info(&self) -> RpcResult<StateInfo>;

    /// Confirmed transaction info by tx_body_hash. Uses the permanent tx index.
    /// Returns null if hash is unknown (not yet confirmed or never submitted).
    #[method(name = "getTx")]
    async fn get_tx(&self, txhash: String) -> RpcResult<Option<TxInfo>>;

    /// Full block (header + transactions) at `height`, as hex.
    /// Only retained recent blocks are served; older block bodies are pruned.
    #[method(name = "getBlock")]
    async fn get_block(&self, height: u64) -> RpcResult<Option<String>>;

    // =========================================================================
    // Network / mining
    // =========================================================================

    /// Mining and network state: difficulty, block reward, local history-cache height.
    #[method(name = "getMiningInfo")]
    async fn get_mining_info(&self) -> RpcResult<MiningInfo>;

    /// Number of currently connected P2P peers.
    #[method(name = "getPeerCount")]
    async fn get_peer_count(&self) -> RpcResult<usize>;

    /// Estimated minimum fee in μNOID for a transaction with `n_outputs` outputs.
    /// Simple u64 method: assumes one live input.
    #[method(name = "estimateFee")]
    async fn estimate_fee(&self, n_outputs: u32) -> RpcResult<u64>;

    /// Detailed shape-aware fee estimate for explicit live input/output counts.
    #[method(name = "estimateFeeDetailed")]
    async fn estimate_fee_detailed(&self, n_inputs: u32, n_outputs: u32) -> RpcResult<FeeEstimate>;

    // =========================================================================
    // Utilities
    // =========================================================================

    /// Validate and normalise an address (bech32m).
    /// Returns the canonical bech32m form on success.
    #[method(name = "validateAddress")]
    async fn validate_address(&self, address: String) -> RpcResult<AddressInfo>;

    /// Candidate empty slot indices for transaction outputs.
    ///
    /// Uses node-local entropy in addition to the tip state so concurrent callers
    /// are unlikely to receive identical hints.
    #[method(name = "getSlotHints")]
    async fn get_slot_hints(&self, count: u32) -> RpcResult<Vec<u32>>;

    /// Candidate empty slot indices salted by wallet/request entropy.
    ///
    /// `salt_hex` can be any caller-chosen bytes encoded as hex (for example a
    /// wallet address plus a random nonce). Different salts on the same tip produce
    /// different hint streams across nodes without creating global reservations.
    #[method(name = "getSlotHintsSalted")]
    async fn get_slot_hints_salted(&self, count: u32, salt_hex: String) -> RpcResult<Vec<u32>>;

    /// Current epoch anchor hash (use as `epoch_anchor` when building transactions).
    #[method(name = "getEpochAnchor")]
    async fn get_epoch_anchor(&self) -> RpcResult<String>;

    /// Submit a raw `TxIntent` (transaction + WalletAuthorizationBundle) to the mempool.
    #[method(name = "submitTxIntent")]
    async fn submit_tx_intent(&self, hex: String) -> RpcResult<String>;

    // =========================================================================
    // Mempool
    // =========================================================================

    /// Full mempool state: count, fee floor, list of pending transactions.
    #[method(name = "getMempoolInfo")]
    async fn get_mempool_info(&self) -> RpcResult<MempoolInfo>;

    /// Pending transaction count (lighter than getMempoolInfo).
    #[method(name = "getMempoolSize")]
    async fn get_mempool_size(&self) -> RpcResult<usize>;

    /// Single pending transaction by hash. Returns null if not in mempool.
    #[method(name = "getMempoolEntry")]
    async fn get_mempool_entry(
        &self,
        txhash: String,
    ) -> RpcResult<Option<crate::types::MempoolTxInfo>>;

    // =========================================================================
    // Receipt
    // =========================================================================

    /// Verify a Merkle payment receipt against the canonical chain.
    #[method(name = "verifyReceipt")]
    async fn verify_receipt(&self, receipt_hex: String) -> RpcResult<ReceiptVerifyResult>;

    // =========================================================================
    // Mining (external miner API)
    // =========================================================================

    /// Get a PoW block template for an external miner.
    #[method(name = "getBlockTemplate")]
    async fn get_block_template(&self, miner_address: String) -> RpcResult<BlockTemplateResponse>;

    /// Submit a solved block plus serialized BlockProof/AuthSidecar bytes.
    /// `block_proof_hex` and `block_auth_sidecar_hex` are empty for coinbase-only blocks.
    #[method(name = "submitBlock")]
    async fn submit_block(
        &self,
        block_hex: String,
        block_proof_hex: String,
        block_auth_sidecar_hex: String,
    ) -> RpcResult<String>;

    // =========================================================================
    // Node control
    // =========================================================================

    /// Gracefully stop the paranoid daemon.
    #[method(name = "stop")]
    async fn stop(&self) -> RpcResult<String>;

    // =========================================================================
    // Wallet RPC methods (noid_walletXxx namespace preserved via method name)
    // =========================================================================

    /// Get wallet status: address, balance, UTXO count.
    #[method(name = "walletStatus")]
    async fn wallet_status(&self) -> RpcResult<WalletStatus>;

    /// Get the address at key index `index`.
    #[method(name = "walletGetAddress")]
    async fn wallet_get_address(&self, index: u32) -> RpcResult<String>;

    /// Get balance breakdown.
    #[method(name = "walletGetBalance")]
    async fn wallet_get_balance(&self) -> RpcResult<WalletBalance>;

    /// List all confirmed UTXOs.
    #[method(name = "walletListUtxos")]
    async fn wallet_list_utxos(&self) -> RpcResult<Vec<WalletUtxoInfo>>;

    /// Transaction history (most recent last).
    #[method(name = "walletHistory")]
    async fn wallet_history(&self) -> RpcResult<Vec<WalletHistoryEntry>>;

    /// Full rescan of the chain state for wallet UTXOs.
    /// WARNING: may take a few seconds on large state.
    #[method(name = "walletScan")]
    async fn wallet_scan(&self) -> RpcResult<WalletScanResult>;

    /// Dry-run wallet send planning without proving or submitting.
    /// `fee_micronoid = 0` uses automatic per-chunk minimum relay fee.
    #[method(name = "walletPlanSend")]
    async fn wallet_plan_send(
        &self,
        to_hex: String,
        amount_micronoid: u64,
        fee_micronoid: u64,
    ) -> RpcResult<WalletSendPlan>;

    /// Send NOID to a recipient address.
    /// `to_hex`: 32-byte recipient address as hex.
    /// `amount_micronoid`: amount in μNOID.
    /// `fee_micronoid`: transaction fee in μNOID (0 = use automatic per-chunk minimum).
    #[method(name = "walletSend")]
    async fn wallet_send(
        &self,
        to_hex: String,
        amount_micronoid: u64,
        fee_micronoid: u64,
    ) -> RpcResult<WalletSendResult>;

    /// Export a receipt for a confirmed transaction (hex-encoded bytes).
    #[method(name = "walletExportReceipt")]
    async fn wallet_export_receipt(&self, txhash_hex: String) -> RpcResult<String>;

    /// Dry-run one consolidation round without proving or submitting.
    /// `fee_micronoid = 0` uses automatic shape-aware minimum relay fee.
    #[method(name = "walletPlanConsolidate")]
    async fn wallet_plan_consolidate(&self, fee_micronoid: u64)
        -> RpcResult<WalletConsolidatePlan>;

    /// Consolidate small UTXOs into one larger UTXO (up to `Sweep25x2` capacity).
    /// Returns tx_hash of the submitted consolidation transaction.
    /// Returns an error if the wallet has 1 or fewer available UTXOs, or insufficient funds.
    /// `fee_micronoid = 0` uses a shape-aware automatic fee for the selected inputs.
    #[method(name = "walletConsolidate")]
    async fn wallet_consolidate(&self, fee_micronoid: u64) -> RpcResult<WalletSendResult>;

    /// Derive and return the next fresh address (increments the internal index).
    /// Use this to get a unique address for each incoming payment.
    #[method(name = "walletNextAddress")]
    async fn wallet_next_address(&self) -> RpcResult<WalletAddressInfo>;

    /// List all addresses that have ever had activity (UTXOs or history),
    /// plus the next fresh address. Shows per-address balance.
    #[method(name = "walletListAddresses")]
    async fn wallet_list_addresses(&self) -> RpcResult<Vec<WalletAddressInfo>>;
}
