// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.
//! JSON-RPC trait definition (generated server + client traits via proc macro).

use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;

use crate::types::{
    BlockTemplateResponse, ChainInfo, MempoolInfo, ReceiptVerifyResult, SlotInfo, WalletBalance,
    WalletHistoryEntry, WalletScanResult, WalletSendResult, WalletStatus, WalletUtxoInfo,
};

#[rpc(server, namespace = "paranoid")]
pub trait ParanoidApi {
    // --- Chain state (always available) ---

    #[method(name = "blockCount")]
    fn block_count(&self) -> RpcResult<u64>;

    #[method(name = "getChainInfo")]
    fn get_chain_info(&self) -> RpcResult<ChainInfo>;

    #[method(name = "getHeaderByHeight")]
    fn get_header_by_height(&self, height: u64) -> RpcResult<Option<String>>;

    #[method(name = "getHeaderByHash")]
    fn get_header_by_hash(&self, hash: String) -> RpcResult<Option<String>>;

    #[method(name = "getRecursiveProof")]
    fn get_recursive_proof(&self) -> RpcResult<Option<String>>;

    #[method(name = "getSlot")]
    fn get_slot(&self, slot_index: u32) -> RpcResult<SlotInfo>;

    #[method(name = "getActiveSlotCount")]
    fn get_active_slot_count(&self) -> RpcResult<u64>;

    // --- Recent blocks (last 18 only) ---

    #[method(name = "getBlock")]
    fn get_block(&self, height: u64) -> RpcResult<Option<String>>;

    // --- Wallet support ---

    #[method(name = "getSlotHints")]
    fn get_slot_hints(&self, count: u32) -> RpcResult<Vec<u32>>;

    #[method(name = "getEpochAnchor")]
    fn get_epoch_anchor(&self) -> RpcResult<String>;

    #[method(name = "submitTxIntent")]
    async fn submit_tx_intent(&self, hex: String) -> RpcResult<String>;

    // --- Node control ---

    /// Gracefully stop the daemon. Cancels the miner, closes the RPC server,
    /// and flushes MDBX. Equivalent to Ctrl-C but callable via RPC or CLI.
    #[method(name = "stop")]
    fn stop(&self) -> RpcResult<String>;

    // --- Mempool ---

    /// Get summary of all pending transactions in the mempool.
    #[method(name = "getMempoolInfo")]
    fn get_mempool_info(&self) -> RpcResult<MempoolInfo>;

    /// Get count of pending transactions.
    #[method(name = "getMempoolSize")]
    fn get_mempool_size(&self) -> RpcResult<usize>;

    // --- Receipt ---

    #[method(name = "verifyReceipt")]
    fn verify_receipt(&self, receipt_hex: String) -> RpcResult<ReceiptVerifyResult>;

    // --- Mining ---

    #[method(name = "getBlockTemplate")]
    async fn get_block_template(&self, miner_address: String) -> RpcResult<BlockTemplateResponse>;

    #[method(name = "submitBlock")]
    async fn submit_block(&self, block_hex: String) -> RpcResult<String>;

    // =========================================================================
    // Wallet RPC methods (noid_walletXxx namespace preserved via method name)
    // =========================================================================

    /// Get wallet status: address, balance, UTXO count.
    #[method(name = "walletStatus")]
    fn wallet_status(&self) -> RpcResult<WalletStatus>;

    /// Get the address at key index `index`.
    #[method(name = "walletGetAddress")]
    fn wallet_get_address(&self, index: u32) -> RpcResult<String>;

    /// Get balance breakdown.
    #[method(name = "walletGetBalance")]
    fn wallet_get_balance(&self) -> RpcResult<WalletBalance>;

    /// List all confirmed UTXOs.
    #[method(name = "walletListUtxos")]
    fn wallet_list_utxos(&self) -> RpcResult<Vec<WalletUtxoInfo>>;

    /// Transaction history (most recent last).
    #[method(name = "walletHistory")]
    fn wallet_history(&self) -> RpcResult<Vec<WalletHistoryEntry>>;

    /// Full rescan of the chain state for wallet UTXOs.
    /// WARNING: may take a few seconds on large state.
    #[method(name = "walletScan")]
    fn wallet_scan(&self) -> RpcResult<WalletScanResult>;

    /// Send NOID to a recipient address.
    /// `to_hex`: 32-byte recipient address as hex.
    /// `amount_micronoid`: amount in μNOID.
    /// `fee_micronoid`: transaction fee in μNOID (0 = use minimum).
    #[method(name = "walletSend")]
    async fn wallet_send(
        &self,
        to_hex: String,
        amount_micronoid: u64,
        fee_micronoid: u64,
    ) -> RpcResult<WalletSendResult>;

    /// Export a receipt for a confirmed transaction (hex-encoded bytes).
    #[method(name = "walletExportReceipt")]
    fn wallet_export_receipt(&self, txhash_hex: String) -> RpcResult<String>;

    /// Consolidate small UTXOs into one larger UTXO (reduces UTXO count by up to 3).
    /// Returns tx_hash of the submitted consolidation transaction.
    /// Returns an error if the wallet has 1 or fewer UTXOs, or insufficient funds.
    /// `fee_micronoid = 0` uses the minimum fee (5000 μNOID).
    #[method(name = "walletConsolidate")]
    async fn wallet_consolidate(&self, fee_micronoid: u64) -> RpcResult<WalletSendResult>;
}
