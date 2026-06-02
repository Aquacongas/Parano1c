// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.
//! noid-cli — Paranoid thin client.
//!
//! Connects to a running `paranoid` daemon via JSON-RPC.
//! No keys, no crypto — all operations happen in the daemon.

use anyhow::Context;
use clap::{Parser, Subcommand};
use serde_json::Value;

/// μNOID per 1 NOID (6 decimal places).
const MICRONOID_PER_NOID: f64 = 1_000_000.0;

// ---------------------------------------------------------------------------
// CLI structure
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "noid-cli",
    about = "Paranoid thin client — connects to a running paranoid daemon via JSON-RPC",
    version = env!("CARGO_PKG_VERSION"),
    long_about = None,
)]
struct Cli {
    /// JSON-RPC endpoint URL.
    #[arg(long, default_value = "http://127.0.0.1:9401")]
    rpc: String,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Node / chain commands.
    Node {
        #[command(subcommand)]
        action: NodeCmd,
    },
    /// Wallet commands (all executed inside the daemon).
    Wallet {
        #[command(subcommand)]
        action: WalletCmd,
    },
}

#[derive(Subcommand)]
enum NodeCmd {
    /// Print chain info: height, best hash, difficulty, and slot counts.
    Status,
    /// Print mempool state: pending transaction count, fee floor, and tx list.
    Mempool,
}

#[derive(Subcommand)]
enum WalletCmd {
    /// Print the wallet address at key index N.
    Address {
        #[arg(long, default_value_t = 0)]
        index: u32,
    },
    /// Print wallet balance and UTXO count.
    Balance,
    /// Send μNOID to an address.
    Send {
        /// Recipient address (32-byte hex, 64 characters).
        to: String,
        /// Amount to send in μNOID (1 NOID = 1,000,000 μNOID).
        amount: u64,
        /// Transaction fee in μNOID (default: 5000 = MIN_FEE_BASE).
        #[arg(long, default_value_t = 5_000)]
        fee: u64,
    },
    /// Print transaction history.
    History,
    /// List all confirmed UTXOs owned by the wallet.
    Utxos,
    /// Rescan the full chain state for wallet UTXOs.
    Scan,
    /// Export a receipt (hex) for a confirmed transaction and print to stdout.
    Receipt {
        /// Transaction hash (hex).
        txhash: String,
    },
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Reuse a single HTTP client for connection pooling.
    let client = reqwest::Client::builder()
        .user_agent(concat!("noid-cli/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("build HTTP client")?;

    match cli.cmd {
        Command::Node { action } => match action {
            NodeCmd::Status => cmd_node_status(&client, &cli.rpc).await?,
            NodeCmd::Mempool => cmd_node_mempool(&client, &cli.rpc).await?,
        },
        Command::Wallet { action } => match action {
            WalletCmd::Address { index } => cmd_wallet_address(&client, &cli.rpc, index).await?,
            WalletCmd::Balance => cmd_wallet_balance(&client, &cli.rpc).await?,
            WalletCmd::Send { to, amount, fee } => {
                cmd_wallet_send(&client, &cli.rpc, &to, amount, fee).await?
            }
            WalletCmd::History => cmd_wallet_history(&client, &cli.rpc).await?,
            WalletCmd::Utxos => cmd_wallet_utxos(&client, &cli.rpc).await?,
            WalletCmd::Scan => cmd_wallet_scan(&client, &cli.rpc).await?,
            WalletCmd::Receipt { txhash } => cmd_wallet_receipt(&client, &cli.rpc, &txhash).await?,
        },
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Subcommand handlers
// ---------------------------------------------------------------------------

async fn cmd_node_status(client: &reqwest::Client, rpc_url: &str) -> anyhow::Result<()> {
    let result = rpc_call(
        client,
        rpc_url,
        "paranoid_getChainInfo",
        serde_json::json!([]),
    )
    .await
    .context("paranoid_getChainInfo")?;

    let height = result["height"].as_u64().unwrap_or(0);
    let best_hash = result["best_hash"].as_str().unwrap_or("?");
    let difficulty = result["difficulty_target"].as_str().unwrap_or("?");
    let active_slots = result["active_slot_count"].as_u64().unwrap_or(0);
    let log_slots = result["log_slots"].as_u64().unwrap_or(0);

    println!("node status:");
    println!("  Height:       {height}");
    println!("  Best hash:    0x{best_hash}");
    println!("  Difficulty:   0x{difficulty}");
    println!("  Active slots: {active_slots}");
    println!("  Log slots:    {log_slots}");

    Ok(())
}

async fn cmd_node_mempool(client: &reqwest::Client, rpc_url: &str) -> anyhow::Result<()> {
    let result = rpc_call(
        client,
        rpc_url,
        "paranoid_getMempoolInfo",
        serde_json::json!([]),
    )
    .await
    .context("paranoid_getMempoolInfo")?;

    let size = result["size"].as_u64().unwrap_or(0);
    let fee_floor = result["fee_floor"].as_u64().unwrap_or(0);
    let txs = result["txs"].as_array().cloned().unwrap_or_default();

    println!("mempool:");
    println!("  Pending txs:  {size}");
    println!(
        "  Fee floor:    {} NOID ({fee_floor} \u{03bc}NOID)",
        fee_floor as f64 / MICRONOID_PER_NOID
    );
    if txs.is_empty() {
        println!("  (empty)");
    } else {
        println!(
            "  {:<66}  {:>12}  {:>4}  {:>4}  {}",
            "tx_hash", "fee (\u{03bc}NOID)", "in", "out", "proof"
        );
        println!("  {}", "-".repeat(100));
        for tx in &txs {
            let hash = tx["tx_hash"].as_str().unwrap_or("?");
            let fee = tx["fee_micronoid"].as_u64().unwrap_or(0);
            let nin = tx["n_inputs"].as_u64().unwrap_or(0);
            let nout = tx["n_outputs"].as_u64().unwrap_or(0);
            let proof = if tx["has_proof"].as_bool().unwrap_or(false) {
                "\u{2713}"
            } else {
                "\u{00b7}"
            };
            println!(
                "  0x{:<64}  {:>12}  {:>4}  {:>4}  {}",
                &hash[..hash.len().min(64)],
                fee,
                nin,
                nout,
                proof
            );
        }
    }

    Ok(())
}

async fn cmd_wallet_address(
    client: &reqwest::Client,
    rpc_url: &str,
    index: u32,
) -> anyhow::Result<()> {
    let result = rpc_call(
        client,
        rpc_url,
        "paranoid_walletGetAddress",
        serde_json::json!([index]),
    )
    .await
    .context("paranoid_walletGetAddress")?;

    let addr = result.as_str().unwrap_or("?");

    println!("wallet address [index={index}]:");
    println!("  {addr}");

    Ok(())
}

async fn cmd_wallet_balance(client: &reqwest::Client, rpc_url: &str) -> anyhow::Result<()> {
    let result = rpc_call(
        client,
        rpc_url,
        "paranoid_walletGetBalance",
        serde_json::json!([]),
    )
    .await
    .context("paranoid_walletGetBalance")?;

    let micronoid = result["total_micronoid"].as_u64().unwrap_or(0);
    let utxo_count = result["utxo_count"].as_u64().unwrap_or(0);
    let noid = micronoid as f64 / MICRONOID_PER_NOID;

    println!("wallet balance:");
    println!("  Balance: {noid:.6} NOID ({micronoid} μNOID)");
    println!("  UTXOs:   {utxo_count}");

    Ok(())
}

async fn cmd_wallet_send(
    client: &reqwest::Client,
    rpc_url: &str,
    to: &str,
    amount: u64,
    fee: u64,
) -> anyhow::Result<()> {
    let result = rpc_call(
        client,
        rpc_url,
        "paranoid_walletSend",
        serde_json::json!([to, amount, fee]),
    )
    .await
    .context("paranoid_walletSend")?;

    let tx_hash = result["tx_hash"].as_str().unwrap_or("?");
    let noid = amount as f64 / MICRONOID_PER_NOID;
    let fee_noid = fee as f64 / MICRONOID_PER_NOID;

    println!("wallet send:");
    println!("  Submitted! tx_hash: 0x{tx_hash}");
    println!("  To:     {to}");
    println!("  Amount: {noid:.6} NOID ({amount} μNOID)");
    println!("  Fee:    {fee_noid:.6} NOID ({fee} μNOID)");

    Ok(())
}

async fn cmd_wallet_history(client: &reqwest::Client, rpc_url: &str) -> anyhow::Result<()> {
    let result = rpc_call(
        client,
        rpc_url,
        "paranoid_walletHistory",
        serde_json::json!([]),
    )
    .await
    .context("paranoid_walletHistory")?;

    let entries = result.as_array().cloned().unwrap_or_default();

    println!("wallet history:");

    if entries.is_empty() {
        println!("  (no transactions)");
        return Ok(());
    }

    for (i, entry) in entries.iter().enumerate() {
        let n = i + 1;
        let height = entry["height"].as_u64().unwrap_or(0);
        let direction = entry["direction"].as_str().unwrap_or("?");
        let micronoid = entry["amount_micronoid"].as_u64().unwrap_or(0);
        let tx_hash = entry["tx_hash"].as_str().unwrap_or("?");
        let noid = micronoid as f64 / MICRONOID_PER_NOID;
        let sign = if direction == "sent" { "-" } else { "+" };

        println!(
            "  #{n:<3} height={height:<6} {direction:<8} {sign}{noid:.6} NOID  (tx: 0x{tx_hash})"
        );
    }

    Ok(())
}

async fn cmd_wallet_utxos(client: &reqwest::Client, rpc_url: &str) -> anyhow::Result<()> {
    let result = rpc_call(
        client,
        rpc_url,
        "paranoid_walletListUtxos",
        serde_json::json!([]),
    )
    .await
    .context("paranoid_walletListUtxos")?;

    let utxos = result.as_array().cloned().unwrap_or_default();

    println!("wallet utxos:");

    if utxos.is_empty() {
        println!("  (no UTXOs)");
        return Ok(());
    }

    // Header
    println!(
        "  {:<6}  {:<14}  {:<7}  {:<8}  {}",
        "slot", "value (NOID)", "key idx", "height", "address"
    );
    println!("  {}", "-".repeat(74));

    for utxo in &utxos {
        let slot = utxo["slot_index"].as_u64().unwrap_or(0);
        let micronoid = utxo["value_micronoid"].as_u64().unwrap_or(0);
        let noid = micronoid as f64 / MICRONOID_PER_NOID;
        let key_index = utxo["key_index"].as_u64().unwrap_or(0);
        let height = utxo["confirmed_height"].as_u64().unwrap_or(0);
        let address = utxo["address"].as_str().unwrap_or("?");

        println!("  {slot:<6}  {noid:<14.6}  {key_index:<7}  {height:<8}  {address}");
    }

    Ok(())
}

async fn cmd_wallet_scan(client: &reqwest::Client, rpc_url: &str) -> anyhow::Result<()> {
    eprintln!("wallet scan: rescanning chain state (this may take a moment)...");

    let result = rpc_call(
        client,
        rpc_url,
        "paranoid_walletScan",
        serde_json::json!([]),
    )
    .await
    .context("paranoid_walletScan")?;

    let found = result["found_utxos"].as_u64().unwrap_or(0);
    let micronoid = result["balance_micronoid"].as_u64().unwrap_or(0);
    let noid = micronoid as f64 / MICRONOID_PER_NOID;

    println!("wallet scan:");
    println!("  Found UTXOs: {found}");
    println!("  Balance:     {noid:.6} NOID ({micronoid} μNOID)");

    Ok(())
}

/// Export a receipt for a confirmed transaction and write hex to stdout.
/// Pipe or redirect to a file as needed: `noid-cli wallet receipt <hash> > receipt.hex`
async fn cmd_wallet_receipt(
    client: &reqwest::Client,
    rpc_url: &str,
    txhash: &str,
) -> anyhow::Result<()> {
    let result = rpc_call(
        client,
        rpc_url,
        "paranoid_walletExportReceipt",
        serde_json::json!([txhash]),
    )
    .await
    .context("paranoid_walletExportReceipt")?;

    let hex = result
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("daemon returned non-string receipt"))?;

    // Print raw hex to stdout — caller can redirect to a file.
    println!("{hex}");

    Ok(())
}

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 helper
// ---------------------------------------------------------------------------

/// Send a JSON-RPC 2.0 request and return the `result` field.
///
/// Returns an error if the HTTP request fails, the response body cannot be
/// decoded as JSON, or the response contains a JSON-RPC `error` object.
async fn rpc_call(
    client: &reqwest::Client,
    rpc_url: &str,
    method: &str,
    params: Value,
) -> anyhow::Result<Value> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id":      1,
        "method":  method,
        "params":  params,
    });

    let resp: Value = client
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("HTTP POST {rpc_url} ({method})"))?
        .json()
        .await
        .with_context(|| format!("decode JSON-RPC response for {method}"))?;

    if let Some(err) = resp.get("error") {
        anyhow::bail!("RPC error: {err}");
    }

    Ok(resp["result"].clone())
}
