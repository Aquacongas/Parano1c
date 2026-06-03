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
    // --- Chain ---
    /// Chain info: height, best hash, difficulty, active slot count.
    Status,
    /// Mempool: pending TX count, fee floor, list of pending TXs.
    Mempool,
    /// Gracefully stop the running paranoid daemon.
    Stop,

    // --- Wallet ---
    /// Wallet address at key index N (default: 0).
    Address {
        #[arg(long, default_value_t = 0)]
        index: u32,
    },
    /// Confirmed balance and UTXO count.
    Balance,
    /// Send μNOID to a recipient address.
    Send {
        /// Recipient address (32-byte hex, 64 characters).
        to: String,
        /// Amount in μNOID (1 NOID = 1,000,000 μNOID).
        amount: u64,
        /// Fee in μNOID. 0 = auto (minimum + current fee floor).
        #[arg(long, default_value_t = 0)]
        fee: u64,
    },
    /// Transaction history.
    History,
    /// List all confirmed UTXOs with slot indices and values.
    Utxos,
    /// Rescan the full chain state to (re)discover owned UTXOs.
    Scan,
    /// Export a Merkle inclusion receipt for a confirmed transaction.
    Receipt {
        /// Transaction hash (hex).
        txhash: String,
    },
    /// Merge small UTXOs into fewer larger ones (reduces UTXO count).
    Consolidate {
        /// Fee per round in μNOID. 0 = auto.
        #[arg(long, default_value_t = 0)]
        fee: u64,
        /// Maximum consolidation rounds.
        #[arg(long, default_value_t = 100)]
        rounds: u32,
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
        Command::Status => cmd_node_status(&client, &cli.rpc).await?,
        Command::Mempool => cmd_node_mempool(&client, &cli.rpc).await?,
        Command::Stop => cmd_node_stop(&client, &cli.rpc).await?,
        Command::Address { index } => cmd_wallet_address(&client, &cli.rpc, index).await?,
        Command::Balance => cmd_wallet_balance(&client, &cli.rpc).await?,
        Command::Send { to, amount, fee } => {
            cmd_wallet_send(&client, &cli.rpc, &to, amount, fee).await?
        }
        Command::History => cmd_wallet_history(&client, &cli.rpc).await?,
        Command::Utxos => cmd_wallet_utxos(&client, &cli.rpc).await?,
        Command::Scan => cmd_wallet_scan(&client, &cli.rpc).await?,
        Command::Receipt { txhash } => cmd_wallet_receipt(&client, &cli.rpc, &txhash).await?,
        Command::Consolidate { fee, rounds } => {
            cmd_wallet_consolidate(&client, &cli.rpc, fee, rounds).await?
        }
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

async fn cmd_node_stop(client: &reqwest::Client, rpc_url: &str) -> anyhow::Result<()> {
    // Best-effort: the server shuts down as soon as the signal fires,
    // so the response may or may not arrive before the connection closes.
    match rpc_call(client, rpc_url, "paranoid_stop", serde_json::json!([])).await {
        Ok(result) => {
            let msg = result.as_str().unwrap_or("ok");
            println!("node stop: {msg}");
        }
        Err(_) => {
            // Connection closed before response — that means the daemon
            // is already shutting down. This is expected.
            println!("node stop: daemon is shutting down");
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
    if micronoid == 0 && utxo_count == 0 {
        println!("  Tip: run 'noid-cli wallet scan' to discover UTXOs from the chain state");
    }

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
    let actual_fee = result["fee_micronoid"].as_u64().unwrap_or(fee);
    let noid = amount as f64 / MICRONOID_PER_NOID;
    let fee_noid = actual_fee as f64 / MICRONOID_PER_NOID;
    let auto_tag = if fee == 0 { " (auto)" } else { "" };

    println!("wallet send:");
    println!("  Submitted! tx_hash: 0x{tx_hash}");
    println!("  To:     {to}");
    println!("  Amount: {noid:.6} NOID ({amount} μNOID)");
    println!("  Fee:    {fee_noid:.6} NOID ({actual_fee} μNOID){auto_tag}");
    println!("  Note: TX is pending confirmation in the next block (~60s)");

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

async fn cmd_wallet_consolidate(
    client: &reqwest::Client,
    rpc_url: &str,
    fee: u64,
    rounds: u32,
) -> anyhow::Result<()> {
    println!("wallet consolidate: merging small UTXOs (fee={fee} \u{03bc}NOID per round)...");

    let mut total_rounds = 0u32;
    loop {
        if total_rounds >= rounds {
            println!("  Reached maximum rounds ({rounds}). Run again to continue.");
            break;
        }

        match rpc_call(
            client,
            rpc_url,
            "paranoid_walletConsolidate",
            serde_json::json!([fee]),
        )
        .await
        {
            Ok(result) => {
                let tx_hash = result["tx_hash"].as_str().unwrap_or("?");
                total_rounds += 1;
                println!("  Round {total_rounds}: tx submitted 0x{tx_hash}");

                // Wait for the TX to be mined and wallet state to update.
                // 1. Poll mempool until empty (TX confirmed in a block).
                // 2. Then do a wallet scan to rebuild from authoritative chain state,
                //    which also clears any stale pending_input_slots.
                for _wait in 0..60u32 {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    let mpool_size = rpc_call(
                        client,
                        rpc_url,
                        "paranoid_getMempoolSize",
                        serde_json::json!([]),
                    )
                    .await
                    .ok()
                    .and_then(|v| v.as_u64())
                    .unwrap_or(1);
                    if mpool_size == 0 {
                        break;
                    }
                }
                // Scan to rebuild wallet from chain state (clears stale pending tracking).
                let _ = rpc_call(
                    client,
                    rpc_url,
                    "paranoid_walletScan",
                    serde_json::json!([]),
                )
                .await;

                match rpc_call(
                    client,
                    rpc_url,
                    "paranoid_walletGetBalance",
                    serde_json::json!([]),
                )
                .await
                {
                    Ok(bal) => {
                        let utxo_count = bal["utxo_count"].as_u64().unwrap_or(0);
                        if utxo_count <= 1 {
                            println!("  Done! UTXO count reduced to {utxo_count}.");
                            break;
                        }
                        println!("  UTXOs remaining: {utxo_count}");
                    }
                    Err(_) => {}
                }
            }
            Err(e) => {
                let msg = e.to_string();
                // "InsufficientFunds have=0" means no UTXOs outside pending set.
                // This is normal when all UTXOs are confirmed in the previous round
                // and the wallet has only 1-3 UTXOs left (fewer than MAX_INPUTS).
                // The sleep above prevents this in most cases; if it still happens
                // it means the wallet is sufficiently consolidated.
                if msg.contains("InsufficientFunds") || msg.contains("nothing to consolidate") {
                    if total_rounds == 0 {
                        println!("  Nothing to consolidate — wallet has too few UTXOs.");
                    } else {
                        println!("  Consolidation complete after {total_rounds} round(s).");
                    }
                } else {
                    println!("  Error: {msg}");
                }
                break;
            }
        }
    }

    if total_rounds > 0 {
        println!("\nTotal rounds: {total_rounds}.");
        println!("Note: submitted TXs are pending. Run 'wallet balance' after confirmation.");
    }

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
