// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! # noid-extminer — External Blake3 PoW miner for the Paranoid blockchain.
//!
//! Connects to any `paranoid` full node via JSON-RPC, fetches a block template,
//! searches for a valid PoW nonce using all available CPU cores (rayon), and
//! submits the solved block.
//!
//! ## Usage
//!
//! ```bash
//! # Solo (node on localhost, no auth)
//! noid-extminer --rpc http://127.0.0.1:9401
//!
//! # Pool (remote node with bearer token)
//! noid-extminer --rpc https://pool.example.com:9401 --key my-secret-token
//!
//! # Limit threads
//! noid-extminer --rpc http://127.0.0.1:9401 --threads 4
//! ```
//!
//! ## Template protocol
//!
//! `getBlockTemplate("")` returns:
//!   - `header_core_hex`       — 212-byte PoW input
//!   - `block_hex`             — full sealed block with nonce = 0
//!   - `nonce_offset`          — byte offset of nonce inside block_hex (always 144)
//!   - `difficulty_target_hex` — 256-bit LE target
//!
//! The miner patches `block_hex[nonce_offset..nonce_offset+16]` with the found
//! 16-byte LE nonce and calls `submitBlock(patched_block_hex)`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name = "noid-extminer",
    version,
    about = "External Blake3 PoW miner for the Paranoid blockchain",
    long_about = "Fetches block templates from a paranoid node and mines blocks \
                  using all available CPU cores.\n\n\
                  The node controls coinbase address — the miner only does PoW.\n\
                  Rewards go to whoever operates the node (pool or solo)."
)]
struct Cli {
    /// JSON-RPC endpoint of the paranoid node or pool.
    #[arg(long, default_value = "http://127.0.0.1:9401", value_name = "URL")]
    rpc: String,

    /// Bearer token for pool/external RPC access.
    /// Must match the node's --mining-key flag.
    /// Not needed for solo miners using the default 127.0.0.1 binding.
    #[arg(long, value_name = "TOKEN")]
    key: Option<String>,

    /// Number of PoW threads. 0 = all physical cores.
    #[arg(long, default_value_t = 0, value_name = "N")]
    threads: usize,

    /// Your own payout address (bech32m noid1... or 64-char hex).
    /// Only works when the node is started with --allow-custom-coinbase.
    /// Leave empty to use the node's configured payout address (pool mode).
    #[arg(long, value_name = "ADDRESS", default_value = "")]
    coinbase: String,

    /// Milliseconds to wait before re-fetching a new template after a solve
    /// or stale detection. Lower = more responsive to new blocks.
    #[arg(long, default_value_t = 500, value_name = "MS")]
    poll_ms: u64,

    /// Log level (error | warn | info | debug).
    #[arg(long, default_value = "info", value_name = "LEVEL")]
    log: String,
}

// ---------------------------------------------------------------------------
// RPC types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct BlockTemplateResponse {
    header_core_hex: String,
    block_hex: String,
    nonce_offset: usize,
    difficulty_target_hex: String,
    height: u64,
    n_txs: usize,
}

#[derive(Debug, Serialize)]
struct JsonRpcRequest<'a, P: Serialize> {
    jsonrpc: &'a str,
    id: u32,
    method: &'a str,
    params: P,
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// RPC client
// ---------------------------------------------------------------------------

struct RpcClient {
    url: String,
    key: Option<String>,
    http: reqwest::blocking::Client,
}

impl RpcClient {
    fn new(url: &str, key: Option<String>) -> Self {
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("build HTTP client");
        Self {
            url: url.to_string(),
            key,
            http,
        }
    }

    fn call<P: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: P,
    ) -> Result<R> {
        let body = JsonRpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method,
            params,
        };
        let mut req = self.http.post(&self.url).json(&body);
        if let Some(ref token) = self.key {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        let resp = req.send().with_context(|| format!("POST {}", self.url))?;
        let status = resp.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(anyhow!(
                "401 Unauthorized — node requires --key <token>. \
                 Make sure --mining-key matches on the node."
            ));
        }
        if !status.is_success() {
            return Err(anyhow!("HTTP {status} from {}", self.url));
        }
        let rpc: JsonRpcResponse<R> = resp.json().context("decode JSON-RPC response")?;
        if let Some(err) = rpc.error {
            return Err(anyhow!("RPC error: {err}"));
        }
        rpc.result
            .ok_or_else(|| anyhow!("RPC returned null result"))
    }

    fn get_template(&self, coinbase: &str) -> Result<BlockTemplateResponse> {
        self.call("paranoid_getBlockTemplate", [coinbase])
    }

    fn submit_block(&self, block_hex: &str) -> Result<String> {
        self.call("paranoid_submitBlock", [block_hex])
    }
}

// ---------------------------------------------------------------------------
// PoW
// ---------------------------------------------------------------------------

const CHUNK_SIZE: u128 = 10_000_000;
/// Byte offset of the nonce inside header_core (= header start).
const NONCE_OFFSET_IN_CORE: usize = 144;

/// Search for a valid nonce using all rayon threads.
/// Returns `Some(nonce)` or `None` if cancelled.
fn search_nonce(header_core: &[u8; 212], target: &[u8; 32], cancel: &AtomicBool) -> Option<u128> {
    let num_threads = rayon::current_num_threads();
    let per_thread = CHUNK_SIZE / num_threads as u128;

    // Random start so multiple miners on the same template don't collide.
    let start_nonce: u128 = {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u128;
        t & 0xFFFF_FFFF_FFFF_FFFF
    };

    let mut chunk_start = start_nonce;

    loop {
        if cancel.load(Ordering::Relaxed) {
            return None;
        }

        let solution = (0..num_threads).into_par_iter().find_map_any(|tid| {
            let ts = chunk_start + tid as u128 * per_thread;
            let te = ts + per_thread;

            let mut buf = *header_core;
            for nonce in ts..te {
                if cancel.load(Ordering::Relaxed) {
                    return None;
                }
                buf[NONCE_OFFSET_IN_CORE..NONCE_OFFSET_IN_CORE + 16]
                    .copy_from_slice(&nonce.to_le_bytes());
                let hash = *blake3::hash(&buf).as_bytes();
                if le256_lt(&hash, target) {
                    return Some(nonce);
                }
            }
            None
        });

        if solution.is_some() {
            return solution;
        }

        chunk_start = chunk_start.wrapping_add(CHUNK_SIZE);
    }
}

/// Compare two 32-byte values as 256-bit LE integers: `a < b`.
#[inline]
fn le256_lt(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if a[i] < b[i] {
            return true;
        }
        if a[i] > b[i] {
            return false;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Mining loop
// ---------------------------------------------------------------------------

fn mine(cli: &Cli) -> Result<()> {
    let rpc = RpcClient::new(&cli.rpc, cli.key.clone());

    // Configure rayon thread pool.
    if cli.threads > 0 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(cli.threads)
            .build_global()
            .ok();
    }
    let threads = rayon::current_num_threads();

    eprintln!(
        "noid-extminer  rpc={}  threads={}  poll={}ms",
        cli.rpc, threads, cli.poll_ms,
    );
    if cli.key.is_some() {
        eprintln!("auth: bearer token configured");
    }
    if !cli.coinbase.is_empty() {
        eprintln!(
            "coinbase: {} (custom — node must have --allow-custom-coinbase)",
            cli.coinbase
        );
    } else {
        eprintln!("coinbase: node's payout address (pool mode)");
    }
    eprintln!("Connecting to node...\n");

    let mut blocks_found: u64 = 0;
    let mut last_height: u64 = 0;

    loop {
        // Fetch template.
        let tmpl = match rpc.get_template(&cli.coinbase) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("template fetch failed: {e}  — retrying in 2s");
                std::thread::sleep(Duration::from_secs(2));
                continue;
            }
        };

        // Skip if height unchanged and we already solved it.
        if tmpl.height == last_height {
            std::thread::sleep(Duration::from_millis(cli.poll_ms));
            continue;
        }

        let height = tmpl.height;
        let n_txs = tmpl.n_txs;

        let header_core: [u8; 212] = hex::decode(&tmpl.header_core_hex)
            .context("decode header_core_hex")?
            .try_into()
            .map_err(|_| anyhow!("header_core must be 212 bytes"))?;

        let target: [u8; 32] = hex::decode(&tmpl.difficulty_target_hex)
            .context("decode difficulty_target_hex")?
            .try_into()
            .map_err(|_| anyhow!("difficulty_target must be 32 bytes"))?;

        let mut block_bytes = hex::decode(&tmpl.block_hex).context("decode block_hex")?;
        let nonce_offset = tmpl.nonce_offset;

        // Count leading zero bits for display.
        let diff_bits = {
            let mut z = 0u32;
            for i in (0..32usize).rev() {
                if target[i] == 0 {
                    z += 8;
                } else if z % 8 == 0 {
                    z += target[i].leading_zeros();
                    break;
                } else {
                    break;
                }
            }
            z
        };

        eprintln!(
            "┌─ h={height} txs={n_txs} diff={diff_bits} leading-zero-bits  \
             target={}…",
            &tmpl.difficulty_target_hex[tmpl.difficulty_target_hex.len().saturating_sub(8)..]
        );

        let cancel = Arc::new(AtomicBool::new(false));
        let t0 = Instant::now();

        let nonce = match search_nonce(&header_core, &target, &cancel) {
            Some(n) => n,
            None => {
                // Was cancelled (shouldn't happen without explicit cancellation).
                continue;
            }
        };

        let elapsed = t0.elapsed();

        // Patch nonce into block bytes.
        let nonce_bytes = nonce.to_le_bytes();
        if nonce_offset + 16 > block_bytes.len() {
            return Err(anyhow!(
                "nonce_offset={nonce_offset} out of range (block_len={})",
                block_bytes.len()
            ));
        }
        block_bytes[nonce_offset..nonce_offset + 16].copy_from_slice(&nonce_bytes);

        // Submit.
        match rpc.submit_block(&hex::encode(&block_bytes)) {
            Ok(hash) => {
                blocks_found += 1;
                last_height = height;
                eprintln!(
                    "└─ SOLVED  nonce={nonce}  time={:.2}s  hash={}…  \
                     [total={blocks_found}]",
                    elapsed.as_secs_f64(),
                    &hash[..20.min(hash.len())],
                );
            }
            Err(e) => {
                eprintln!("└─ submit failed (stale block?): {e}");
                last_height = height; // skip this height, get a fresh template
            }
        }

        std::thread::sleep(Duration::from_millis(cli.poll_ms));
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();
    if let Err(e) = mine(&cli) {
        eprintln!("fatal: {e}");
        std::process::exit(1);
    }
}
