// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! # noid-extminer — External Poseidon2b PoW miner for the Paranoid blockchain.
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
//!   - `pow_fields_hex`           — 16-field Poseidon2b PoW input
//!   - `block_hex`                — full sealed block with nonce = 0
//!   - `block_proof_hex`          — serialized BlockProof, empty for coinbase-only
//!   - `block_auth_sidecar_hex`   — serialized public Auth sidecar, empty when absent
//!   - `nonce_offset`             — byte offset of nonce inside block_hex (always 144)
//!   - `difficulty_target_hex`    — 256-bit LE target
//!   - shape/proof metadata       — operator display only; PoW uses pow_fields
//!
//! The miner patches `block_hex[nonce_offset..nonce_offset+16]` with the found
//! 16-byte LE nonce and calls `submitBlock(patched_block_hex, block_proof_hex,
//! block_auth_sidecar_hex)`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use noid_core::packed::{PackedBlock128, PACKED_LANES};
use noid_core::{Block128, TowerField};
use noid_poseidon2b::batch::packed_poseidon2b_permute;
use noid_poseidon2b::native::domain::{capacity_iv, TAG_POWHDR};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name = "noid-extminer",
    version,
    about = "External Poseidon2b PoW miner for the Paranoid blockchain",
    long_about = "Fetches block templates from a paranoid node and mines blocks \
                  using all available CPU cores.\n\n\
                  The node builds the proven template; this worker only does PoW.\n\
                  Coinbase is the node payout address unless the node enables \
                  --allow-custom-coinbase and the worker supplies --coinbase."
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

    /// Your own payout address (bech32m o1...).
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
    pow_fields_hex: String,
    block_hex: String,
    block_proof_hex: String,
    #[serde(default)]
    block_auth_sidecar_hex: String,
    nonce_offset: usize,
    difficulty_target_hex: String,
    height: u64,
    n_txs: usize,
    #[serde(default)]
    tx_shapes: Vec<String>,
    #[serde(default)]
    standard_tx_count: usize,
    #[serde(default)]
    sweep_tx_count: usize,
    #[serde(default)]
    block_proof_size_bytes: usize,
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

    fn submit_block(
        &self,
        block_hex: &str,
        block_proof_hex: &str,
        block_auth_sidecar_hex: &str,
    ) -> Result<String> {
        self.call(
            "paranoid_submitBlock",
            (block_hex, block_proof_hex, block_auth_sidecar_hex),
        )
    }
}

// ---------------------------------------------------------------------------
// PoW
// ---------------------------------------------------------------------------

const CHUNK_SIZE: u128 = 10_000_000;
const DIGEST_BATCH: usize = 256;
const POW_HEADER_FIELD_COUNT: usize = 16;
const POW_NONCE_FIELD_INDEX: usize = 10;
const POW_FIELDS_HEX_BYTES: usize = POW_HEADER_FIELD_COUNT * 16;
/// Byte offset of the nonce inside block header wire.
const BLOCK_HEADER_NONCE_OFFSET: usize = 144;
/// Serialized semantic block header size.
const BLOCK_HEADER_WIRE_SIZE: usize = 212;

/// Search for a valid nonce using all rayon threads.
/// Returns `Some(nonce)` or `None` if cancelled.
fn search_nonce(
    pow_fields: &[Block128; POW_HEADER_FIELD_COUNT],
    target: &[u8; 32],
    cancel: &AtomicBool,
) -> Option<u128> {
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

            let fields = *pow_fields;
            let mut digests = [[0u8; 32]; DIGEST_BATCH];
            let mut nonce = ts;
            while nonce < te {
                if cancel.load(Ordering::Relaxed) {
                    return None;
                }
                let n = ((te - nonce).min(DIGEST_BATCH as u128)) as usize;
                poseidon_pow_digest_nonce_batch(&fields, nonce, &mut digests[..n]);
                for (i, hash) in digests[..n].iter().enumerate() {
                    if le256_lt(hash, target) {
                        return Some(nonce + i as u128);
                    }
                }
                nonce += n as u128;
            }
            None
        });

        if solution.is_some() {
            return solution;
        }

        chunk_start = chunk_start.wrapping_add(CHUNK_SIZE);
    }
}

fn decode_pow_fields_hex(hex_str: &str) -> Result<[Block128; POW_HEADER_FIELD_COUNT]> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != POW_FIELDS_HEX_BYTES {
        return Err(anyhow!(
            "pow_fields_hex must be {POW_FIELDS_HEX_BYTES} bytes, got {}",
            bytes.len()
        ));
    }
    let mut fields = [Block128::ZERO; POW_HEADER_FIELD_COUNT];
    for (i, chunk) in bytes.chunks_exact(16).enumerate() {
        fields[i] = Block128::from(u128::from_le_bytes(chunk.try_into().unwrap()));
    }
    Ok(fields)
}

fn pow_fields_from_block_header(block_bytes: &[u8]) -> Result<[Block128; POW_HEADER_FIELD_COUNT]> {
    if block_bytes.len() < BLOCK_HEADER_WIRE_SIZE {
        return Err(anyhow!(
            "block_hex too short: {} bytes, need at least {BLOCK_HEADER_WIRE_SIZE}",
            block_bytes.len()
        ));
    }

    let mut fields = [Block128::ZERO; POW_HEADER_FIELD_COUNT];
    let mut field = 0usize;
    put_digest_fields(&mut fields, &mut field, &block_bytes[0..32]);
    put_digest_fields(&mut fields, &mut field, &block_bytes[32..64]);
    put_digest_fields(&mut fields, &mut field, &block_bytes[64..96]);
    fields[field] = Block128::from(read_u64(&block_bytes[96..104]) as u128);
    field += 1;
    fields[field] = Block128::from(read_u64(&block_bytes[104..112]) as u128);
    field += 1;
    put_digest_fields(&mut fields, &mut field, &block_bytes[112..144]);
    fields[field] = Block128::from(read_u128(&block_bytes[144..160]));
    field += 1;
    put_digest_fields(&mut fields, &mut field, &block_bytes[160..192]);
    fields[field] = Block128::from(read_u32(&block_bytes[192..196]) as u128);
    field += 1;
    fields[field] = Block128::from(read_u64(&block_bytes[196..204]) as u128);
    field += 1;
    fields[field] = Block128::from(read_u64(&block_bytes[204..212]) as u128);
    field += 1;
    debug_assert_eq!(field, POW_HEADER_FIELD_COUNT);
    Ok(fields)
}

fn put_digest_fields(
    fields: &mut [Block128; POW_HEADER_FIELD_COUNT],
    index: &mut usize,
    bytes: &[u8],
) {
    fields[*index] = Block128::from(u128::from_le_bytes(bytes[..16].try_into().unwrap()));
    *index += 1;
    fields[*index] = Block128::from(u128::from_le_bytes(bytes[16..32].try_into().unwrap()));
    *index += 1;
}

fn poseidon_pow_digest_nonce_batch(
    fields: &[Block128; POW_HEADER_FIELD_COUNT],
    start_nonce: u128,
    out: &mut [[u8; 32]],
) {
    if out.is_empty() {
        return;
    }

    let [iv_hi, iv_lo] = capacity_iv(TAG_POWHDR);
    let mut offset = 0usize;
    while offset < out.len() {
        let lanes = (out.len() - offset).min(PACKED_LANES);
        let mut states = [PackedBlock128::ZERO; 4];
        states[2] = PackedBlock128::broadcast(iv_hi);
        states[3] = PackedBlock128::broadcast(iv_lo);

        for pair in 0..(POW_HEADER_FIELD_COUNT / 2) {
            let left_idx = pair * 2;
            let right_idx = left_idx + 1;
            let mut left = PackedBlock128::broadcast(fields[left_idx]);
            let mut right = PackedBlock128::broadcast(fields[right_idx]);
            if left_idx == POW_NONCE_FIELD_INDEX {
                left = PackedBlock128::ZERO;
                for lane in 0..lanes {
                    let nonce = start_nonce.saturating_add((offset + lane) as u128);
                    left = left.set_lane(lane, Block128::from(nonce));
                }
            } else if right_idx == POW_NONCE_FIELD_INDEX {
                right = PackedBlock128::ZERO;
                for lane in 0..lanes {
                    let nonce = start_nonce.saturating_add((offset + lane) as u128);
                    right = right.set_lane(lane, Block128::from(nonce));
                }
            }
            states[0] = states[0].xor(left);
            states[1] = states[1].xor(right);
            packed_poseidon2b_permute(&mut states);
        }

        for lane in 0..lanes {
            let s0 = states[0].get_lane(lane);
            let s1 = states[1].get_lane(lane);
            out[offset + lane][..16].copy_from_slice(&s0.to_u128().to_le_bytes());
            out[offset + lane][16..].copy_from_slice(&s1.to_u128().to_le_bytes());
        }
        offset += lanes;
    }
}

#[inline]
fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().unwrap())
}

#[inline]
fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().unwrap())
}

#[inline]
fn read_u128(bytes: &[u8]) -> u128 {
    u128::from_le_bytes(bytes.try_into().unwrap())
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

fn validate_template_layout(
    pow_fields: &[Block128; POW_HEADER_FIELD_COUNT],
    block_bytes: &[u8],
    nonce_offset: usize,
) -> Result<()> {
    if nonce_offset != BLOCK_HEADER_NONCE_OFFSET {
        return Err(anyhow!(
            "unexpected nonce_offset={nonce_offset}; expected {BLOCK_HEADER_NONCE_OFFSET}"
        ));
    }
    if block_bytes.len() < BLOCK_HEADER_WIRE_SIZE {
        return Err(anyhow!(
            "block_hex too short: {} bytes, need at least {BLOCK_HEADER_WIRE_SIZE}",
            block_bytes.len()
        ));
    }

    let block_fields = pow_fields_from_block_header(block_bytes)?;
    if &block_fields != pow_fields {
        return Err(anyhow!(
            "template mismatch: pow_fields_hex does not match the semantic header embedded in block_hex"
        ));
    }

    Ok(())
}

fn shape_summary(tmpl: &BlockTemplateResponse) -> String {
    let proof_size = if tmpl.block_proof_size_bytes > 0 {
        tmpl.block_proof_size_bytes
    } else {
        tmpl.block_proof_hex.len() / 2
    };
    if tmpl.standard_tx_count > 0 || tmpl.sweep_tx_count > 0 {
        return format!(
            "std={} sweep={} proof={}B",
            tmpl.standard_tx_count, tmpl.sweep_tx_count, proof_size
        );
    }
    if !tmpl.tx_shapes.is_empty() {
        return format!("shapes={} proof={}B", tmpl.tx_shapes.join(","), proof_size);
    }
    format!("proof={proof_size}B")
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

        let pow_fields =
            decode_pow_fields_hex(&tmpl.pow_fields_hex).context("decode pow_fields_hex")?;

        let target: [u8; 32] = hex::decode(&tmpl.difficulty_target_hex)
            .context("decode difficulty_target_hex")?
            .try_into()
            .map_err(|_| anyhow!("difficulty_target must be 32 bytes"))?;

        let mut block_bytes = hex::decode(&tmpl.block_hex).context("decode block_hex")?;
        let nonce_offset = tmpl.nonce_offset;
        validate_template_layout(&pow_fields, &block_bytes, nonce_offset)?;

        // Count leading zero bits for display.
        let diff_bits = {
            let mut z = 0u32;
            for i in (0..32usize).rev() {
                if target[i] == 0 {
                    z += 8;
                } else if z.is_multiple_of(8) {
                    z += target[i].leading_zeros();
                    break;
                } else {
                    break;
                }
            }
            z
        };

        eprintln!(
            "┌─ h={height} txs={n_txs} {} diff={diff_bits} leading-zero-bits  \
             target={}…",
            shape_summary(&tmpl),
            &tmpl.difficulty_target_hex[tmpl.difficulty_target_hex.len().saturating_sub(8)..]
        );

        let cancel = Arc::new(AtomicBool::new(false));
        let t0 = Instant::now();

        let nonce = match search_nonce(&pow_fields, &target, &cancel) {
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
        match rpc.submit_block(
            &hex::encode(&block_bytes),
            &tmpl.block_proof_hex,
            &tmpl.block_auth_sidecar_hex,
        ) {
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
                let err = e.to_string();
                if err.contains("BadParentHash") {
                    eprintln!("└─ STALE  template parent lost race; fetching fresh template");
                } else {
                    eprintln!("└─ submit failed: {err}");
                }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn matching_pow_fields_and_block_bytes() -> ([Block128; POW_HEADER_FIELD_COUNT], Vec<u8>) {
        let mut block = vec![0u8; BLOCK_HEADER_WIRE_SIZE + 4];
        for (i, b) in block[..BLOCK_HEADER_WIRE_SIZE].iter_mut().enumerate() {
            *b = i as u8;
        }
        let fields = pow_fields_from_block_header(&block).expect("valid header bytes");
        (fields, block)
    }

    #[test]
    fn template_layout_accepts_matching_pow_fields_and_full_header() {
        let (fields, block) = matching_pow_fields_and_block_bytes();
        validate_template_layout(&fields, &block, BLOCK_HEADER_NONCE_OFFSET).unwrap();
    }

    #[test]
    fn template_layout_rejects_mismatched_pow_fields() {
        let (mut fields, block) = matching_pow_fields_and_block_bytes();
        fields[0] += Block128::from(1u128);
        assert!(validate_template_layout(&fields, &block, BLOCK_HEADER_NONCE_OFFSET).is_err());
    }

    #[test]
    fn template_layout_rejects_unexpected_nonce_offset() {
        let (fields, block) = matching_pow_fields_and_block_bytes();
        assert!(validate_template_layout(&fields, &block, BLOCK_HEADER_NONCE_OFFSET + 1).is_err());
    }
}
