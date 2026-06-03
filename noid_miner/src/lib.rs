// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! # noid_miner — Block Production Engine
//!
//! Implements the parallel PoW + Prove pipeline. See ARCHITECTURE.md §13.2.
//!
//! ## Pipeline
//!
//! ```text
//!  ┌────────────────────────────────────────────────────────────┐
//!  │                   Block Production Loop                    │
//!  │                                                            │
//!  │  1. Build template (txs from mempool + coinbase)           │
//!  │     ├─ Empty block template first (instant, no ZK)         │
//!  │     └─ Full template with txs (~1s state transition)       │
//!  │                                                            │
//!  │  2. Parallel execution:                                    │
//!  │     ┌──────────────────┐   ┌──────────────────────────┐   │
//!  │     │  PoW Search      │   │  ZK Block Prove          │   │
//!  │     │  Blake3(core||n) │   │  prove_block(witnesses)  │   │
//!  │     │  < target        │   │  ~10s on 8 cores         │   │
//!  │     └───────┬──────────┘   └──────────┬───────────────┘   │
//!  │             │                         │                   │
//!  │             └──────────┬──────────────┘                   │
//!  │                        │ both complete                    │
//!  │                        ▼                                  │
//!  │  3. Seal: BlockHeader(core + proof_hash + nonce)          │
//!  │  4. Broadcast via P2P                                     │
//!  └────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Security property
//!
//! `state_root` (derived from all txs + miner_address via coinbase output) is
//! in `header_core` which is the PoW input. An external miner CANNOT change
//! the coinbase without regenerating the BlockProof — the miner only brute-forces
//! the nonce.

pub mod miner;
pub mod pow;
pub mod template;

pub use miner::{BlockMiner, MinerConfig, MinerEvent};
pub use pow::{search_pow_parallel, PowSolution};
pub use template::{BlockTemplate, TemplateBuilder, TemplateRefreshTrigger};
