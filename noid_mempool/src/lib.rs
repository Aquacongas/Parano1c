// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! # noid_mempool — Async Mempool for the Paranoid Full Node
//!
//! This crate wraps the synchronous `noid_chain::Mempool` in an async
//! (`tokio`-based) interface that drives the full node's transaction pipeline:
//!
//! ```text
//!  wallet
//!    │  TxIntent (body + LogicProof bytes)
//!    ▼
//!  AsyncMempool::submit()
//!    ├─ fee ≥ dynamic floor
//!    ├─ consensus (fee overflow, body hash, anchor non-zero, nullifier)
//!    ├─ epoch_anchor hash ∈ known headers within ANCHOR_DEPTH window
//!    ├─ no slot conflict with already-admitted pool txs
//!    ├─ input slots live in state (value + owner match)
//!    └─ output slots empty in state
//!         │
//!         ▼ admitted
//!    broadcast MempoolEvent::TxAdmitted
//!         │
//!         ├──► P2P: gossip to peers
//!         ├──► RPC WebSocket: notify subscribed wallets
//!         └──► Block builder: wake up if 100+ new txs
//!
//!  Background: ZK verify on admission + pre-prove cache
//! ```
//!
//! ## Usage
//!
//! ```no_run
//! use noid_mempool::{AsyncMempool, ChainView, MempoolConfig};
//! use noid_chain::storage::MdbxChainContext;
//!
//! async fn example(ctx: &MdbxChainContext) {
//!     let view = ChainView::from_mdbx(ctx);
//!     let mp = AsyncMempool::new(view, MempoolConfig::default());
//!
//!     // Subscribe to events (P2P, RPC, block builder).
//!     let mut rx = mp.subscribe();
//!
//!     // Submit a transaction from a wallet.
//!     // let hash = mp.submit(intent, intent_bytes).await?;
//! }
//! ```

pub mod config;
pub mod error;
pub mod event;
pub mod floor;
pub mod pool;
pub mod view;

// ---------------------------------------------------------------------------
// Public re-exports
// ---------------------------------------------------------------------------

pub use config::MempoolConfig;
pub use error::SubmitError;
pub use event::{EvictReason, MempoolEvent};
pub use floor::FeeFloor;
pub use pool::AsyncMempool;
pub use view::ChainView;

// Re-export `MempoolEntry` from noid_chain for block builder convenience.
pub use noid_chain::mempool::MempoolEntry;
