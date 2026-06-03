// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Mempool configuration.

use noid_chain::consensus::params::BLOCK_MAX_TXS;

/// Configuration for the async mempool.
#[derive(Debug, Clone)]
pub struct MempoolConfig {
    /// Maximum number of admitted transactions. Default: 8 × BLOCK_MAX_TXS.
    pub capacity: usize,

    /// Number of recent admitted-tx fees used to compute the dynamic fee floor.
    /// Floor = max(MIN_FEE_BASE, median(last N fees) × 0.9).
    pub fee_floor_window: usize,

    /// Enable Phase 1.5 background ZK pre-proving on admission.
    /// When true, each admitted tx spawns a `prove_air_algebraic_pretx` task.
    /// Cached proofs reduce block assembly from ~44s to ~12s at 1024 txs.
    pub pre_prove_enabled: bool,

    /// Number of concurrent ZK verification workers (tokio::spawn_blocking slots).
    /// 0 = skip ZK verification at admission (native checks only).
    /// Recommended: number of physical cores.
    pub zk_verify_workers: usize,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            capacity: BLOCK_MAX_TXS * 8,
            fee_floor_window: 50,
            pre_prove_enabled: false, // activated in Phase 1.5
            zk_verify_workers: 4,     // 4 concurrent ZK verification workers (DoS bound)
        }
    }
}

impl MempoolConfig {
    pub fn with_capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity;
        self
    }

    pub fn with_pre_prove(mut self, enabled: bool) -> Self {
        self.pre_prove_enabled = enabled;
        self
    }

    pub fn with_zk_workers(mut self, n: usize) -> Self {
        self.zk_verify_workers = n;
        self
    }
}
