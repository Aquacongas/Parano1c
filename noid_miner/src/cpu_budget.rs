// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Process-wide CPU admission for proof pipelines and internal PoW.
//!
//! A selected-history drain has three concurrent callers (Block, Link, and
//! terminal verification). Giving each caller the global Rayon pool lets all
//! three independently activate every logical CPU. An exclusive proof mutex
//! avoids that oversubscription, but turns useful overlap into queue time on
//! the critical Link path.
//!
//! This module instead gives every proof caller the same work-conserving Rayon
//! pool. Concurrent `install` calls share one fixed worker set, so idle proof
//! capacity is immediately stealable by another stage without multiplying the
//! number of active workers. Internal PoW uses a disjoint fixed pool and the
//! planner enforces `pow_threads + proof_threads == available_threads`.

use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc, OnceLock,
};
use std::time::Instant;

const PROCESS_PROOF_WORKER_STACK_BYTES: usize = 64 * 1024 * 1024;

thread_local! {
    /// Rayon exposes a thread index for every pool, so an index alone cannot
    /// distinguish our proof pool from the global or PoW pool. Mark the actual
    /// worker lifetime instead; nested stage boundaries can then execute
    /// directly without re-injecting a job into the same scheduler.
    static PROCESS_PROOF_POOL_WORKER: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
}

/// Whether this process performs PoW internally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessCpuBudgetMode {
    /// Prover and external-miner nodes have no in-process PoW workers. The
    /// complete host-visible CPU set remains available to an isolated Link.
    ProofOnly,
    /// Internal mining reserves exactly the effective PoW thread count; zero
    /// selects the proof-latency default of one dedicated PoW worker.
    InternalMiner { mining_threads: usize },
}

/// Immutable worker-count plan for one process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessCpuBudgetPlan {
    pub available_threads: usize,
    pub pow_threads: usize,
    pub proof_threads: usize,
}

impl ProcessCpuBudgetPlan {
    /// Total active Rayon workers admitted by this plan. This excludes idle
    /// global-pool threads owned by unrelated callers and ordinary Tokio/P2P
    /// control threads.
    pub const fn admitted_rayon_threads(self) -> usize {
        self.pow_threads + self.proof_threads
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProcessCpuBudgetError {
    #[error("process CPU budget is not configured")]
    NotConfigured,
    #[error("process CPU budget requires at least one available logical CPU")]
    NoAvailableThreads,
    #[error("internal mining requires at least two available logical CPUs")]
    InternalMiningNeedsTwoThreads,
    #[error(
        "configured internal mining threads ({configured}) must be less than available logical CPUs ({available})"
    )]
    InvalidMiningThreads { configured: usize, available: usize },
    #[error("failed to build {role} Rayon pool: {detail}")]
    PoolBuild { role: &'static str, detail: String },
    #[error(
        "process CPU budget is already configured as {active:?}, requested incompatible {requested:?}"
    )]
    AlreadyConfigured {
        active: ProcessCpuBudgetPlan,
        requested: ProcessCpuBudgetPlan,
    },
}

/// Calculate the exact fixed-worker split without constructing any threads.
///
/// `mining_threads == 0` reserves one dedicated PoW worker and gives every
/// remaining worker to the common Block/Link/Verify pool. PoW difficulty
/// adapts to sustained hashrate, while splitting the machine in half would
/// immediately lengthen every proof stage on the critical block-cadence path.
/// An explicit value is fail-closed rather than clamped, so library callers
/// cannot accidentally construct an oversubscribed miner outside the node's
/// CLI validation.
pub fn plan_process_cpu_budget(
    available_threads: usize,
    mode: ProcessCpuBudgetMode,
) -> Result<ProcessCpuBudgetPlan, ProcessCpuBudgetError> {
    if available_threads == 0 {
        return Err(ProcessCpuBudgetError::NoAvailableThreads);
    }

    let pow_threads = match mode {
        ProcessCpuBudgetMode::ProofOnly => 0,
        ProcessCpuBudgetMode::InternalMiner { .. } if available_threads < 2 => {
            return Err(ProcessCpuBudgetError::InternalMiningNeedsTwoThreads);
        }
        ProcessCpuBudgetMode::InternalMiner { mining_threads: 0 } => 1,
        ProcessCpuBudgetMode::InternalMiner { mining_threads }
            if mining_threads >= available_threads =>
        {
            return Err(ProcessCpuBudgetError::InvalidMiningThreads {
                configured: mining_threads,
                available: available_threads,
            });
        }
        ProcessCpuBudgetMode::InternalMiner { mining_threads } => mining_threads,
    };
    let proof_threads = available_threads - pow_threads;
    debug_assert!(proof_threads > 0);
    let plan = ProcessCpuBudgetPlan {
        available_threads,
        pow_threads,
        proof_threads,
    };
    debug_assert_eq!(plan.admitted_rayon_threads(), available_threads);
    Ok(plan)
}

/// CPU-heavy selected-history boundary entering the shared proof pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectedHistoryCpuStage {
    Block,
    Link,
    Verify,
}

impl SelectedHistoryCpuStage {
    const fn label(self) -> &'static str {
        match self {
            Self::Block => "Block",
            Self::Link => "Link",
            Self::Verify => "Verify",
        }
    }

    const fn bit(self) -> u8 {
        match self {
            Self::Block => 1 << 0,
            Self::Link => 1 << 1,
            Self::Verify => 1 << 2,
        }
    }
}

struct ProcessCpuBudget {
    plan: ProcessCpuBudgetPlan,
    proof_pool: Arc<rayon::ThreadPool>,
    pow_pool: Option<Arc<rayon::ThreadPool>>,
    observed_history_stages: AtomicU8,
}

impl ProcessCpuBudget {
    fn build(plan: ProcessCpuBudgetPlan) -> Result<Self, ProcessCpuBudgetError> {
        let proof_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(plan.proof_threads)
            .stack_size(PROCESS_PROOF_WORKER_STACK_BYTES)
            .thread_name(|index| format!("noid-proof-{index}"))
            .start_handler(|_| {
                PROCESS_PROOF_POOL_WORKER.with(|marker| {
                    debug_assert!(!marker.get());
                    marker.set(true);
                });
                // These workers own the 64-MiB stack required by the deep
                // recursive verifier. Keep verification on this admitted
                // worker instead of activating an extra compatibility pool.
                noid_ivc_core::verifier::set_budgeted_large_stack_worker(true);
            })
            .exit_handler(|_| {
                noid_ivc_core::verifier::set_budgeted_large_stack_worker(false);
                PROCESS_PROOF_POOL_WORKER.with(|marker| marker.set(false));
            })
            .build()
            .map(Arc::new)
            .map_err(|error| ProcessCpuBudgetError::PoolBuild {
                role: "proof",
                detail: error.to_string(),
            })?;
        let pow_pool = (plan.pow_threads > 0)
            .then(|| {
                rayon::ThreadPoolBuilder::new()
                    .num_threads(plan.pow_threads)
                    .thread_name(|index| format!("noid-pow-{index}"))
                    .build()
                    .map(Arc::new)
                    .map_err(|error| ProcessCpuBudgetError::PoolBuild {
                        role: "PoW",
                        detail: error.to_string(),
                    })
            })
            .transpose()?;
        Ok(Self {
            plan,
            proof_pool,
            pow_pool,
            observed_history_stages: AtomicU8::new(0),
        })
    }

    fn install_history<R: Send>(
        &self,
        stage: SelectedHistoryCpuStage,
        operation: impl FnOnce() -> R + Send,
    ) -> R {
        if PROCESS_PROOF_POOL_WORKER.with(|marker| marker.get()) {
            return self.run_history_operation(stage, 0, true, operation);
        }
        let queued_at = Instant::now();
        self.proof_pool.install(|| {
            let pool_queue_ms = queued_at.elapsed().as_millis() as u64;
            self.run_history_operation(stage, pool_queue_ms, false, operation)
        })
    }

    fn install_proof<R: Send>(&self, operation: impl FnOnce() -> R + Send) -> R {
        if PROCESS_PROOF_POOL_WORKER.with(|marker| marker.get()) {
            operation()
        } else {
            self.proof_pool.install(operation)
        }
    }

    fn run_history_operation<R>(
        &self,
        stage: SelectedHistoryCpuStage,
        pool_queue_ms: u64,
        nested_same_pool: bool,
        operation: impl FnOnce() -> R,
    ) -> R {
        debug_assert!(PROCESS_PROOF_POOL_WORKER.with(|marker| marker.get()));
        let observed_threads = rayon::current_num_threads();
        debug_assert_eq!(observed_threads, self.plan.proof_threads);
        let first_stage_entry = self
            .observed_history_stages
            .fetch_or(stage.bit(), Ordering::AcqRel)
            & stage.bit()
            == 0;
        tracing::info!(
            stage = stage.label(),
            proof_threads = self.plan.proof_threads,
            observed_threads,
            pool_queue_ms,
            nested_same_pool,
            first_stage_entry,
            "selected-history stage entered shared proof Rayon pool"
        );
        operation()
    }

    fn proof_pool(&self) -> Arc<rayon::ThreadPool> {
        Arc::clone(&self.proof_pool)
    }

    fn pow_pool(&self) -> Option<Arc<rayon::ThreadPool>> {
        self.pow_pool.as_ref().map(Arc::clone)
    }
}

static PROCESS_CPU_BUDGET: OnceLock<Arc<ProcessCpuBudget>> = OnceLock::new();

fn host_available_threads() -> usize {
    let host = std::thread::available_parallelism()
        .map(|parallelism| parallelism.get())
        .unwrap_or(1)
        .max(1);
    let explicit_rayon_ceiling = std::env::var("RAYON_NUM_THREADS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|threads| *threads > 0);
    explicit_rayon_ceiling
        .map(|ceiling| ceiling.min(host))
        .unwrap_or(host)
}

/// Configure the fixed process pools exactly once. Repeating the same plan is
/// idempotent; attempting to change it after any worker can have started is a
/// startup error. `RAYON_NUM_THREADS`, when it is a positive integer, is an
/// upper bound on the host-visible budget rather than an independent pool.
pub fn configure_process_cpu_budget(
    mode: ProcessCpuBudgetMode,
) -> Result<ProcessCpuBudgetPlan, ProcessCpuBudgetError> {
    let requested = plan_process_cpu_budget(host_available_threads(), mode)?;
    if let Some(active) = PROCESS_CPU_BUDGET.get() {
        return if active.plan == requested {
            Ok(active.plan)
        } else {
            Err(ProcessCpuBudgetError::AlreadyConfigured {
                active: active.plan,
                requested,
            })
        };
    }

    let candidate = Arc::new(ProcessCpuBudget::build(requested)?);
    if PROCESS_CPU_BUDGET.set(candidate).is_err() {
        let active = PROCESS_CPU_BUDGET
            .get()
            .expect("process CPU budget initialized by racing caller");
        if active.plan != requested {
            return Err(ProcessCpuBudgetError::AlreadyConfigured {
                active: active.plan,
                requested,
            });
        }
    }
    tracing::info!(
        available_threads = requested.available_threads,
        pow_threads = requested.pow_threads,
        proof_threads = requested.proof_threads,
        admitted_rayon_threads = requested.admitted_rayon_threads(),
        "process CPU budget configured"
    );
    Ok(requested)
}

/// The active plan, if startup has already configured the process pools.
pub fn configured_process_cpu_budget() -> Option<ProcessCpuBudgetPlan> {
    PROCESS_CPU_BUDGET.get().map(|budget| budget.plan)
}

fn process_cpu_budget_from(
    configured: &OnceLock<Arc<ProcessCpuBudget>>,
) -> Result<Arc<ProcessCpuBudget>, ProcessCpuBudgetError> {
    configured
        .get()
        .map(Arc::clone)
        .ok_or(ProcessCpuBudgetError::NotConfigured)
}

fn process_cpu_budget() -> Result<Arc<ProcessCpuBudget>, ProcessCpuBudgetError> {
    process_cpu_budget_from(&PROCESS_CPU_BUDGET)
}

/// Run one complete selected-history CPU boundary inside the common proof
/// pool. Concurrent Block/Link/Verify calls are work-conserving jobs in the
/// same fixed worker set; this is deliberately not an exclusive proof gate.
pub fn install_selected_history_cpu<R: Send>(
    stage: SelectedHistoryCpuStage,
    operation: impl FnOnce() -> R + Send,
) -> Result<R, ProcessCpuBudgetError> {
    Ok(process_cpu_budget()?.install_history(stage, operation))
}

/// Run arbitrary proof work inside the same fixed process pool as the
/// selected-history lanes. This boundary intentionally has no stage label: it
/// is for native block assembly, template exact-state construction, and local
/// acceptance/verifier work. An unconfigured process fails closed, and a
/// nested call already on one of our workers executes directly.
pub fn install_process_proof_cpu<R: Send>(
    operation: impl FnOnce() -> R + Send,
) -> Result<R, ProcessCpuBudgetError> {
    Ok(process_cpu_budget()?.install_proof(operation))
}

pub(crate) fn process_proof_pool() -> Result<Arc<rayon::ThreadPool>, ProcessCpuBudgetError> {
    Ok(process_cpu_budget()?.proof_pool())
}

pub(crate) fn process_pow_pool() -> Result<Option<Arc<rayon::ThreadPool>>, ProcessCpuBudgetError> {
    Ok(process_cpu_budget()?.pow_pool())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unconfigured_process_budget_fails_closed_without_panicking() {
        let unconfigured = OnceLock::new();
        assert!(matches!(
            process_cpu_budget_from(&unconfigured),
            Err(ProcessCpuBudgetError::NotConfigured)
        ));
    }

    #[test]
    fn twelve_thread_plans_are_exact_and_never_oversubscribed() {
        assert_eq!(
            plan_process_cpu_budget(12, ProcessCpuBudgetMode::ProofOnly).unwrap(),
            ProcessCpuBudgetPlan {
                available_threads: 12,
                pow_threads: 0,
                proof_threads: 12,
            }
        );
        assert_eq!(
            plan_process_cpu_budget(
                12,
                ProcessCpuBudgetMode::InternalMiner { mining_threads: 1 },
            )
            .unwrap(),
            ProcessCpuBudgetPlan {
                available_threads: 12,
                pow_threads: 1,
                proof_threads: 11,
            }
        );
        assert_eq!(
            plan_process_cpu_budget(
                12,
                ProcessCpuBudgetMode::InternalMiner { mining_threads: 0 },
            )
            .unwrap(),
            ProcessCpuBudgetPlan {
                available_threads: 12,
                pow_threads: 1,
                proof_threads: 11,
            }
        );
    }

    #[test]
    fn invalid_library_miner_configuration_fails_instead_of_clamping() {
        assert!(matches!(
            plan_process_cpu_budget(
                12,
                ProcessCpuBudgetMode::InternalMiner { mining_threads: 12 },
            ),
            Err(ProcessCpuBudgetError::InvalidMiningThreads {
                configured: 12,
                available: 12,
            })
        ));
        assert!(matches!(
            plan_process_cpu_budget(1, ProcessCpuBudgetMode::InternalMiner { mining_threads: 0 },),
            Err(ProcessCpuBudgetError::InternalMiningNeedsTwoThreads)
        ));
    }
}
