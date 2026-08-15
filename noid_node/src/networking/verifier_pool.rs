// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Bounded off-reactor verification jobs and exact-object capabilities.

use std::{fmt, sync::Arc};

use tokio::sync::Semaphore;

use super::types::{ObjectId, PlanId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationClass {
    Live,
    Historical,
    Snapshot,
}

/// Proof that the supplied verifier accepted one exact object for one exact
/// immutable plan. Private fields prevent transport code from manufacturing it.
#[derive(Debug)]
pub struct VerifiedObject {
    plan_id: PlanId,
    object: ObjectId,
}

impl VerifiedObject {
    pub const fn plan_id(&self) -> PlanId {
        self.plan_id
    }

    pub const fn object(&self) -> ObjectId {
        self.object
    }
}

#[derive(Debug)]
pub enum VerificationError<E> {
    PoolClosed,
    WorkerPanicked(String),
    Rejected(E),
}

impl<E: fmt::Display> fmt::Display for VerificationError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PoolClosed => formatter.write_str("verification pool is closed"),
            Self::WorkerPanicked(message) => {
                write!(formatter, "verification worker failed: {message}")
            }
            Self::Rejected(error) => write!(formatter, "object verification rejected: {error}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for VerificationError<E> {}

/// The network reactor submits bounded descriptors here; CPU-heavy native or
/// recursive verification always executes on a blocking worker.
pub struct VerifierPool {
    all: Arc<Semaphore>,
    live: Arc<Semaphore>,
    historical: Arc<Semaphore>,
    snapshot: Arc<Semaphore>,
}

impl VerifierPool {
    pub fn new(
        total_concurrency: usize,
        live_concurrency: usize,
        historical_concurrency: usize,
        snapshot_concurrency: usize,
    ) -> Self {
        assert!(total_concurrency > 0);
        assert!(live_concurrency > 0);
        assert!(historical_concurrency > 0);
        assert!(snapshot_concurrency > 0);
        Self {
            all: Arc::new(Semaphore::new(total_concurrency)),
            live: Arc::new(Semaphore::new(live_concurrency)),
            historical: Arc::new(Semaphore::new(historical_concurrency)),
            snapshot: Arc::new(Semaphore::new(snapshot_concurrency)),
        }
    }

    pub async fn verify<F, E>(
        &self,
        class: VerificationClass,
        plan_id: PlanId,
        object: ObjectId,
        verifier: F,
    ) -> Result<VerifiedObject, VerificationError<E>>
    where
        F: FnOnce() -> Result<(), E> + Send + 'static,
        E: Send + 'static,
    {
        let class_semaphore = match class {
            VerificationClass::Live => Arc::clone(&self.live),
            VerificationClass::Historical => Arc::clone(&self.historical),
            VerificationClass::Snapshot => Arc::clone(&self.snapshot),
        };
        let _global_permit = Arc::clone(&self.all)
            .acquire_owned()
            .await
            .map_err(|_| VerificationError::PoolClosed)?;
        let _class_permit = class_semaphore
            .acquire_owned()
            .await
            .map_err(|_| VerificationError::PoolClosed)?;
        tokio::task::spawn_blocking(verifier)
            .await
            .map_err(|error| VerificationError::WorkerPanicked(error.to_string()))?
            .map_err(VerificationError::Rejected)?;
        Ok(VerifiedObject { plan_id, object })
    }

    pub fn available_global_permits(&self) -> usize {
        self.all.available_permits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::networking::types::{BlockBodyClaimId, BlockBodyObjectId, ObjectId};

    fn object() -> ObjectId {
        let claim = BlockBodyClaimId {
            height: 1,
            block_hash: [1; 32],
        };
        ObjectId::BlockBody(BlockBodyObjectId {
            claim,
            byte_digest: [2; 32],
            encoded_len: 3,
        })
    }

    #[tokio::test]
    async fn capability_binds_exact_plan_and_object() {
        let pool = VerifierPool::new(2, 1, 1, 1);
        let plan_id = PlanId([7; 32]);
        let exact_object = object();
        let verified = pool
            .verify(VerificationClass::Live, plan_id, exact_object, || {
                Ok::<_, &'static str>(())
            })
            .await
            .unwrap();
        assert_eq!(verified.plan_id(), plan_id);
        assert_eq!(verified.object(), exact_object);
    }

    #[tokio::test]
    async fn rejected_verifier_never_returns_a_capability() {
        let pool = VerifierPool::new(1, 1, 1, 1);
        let result = pool
            .verify(VerificationClass::Live, PlanId([0; 32]), object(), || {
                Err::<(), _>("invalid terminal")
            })
            .await;
        assert!(matches!(
            result,
            Err(VerificationError::Rejected("invalid terminal"))
        ));
    }
}
