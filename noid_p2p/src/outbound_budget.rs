// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Process-wide admission for large P2P response payloads.
//!
//! A request-response behaviour owns a response after `send_response`, so a
//! permit stored only in the swarm event loop would be released too early.
//! Large response structs carry their owned permit into the wire codec.  The
//! codec keeps it alive until the final payload write completes (or fails).

use std::{
    io,
    sync::{Arc, OnceLock},
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Aggregate encoded bytes of large responses that may be resident while
/// being prepared, queued, or written, without scaling with peer count.
pub const OUTBOUND_RESPONSE_BUDGET_BYTES: usize = 64 * 1024 * 1024;

pub(crate) type OutboundMemoryPermit = Arc<OwnedSemaphorePermit>;

#[derive(Debug, Clone)]
pub(crate) struct OutboundResponseBudget {
    semaphore: Arc<Semaphore>,
}

impl OutboundResponseBudget {
    /// The single production admission domain shared by every P2P protocol.
    pub(crate) fn process_global() -> Self {
        static BUDGET: OnceLock<Arc<Semaphore>> = OnceLock::new();
        Self {
            semaphore: BUDGET
                .get_or_init(|| Arc::new(Semaphore::new(OUTBOUND_RESPONSE_BUDGET_BYTES)))
                .clone(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_capacity(bytes: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(bytes)),
        }
    }

    pub(crate) async fn acquire(&self, bytes: usize) -> io::Result<Option<OutboundMemoryPermit>> {
        if bytes == 0 {
            return Ok(None);
        }
        let permits = u32::try_from(bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "outbound response byte budget overflow",
            )
        })?;
        let permit = self
            .semaphore
            .clone()
            .acquire_many_owned(permits)
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "outbound response byte budget closed",
                )
            })?;
        Ok(Some(Arc::new(permit)))
    }

    #[cfg(test)]
    pub(crate) fn available_bytes(&self) -> usize {
        self.semaphore.available_permits()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    #[tokio::test]
    async fn second_payload_is_not_allocated_until_first_permit_drops() {
        let budget = OutboundResponseBudget::with_capacity(12);
        let first = budget.acquire(12).await.unwrap().unwrap();
        assert_eq!(budget.available_bytes(), 0);
        let allocated = Arc::new(AtomicBool::new(false));
        let second_budget = budget.clone();
        let second_allocated = allocated.clone();
        let second = tokio::spawn(async move {
            let permit = second_budget.acquire(12).await.unwrap().unwrap();
            // Payload allocation belongs after admission.  This flag stands in
            // for the storage read/Vec allocation in the network workers.
            let payload = vec![0u8; 12];
            second_allocated.store(true, Ordering::SeqCst);
            (permit, payload)
        });

        tokio::task::yield_now().await;
        assert!(!allocated.load(Ordering::SeqCst));
        assert!(!second.is_finished());
        drop(first);

        let (_permit, payload) = tokio::time::timeout(std::time::Duration::from_secs(1), second)
            .await
            .expect("second response must be admitted after release")
            .unwrap();
        assert_eq!(payload.len(), 12);
        assert!(allocated.load(Ordering::SeqCst));
    }
}
