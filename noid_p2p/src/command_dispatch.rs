// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Bounded priority dispatch from the node to the swarm reactor.

use std::future::{ready, Ready};

use tokio::sync::mpsc;

use crate::network::{NetworkCommand, NetworkCommand::*};

// These are independent capacities. Saturating bulk transfers therefore
// cannot consume the slots reserved for topology/fork-control or headers.
const CONTROL_CAPACITY: usize = 128;
const HEADER_CAPACITY: usize = 128;
const DATA_CAPACITY: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommandClass {
    Control,
    Header,
    Data,
}

impl CommandClass {
    const fn index(self) -> usize {
        match self {
            Self::Control => 0,
            Self::Header => 1,
            Self::Data => 2,
        }
    }
}

/// Cloneable node-side handle. Its `send` API deliberately mirrors a Tokio
/// sender so existing producers do not need to know which physical lane owns
/// a command.
#[derive(Clone)]
pub struct NetworkCommandSender {
    control: mpsc::Sender<NetworkCommand>,
    header: mpsc::Sender<NetworkCommand>,
    data: mpsc::Sender<NetworkCommand>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CommandQueueDepths {
    pub control: usize,
    pub header: usize,
    pub data: usize,
}

impl CommandQueueDepths {
    pub const fn total(self) -> usize {
        self.control + self.header + self.data
    }
}

pub(crate) struct NetworkCommandReceiver {
    control: mpsc::Receiver<NetworkCommand>,
    header: mpsc::Receiver<NetworkCommand>,
    data: mpsc::Receiver<NetworkCommand>,
    closed: [bool; 3],
    schedule_cursor: usize,
}

pub(crate) fn channel() -> (NetworkCommandSender, NetworkCommandReceiver) {
    let (control_tx, control_rx) = mpsc::channel(CONTROL_CAPACITY);
    let (header_tx, header_rx) = mpsc::channel(HEADER_CAPACITY);
    let (data_tx, data_rx) = mpsc::channel(DATA_CAPACITY);
    (
        NetworkCommandSender {
            control: control_tx,
            header: header_tx,
            data: data_tx,
        },
        NetworkCommandReceiver {
            control: control_rx,
            header: header_rx,
            data: data_rx,
            closed: [false; 3],
            schedule_cursor: 0,
        },
    )
}

impl NetworkCommandSender {
    /// Compatibility surface for existing async callers. Dispatch is always
    /// immediate: the sole node event loop must never await swarm capacity.
    /// A full lane is returned to the caller so its owning planner can leave
    /// the exact job Wanted and retry it later.
    pub fn send(
        &self,
        command: NetworkCommand,
    ) -> Ready<Result<(), mpsc::error::TrySendError<NetworkCommand>>> {
        ready(self.try_send(command))
    }

    pub fn try_send(
        &self,
        command: NetworkCommand,
    ) -> Result<(), mpsc::error::TrySendError<NetworkCommand>> {
        match classify(&command) {
            CommandClass::Control => self.control.try_send(command),
            CommandClass::Header => self.header.try_send(command),
            CommandClass::Data => self.data.try_send(command),
        }
    }
}

impl NetworkCommandReceiver {
    pub(crate) fn is_closed(&self) -> bool {
        self.closed.into_iter().all(|closed| closed)
    }

    pub(crate) fn queue_depths(&self) -> CommandQueueDepths {
        CommandQueueDepths {
            control: self.control.len(),
            header: self.header.len(),
            data: self.data.len(),
        }
    }

    /// Work-conserving weighted priority. Control receives half the schedule,
    /// headers one quarter, and bulk data one quarter. Empty higher-priority
    /// lanes never prevent lower-priority progress.
    pub(crate) fn try_recv(&mut self) -> Result<NetworkCommand, mpsc::error::TryRecvError> {
        const SCHEDULE: [CommandClass; 8] = [
            CommandClass::Control,
            CommandClass::Header,
            CommandClass::Control,
            CommandClass::Data,
            CommandClass::Control,
            CommandClass::Header,
            CommandClass::Control,
            CommandClass::Data,
        ];

        for offset in 0..SCHEDULE.len() {
            let index = (self.schedule_cursor + offset) % SCHEDULE.len();
            let class = SCHEDULE[index];
            let result = match class {
                CommandClass::Control => self.control.try_recv(),
                CommandClass::Header => self.header.try_recv(),
                CommandClass::Data => self.data.try_recv(),
            };
            match result {
                Ok(command) => {
                    self.schedule_cursor = (index + 1) % SCHEDULE.len();
                    return Ok(command);
                }
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    self.closed[class.index()] = true;
                }
                Err(mpsc::error::TryRecvError::Empty) => {}
            }
        }

        if self.is_closed() {
            Err(mpsc::error::TryRecvError::Disconnected)
        } else {
            Err(mpsc::error::TryRecvError::Empty)
        }
    }

    pub(crate) async fn recv(&mut self) -> Option<NetworkCommand> {
        loop {
            if let Ok(command) = self.try_recv() {
                return Some(command);
            }
            if self.is_closed() {
                return None;
            }

            tokio::select! {
                biased;
                command = self.control.recv(), if !self.closed[CommandClass::Control.index()] => {
                    if let Some(command) = command { return Some(command); }
                    self.closed[CommandClass::Control.index()] = true;
                }
                command = self.header.recv(), if !self.closed[CommandClass::Header.index()] => {
                    if let Some(command) = command { return Some(command); }
                    self.closed[CommandClass::Header.index()] = true;
                }
                command = self.data.recv(), if !self.closed[CommandClass::Data.index()] => {
                    if let Some(command) = command { return Some(command); }
                    self.closed[CommandClass::Data.index()] = true;
                }
            }
        }
    }
}

fn classify(command: &NetworkCommand) -> CommandClass {
    match command {
        Dial { .. }
        | BootstrapComplete
        | PeerCount { .. }
        | AdvanceSnapshotGeneration { .. }
        | CancelHistoryStepTerminalRace { .. } => CommandClass::Control,
        AnnounceBlock { .. } | AnnounceAvailability { .. } | FetchHeaders { .. } => {
            CommandClass::Header
        }
        BroadcastTx { .. }
        | FetchObjects { .. }
        | FetchSnapshotHeaders { .. }
        | RequestStateManifest { .. }
        | RequestStateSegment { .. }
        | RequestHistoryStepTerminal { .. }
        | RequestMempoolSync { .. } => CommandClass::Data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::PeerId;

    fn data_command() -> NetworkCommand {
        RequestMempoolSync {
            peer: PeerId::random(),
        }
    }

    #[test]
    fn saturated_data_lane_cannot_consume_control_or_header_capacity() {
        let (tx, _rx) = channel();
        for _ in 0..DATA_CAPACITY {
            tx.try_send(data_command()).unwrap();
        }
        assert!(matches!(
            tx.try_send(data_command()),
            Err(mpsc::error::TrySendError::Full(_))
        ));

        let (reply, _reply_rx) = tokio::sync::oneshot::channel();
        tx.try_send(PeerCount { reply }).unwrap();
        tx.try_send(FetchHeaders {
            peer: PeerId::random(),
            start_height: 1,
            count: 1,
        })
        .unwrap();
    }

    #[tokio::test]
    async fn compatibility_send_never_waits_for_a_full_data_lane() {
        let (tx, _rx) = channel();
        for _ in 0..DATA_CAPACITY {
            tx.try_send(data_command()).unwrap();
        }
        assert!(matches!(
            tx.send(data_command()).await,
            Err(mpsc::error::TrySendError::Full(_))
        ));
    }

    #[test]
    fn control_is_drained_before_existing_bulk_work() {
        let (tx, mut rx) = channel();
        tx.try_send(data_command()).unwrap();
        let (reply, _reply_rx) = tokio::sync::oneshot::channel();
        tx.try_send(PeerCount { reply }).unwrap();

        assert!(matches!(rx.try_recv().unwrap(), PeerCount { .. }));
        assert!(matches!(rx.try_recv().unwrap(), RequestMempoolSync { .. }));
    }

    #[test]
    fn queue_depths_are_reported_per_lane() {
        let (tx, rx) = channel();
        let (reply, _reply_rx) = tokio::sync::oneshot::channel();
        tx.try_send(PeerCount { reply }).unwrap();
        tx.try_send(FetchHeaders {
            peer: PeerId::random(),
            start_height: 1,
            count: 1,
        })
        .unwrap();
        tx.try_send(data_command()).unwrap();

        assert_eq!(
            rx.queue_depths(),
            CommandQueueDepths {
                control: 1,
                header: 1,
                data: 1,
            }
        );
    }
}
