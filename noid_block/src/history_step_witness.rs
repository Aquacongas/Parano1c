// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! One-shot, nonce-independent HistoryStep witness preparation.

use noid_chain::consensus::{
    validate_block_checks, validate_block_epoch_anchors, validate_block_resource_preflight,
    validate_mandatory_coinbase, validate_tx_consensus, AnchorInfo, ConsensusError,
};
use noid_chain::exact_state_hash::{slot_leaf_hash, StateHash};
use noid_chain::sparse_merkle::{
    derive_structural_frontier_plan, evaluate_structural_frontier, SparseMerkleError,
};
use noid_chain::state::{ChainState, ExactFrontierError};
use noid_chain::{
    build_exact_action_surface_for_transactions_at_log_slots, compute_tx_root, Block, BlockHeader,
    StateDeltaError,
};
use noid_core::{Block128, TowerField};
use noid_gkr::zk_authorization::ZkAuthorizationProof;
use noid_gkr::{
    canonical_authorization_statement_from_body, spine_inputs_from_body, MerklePathInputs,
    OwnerAuthStatementError, SlotLeafInputs, MAX_MERKLE_DEPTH,
};
use noid_poseidon2b::native::compress;
use noid_recursive::acceptance::history_step::{
    prepare_history_step_authorizations, prepare_history_step_for_pow,
    HistoryStepAuthorizationError, HistoryStepBlockInput, HistoryStepError, HistoryStepInputError,
    HistoryStepRuntime, HistoryStepTerminal, PreparedHistoryStepAuthorizations,
    PreparedHistoryStepForPow, PreparedHistoryStepGhostAuthorization,
};
use noid_recursive::{
    AuthorizationComponentInput, ChainAccumulator, ChainAccumulatorAdvanceError,
    ChainAccumulatorLocalBoundaryError, ExactStateStructuralFrontierInputs,
    HistoryStepBlockComponents,
};
use noid_tx::PublicLogicError;

/// Native chain data that fixes one mining template to its current parent.
///
/// Every reference is consumed during preparation. The resulting capability
/// owns the immutable consensus context plus the staged recursive witness; it
/// never retains the mutable parent state.
pub struct HistoryStepPreparationContext<'a> {
    pub parent_header: &'a BlockHeader,
    pub tx_epoch_anchor_header: &'a BlockHeader,
    pub parent_state: &'a ChainState,
    pub start_accumulator: &'a ChainAccumulator,
    pub previous_timestamps: &'a [u64],
    pub previous_active_counts: &'a [u64],
    pub asert_anchor: &'a AnchorInfo,
    pub local_time: u64,
}

struct PreparedNativeHistoryStep<const TIER: usize> {
    template: Block,
    parent_header: BlockHeader,
    expected_start: ChainAccumulator,
    previous_timestamps: Vec<u64>,
    previous_active_counts: Vec<u64>,
    asert_anchor: AnchorInfo,
    local_time: u64,
    components: HistoryStepBlockComponents,
    authorizations: PreparedHistoryStepAuthorizations,
}

/// Release-freezer handoff that delays only the complete HistoryStep input;
/// production mining uses [`PreparedHistoryStepWitness`] instead.
#[doc(hidden)]
#[must_use = "dropping the prepared input cancels this freezer fixture"]
pub struct PreparedHistoryStepInputWitness<const TIER: usize> {
    native: PreparedNativeHistoryStep<TIER>,
}

/// The sole hot handoff between template construction, PoW and HistoryStep.
///
/// This type is deliberately neither `Clone` nor serializable. Dropping it
/// cancels the block attempt and drops its already-verified authorization
/// authority; finishing it consumes that authority exactly once.
#[must_use = "dropping the prepared witness cancels this block attempt"]
pub struct PreparedHistoryStepWitness<const TIER: usize> {
    template: Block,
    parent_header: BlockHeader,
    expected_start: ChainAccumulator,
    previous_timestamps: Vec<u64>,
    previous_active_counts: Vec<u64>,
    asert_anchor: AnchorInfo,
    local_time: u64,
    prepared_history_step: PreparedHistoryStepForPow<TIER>,
}

impl<const TIER: usize> PreparedHistoryStepInputWitness<TIER> {
    pub fn finish(
        self,
        nonce: u128,
        start_accumulator: &ChainAccumulator,
        end_accumulator: &ChainAccumulator,
    ) -> Result<(Block, HistoryStepBlockInput<TIER>), HistoryStepWitnessError> {
        let PreparedNativeHistoryStep {
            mut template,
            parent_header,
            expected_start,
            previous_timestamps,
            previous_active_counts,
            asert_anchor,
            local_time,
            components,
            authorizations,
        } = self.native;
        if start_accumulator != &expected_start {
            return Err(HistoryStepWitnessError::StartAccumulatorChanged);
        }
        template.header.nonce = nonce;
        validate_block_checks(
            &template,
            &parent_header,
            &previous_timestamps,
            &previous_active_counts,
            local_time,
            &asert_anchor,
        )?;
        let expected_end = start_accumulator
            .advance(&parent_header, &template.header)
            .map_err(HistoryStepWitnessError::AccumulatorAdvance)?;
        if end_accumulator != &expected_end {
            return Err(HistoryStepWitnessError::EndAccumulatorMismatch);
        }
        let input = HistoryStepBlockInput::try_new(
            start_accumulator,
            end_accumulator,
            components,
            authorizations,
            &template.header,
            &parent_header,
        )?;
        Ok((template, input))
    }
}

impl<const TIER: usize> PreparedHistoryStepWitness<TIER> {
    /// Exact PoW header for this node-owned template and a candidate nonce.
    /// No other semantic field can be changed after witness preparation.
    pub fn header_for_nonce(&self, nonce: u128) -> BlockHeader {
        let mut header = self.template.header;
        header.nonce = nonce;
        header
    }

    pub fn user_transaction_count(&self) -> usize {
        self.template.transactions.len().saturating_sub(1)
    }

    pub fn retained_witness_bytes(&self) -> usize {
        self.prepared_history_step.retained_witness_bytes()
    }

    /// Run every native consensus check of the exact template except proof
    /// of work, and consume the prepared authority into the complete
    /// nonce-free recursive witness.
    ///
    /// The relation and terminal bind the semantic projection, so the block
    /// can be proven before PoW; the caller seals the winning nonce with one
    /// native `validate_pow` and commits the `(block, terminal)` bundle
    /// atomically. The returned end boundary is final for every nonce.
    pub fn finish_template(
        self,
        runtime: &HistoryStepRuntime,
    ) -> Result<
        (
            Block,
            noid_recursive::BuiltHistoryStep,
            ChainAccumulator,
        ),
        HistoryStepWitnessError,
    > {
        let Self {
            template,
            parent_header,
            expected_start,
            previous_timestamps,
            previous_active_counts,
            asert_anchor,
            local_time,
            prepared_history_step,
        } = self;

        noid_chain::consensus::validation::validate_block_checks_template(
            &template,
            &parent_header,
            &previous_timestamps,
            &previous_active_counts,
            local_time,
            &asert_anchor,
        )?;

        let end_accumulator = expected_start
            .advance(&parent_header, &template.header)
            .map_err(HistoryStepWitnessError::AccumulatorAdvance)?;

        let built = prepared_history_step.seal_nonce(runtime, template.header.nonce)?;
        if built.semantic_id() != end_accumulator.tip_semantic_id {
            return Err(HistoryStepWitnessError::EndAccumulatorMismatch);
        }
        Ok((template, built, end_accumulator))
    }
}

/// Prepare every nonce-independent component for one node-owned block
/// template, including live authorization verification and the exact-state
/// sibling frontier. This path is identical for coinbase-only and tx-bearing
/// blocks.
pub fn prepare_history_step_witness<const TIER: usize>(
    template: Block,
    context: HistoryStepPreparationContext<'_>,
    live_authorization_proofs: Vec<ZkAuthorizationProof>,
    ghost_authorization: &PreparedHistoryStepGhostAuthorization,
    runtime: &HistoryStepRuntime,
    parent_terminal: Option<&HistoryStepTerminal>,
) -> Result<PreparedHistoryStepWitness<TIER>, HistoryStepWitnessError> {
    let native = prepare_native_history_step::<TIER>(
        template,
        context,
        live_authorization_proofs,
        ghost_authorization,
    )?;
    let PreparedNativeHistoryStep {
        template,
        parent_header,
        expected_start,
        previous_timestamps,
        previous_active_counts,
        asert_anchor,
        local_time,
        components,
        authorizations,
    } = native;
    // The relation is nonce-free: the template advance is already the exact
    // final boundary for every nonce of this template.
    let template_end = expected_start
        .advance(&parent_header, &template.header)
        .map_err(HistoryStepWitnessError::AccumulatorAdvance)?;
    let current = HistoryStepBlockInput::try_new(
        &expected_start,
        &template_end,
        components,
        authorizations,
        &template.header,
        &parent_header,
    )?;
    let prepared_history_step = prepare_history_step_for_pow(runtime, parent_terminal, current)?;
    Ok(PreparedHistoryStepWitness {
        template,
        parent_header,
        expected_start,
        previous_timestamps,
        previous_active_counts,
        asert_anchor,
        local_time,
        prepared_history_step,
    })
}

/// Release tooling twin that produces the complete sealed input without a
/// runtime matrix. It is intentionally separate from production mining.
#[doc(hidden)]
pub fn prepare_history_step_input_witness<const TIER: usize>(
    template: Block,
    context: HistoryStepPreparationContext<'_>,
    live_authorization_proofs: Vec<ZkAuthorizationProof>,
    ghost_authorization: &PreparedHistoryStepGhostAuthorization,
) -> Result<PreparedHistoryStepInputWitness<TIER>, HistoryStepWitnessError> {
    Ok(PreparedHistoryStepInputWitness {
        native: prepare_native_history_step::<TIER>(
            template,
            context,
            live_authorization_proofs,
            ghost_authorization,
        )?,
    })
}

fn prepare_native_history_step<const TIER: usize>(
    template: Block,
    context: HistoryStepPreparationContext<'_>,
    live_authorization_proofs: Vec<ZkAuthorizationProof>,
    ghost_authorization: &PreparedHistoryStepGhostAuthorization,
) -> Result<PreparedNativeHistoryStep<TIER>, HistoryStepWitnessError> {
    if template.header.nonce != 0 {
        return Err(HistoryStepWitnessError::TemplateNonceNotZero);
    }

    context
        .start_accumulator
        .validate_local_header_boundary(context.parent_header, context.tx_epoch_anchor_header)
        .map_err(HistoryStepWitnessError::StartBoundary)?;
    validate_parent_state_boundary(context.parent_header, context.parent_state)?;
    validate_nonce_independent_block(&template, &context)?;

    let components = build_history_step_components(&template, context.parent_state)?;
    let actual_tier =
        noid_chain::consensus::params::user_tx_class_tier(components.authorization_inputs.len());
    if actual_tier != Some(TIER) {
        return Err(HistoryStepWitnessError::WrongTier {
            expected: TIER,
            actual: actual_tier,
            user_transactions: components.authorization_inputs.len(),
        });
    }
    let authorizations = prepare_history_step_authorizations::<TIER>(
        &components.authorization_inputs,
        live_authorization_proofs,
        ghost_authorization,
    )?;
    Ok(PreparedNativeHistoryStep {
        template,
        parent_header: *context.parent_header,
        expected_start: context.start_accumulator.clone(),
        previous_timestamps: context.previous_timestamps.to_vec(),
        previous_active_counts: context.previous_active_counts.to_vec(),
        asert_anchor: context.asert_anchor.clone(),
        local_time: context.local_time,
        components,
        authorizations,
    })
}

fn validate_parent_state_boundary(
    parent: &BlockHeader,
    state: &ChainState,
) -> Result<(), HistoryStepWitnessError> {
    if state.cached_state_root() != parent.state_root {
        return Err(HistoryStepWitnessError::ParentStateBoundary("state_root"));
    }
    if state.state.log_slots() as u32 != parent.log_slots {
        return Err(HistoryStepWitnessError::ParentStateBoundary("log_slots"));
    }
    if state.active_slot_count != parent.active_slot_count {
        return Err(HistoryStepWitnessError::ParentStateBoundary(
            "active_slot_count",
        ));
    }
    if state.alloc_counter != parent.alloc_counter {
        return Err(HistoryStepWitnessError::ParentStateBoundary(
            "alloc_counter",
        ));
    }
    Ok(())
}

fn validate_nonce_independent_block(
    block: &Block,
    context: &HistoryStepPreparationContext<'_>,
) -> Result<(), HistoryStepWitnessError> {
    if block.header.prev_block_hash != noid_chain::hash_block_header(context.parent_header)
        || context
            .start_accumulator
            .height
            .checked_add(1)
            .is_none_or(|height| block.header.height != height)
    {
        return Err(HistoryStepWitnessError::TemplateParentMismatch);
    }
    validate_block_resource_preflight(block)?;
    validate_mandatory_coinbase(block, context.parent_header)?;
    noid_chain::consensus::checks::validate_block_slot_conflicts(&block.transactions)?;
    for (tx_index, transaction) in block.transactions.iter().enumerate() {
        validate_tx_consensus(transaction)?;
        if !transaction.body.is_coinbase {
            noid_tx::validate_public_tx_logic(&transaction.body).map_err(|source| {
                HistoryStepWitnessError::TransactionPublicLogic { tx_index, source }
            })?;
        }
    }
    let parent_block_id = noid_chain::hash_block_header(context.parent_header);
    let user_epoch_anchor = if context
        .start_accumulator
        .height
        .is_multiple_of(noid_chain::consensus::params::TX_EPOCH_BLOCKS)
    {
        parent_block_id
    } else {
        context.start_accumulator.epoch_anchor_id
    };
    validate_block_epoch_anchors(block, user_epoch_anchor, parent_block_id)?;
    if block.header.tx_root != compute_tx_root(&block.transactions) {
        return Err(HistoryStepWitnessError::TransactionRootMismatch);
    }
    Ok(())
}

fn build_history_step_components(
    block: &Block,
    parent_state: &ChainState,
) -> Result<HistoryStepBlockComponents, HistoryStepWitnessError> {
    let body_hashes = block
        .transactions
        .iter()
        .map(|transaction| transaction.txid().0)
        .collect::<Vec<_>>();
    let tx_body_inputs = block
        .transactions
        .iter()
        .map(|transaction| spine_inputs_from_body(&transaction.body))
        .collect();
    let tx_body_hashes = body_hashes.iter().copied().map(digest_to_fields).collect();
    let tx_root_inputs = tx_root_merkle_inputs(block, &body_hashes)?;

    let mut authorization_inputs = Vec::with_capacity(block.transactions.len().saturating_sub(1));
    for (tx_index, transaction) in block.transactions.iter().enumerate() {
        if transaction.body.is_coinbase {
            continue;
        }
        let statement = canonical_authorization_statement_from_body(
            tx_index,
            transaction.txid().as_fields(),
            &transaction.body,
        )
        .map_err(|source| HistoryStepWitnessError::AuthorizationStatement { tx_index, source })?;
        authorization_inputs.push(AuthorizationComponentInput {
            block_index: 0,
            tx_index: statement.tx_index,
            tx_body_hash: statement.tx_body_hash,
            live_input_count: statement.live_input_count,
            public: statement.public,
        });
    }

    Ok(HistoryStepBlockComponents {
        tx_body_inputs,
        tx_body_hashes,
        tx_root_inputs,
        authorization_inputs,
        exact_state: build_exact_state_frontier(block, parent_state)?,
    })
}

fn build_exact_state_frontier(
    block: &Block,
    parent_state: &ChainState,
) -> Result<ExactStateStructuralFrontierInputs, HistoryStepWitnessError> {
    let surface = build_exact_action_surface_for_transactions_at_log_slots(
        &parent_state.state,
        block.header.log_slots,
        &block.transactions,
        parent_state.alloc_counter,
        block.header.height,
    )?;
    if surface.touched_indices.is_empty() {
        return Err(HistoryStepWitnessError::EmptyExactStateSurface);
    }

    let (siblings, expected_old_root) = match block
        .header
        .log_slots
        .cmp(&(parent_state.state.log_slots() as u32))
    {
        std::cmp::Ordering::Equal => (
            parent_state
                .exact_frontier_siblings(&surface.touched_indices, block.header.log_slots)?,
            parent_state.cached_state_root(),
        ),
        std::cmp::Ordering::Greater
            if block.header.log_slots == parent_state.state.log_slots() as u32 + 1 =>
        {
            let mut expanded = parent_state.clone();
            expanded.expand_one();
            (
                expanded
                    .exact_frontier_siblings(&surface.touched_indices, block.header.log_slots)?,
                expanded.cached_state_root(),
            )
        }
        _ => return Err(HistoryStepWitnessError::InvalidStateDepthTransition),
    };

    let plan = derive_structural_frontier_plan(&surface.touched_indices, block.header.log_slots)?;
    let old_hashes = surface
        .old_slots
        .iter()
        .copied()
        .map(slot_leaf_hash)
        .collect::<Vec<_>>();
    let new_hashes = surface
        .new_slots
        .iter()
        .copied()
        .map(slot_leaf_hash)
        .collect::<Vec<_>>();
    let old_evaluation = evaluate_structural_frontier(&plan, &old_hashes, &siblings)?;
    if old_evaluation.root != expected_old_root {
        return Err(HistoryStepWitnessError::ParentStateRootMismatch);
    }
    let new_evaluation = evaluate_structural_frontier(&plan, &new_hashes, &siblings)?;
    if new_evaluation.root != block.header.state_root {
        return Err(HistoryStepWitnessError::ChildStateRootMismatch);
    }

    let expected_active = parent_state
        .active_slot_count
        .checked_sub(u64::from(surface.spends))
        .and_then(|count| count.checked_add(u64::from(surface.mints)))
        .ok_or(HistoryStepWitnessError::StateCounterOverflow)?;
    if expected_active != block.header.active_slot_count {
        return Err(HistoryStepWitnessError::ActiveSlotCountMismatch);
    }
    let expected_alloc = parent_state
        .alloc_counter
        .checked_add(u64::from(surface.mints))
        .ok_or(HistoryStepWitnessError::StateCounterOverflow)?;
    if expected_alloc != block.header.alloc_counter {
        return Err(HistoryStepWitnessError::AllocCounterMismatch);
    }

    Ok(ExactStateStructuralFrontierInputs {
        touched_indices: surface.touched_indices,
        active_depth: block.header.log_slots,
        old_slot_leaves: surface.old_slots.into_iter().map(slot_leaf_input).collect(),
        new_slot_leaves: surface.new_slots.into_iter().map(slot_leaf_input).collect(),
        live_sibling_digests: siblings,
        old_combine_digests: old_evaluation.combines,
        new_combine_digests: new_evaluation.combines,
        old_root: expected_old_root,
        new_root: block.header.state_root,
    })
}

fn slot_leaf_input(slot: noid_chain::SlotValue) -> SlotLeafInputs {
    SlotLeafInputs {
        packed_value: slot.value,
        owner_hi: slot.owner_hi,
        owner_lo: slot.owner_lo,
        expected_leaf: digest_to_fields(slot_leaf_hash(slot)),
    }
}

fn tx_root_merkle_inputs(
    block: &Block,
    body_hashes: &[[u8; 32]],
) -> Result<Vec<MerklePathInputs>, HistoryStepWitnessError> {
    if body_hashes.len() != block.transactions.len() || body_hashes.is_empty() {
        return Err(HistoryStepWitnessError::TransactionRootMismatch);
    }
    let leaf_capacity = noid_chain::tx_tree::TX_TREE_LEAVES;
    let depth = noid_chain::tx_tree::TX_TREE_DEPTH;
    if body_hashes.len() > leaf_capacity || depth > MAX_MERKLE_DEPTH {
        return Err(HistoryStepWitnessError::TransactionRootMismatch);
    }

    let mut levels = Vec::with_capacity(depth + 1);
    let mut level = body_hashes.to_vec();
    level.resize(leaf_capacity, [0u8; 32]);
    levels.push(level.clone());
    while level.len() > 1 {
        level = level
            .chunks_exact(2)
            .map(|pair| compress(&pair[0], &pair[1]))
            .collect();
        levels.push(level.clone());
    }

    let root = levels[depth][0];
    if noid_chain::tx_tree::bind_tx_count(root, body_hashes.len()) != block.header.tx_root {
        return Err(HistoryStepWitnessError::TransactionRootMismatch);
    }
    let expected_root = digest_to_fields(root);
    let mut inputs = Vec::with_capacity(body_hashes.len());
    for leaf_index in 0..body_hashes.len() {
        let mut siblings = [[Block128::ZERO; 2]; MAX_MERKLE_DEPTH];
        let mut directions = [false; MAX_MERKLE_DEPTH];
        let mut index = leaf_index;
        for level_index in 0..depth {
            siblings[level_index] = digest_to_fields(levels[level_index][index ^ 1]);
            directions[level_index] = index & 1 == 1;
            index >>= 1;
        }
        inputs.push(MerklePathInputs {
            leaf: digest_to_fields(levels[0][leaf_index]),
            siblings,
            directions,
            expected_root,
            active_depth: depth,
        });
    }
    Ok(inputs)
}

fn digest_to_fields(digest: StateHash) -> [Block128; 2] {
    [
        Block128::from(u128::from_le_bytes(digest[..16].try_into().unwrap())),
        Block128::from(u128::from_le_bytes(digest[16..].try_into().unwrap())),
    ]
}

#[derive(Debug)]
pub enum HistoryStepWitnessError {
    TemplateNonceNotZero,
    TemplateParentMismatch,
    WrongTier {
        expected: usize,
        actual: Option<usize>,
        user_transactions: usize,
    },
    StartBoundary(ChainAccumulatorLocalBoundaryError),
    ParentStateBoundary(&'static str),
    Consensus(ConsensusError),
    TransactionPublicLogic {
        tx_index: usize,
        source: PublicLogicError,
    },
    AuthorizationStatement {
        tx_index: usize,
        source: OwnerAuthStatementError,
    },
    Authorization(HistoryStepAuthorizationError),
    StateSurface(StateDeltaError),
    StateFrontier(ExactFrontierError),
    SparseMerkle(SparseMerkleError),
    TransactionRootMismatch,
    EmptyExactStateSurface,
    InvalidStateDepthTransition,
    ParentStateRootMismatch,
    ChildStateRootMismatch,
    ActiveSlotCountMismatch,
    AllocCounterMismatch,
    StateCounterOverflow,
    StartAccumulatorChanged,
    AccumulatorAdvance(ChainAccumulatorAdvanceError),
    EndAccumulatorMismatch,
    RecursiveInput(HistoryStepInputError),
    Recursive(HistoryStepError),
}

impl From<ConsensusError> for HistoryStepWitnessError {
    fn from(source: ConsensusError) -> Self {
        Self::Consensus(source)
    }
}

impl From<HistoryStepAuthorizationError> for HistoryStepWitnessError {
    fn from(source: HistoryStepAuthorizationError) -> Self {
        Self::Authorization(source)
    }
}

impl From<StateDeltaError> for HistoryStepWitnessError {
    fn from(source: StateDeltaError) -> Self {
        Self::StateSurface(source)
    }
}

impl From<ExactFrontierError> for HistoryStepWitnessError {
    fn from(source: ExactFrontierError) -> Self {
        Self::StateFrontier(source)
    }
}

impl From<SparseMerkleError> for HistoryStepWitnessError {
    fn from(source: SparseMerkleError) -> Self {
        Self::SparseMerkle(source)
    }
}

impl From<HistoryStepInputError> for HistoryStepWitnessError {
    fn from(source: HistoryStepInputError) -> Self {
        Self::RecursiveInput(source)
    }
}

impl From<HistoryStepError> for HistoryStepWitnessError {
    fn from(source: HistoryStepError) -> Self {
        Self::Recursive(source)
    }
}

impl std::fmt::Display for HistoryStepWitnessError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TemplateNonceNotZero => {
                formatter.write_str("HistoryStep template nonce must be zero before PoW")
            }
            Self::TemplateParentMismatch => {
                formatter.write_str("HistoryStep template does not extend its prepared parent")
            }
            Self::WrongTier {
                expected,
                actual,
                user_transactions,
            } => write!(
                formatter,
                "HistoryStep B{expected} cannot hold {user_transactions} user transactions (canonical tier {actual:?})",
            ),
            Self::StartBoundary(source) => write!(formatter, "invalid HistoryStep start: {source}"),
            Self::ParentStateBoundary(field) => {
                write!(formatter, "parent state {field} does not match its header")
            }
            Self::Consensus(source) => write!(formatter, "block consensus failed: {source}"),
            Self::TransactionPublicLogic { tx_index, source } => {
                write!(formatter, "transaction {tx_index} public logic failed: {source}")
            }
            Self::AuthorizationStatement { tx_index, source } => write!(
                formatter,
                "transaction {tx_index} authorization statement failed: {source}",
            ),
            Self::Authorization(source) => {
                write!(formatter, "HistoryStep authorization failed: {source}")
            }
            Self::StateSurface(source) => {
                write!(formatter, "exact state surface failed: {source:?}")
            }
            Self::StateFrontier(source) => write!(formatter, "exact state frontier failed: {source}"),
            Self::SparseMerkle(source) => write!(formatter, "exact state topology failed: {source}"),
            Self::TransactionRootMismatch => formatter.write_str("transaction root mismatch"),
            Self::EmptyExactStateSurface => {
                formatter.write_str("non-genesis block has no exact-state actions")
            }
            Self::InvalidStateDepthTransition => {
                formatter.write_str("block state depth is not parent depth or parent depth + 1")
            }
            Self::ParentStateRootMismatch => {
                formatter.write_str("exact frontier does not reconstruct the parent state root")
            }
            Self::ChildStateRootMismatch => {
                formatter.write_str("exact frontier does not reconstruct the child state root")
            }
            Self::ActiveSlotCountMismatch => {
                formatter.write_str("block active slot count does not match exact actions")
            }
            Self::AllocCounterMismatch => {
                formatter.write_str("block allocation counter does not match exact actions")
            }
            Self::StateCounterOverflow => formatter.write_str("exact state counter overflow"),
            Self::StartAccumulatorChanged => {
                formatter.write_str("HistoryStep start changed after witness preparation")
            }
            Self::AccumulatorAdvance(source) => {
                write!(formatter, "HistoryStep accumulator advance failed: {source:?}")
            }
            Self::EndAccumulatorMismatch => {
                formatter.write_str("HistoryStep end is not the sealed-header transition")
            }
            Self::RecursiveInput(source) => write!(formatter, "HistoryStep input failed: {source}"),
            Self::Recursive(source) => write!(formatter, "HistoryStep assembly failed: {source}"),
        }
    }
}

impl std::error::Error for HistoryStepWitnessError {}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::consensus::params::GENESIS_TARGET;
    use noid_chain::consensus::template::build_block_template;
    use noid_poseidon2b::primitives::Address;

    fn coinbase_only_fixture() -> (Block, ChainState) {
        let state = ChainState::with_log_slots(8);
        let parent = BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root: state.cached_state_root(),
            tx_root: [0u8; 32],
            timestamp: 1_000,
            height: 0,
            miner_address: Address([0x11; 32]),
            nonce: 0,
            difficulty_target: GENESIS_TARGET,
            log_slots: 8,
            active_slot_count: 0,
            alloc_counter: 0,
        };
        let template = build_block_template(
            &parent,
            &state,
            &[0],
            Vec::new(),
            Address([0x22; 32]),
            1_015,
            GENESIS_TARGET,
        )
        .expect("coinbase template");
        let block = Block {
            header: template.to_pow_header(0),
            transactions: template.all_txs(),
        };
        (block, state)
    }

    #[test]
    fn coinbase_only_builds_the_same_exact_frontier_path() {
        let (block, state) = coinbase_only_fixture();
        let frontier = build_exact_state_frontier(&block, &state).expect("exact frontier");
        assert_eq!(frontier.touched_indices.len(), 1);
        assert_eq!(frontier.old_slot_leaves.len(), 1);
        assert_eq!(frontier.new_slot_leaves.len(), 1);
        assert_eq!(frontier.new_root, block.header.state_root);
        assert_eq!(block.header.active_slot_count, 1);
        assert_eq!(block.header.alloc_counter, 1);
    }

    #[test]
    fn tx_root_paths_bind_every_real_body_to_the_count_wrapped_root() {
        let (block, _) = coinbase_only_fixture();
        let hashes = block
            .transactions
            .iter()
            .map(|transaction| transaction.txid().0)
            .collect::<Vec<_>>();
        let paths = tx_root_merkle_inputs(&block, &hashes).expect("tx-root paths");
        assert_eq!(paths.len(), block.transactions.len());
        assert_eq!(paths[0].leaf, digest_to_fields(hashes[0]));
        assert_eq!(paths[0].active_depth, noid_chain::tx_tree::TX_TREE_DEPTH);
    }
}
