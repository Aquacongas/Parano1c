// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Isolated production HistoryStep proving benchmark.
//!
//! The benchmark requires a completed, pinned v1 pack:
//!
//! ```text
//! source "$PACK_ROOT/pins.env"
//! export NOID_HISTORY_STEP_PACK_DIR="$PACK_ROOT"
//! cargo bench -p bench_prover --bench history_step_proof
//! ```
//!
//! Set `NOID_HISTORY_STEP_BENCH_FILTER=B255` (or its fixed class alias `c12`)
//! to run B255 after a B8 parent. Use `c15` (or `B255-B255`) for the worst
//! B255-after-B255 class. With no filter, all four B8-parent tiers run.
//!
//! Honest native-valid fixtures and matrix assembly are setup.  Each reported
//! `prove_ms` covers only production HistoryStep proof + terminal creation —
//! in the nonce-free pipeline this entire cost sits before PoW; the post-nonce
//! path is one native PoW check plus the atomic commit and is measured live
//! as `nonce_to_commit_ms`.  `verify_ms` covers bounded wire decode and
//! complete terminal verification.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufReader, Read as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bench_prover::{
    HonestHistoryStepFixtureProvider, PreparedHistoryStepBackboneInput,
    PreparedHistoryStepTierFixture,
};
use noid_ivc_core::field_r1cs::CompactFieldR1cs;
use noid_miner::history_step_artifacts::{
    history_step_matrix_file_name, HISTORY_STEP_PACK_LEAF_HASH_DOMAIN,
    HISTORY_STEP_PACK_VERSION_DIRECTORY, HISTORY_STEP_RUNTIME_METADATA_FILE,
    HISTORY_STEP_RUNTIME_METADATA_MAX_BYTES,
};
use noid_poseidon2b::native::poseidon2b_hash_byte_slices;
use noid_recursive::acceptance::history_step::{
    assemble_history_step_recursive, HistoryStepParent,
};
use noid_recursive::{
    canonical_history_step_shape, decode_verify_history_step_terminal,
    encode_history_step_terminal, prove_built_history_step_terminal, prove_history_step,
    CanonicalHistoryStepClassId, ChainAccumulator, HistoryStepBlockInput, HistoryStepMatrixLease,
    HistoryStepMatrixSource, HistoryStepMatrixSourceError, HistoryStepRuntime, HistoryStepTerminal,
    HISTORY_STEP_CLASS_COUNT,
};

const FIXTURE_SEED: u128 = 0x4849_5354_4550_5f56_31;
const PACK_DIRECTORY_ENV: &str = "NOID_HISTORY_STEP_PACK_DIR";
const BENCH_FILTER_ENV: &str = "NOID_HISTORY_STEP_BENCH_FILTER";
const METADATA_DIGEST_ENV: &str = "NOID_HISTORY_STEP_RUNTIME_METADATA_RELEASE_DIGEST";
const LEAF_DIGESTS_ENV: &str = "NOID_HISTORY_STEP_PACK_LEAF_DIGESTS";
const MAX_COMPRESSED_MATRIX_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_CANONICAL_MATRIX_BYTES: usize = 1024 * 1024 * 1024;
const ZSTD_WINDOW_LOG_MAX: u32 = 27;
const MATRIX_CACHE_CAPACITY: usize = 2;

struct PinnedDiskMatrixSource {
    directory: PathBuf,
    matrix_digests: [[u8; 32]; HISTORY_STEP_CLASS_COUNT],
    leaf_digests: [[u8; 32]; HISTORY_STEP_CLASS_COUNT],
    cache: Mutex<VecDeque<(CanonicalHistoryStepClassId, Arc<CompactFieldR1cs>)>>,
}

struct SharedPinnedDiskMatrixSource(Arc<PinnedDiskMatrixSource>);

impl PinnedDiskMatrixSource {
    fn load_checked(
        &self,
        class: CanonicalHistoryStepClassId,
    ) -> Result<Arc<CompactFieldR1cs>, String> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| "HistoryStep benchmark matrix cache is poisoned".to_owned())?;
        if let Some(position) = cache.iter().position(|(cached, _)| *cached == class) {
            let entry = cache
                .remove(position)
                .expect("located benchmark matrix cache entry exists");
            let matrix = Arc::clone(&entry.1);
            cache.push_back(entry);
            return Ok(matrix);
        }
        let path = self.directory.join(history_step_matrix_file_name(class));
        let compressed = read_regular_bounded(&path, MAX_COMPRESSED_MATRIX_BYTES)?;
        let actual =
            poseidon2b_hash_byte_slices(HISTORY_STEP_PACK_LEAF_HASH_DOMAIN, &[&compressed]);
        if actual != self.leaf_digests[class.index()] {
            return Err(format!(
                "compressed leaf pin mismatch for {}",
                path.display()
            ));
        }
        let mut decoder = zstd::stream::read::Decoder::new(BufReader::new(compressed.as_slice()))
            .map_err(|error| format!("open zstd {}: {error}", path.display()))?;
        decoder
            .window_log_max(ZSTD_WINDOW_LOG_MAX)
            .map_err(|error| format!("bound zstd window {}: {error}", path.display()))?;
        let mut canonical = Vec::new();
        decoder
            .take((MAX_CANONICAL_MATRIX_BYTES + 1) as u64)
            .read_to_end(&mut canonical)
            .map_err(|error| format!("decode {}: {error}", path.display()))?;
        if canonical.len() > MAX_CANONICAL_MATRIX_BYTES {
            return Err(format!(
                "{} exceeds the canonical size bound",
                path.display()
            ));
        }
        let matrix = CompactFieldR1cs::open(
            canonical.into_boxed_slice(),
            canonical_history_step_shape(class),
            self.matrix_digests[class.index()],
        )
        .and_then(CompactFieldR1cs::into_startup_packed)
        .map_err(|error| format!("authenticate {}: {error}", path.display()))?;
        let matrix = Arc::new(matrix);
        cache.push_back((class, Arc::clone(&matrix)));
        while cache.len() > MATRIX_CACHE_CAPACITY {
            cache.pop_front();
        }
        Ok(matrix)
    }
}

impl HistoryStepMatrixSource for SharedPinnedDiskMatrixSource {
    fn load(
        &self,
        class: CanonicalHistoryStepClassId,
    ) -> Result<HistoryStepMatrixLease, HistoryStepMatrixSourceError> {
        self.0
            .load_checked(class)
            .map(HistoryStepMatrixLease::Compact)
            .map_err(|_| HistoryStepMatrixSourceError)
    }
}

fn read_regular_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > max_bytes {
        return Err(format!("{} is not a bounded regular file", path.display()));
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| format!("{} length does not fit usize", path.display()))?;
    let mut bytes = Vec::with_capacity(capacity);
    File::open(path)
        .map_err(|error| format!("open {}: {error}", path.display()))?
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!("{} exceeds its byte bound", path.display()));
    }
    Ok(bytes)
}

fn parse_digest(name: &str) -> Result<[u8; 32], String> {
    let encoded = std::env::var(name).map_err(|_| format!("{name} is required"))?;
    if encoded.len() != 64
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{name} must be 64 lowercase hex characters"));
    }
    let decoded = hex::decode(encoded).map_err(|error| format!("decode {name}: {error}"))?;
    decoded
        .try_into()
        .map_err(|_| format!("{name} must decode to 32 bytes"))
}

fn parse_leaf_digests() -> Result<[[u8; 32]; HISTORY_STEP_CLASS_COUNT], String> {
    let encoded =
        std::env::var(LEAF_DIGESTS_ENV).map_err(|_| format!("{LEAF_DIGESTS_ENV} is required"))?;
    if encoded.len() != HISTORY_STEP_CLASS_COUNT * 64
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{LEAF_DIGESTS_ENV} must contain {HISTORY_STEP_CLASS_COUNT} lowercase hex digests"
        ));
    }
    let mut digests = [[0u8; 32]; HISTORY_STEP_CLASS_COUNT];
    for (index, digest) in digests.iter_mut().enumerate() {
        let start = index * 64;
        let decoded = hex::decode(&encoded[start..start + 64])
            .map_err(|error| format!("decode {LEAF_DIGESTS_ENV} class {index}: {error}"))?;
        digest.copy_from_slice(&decoded);
    }
    Ok(digests)
}

/// Selected case: the current-tier class plus the parent tier the honest
/// fixture chain should build. The legacy 4x4 aliases keep working: their
/// parent component now only picks the fixture parent tier — the class and
/// matrix are parent-independent.
fn benchmark_filter() -> Result<Option<(CanonicalHistoryStepClassId, usize)>, String> {
    let value = match std::env::var(BENCH_FILTER_ENV) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(format!("{BENCH_FILTER_ENV} must be valid UTF-8"));
        }
    };
    let class = |slot: usize| CanonicalHistoryStepClassId::new(slot).expect("canonical tier slot");
    let case = match value.trim().to_ascii_lowercase().as_str() {
        "b8" | "8" | "c00" => (class(0), 0),
        "b32" | "32" | "c04" | "c01" => (class(1), 0),
        "b64" | "64" | "c08" | "c02" => (class(2), 0),
        "b255" | "255" | "c12" | "c03" => (class(3), 0),
        "c15" | "b255-b255" => (class(3), 3),
        _ => {
            return Err(format!(
                "{BENCH_FILTER_ENV} must be one of B8/c00, B32/c01, B64/c02, B255/c03, or B255-B255",
            ));
        }
    };
    Ok(Some(case))
}

fn class_is_selected(
    filter: Option<(CanonicalHistoryStepClassId, usize)>,
    class: CanonicalHistoryStepClassId,
) -> bool {
    filter.map_or(true, |(selected, _)| selected == class)
}

fn load_runtime() -> Result<(HistoryStepRuntime, Arc<PinnedDiskMatrixSource>), String> {
    let root = PathBuf::from(
        std::env::var_os(PACK_DIRECTORY_ENV)
            .ok_or_else(|| format!("{PACK_DIRECTORY_ENV} is required"))?,
    );
    let directory = root.join(HISTORY_STEP_PACK_VERSION_DIRECTORY);
    let metadata_path = directory.join(HISTORY_STEP_RUNTIME_METADATA_FILE);
    let encoded = read_regular_bounded(
        &metadata_path,
        HISTORY_STEP_RUNTIME_METADATA_MAX_BYTES as u64,
    )?;
    let metadata = noid_miner::decode_history_step_runtime_metadata_pinned(
        &encoded,
        parse_digest(METADATA_DIGEST_ENV)?,
    )
    .map_err(|error| format!("authenticate {}: {error}", metadata_path.display()))?;
    let matrix_digests =
        std::array::from_fn(|index| metadata.bank().entries()[index].matrix_digest());
    let source = Arc::new(PinnedDiskMatrixSource {
        directory,
        matrix_digests,
        leaf_digests: parse_leaf_digests()?,
        cache: Mutex::new(VecDeque::with_capacity(MATRIX_CACHE_CAPACITY)),
    });
    let (bank, parts) = metadata.into_parts();
    let runtime = HistoryStepRuntime::new(
        bank,
        Box::new(SharedPinnedDiskMatrixSource(Arc::clone(&source))),
        parts,
    )
    .map_err(|error| format!("construct pinned HistoryStep runtime: {error}"))?;
    Ok((runtime, source))
}

fn finish_fixture<const TIER: usize>(
    fixture: PreparedHistoryStepTierFixture<TIER>,
) -> Result<(noid_chain::Block, HistoryStepBlockInput<TIER>), String> {
    let (witness, nonce, start, end) = fixture.into_parts();
    witness
        .finish(nonce, &start, &end)
        .map_err(|error| format!("finish honest B{TIER} fixture: {error}"))
}

fn prove_parent_step<const TIER: usize>(
    runtime: &HistoryStepRuntime,
    parent: Option<&HistoryStepTerminal>,
    fixture: PreparedHistoryStepTierFixture<TIER>,
) -> Result<(noid_chain::Block, HistoryStepTerminal), String> {
    let (block, input) = finish_fixture(fixture)?;
    let terminal = prove_history_step(runtime, parent, input)
        .map_err(|error| format!("prove honest B{TIER} setup step: {error}"))?;
    Ok((block, terminal))
}

fn build_parent(
    runtime: &HistoryStepRuntime,
    provider: &mut HonestHistoryStepFixtureProvider,
    target_parent_slot: usize,
) -> Result<(noid_chain::Block, HistoryStepTerminal), String> {
    let mut expected = noid_recursive::genesis_accumulator();
    let mut parent = None;
    loop {
        let step = provider.next_backbone(&expected)?.ok_or_else(|| {
            format!("honest backbone ended before parent checkpoint {target_parent_slot}")
        })?;
        let capture = step.capture_parent_slot;
        let (block, terminal) = match step.input {
            PreparedHistoryStepBackboneInput::B8(fixture) => {
                prove_parent_step(runtime, parent.as_ref(), fixture)?
            }
            PreparedHistoryStepBackboneInput::B32(fixture) => {
                prove_parent_step(runtime, parent.as_ref(), fixture)?
            }
            PreparedHistoryStepBackboneInput::B64(fixture) => {
                prove_parent_step(runtime, parent.as_ref(), fixture)?
            }
            PreparedHistoryStepBackboneInput::B255(fixture) => {
                prove_parent_step(runtime, parent.as_ref(), fixture)?
            }
        };
        expected = terminal.accumulator().clone();
        if capture == Some(target_parent_slot) {
            return Ok((block, terminal));
        }
        parent = Some(terminal);
    }
}

fn benchmark_tier<const TIER: usize>(
    runtime: &HistoryStepRuntime,
    parent: &HistoryStepTerminal,
    fixture: PreparedHistoryStepTierFixture<TIER>,
) -> Result<(), String> {
    let (block, input) = finish_fixture(fixture)?;
    let assemble_started = Instant::now();
    let parent = HistoryStepParent::new(runtime, parent)
        .map_err(|error| format!("bind honest B{TIER} benchmark parent: {error}"))?;
    let built = assemble_history_step_recursive(runtime, parent, input)
        .map_err(|error| format!("assemble honest B{TIER} benchmark: {error}"))?;
    let assemble_ms = assemble_started.elapsed().as_millis();
    let class = built.class_id();
    let wires = built.useful_rows();

    let prove_started = Instant::now();
    let terminal = prove_built_history_step_terminal(runtime, &built)
        .map_err(|error| format!("prove honest B{TIER} benchmark: {error}"))?;
    let prove_ms = prove_started.elapsed().as_millis();

    let encoded = encode_history_step_terminal(runtime, &terminal)
        .map_err(|error| format!("encode honest B{TIER} terminal: {error}"))?;
    let terminal_bytes = encoded.len();
    let epoch_anchor = noid_chain::consensus::genesis_header();
    let verify_started = Instant::now();
    let accepted =
        decode_verify_history_step_terminal(runtime, &encoded, &block.header, &epoch_anchor)
            .map_err(|error| format!("verify honest B{TIER} terminal: {error}"))?;
    let verify_ms = verify_started.elapsed().as_millis();
    if accepted.class_id() != class || accepted.semantic_id() != terminal.semantic_id() {
        return Err(format!("B{TIER} accepted terminal boundary drift"));
    }

    println!(
        "B{TIER} class=c{:02} wires={wires} assemble_ms={assemble_ms} prove_ms={prove_ms} verify_ms={verify_ms} terminal_bytes={terminal_bytes}",
        class.index(),
    );
    Ok(())
}

fn run() -> Result<(), String> {
    noid_ivc_prover::init_perf_thread_pool();
    let filter = benchmark_filter()?;
    let (runtime, source) = load_runtime()?;
    let mut provider = HonestHistoryStepFixtureProvider::new(FIXTURE_SEED)?;
    let c00 = CanonicalHistoryStepClassId::new(0).expect("B8 class");
    let target_parent_slot = filter.map_or(0, |(_, parent_slot)| parent_slot);
    // Authenticate and convert outside every reported assembly interval. The
    // production node receives the same packed layout from its release build;
    // this file-backed benchmark deliberately performs the full canonical
    // authentication itself instead of minting a file-derived build seal.
    source.load_checked(c00)?;
    let (parent_block, parent) = build_parent(&runtime, &mut provider, target_parent_slot)?;

    let parent_wire = encode_history_step_terminal(&runtime, &parent)
        .map_err(|error| format!("encode B8 benchmark parent: {error}"))?;
    let accepted_parent = decode_verify_history_step_terminal(
        &runtime,
        &parent_wire,
        &parent_block.header,
        &noid_chain::consensus::genesis_header(),
    )
    .map_err(|error| format!("verify B8 benchmark parent: {error}"))?;
    if accepted_parent.class_id() != parent.class_id()
        || accepted_parent.semantic_id() != parent.semantic_id()
    {
        return Err("verified benchmark parent boundary drift".to_owned());
    }
    if provider.parent_accumulator(target_parent_slot) != Some(parent.accumulator()) {
        return Err("benchmark checkpoint and proved parent disagree".to_owned());
    }

    let parent_accumulator: &ChainAccumulator = parent.accumulator();
    let parent_class = parent.class_id();
    // The production LRU holds exactly two matrices. Preload current first
    // and the exact parent class second before every timed recursive build;
    // this remains
    // correct when the unfiltered benchmark advances through several tiers
    // and would otherwise evict the parent while admitting the next current
    // class.
    if class_is_selected(filter, c00) {
        source.load_checked(c00)?;
        source.load_checked(parent_class)?;
        benchmark_tier(&runtime, &parent, provider.b8(c00, parent_accumulator)?)?;
    }
    let c01 = CanonicalHistoryStepClassId::new(1).expect("B32 class");
    if class_is_selected(filter, c01) {
        source.load_checked(c01)?;
        source.load_checked(parent_class)?;
        benchmark_tier(&runtime, &parent, provider.b32(c01, parent_accumulator)?)?;
    }
    let c02 = CanonicalHistoryStepClassId::new(2).expect("B64 class");
    if class_is_selected(filter, c02) {
        source.load_checked(c02)?;
        source.load_checked(parent_class)?;
        benchmark_tier(&runtime, &parent, provider.b64(c02, parent_accumulator)?)?;
    }
    let c03 = CanonicalHistoryStepClassId::new(3).expect("B255 class");
    if class_is_selected(filter, c03) {
        source.load_checked(c03)?;
        source.load_checked(parent_class)?;
        benchmark_tier(&runtime, &parent, provider.b255(c03, parent_accumulator)?)?;
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        panic!("HistoryStep production benchmark: {error}");
    }
}
