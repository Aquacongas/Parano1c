// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Build the canonical `HistoryStep` v1 release pack from honest chain data.
//!
//! Usage: `noid_matrix_gen <pack-root>`
//!
//! The fixture provider starts at the real genesis state, mines every header,
//! verifies every wallet authorization and materializes every backbone state.
//! It saves the exact B25 and B255 parent boundaries, then forks native-valid
//! children for both current classes. The two resulting matrices are assembled
//! from native-valid block witnesses rather than shape-only or synthetic inputs.

use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use bench_prover::HonestHistoryStepFixtureProvider;
use noid_ivc_core::field_r1cs::FieldR1cs;
use noid_ivc_core::proof::FieldShape;
use noid_miner::history_step_artifacts::{
    decode_history_step_runtime_metadata_pinned, encode_history_step_runtime_metadata,
    history_step_matrix_file_name, HISTORY_STEP_PACK_LEAF_COUNT,
    HISTORY_STEP_PACK_VERSION_DIRECTORY, HISTORY_STEP_RUNTIME_METADATA_FILE,
};
use noid_recursive::{
    canonical_history_step_shape, freeze_history_step_bank, CanonicalHistoryStepClassId,
    HistoryStepFreezeMatrixStore, HistoryStepMatrixLease, HistoryStepMatrixSource,
    HistoryStepMatrixSourceError,
};

const FIXTURE_SEED: u128 = 0x4849_5354_4550_5f56_31;
const DEFAULT_ZSTD_LEVEL: i32 = 19;
const MAX_COMPRESSED_MATRIX_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_CANONICAL_MATRIX_BYTES: usize = 1024 * 1024 * 1024;
const ZSTD_WINDOW_LOG_MAX: u32 = 27;

fn class_label(class: CanonicalHistoryStepClassId) -> String {
    format!("H(B{})", class.current_tier())
}

struct CanonicalMatrixStore {
    directory: PathBuf,
    zstd_level: i32,
    installed_digests: Mutex<[Option<[u8; 32]>; HISTORY_STEP_PACK_LEAF_COUNT]>,
}

impl CanonicalMatrixStore {
    fn new(directory: PathBuf, zstd_level: i32) -> Self {
        Self {
            directory,
            zstd_level,
            installed_digests: Mutex::new(std::array::from_fn(|_| None)),
        }
    }

    fn path(&self, class: CanonicalHistoryStepClassId) -> PathBuf {
        self.directory.join(history_step_matrix_file_name(class))
    }

    fn temporary_path(&self, class: CanonicalHistoryStepClassId) -> PathBuf {
        self.directory.join(format!(
            ".{}.{}.tmp",
            history_step_matrix_file_name(class),
            std::process::id()
        ))
    }

    fn installed_digest(&self, class: CanonicalHistoryStepClassId) -> Result<[u8; 32], String> {
        self.installed_digests
            .lock()
            .map_err(|_| "HistoryStep matrix digest lock is poisoned".to_owned())?[class.index()]
        .ok_or_else(|| format!("{} matrix is not installed", class_label(class)))
    }

    fn load_checked(&self, class: CanonicalHistoryStepClassId) -> Result<FieldR1cs, String> {
        let path = self.path(class);
        let metadata = std::fs::metadata(&path)
            .map_err(|error| format!("inspect {}: {error}", path.display()))?;
        if !metadata.is_file() || metadata.len() > MAX_COMPRESSED_MATRIX_BYTES {
            return Err(format!(
                "{} is not a bounded regular matrix artifact",
                path.display()
            ));
        }
        let file =
            File::open(&path).map_err(|error| format!("open {}: {error}", path.display()))?;
        let mut decoder = zstd::stream::read::Decoder::new(BufReader::new(file))
            .map_err(|error| format!("open zstd {}: {error}", path.display()))?;
        decoder
            .window_log_max(ZSTD_WINDOW_LOG_MAX)
            .map_err(|error| format!("bound zstd window {}: {error}", path.display()))?;
        let matrix = FieldR1cs::read_artifact(
            &mut decoder,
            canonical_history_step_shape(class),
            self.installed_digest(class)?,
            MAX_CANONICAL_MATRIX_BYTES,
        )
        .map_err(|error| format!("decode {}: {error}", path.display()))?;
        let mut trailing = [0u8; 1];
        if decoder
            .read(&mut trailing)
            .map_err(|error| format!("finish zstd {}: {error}", path.display()))?
            != 0
        {
            return Err(format!(
                "{} has trailing decompressed bytes",
                path.display()
            ));
        }
        Ok(matrix)
    }

    fn install_checked(
        &self,
        class: CanonicalHistoryStepClassId,
        matrix: FieldR1cs,
    ) -> Result<(), String> {
        let actual_shape = FieldShape::of(&matrix);
        let expected_shape = canonical_history_step_shape(class);
        if actual_shape != expected_shape {
            return Err(format!(
                "{} has shape {actual_shape:?}, expected {expected_shape:?}",
                class_label(class)
            ));
        }
        let digest = matrix.structural_statement_digest();
        let temporary = self.temporary_path(class);
        let final_path = self.path(class);
        let result = (|| -> Result<(), String> {
            let file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)
                .map_err(|error| format!("create {}: {error}", temporary.display()))?;
            let mut encoder = zstd::stream::write::Encoder::new(file, self.zstd_level)
                .map_err(|error| format!("open zstd {}: {error}", temporary.display()))?;
            encoder
                .multithread(rayon::current_num_threads().max(1) as u32)
                .map_err(|error| format!("enable zstd workers {}: {error}", temporary.display()))?;
            encoder.include_checksum(true).map_err(|error| {
                format!("enable zstd checksum {}: {error}", temporary.display())
            })?;
            matrix
                .write_artifact(&mut encoder)
                .map_err(|error| format!("encode {}: {error}", class_label(class)))?;
            let file = encoder
                .finish()
                .map_err(|error| format!("finish zstd {}: {error}", temporary.display()))?;
            file.sync_all()
                .map_err(|error| format!("sync {}: {error}", temporary.display()))?;
            std::fs::rename(&temporary, &final_path).map_err(|error| {
                format!(
                    "publish {} as {}: {error}",
                    temporary.display(),
                    final_path.display()
                )
            })?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
            return result;
        }
        self.installed_digests
            .lock()
            .map_err(|_| "HistoryStep matrix digest lock is poisoned".to_owned())?[class.index()] =
            Some(digest);
        Ok(())
    }
}

impl HistoryStepMatrixSource for CanonicalMatrixStore {
    fn load(
        &self,
        class: CanonicalHistoryStepClassId,
    ) -> Result<HistoryStepMatrixLease, HistoryStepMatrixSourceError> {
        self.load_checked(class)
            .map(HistoryStepMatrixLease::resident)
            .map_err(|_| HistoryStepMatrixSourceError)
    }
}

impl HistoryStepFreezeMatrixStore for CanonicalMatrixStore {
    type Error = String;

    fn install(
        &self,
        class: CanonicalHistoryStepClassId,
        matrix: FieldR1cs,
    ) -> Result<(), Self::Error> {
        self.install_checked(class, matrix)
    }

    fn final_class_built(
        &self,
        class: CanonicalHistoryStepClassId,
        wires: usize,
        elapsed: std::time::Duration,
    ) {
        let path = self.path(class);
        let bytes = std::fs::metadata(&path)
            .unwrap_or_else(|error| panic!("inspect exported {}: {error}", path.display()))
            .len();
        println!(
            "  c{:02} current=B{} wires={wires} bytes={bytes} build_export_ms={}",
            class.index(),
            class.current_tier(),
            elapsed.as_millis(),
        );
        std::io::stdout()
            .flush()
            .expect("flush HistoryStep freezer progress");
    }
}

fn parse_zstd_level() -> i32 {
    match std::env::var("NOID_ARTIFACT_ZSTD_LEVEL") {
        Ok(value) => value
            .parse::<i32>()
            .unwrap_or_else(|error| panic!("NOID_ARTIFACT_ZSTD_LEVEL must be an integer: {error}")),
        Err(std::env::VarError::NotPresent) => DEFAULT_ZSTD_LEVEL,
        Err(error) => panic!("read NOID_ARTIFACT_ZSTD_LEVEL: {error}"),
    }
}

fn write_metadata(path: &Path, bytes: &[u8]) {
    let temporary = path.with_extension(format!("runtime.{}.tmp", std::process::id()));
    let result = (|| -> Result<(), std::io::Error> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = std::fs::remove_file(&temporary);
        panic!("publish {}: {error}", path.display());
    }
}

fn main() {
    noid_ivc_prover::init_perf_thread_pool();
    let root = std::env::args()
        .nth(1)
        .expect("usage: noid_matrix_gen <pack-root>");
    assert!(
        std::env::args().nth(2).is_none(),
        "usage: noid_matrix_gen <pack-root>"
    );
    let root = PathBuf::from(root);
    let version = root.join(HISTORY_STEP_PACK_VERSION_DIRECTORY);
    std::fs::create_dir(&root).unwrap_or_else(|error| {
        panic!(
            "create fresh HistoryStep pack root {}: {error}",
            root.display()
        )
    });
    std::fs::create_dir(&version).unwrap_or_else(|error| {
        panic!(
            "create fresh HistoryStep pack directory {}: {error}",
            version.display()
        )
    });

    let zstd_level = parse_zstd_level();
    let debug = std::env::var_os("NOID_HISTORY_STEP_GENERATOR_DEBUG").is_some();
    println!("PARANOID canonical HistoryStep v1 freezer");
    println!("  pack:          {}", version.display());
    println!("  rayon threads: {}", rayon::current_num_threads());
    println!("  witnesses:     real genesis chain + two exact parent checkpoints");
    println!("  classes:       2 (B25/m22 and B255/m24)");
    println!("\nBuilding and exporting canonical matrices:");

    let started = Instant::now();
    let mut provider = HonestHistoryStepFixtureProvider::new(FIXTURE_SEED)
        .unwrap_or_else(|error| panic!("initialize honest HistoryStep fixtures: {error}"));
    let store = std::sync::Arc::new(CanonicalMatrixStore::new(version.clone(), zstd_level));
    let frozen = freeze_history_step_bank(&mut provider, std::sync::Arc::clone(&store))
        .unwrap_or_else(|error| panic!("freeze honest HistoryStep bank: {error}"));

    let metadata = encode_history_step_runtime_metadata(frozen.bank(), frozen.parts())
        .unwrap_or_else(|error| panic!("encode HistoryStep runtime metadata: {error}"));
    let metadata_digest: [u8; 32] = metadata[metadata.len() - 32..]
        .try_into()
        .expect("fixed metadata digest trailer");
    let decoded = decode_history_step_runtime_metadata_pinned(&metadata, metadata_digest)
        .unwrap_or_else(|error| panic!("self-check HistoryStep runtime metadata: {error}"));
    assert_eq!(
        decoded.bank().digest(),
        frozen.bank().digest(),
        "runtime metadata rebuilt a different canonical bank"
    );
    write_metadata(&version.join(HISTORY_STEP_RUNTIME_METADATA_FILE), &metadata);

    println!("\nAuthenticating exported pack...");
    for index in 0..HISTORY_STEP_PACK_LEAF_COUNT {
        let class_started = Instant::now();
        let class = CanonicalHistoryStepClassId::from_index(index).expect("canonical class");
        let matrix = store
            .load_checked(class)
            .unwrap_or_else(|error| panic!("reload final {}: {error}", class_label(class)));
        frozen
            .bank()
            .authenticate_resident_matrix(class, &matrix)
            .unwrap_or_else(|error| panic!("authenticate final {}: {error}", class_label(class)));
        drop(matrix);
        if debug {
            println!(
                "  c{index:02} load_verify_ms={} matrix_digest={}",
                class_started.elapsed().as_millis(),
                hex::encode(frozen.bank().entry(class).matrix_digest())
            );
        }
    }
    println!("  matrices:      {HISTORY_STEP_PACK_LEAF_COUNT}/{HISTORY_STEP_PACK_LEAF_COUNT}");
    println!("\nRuntime metadata: {}", hex::encode(metadata_digest));
    println!("Bank digest:       {}", hex::encode(frozen.bank().digest()));
    println!("Completed in {:.1} s", started.elapsed().as_secs_f64());
}
