//! Manual measurement harness for the Poseidon2 cost of sealing a batch.
//!
//! Sealing is the one gateway step this example adds to the dispersal path that is not already
//! benchmarked upstream: before a batch can be encoded, every blob must be paged and hashed into a
//! [`BlobId`](crate::types::BlobId) and those identities folded into a blob-tree root. The question
//! this answers is whether that fits inside the batch timer at the production batch size, and
//! whether it has to be parallel to do so.
//!
//! Ignored by default because it is a measurement, not an assertion. Release mode is required;
//! debug timings for field arithmetic are meaningless:
//!
//! ```sh
//! cargo test --release -p commonware-blob p1_measure -- --ignored --nocapture
//! ```

use crate::{
    blob_tree::BlobTree,
    constants::{BATCH_TARGET, BATCH_TIMEOUT, MAX_BLOB_SIZE},
    types::{Blob, BlobId},
};
use bytes::Bytes;
use rayon::prelude::*;
use std::time::{Duration, Instant};

/// Timed iterations per case. Odd, so the median is a real sample.
const ITERATIONS: usize = 5;

/// Blob size used for the full-batch case: 32 of these make one 8 MiB batch.
const BATCH_BLOB: usize = 256 * 1024;

/// Builds a blob of `len` pseudorandom bytes.
fn blob(len: usize, seed: u32) -> Blob {
    let mut state = seed;
    let mut bytes = vec![0u8; len];
    for byte in &mut bytes {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        *byte = (state >> 16) as u8;
    }
    Blob::new(Bytes::from(bytes)).expect("blob is within bounds")
}

/// The middle sample of `samples`, which must be non-empty.
fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

/// Renders a duration in milliseconds.
fn ms(duration: Duration) -> String {
    format!("{:.3} ms", duration.as_secs_f64() * 1000.0)
}

/// Times `operation` [`ITERATIONS`] times and returns the median.
///
/// One untimed warm-up runs first, so the first case measured does not carry the process's cold
/// start.
fn time<T>(mut operation: impl FnMut() -> T) -> Duration {
    drop(operation());
    let mut samples = Vec::with_capacity(ITERATIONS);
    for _ in 0..ITERATIONS {
        let start = Instant::now();
        let output = operation();
        samples.push(start.elapsed());
        drop(output);
    }
    median(samples)
}

#[test]
#[ignore = "manual measurement harness"]
fn p1_measure_poseidon2_sealing() {
    const KIB: usize = 1 << 10;

    println!();
    println!("Poseidon2-BN254 (t=4, rate 3), median of {ITERATIONS} iterations");
    println!("{:<16} {:>14} {:>16}", "blob size", "BlobId", "throughput");
    println!("{}", "-".repeat(48));
    for len in [64 * KIB, 256 * KIB, MAX_BLOB_SIZE] {
        let blob = blob(len, len as u32);
        let elapsed = time(|| blob.id());
        let throughput = len as f64 / elapsed.as_secs_f64() / (1 << 20) as f64;
        println!(
            "{:<16} {:>14} {:>16}",
            format!("{} KiB", len / KIB),
            ms(elapsed),
            format!("{throughput:.1} MiB/s")
        );
    }

    // A full production batch: 32 blobs of 256 KiB, sealed the way the gateway will seal it.
    let blobs: Vec<Blob> = (0..(BATCH_TARGET / BATCH_BLOB))
        .map(|index| blob(BATCH_BLOB, index as u32 + 1))
        .collect();
    let serial = time(|| blobs.iter().map(Blob::id).collect::<Vec<_>>());
    let parallel = time(|| blobs.par_iter().map(Blob::id).collect::<Vec<_>>());
    let ids: Vec<BlobId> = blobs.iter().map(Blob::id).collect();
    let tree = time(|| {
        BlobTree::build(&ids)
            .expect("count is within bounds")
            .root()
    });

    println!();
    println!(
        "8 MiB batch ({} x {} KiB), rayon threads {}",
        blobs.len(),
        BATCH_BLOB / KIB,
        rayon::current_num_threads()
    );
    println!("{:<26} {:>14} {:>16}", "stage", "elapsed", "of batch timer");
    println!("{}", "-".repeat(58));
    for (label, elapsed) in [
        ("BlobId hashing, serial", serial),
        ("BlobId hashing, rayon", parallel),
        ("blob-tree root", tree),
        ("seal total, serial", serial + tree),
        ("seal total, rayon", parallel + tree),
    ] {
        let share = elapsed.as_secs_f64() / BATCH_TIMEOUT.as_secs_f64() * 100.0;
        println!(
            "{:<26} {:>14} {:>16}",
            label,
            ms(elapsed),
            format!("{share:.1} %")
        );
    }
    println!();
    println!(
        "batch timer {}; speedup {:.2}x",
        ms(BATCH_TIMEOUT),
        serial.as_secs_f64() / parallel.as_secs_f64()
    );
    println!();
}
