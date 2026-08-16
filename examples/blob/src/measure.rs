//! Manual measurement harnesses for the two hash-heavy paths this example owns.
//!
//! Two costs bound the design, and each has a harness here:
//!
//! - **Sealing** ([`p1_measure_poseidon2_sealing`]): before a batch can be encoded, every blob is
//!   paged and hashed into a [`BlobId`](crate::types::BlobId) and the identities folded into a
//!   blob-tree root. This answers whether that fits inside the batch timer at the production
//!   batch size, and whether it must be parallel to do so.
//! - **Attestation and retrieval** ([`zoda::p0_measure_zoda_attestation_path`]): every validator
//!   runs `weaken` once per dispersal, and retrieval re-runs it per gathered shard. The gateway's
//!   `encode` is benchmarked upstream in `commonware-coding`; these two are not.
//!
//! Both are ignored by default because they are measurements, not assertions. Release mode is
//! required; debug timings for field arithmetic are meaningless:
//!
//! ```sh
//! cargo test --release -p commonware-blob p1_measure -- --ignored --nocapture
//! cargo test --release -p commonware-blob p0_measure -- --ignored --nocapture
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

/// The ZODA attestation-path harness, moved here from `tests/measure.rs` once the crate had
/// modules of its own (a bin crate's integration tests cannot import them; the reverse move is
/// the only one possible).
mod zoda {
    use super::{median, ms};
    use crate::{assignment, wire::Coder};
    use commonware_codec::EncodeSize as _;
    use commonware_coding::PhasedScheme as _;
    use commonware_parallel::Sequential;
    use rand::{Rng as _, SeedableRng as _};
    use rand_chacha::ChaCha8Rng;
    use std::time::{Duration, Instant};

    /// Domain separation for this harness. Never used on a live rail.
    const NAMESPACE: &[u8] = b"_COMMONWARE_EXAMPLES_BLOB_MEASURE";

    /// Single-threaded: one validator attesting on one core is the cost being bounded.
    const STRATEGY: Sequential = Sequential;

    /// Timed iterations per operation. Odd, so the median is a real sample.
    const ITERATIONS: usize = 9;

    /// The shard a validator weakens; also the source of the checking data.
    const OWN_INDEX: u16 = 0;

    /// The shard whose weak form is checked, distinct from [`OWN_INDEX`] so `check` does the work
    /// it does on the retrieval path.
    const PEER_INDEX: u16 = 1;

    /// One measured configuration.
    struct Case {
        /// Human-readable data size.
        size: &'static str,
        /// Bytes of blob data encoded.
        data_len: usize,
        /// Number of participants the data is sharded across.
        participants: u16,
    }

    /// The results of measuring one [`Case`].
    struct Row {
        label: String,
        encode: Duration,
        weaken: Duration,
        check: Duration,
        strong_shard: usize,
        weak_shard: usize,
    }

    /// Measures one case end to end.
    fn measure(case: &Case, rng: &mut ChaCha8Rng) -> Row {
        let config = assignment::coding_config(usize::from(case.participants))
            .expect("participant count supports coding");
        let mut data = vec![0u8; case.data_len];
        rng.fill_bytes(&mut data);

        // Encode once. This is the gateway's cost, recorded for scale rather than as the target.
        let start = Instant::now();
        let (commitment, shards) =
            Coder::encode(NAMESPACE, &config, data.as_slice(), &STRATEGY).expect("encode failed");
        let encode = start.elapsed();
        let strong_shard = shards[usize::from(OWN_INDEX)].encode_size();

        // Weaken consumes the shard, so build the whole iteration set before timing anything.
        let inputs: Vec<_> = (0..ITERATIONS)
            .map(|_| shards[usize::from(OWN_INDEX)].clone())
            .collect();
        let mut samples = Vec::with_capacity(ITERATIONS);
        for shard in inputs {
            let start = Instant::now();
            let weakened = Coder::weaken(NAMESPACE, &config, &commitment, OWN_INDEX, shard);
            samples.push(start.elapsed());
            weakened.expect("weaken failed");
        }
        let weaken = median(samples);

        // Checking data comes from our own shard; the shard being checked comes from a peer.
        let (checking_data, _, _) = Coder::weaken(
            NAMESPACE,
            &config,
            &commitment,
            OWN_INDEX,
            shards[usize::from(OWN_INDEX)].clone(),
        )
        .expect("weaken failed");
        let (_, _, peer_weak) = Coder::weaken(
            NAMESPACE,
            &config,
            &commitment,
            PEER_INDEX,
            shards[usize::from(PEER_INDEX)].clone(),
        )
        .expect("weaken failed");
        let weak_shard = peer_weak.encode_size();

        // Check takes the weak shard by value, so clone outside the timed region.
        let inputs: Vec<_> = (0..ITERATIONS).map(|_| peer_weak.clone()).collect();
        let mut samples = Vec::with_capacity(ITERATIONS);
        for weak in inputs {
            let start = Instant::now();
            let checked = Coder::check(&config, &commitment, &checking_data, PEER_INDEX, weak);
            samples.push(start.elapsed());
            checked.expect("check failed");
        }
        let check = median(samples);

        Row {
            label: format!(
                "{:<8} n={:<4} ({}+{})",
                case.size,
                case.participants,
                config.minimum_shards.get(),
                config.extra_shards.get()
            ),
            encode,
            weaken,
            check,
            strong_shard,
            weak_shard,
        }
    }

    #[test]
    #[ignore = "manual measurement harness"]
    fn p0_measure_zoda_attestation_path() {
        const KIB: usize = 1 << 10;
        const MIB: usize = 1 << 20;

        let cases = [
            Case {
                size: "256 KiB",
                data_len: 256 * KIB,
                participants: 10,
            },
            Case {
                size: "256 KiB",
                data_len: 256 * KIB,
                participants: 100,
            },
            Case {
                size: "1 MiB",
                data_len: MIB,
                participants: 10,
            },
            Case {
                size: "1 MiB",
                data_len: MIB,
                participants: 100,
            },
            Case {
                size: "8 MiB",
                data_len: 8 * MIB,
                participants: 10,
            },
            Case {
                size: "8 MiB",
                data_len: 8 * MIB,
                participants: 100,
            },
            // Shard sizing for the four-validator binary deployment.
            Case {
                size: "8 MiB",
                data_len: 8 * MIB,
                participants: 4,
            },
        ];

        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let rows: Vec<_> = cases.iter().map(|case| measure(case, &mut rng)).collect();

        println!();
        println!(
            "Zoda<Sha256>, conc=1 (Sequential), median of {ITERATIONS} iterations, namespace {}",
            String::from_utf8_lossy(NAMESPACE)
        );
        println!(
            "{:<24} {:>12} {:>12} {:>12} {:>16} {:>16}",
            "case", "encode", "weaken", "check", "strong shard", "weak shard"
        );
        println!("{}", "-".repeat(98));
        for row in &rows {
            println!(
                "{:<24} {:>12} {:>12} {:>12} {:>16} {:>16}",
                row.label,
                ms(row.encode),
                ms(row.weaken),
                ms(row.check),
                format!("{} B", row.strong_shard),
                format!("{} B", row.weak_shard),
            );
        }
        println!();
    }
}
