//! Manual measurement harness for the ZODA operations on the attestation critical path.
//!
//! Dispersal cost is dominated by the gateway's `encode`, which is already benchmarked in
//! `commonware-coding`. The per-validator attestation path is not: every validator runs `weaken`
//! once on its own strong shard, and the retrieval path runs `check` once per shard gathered from
//! a peer. Those two costs bound how often a batch can be dispersed, so they are measured here at
//! `conc = 1` (a single validator attesting on one core) before batch parameters are fixed.
//!
//! This harness is ignored by default because it is a measurement, not an assertion. Run it in
//! release mode; debug timings are meaningless:
//!
//! ```sh
//! cargo test --release -p commonware-blob --test measure -- --ignored --nocapture
//! ```

use commonware_codec::EncodeSize as _;
use commonware_coding::{Config, PhasedScheme as _, Zoda};
use commonware_cryptography::Sha256;
use commonware_parallel::Sequential;
use commonware_utils::NZU16;
use rand::{Rng as _, SeedableRng as _};
use rand_chacha::ChaCha8Rng;
use std::time::{Duration, Instant};

/// Domain separation for this harness. Never used on a live rail.
const NAMESPACE: &[u8] = b"_COMMONWARE_EXAMPLES_BLOB_MEASURE";

/// Single-threaded: one validator attesting on one core is the cost we are bounding.
const STRATEGY: Sequential = Sequential;

/// Timed iterations per operation. Odd, so the median is a real sample.
const ITERATIONS: usize = 9;

/// The shard a validator weakens; also the source of the checking data.
const OWN_INDEX: u16 = 0;

/// The shard whose weak form is checked, distinct from [`OWN_INDEX`] so `check` does the work it
/// does on the retrieval path.
const PEER_INDEX: u16 = 1;

type Scheme = Zoda<Sha256>;

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

/// Coding parameters for `n = 3f + 1` participants: `f + 1` shards reconstruct the data, and the
/// remaining `n - (f + 1)` are redundancy.
const fn coding_config(participants: u16) -> Config {
    let f = (participants - 1) / 3;
    Config {
        minimum_shards: NZU16!(f + 1),
        extra_shards: NZU16!(participants - (f + 1)),
    }
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

/// Measures one case end to end.
fn measure(case: &Case, rng: &mut ChaCha8Rng) -> Row {
    let config = coding_config(case.participants);
    let mut data = vec![0u8; case.data_len];
    rng.fill_bytes(&mut data);

    // Encode once. This is the gateway's cost, recorded for scale rather than as the target.
    let start = Instant::now();
    let (commitment, shards) =
        Scheme::encode(NAMESPACE, &config, data.as_slice(), &STRATEGY).expect("encode failed");
    let encode = start.elapsed();
    let strong_shard = shards[usize::from(OWN_INDEX)].encode_size();

    // Weaken consumes the shard, so build the whole iteration set before timing anything.
    let inputs: Vec<_> = (0..ITERATIONS)
        .map(|_| shards[usize::from(OWN_INDEX)].clone())
        .collect();
    let mut samples = Vec::with_capacity(ITERATIONS);
    for shard in inputs {
        let start = Instant::now();
        let weakened = Scheme::weaken(NAMESPACE, &config, &commitment, OWN_INDEX, shard);
        samples.push(start.elapsed());
        weakened.expect("weaken failed");
    }
    let weaken = median(samples);

    // Checking data comes from our own shard; the shard being checked comes from a peer.
    let (checking_data, _, _) = Scheme::weaken(
        NAMESPACE,
        &config,
        &commitment,
        OWN_INDEX,
        shards[usize::from(OWN_INDEX)].clone(),
    )
    .expect("weaken failed");
    let (_, _, peer_weak) = Scheme::weaken(
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
        let checked = Scheme::check(&config, &commitment, &checking_data, PEER_INDEX, weak);
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
fn measure_attestation_path() {
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
