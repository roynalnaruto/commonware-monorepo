//! Conformance vectors for the Poseidon2 sponge the blob rail hashes with.
//!
//! `sponge` below is the Noir side of `examples/blob/src/poseidon2/sponge.rs`: the semantics of
//! `Poseidon2Hasher::finish_ref` (capacity slot `len << 64`, rate-3 absorb, trailing permutation)
//! rebuilt on top of the public `std::hash::poseidon2_permutation`, which is the only Poseidon2
//! entry point the standard library still exports. Nothing here reaches into a private module, so
//! a future circuit can be written exactly this way.
//!
//! `nargo test --show-output` asserts every vector and prints it, so the Rust conformance test and
//! this file can be compared without trusting either one's arithmetic.

use std::hash::poseidon2_permutation;

/// Field elements in the permutation state.
global WIDTH: u32 = 4;

/// Field elements absorbed per permutation.
global RATE: u32 = 3;

/// `2^64`, the multiplier that lifts the input length into the capacity slot.
global IV_SHIFT: Field = 18446744073709551616;

/// Hashes `inputs` with the sponge the blob rail commits to.
fn sponge<let N: u32>(inputs: [Field; N]) -> Field {
    let mut state: [Field; WIDTH] = [0; WIDTH];
    state[RATE] = (N as Field) * IV_SHIFT;
    let blocks = N / RATE;
    for block in 0..blocks {
        for j in 0..RATE {
            state[j] = state[j] + inputs[block * RATE + j];
        }
        state = poseidon2_permutation(state);
    }
    let tail = N % RATE;
    for j in 0..tail {
        state[j] = state[j] + inputs[blocks * RATE + j];
    }
    // The trailing permutation runs even when the tail is empty; that is the reference behaviour.
    let squeezed: [Field; WIDTH] = poseidon2_permutation(state);
    squeezed[0]
}

/// Hashes `1, 2, ..., N`, the shape every vector below uses.
fn ramp<let N: u32>() -> Field {
    let mut inputs: [Field; N] = [0; N];
    for i in 0..N {
        inputs[i] = (i + 1) as Field;
    }
    sponge(inputs)
}

fn main() {}

/// The permutation itself, against barretenberg's published test vector.
#[test]
fn permutation_vector() {
    let state: [Field; WIDTH] = [0, 1, 2, 3];
    let out: [Field; WIDTH] = poseidon2_permutation(state);
    assert(out[0] == 0x01bd538c2ee014ed5141b29e9ae240bf8db3fe5b9a38629a9647cf8d76c01737);
    assert(out[1] == 0x239b62e7db98aa3a2a8f6a0d2fa1709e7a35959aa6c7034814d9daa90cbac662);
    assert(out[2] == 0x04cbb44c61d928ed06808456bf758cbf0c18d1e15a7b6dbc8245fa7515d5e3cb);
    assert(out[3] == 0x2e11c5cff2a22c64d01304b778d78f6998eff1ab73163a35603f54794c30847a);
}

/// The sponge, against the digest `noir_stdlib/src/hash/poseidon2.nr` asserts about itself in
/// `finish_ref_matches_known_digest`. Reproducing it is what says this rebuild is the reference
/// sponge rather than merely a self-consistent one.
#[test]
fn sponge_matches_stdlib_known_digest() {
    assert(ramp::<5>() == 0x2247be7014a54d17342a7ef677f58d28877780d203860396967f5d0a18d259db);
}

/// The input lengths the rail actually hashes: empty, every residue of the rate, and a 4 KiB page
/// worth of limbs plus a tag.
#[test]
fn sponge_vectors() {
    let vectors: [(u32, Field); 9] = [
        (0, 0x18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e),
        (1, 0x168758332d5b3e2d13be8048c8011b454590e06c44bce7f702f09103eef5a373),
        (2, 0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383),
        (3, 0x16f5da1a6b40e7d71bcdf29687e7908cdf74da44c09058fe36a0a99e269c6972),
        (4, 0x130bf204a32cac1f0ace56c78b731aa3809f06df2731ebcf6b3464a15788b1b9),
        (6, 0x04a7639afe4c6a14a65325370b03098ad98d16594dc67e28d9b6d28b2b01c15e),
        (7, 0x16f929bc0d216df4b05bdc44222463edf2b9791bd949ab926eebda06a502d238),
        (10, 0x1cf91a7e72341f2804e3a5dd7c7e2b05cb27beb864104a26a4c6c39738b52947),
        (134, 0x10c9e4d01fa7959ea4ef908ded893ed8662ffbb69d728636af788bd6cc2052db),
    ];
    let digests: [Field; 9] = [
        ramp::<0>(),
        ramp::<1>(),
        ramp::<2>(),
        ramp::<3>(),
        ramp::<4>(),
        ramp::<6>(),
        ramp::<7>(),
        ramp::<10>(),
        ramp::<134>(),
    ];
    for i in 0..9 {
        let (len, expected) = vectors[i];
        let digest: Field = digests[i];
        println(f"len {len}: {digest}");
        assert(digest == expected);
    }
}
