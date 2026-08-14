//! Poseidon2 over the BN254 scalar field, parameter-identical to Noir and Barretenberg.
//!
//! Every hash this example commits to on the data-availability rail (blob identities, page trees,
//! blob trees) is computed here. The point of using Poseidon2-BN254 rather than a byte hash is
//! that a future execution layer can re-check the same statements inside a Noir/UltraHonk circuit
//! for a few dozen permutations instead of tens of thousands of bit operations.
//!
//! # Parameters
//!
//! State width `t = 4`, rate 3, capacity 1, S-box `x^5`, 8 full rounds and 56 partial rounds. The
//! round constants live in [`crate::poseidon2_constants`] and carry their provenance there.
//!
//! # Sponge
//!
//! [`hash`] is a line-for-line port of `Poseidon2Hasher::finish_ref` from
//! `noir_stdlib/src/hash/poseidon2.nr` (tag `v1.0.0-beta.26`), the only Poseidon2 sponge the Noir
//! standard library ships today:
//!
//! ```text
//! iv         = len(inputs) * 2^64                  // capacity slot
//! state      = [0, 0, 0, iv]
//! for block in inputs.chunks_exact(3):             // full blocks
//!     state[0..3] += block; state = permute(state)
//! state[0..n] += tail                              // 0 <= n < 3 leftover elements
//! return permute(state)[0]
//! ```
//!
//! A Noir circuit reproduces it verbatim on top of the public `std::hash::poseidon2_permutation`,
//! so nothing here depends on a Noir-internal API. Note the final permutation runs even when the
//! tail is empty; that is Noir's behaviour and matching it matters more than saving a permutation.
//!
//! # Domain separation
//!
//! Inputs are always prefixed with one of the tags below, so a page leaf can never be reinterpreted
//! as an inner node or a blob identity. The tags, the 31-byte packing in [`pack`], and the sponge
//! above are the complete normative description of the hashing scheme; a Noir port needs nothing
//! else.
//!
//! | Tag | Input shape | Meaning |
//! |---|---|---|
//! | [`TAG_PAGE`] | `[TAG_PAGE, ..pack(page)]` | leaf of the page tree |
//! | [`TAG_BLOB`] | `[TAG_BLOB, len, page_root]` | field element inside a [`BlobId`](crate::types::BlobId) |
//! | [`TAG_LEAF`] | `[TAG_LEAF, blob_id]` | leaf of the blob tree |
//! | [`TAG_NODE`] | `[TAG_NODE, left, right]` | inner node of either tree |
//! | [`TAG_EMPTY`] | `[TAG_EMPTY]` | padding leaf of either tree |

use crate::poseidon2_constants::{INTERNAL_DIAGONAL, ROUND_CONSTANTS};
use ark_ff::{AdditiveGroup, BigInt, BigInteger, MontFp, PrimeField};

/// The BN254 scalar field.
pub type Fr = ark_bn254::Fr;

/// Number of field elements in the permutation state.
pub const WIDTH: usize = 4;

/// Number of field elements absorbed per permutation.
pub const RATE: usize = 3;

/// Full rounds, split evenly before and after the partial rounds.
const ROUNDS_F: usize = 8;

/// Partial rounds, applying the S-box to the first state element only.
const ROUNDS_P: usize = 56;

/// Total rounds, and the number of round-constant rows.
pub(crate) const ROUNDS: usize = ROUNDS_F + ROUNDS_P;

/// Encoded size of a field element on the wire.
pub const FR_SIZE: usize = 32;

/// Bytes packed into a single field element by [`pack`].
pub const LIMB_SIZE: usize = 31;

/// Domain tag for a page-tree leaf.
pub const TAG_PAGE: Fr = MontFp!("1");

/// Domain tag for the field element inside a [`BlobId`](crate::types::BlobId).
pub const TAG_BLOB: Fr = MontFp!("2");

/// Domain tag for a blob-tree leaf.
pub const TAG_LEAF: Fr = MontFp!("3");

/// Domain tag for an inner node of either tree.
pub const TAG_NODE: Fr = MontFp!("4");

/// Domain tag for the padding leaf of either tree.
pub const TAG_EMPTY: Fr = MontFp!("5");

/// The S-box `x^5`.
#[inline]
fn sbox(x: Fr) -> Fr {
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x
}

/// The external (full-round) matrix, using Barretenberg's addition chain.
#[inline]
fn external_matrix(state: &mut [Fr; WIDTH]) {
    let t0 = state[0] + state[1];
    let t1 = state[2] + state[3];
    let mut t2 = state[1] + state[1];
    t2 += t1;
    let mut t3 = state[3] + state[3];
    t3 += t0;
    let mut t4 = t1 + t1;
    t4 += t4;
    t4 += t3;
    let mut t5 = t0 + t0;
    t5 += t5;
    t5 += t2;
    let t6 = t3 + t5;
    let t7 = t2 + t4;
    state[0] = t6;
    state[1] = t5;
    state[2] = t7;
    state[3] = t4;
}

/// The internal (partial-round) matrix: `(D_i - 1) * x_i + sum(x)`.
#[inline]
fn internal_matrix(state: &mut [Fr; WIDTH]) {
    let sum = state[0] + state[1] + state[2] + state[3];
    for (element, diagonal) in state.iter_mut().zip(INTERNAL_DIAGONAL.iter()) {
        *element *= diagonal;
        *element += sum;
    }
}

/// Applies the Poseidon2 permutation in place.
pub fn permute(state: &mut [Fr; WIDTH]) {
    external_matrix(state);

    let half = ROUNDS_F / 2;
    for constants in ROUND_CONSTANTS.iter().take(half) {
        for (element, constant) in state.iter_mut().zip(constants.iter()) {
            *element += constant;
            *element = sbox(*element);
        }
        external_matrix(state);
    }
    for constants in ROUND_CONSTANTS.iter().take(half + ROUNDS_P).skip(half) {
        state[0] += constants[0];
        state[0] = sbox(state[0]);
        internal_matrix(state);
    }
    for constants in ROUND_CONSTANTS.iter().skip(half + ROUNDS_P) {
        for (element, constant) in state.iter_mut().zip(constants.iter()) {
            *element += constant;
            *element = sbox(*element);
        }
        external_matrix(state);
    }
}

/// Incremental form of [`hash`], for inputs that would be wasteful to materialize.
///
/// The total number of inputs must be known up front because it is bound into the capacity slot.
/// Absorbing a different number of elements than declared produces a digest that no verifier will
/// reproduce.
pub struct Hasher {
    /// Sponge state; `state[RATE]` starts at the length-derived initialization value.
    state: [Fr; WIDTH],
    /// Elements absorbed into the current block.
    buffered: usize,
}

impl Hasher {
    /// Starts a sponge that will absorb exactly `inputs` elements.
    pub fn new(inputs: usize) -> Self {
        let mut state = [Fr::ZERO; WIDTH];
        state[RATE] = Fr::from((inputs as u128) << 64);
        Self { state, buffered: 0 }
    }

    /// Absorbs one element.
    pub fn absorb(&mut self, input: Fr) {
        self.state[self.buffered] += input;
        self.buffered += 1;
        if self.buffered == RATE {
            permute(&mut self.state);
            self.buffered = 0;
        }
    }

    /// Absorbs `bytes` as 31-byte little-endian limbs.
    pub fn absorb_bytes(&mut self, bytes: &[u8]) {
        for limb in pack(bytes) {
            self.absorb(limb);
        }
    }

    /// Squeezes the digest.
    pub fn finish(mut self) -> Fr {
        permute(&mut self.state);
        self.state[0]
    }
}

/// Hashes `inputs` with the Noir standard library's Poseidon2 sponge.
pub fn hash(inputs: &[Fr]) -> Fr {
    let mut hasher = Hasher::new(inputs.len());
    for input in inputs {
        hasher.absorb(*input);
    }
    hasher.finish()
}

/// Packs `bytes` into field elements, 31 little-endian bytes at a time.
///
/// Every limb is below `2^248 < r`, so packing is canonical and, given a length bound elsewhere in
/// the preimage, injective. A trailing partial limb is zero-extended, which is why the byte length
/// must always be committed separately (it is, inside every [`BlobId`](crate::types::BlobId)).
pub fn pack(bytes: &[u8]) -> impl Iterator<Item = Fr> + '_ {
    bytes.chunks(LIMB_SIZE).map(|chunk| {
        let mut limbs = [0u64; 4];
        for (index, word) in chunk.chunks(8).enumerate() {
            let mut bytes = [0u8; 8];
            bytes[..word.len()].copy_from_slice(word);
            limbs[index] = u64::from_le_bytes(bytes);
        }
        Fr::from_bigint(BigInt::new(limbs)).expect("limb is below 2^248")
    })
}

/// Number of field elements [`pack`] produces for `bytes` bytes.
pub const fn packed_len(bytes: usize) -> usize {
    bytes.div_ceil(LIMB_SIZE)
}

/// Encodes a field element as 32 canonical little-endian bytes.
pub fn to_bytes(element: &Fr) -> [u8; FR_SIZE] {
    let mut encoded = [0u8; FR_SIZE];
    let bytes = element.into_bigint().to_bytes_le();
    encoded.copy_from_slice(&bytes);
    encoded
}

/// Decodes a field element from 32 little-endian bytes, rejecting any value at or above the field
/// modulus.
///
/// Non-canonical encodings are rejected rather than reduced: two encodings of one element would
/// give two wire forms of the same [`BlobId`](crate::types::BlobId).
pub fn from_bytes(encoded: &[u8; FR_SIZE]) -> Option<Fr> {
    let mut limbs = [0u64; 4];
    for (limb, word) in limbs.iter_mut().zip(encoded.chunks_exact(8)) {
        *limb = u64::from_le_bytes(word.try_into().expect("chunk is eight bytes"));
    }
    Fr::from_bigint(BigInt::new(limbs))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The largest canonical field element, `r - 1`.
    const MAX: Fr =
        MontFp!("21888242871839275222246405745257275088548364400416034343698204186575808495616");

    #[test]
    fn p1_poseidon2_noir_vectors() {
        // Permutation, `Poseidon2Bn254ScalarFieldParams::TEST_VECTOR_{INPUT,OUTPUT}` from
        // barretenberg's poseidon2_params.hpp @ 62c2197f7741a80864861e0ebb3462cd3ff4fa24.
        let mut state = [
            Fr::from(0u64),
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
        ];
        permute(&mut state);
        assert_eq!(
            state,
            [
                MontFp!("0x01bd538c2ee014ed5141b29e9ae240bf8db3fe5b9a38629a9647cf8d76c01737"),
                MontFp!("0x239b62e7db98aa3a2a8f6a0d2fa1709e7a35959aa6c7034814d9daa90cbac662"),
                MontFp!("0x04cbb44c61d928ed06808456bf758cbf0c18d1e15a7b6dbc8245fa7515d5e3cb"),
                MontFp!("0x2e11c5cff2a22c64d01304b778d78f6998eff1ab73163a35603f54794c30847a"),
            ]
        );

        // Permutation, `Poseidon2Permutation.ConsistencyCheck` from barretenberg's
        // poseidon2_permutation.test.cpp @ 62c2197f7741a80864861e0ebb3462cd3ff4fa24.
        let repeated: Fr =
            MontFp!("0x9a807b615c4d3e2fa0b1c2d3e4f56789fedcba9876543210abcdef0123456789");
        let mut state = [repeated; WIDTH];
        permute(&mut state);
        assert_eq!(
            state,
            [
                MontFp!("0x2bf1eaf87f7d27e8dc4056e9af975985bccc89077a21891d6c7b6ccce0631f95"),
                MontFp!("0x0c01fa1b8d0748becafbe452c0cb0231c38224ea824554c9362518eebdd5701f"),
                MontFp!("0x018555a8eb50cf07f64b019ebaf3af3c925c93e631f3ecd455db07bbb52bbdd3"),
                MontFp!("0x0cbea457c91c22c6c31fd89afd2541efc2edf31736b9f721e823b2165c90fd41"),
            ]
        );

        // Sponge, `finish_ref_matches_known_digest` from noir_stdlib/src/hash/poseidon2.nr @
        // v1.0.0-beta.26. This is the Noir standard library asserting its own digest, so it pins
        // the sponge, the permutation, and every round constant at once.
        let inputs: Vec<Fr> = (1u64..=5).map(Fr::from).collect();
        assert_eq!(
            hash(&inputs),
            MontFp!("0x2247be7014a54d17342a7ef677f58d28877780d203860396967f5d0a18d259db")
        );

        // Regression vectors for the input lengths the rail actually uses, generated by running
        // the same sponge over Noir's own permutation (`bn254_blackbox_solver::poseidon2_permutation`
        // at v1.0.0-beta.26) rather than the one below. They cover an empty input, every residue of
        // the rate, and a full 4 KiB page worth of limbs plus a tag.
        for (len, expected) in [
            (
                0,
                MontFp!("0x18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e"),
            ),
            (
                1,
                MontFp!("0x168758332d5b3e2d13be8048c8011b454590e06c44bce7f702f09103eef5a373"),
            ),
            (
                2,
                MontFp!("0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383"),
            ),
            (
                3,
                MontFp!("0x16f5da1a6b40e7d71bcdf29687e7908cdf74da44c09058fe36a0a99e269c6972"),
            ),
            (
                4,
                MontFp!("0x130bf204a32cac1f0ace56c78b731aa3809f06df2731ebcf6b3464a15788b1b9"),
            ),
            (
                6,
                MontFp!("0x04a7639afe4c6a14a65325370b03098ad98d16594dc67e28d9b6d28b2b01c15e"),
            ),
            (
                7,
                MontFp!("0x16f929bc0d216df4b05bdc44222463edf2b9791bd949ab926eebda06a502d238"),
            ),
            (
                10,
                MontFp!("0x1cf91a7e72341f2804e3a5dd7c7e2b05cb27beb864104a26a4c6c39738b52947"),
            ),
            (
                134,
                MontFp!("0x10c9e4d01fa7959ea4ef908ded893ed8662ffbb69d728636af788bd6cc2052db"),
            ),
        ] {
            let inputs: Vec<Fr> = (1..=len as u64).map(Fr::from).collect();
            assert_eq!(hash(&inputs), expected, "sponge vector for length {len}");
        }
    }

    #[test]
    fn p1_poseidon2_hasher_matches_hash() {
        for len in [0usize, 1, 2, 3, 4, 5, 9, 64] {
            let inputs: Vec<Fr> = (1..=len as u64).map(Fr::from).collect();
            let mut hasher = Hasher::new(len);
            for input in &inputs {
                hasher.absorb(*input);
            }
            assert_eq!(hasher.finish(), hash(&inputs), "length {len}");
        }
    }

    #[test]
    fn p1_poseidon2_length_and_tag_separate_domains() {
        // The capacity slot is derived from the input length, so a shorter input is never a
        // prefix-collision of a longer one.
        assert_ne!(hash(&[Fr::from(1u64)]), hash(&[Fr::from(1u64), Fr::ZERO]));
        // Distinct tags separate the shapes that share an arity.
        assert_ne!(
            hash(&[TAG_NODE, Fr::from(7u64), Fr::from(8u64)]),
            hash(&[TAG_BLOB, Fr::from(7u64), Fr::from(8u64)])
        );
    }

    #[test]
    fn p1_poseidon2_fr_wire_roundtrip() {
        for element in [Fr::ZERO, Fr::from(1u64), Fr::from(u64::MAX), MAX] {
            assert_eq!(from_bytes(&to_bytes(&element)), Some(element));
        }

        // The modulus itself and everything above it must be rejected, not reduced.
        let modulus = {
            let mut encoded = to_bytes(&MAX);
            encoded[0] += 1;
            encoded
        };
        assert_eq!(from_bytes(&modulus), None);
        assert_eq!(from_bytes(&[0xff; FR_SIZE]), None);
    }

    #[test]
    fn p1_poseidon2_pack_is_injective_for_fixed_length() {
        assert_eq!(packed_len(0), 0);
        assert_eq!(packed_len(1), 1);
        assert_eq!(packed_len(LIMB_SIZE), 1);
        assert_eq!(packed_len(LIMB_SIZE + 1), 2);
        assert_eq!(packed_len(4096), 133);

        // Little-endian limbs: the first byte is the least significant.
        let mut bytes = [0u8; LIMB_SIZE];
        bytes[0] = 3;
        assert_eq!(pack(&bytes).collect::<Vec<_>>(), vec![Fr::from(3u64)]);

        // Distinct byte strings of the same length pack to distinct limb sequences.
        let a: Vec<u8> = (0..64u8).collect();
        let mut b = a.clone();
        b[63] ^= 1;
        assert_ne!(
            pack(&a).collect::<Vec<_>>(),
            pack(&b).collect::<Vec<_>>(),
            "packing must not drop the tail"
        );
        assert_eq!(pack(&a).count(), packed_len(a.len()));
    }
}
