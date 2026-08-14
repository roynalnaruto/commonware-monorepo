//! The Noir-compatible Poseidon2 sponge and the byte packing it absorbs.
//!
//! [`hash`] and [`Hasher`] are the two forms of one sponge: the same state, the same
//! length-derived capacity slot, and the same final permutation. [`pack`] is the only way bytes
//! enter it.

use super::{
    Fr,
    permutation::{RATE, WIDTH, permute},
};
use ark_ff::{AdditiveGroup, BigInt, BigInteger, PrimeField};

/// Encoded size of a field element on the wire.
pub const FR_SIZE: usize = 32;

/// Bytes packed into a single field element by [`pack`].
pub const LIMB_SIZE: usize = 31;

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
    use crate::poseidon2::{TAG_BLOB, TAG_NODE};
    use ark_ff::MontFp;

    /// The largest canonical field element, `r - 1`.
    const MAX: Fr =
        MontFp!("21888242871839275222246405745257275088548364400416034343698204186575808495616");

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
