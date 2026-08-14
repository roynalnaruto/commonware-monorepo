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
//! round constants live in [`crate::poseidon2::constants`] and carry their provenance there.
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

mod constants;
mod permutation;
mod sponge;

// The hashing scheme is exported in full, so some of these names have no caller inside this
// binary yet.
#[allow(unused_imports)]
pub use self::{
    permutation::{RATE, WIDTH, permute},
    sponge::{FR_SIZE, Hasher, LIMB_SIZE, from_bytes, hash, pack, packed_len, to_bytes},
};
use ark_ff::MontFp;

/// The BN254 scalar field.
pub type Fr = ark_bn254::Fr;

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
