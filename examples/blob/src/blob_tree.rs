//! Fixed-depth padded Poseidon2 Merkle trees over pages and over blob identities.
//!
//! Two trees, one shape. The **page tree** ([`PageTree`]) sits inside a blob: its leaves are the
//! blob's 4 KiB pages and its root is folded into the [`BlobId`]. The **blob tree**
//! ([`BlobTree`]) sits over a batch: its leaves are the batch's blob identities and its root is
//! what a gateway claims inside a [`DaCert`](crate::types::DaCert).
//!
//! Both are binary, both are a fixed depth, and both pad missing slots with precomputed
//! empty-subtree digests. Fixed depth is the point: a membership path is always exactly
//! [`PAGE_DEPTH`] or [`BATCH_DEPTH`] field elements, so a Noir circuit verifying one has no
//! variable-length loop. `commonware_storage::bmt` is deliberately not used here, because its
//! depth follows the leaf count and its padding is a library detail rather than a wire constant.
//!
//! A tree is folded once by [`BlobTree::build`] or [`PageTree::build`] and then answers any number
//! of [`prove`](BlobTree::prove) calls from the levels it kept. A proof carries the index it was
//! taken at, so verification needs only the root and the content being opened, and a verifier
//! never builds a tree at all.
//!
//! # Integrity tier
//!
//! Everything in this module is **derived**: any reader who holds the decoded batch recomputes
//! these roots and needs to trust nobody. Attestors cannot verify them from a single shard, which
//! is exactly why the batch root travels as a gateway *claim* rather than inside the attested
//! subject.

use crate::{
    constants::BLOB_PAGE,
    poseidon2::{self, Fr, Hasher, TAG_EMPTY, TAG_LEAF, TAG_NODE, TAG_PAGE},
    types::{Blob, BlobId, Error},
};
use ark_ff::AdditiveGroup;
use std::sync::LazyLock;

/// Depth of the blob tree: `2^8 = 256 = MAX_BLOBS_PER_BATCH` leaves.
pub const BATCH_DEPTH: usize = 8;

/// Depth of the page tree: `2^7 = 128 = MAX_BLOB_SIZE / BLOB_PAGE` leaves.
pub const PAGE_DEPTH: usize = 7;

/// Roots of the all-empty subtree at each level, `EMPTY[k]` covering `2^k` padded leaves.
static EMPTY: LazyLock<[Fr; BATCH_DEPTH + 1]> = LazyLock::new(|| {
    let mut levels = [Fr::ZERO; BATCH_DEPTH + 1];
    levels[0] = poseidon2::hash(&[TAG_EMPTY]);
    for level in 1..=BATCH_DEPTH {
        levels[level] = node(levels[level - 1], levels[level - 1]);
    }
    levels
});

/// Hashes an inner node.
fn node(left: Fr, right: Fr) -> Fr {
    poseidon2::hash(&[TAG_NODE, left, right])
}

/// Hashes a page into a page-tree leaf.
///
/// The page is packed as 31-byte little-endian limbs; a short final page hashes only the limbs it
/// fills, and its byte length is pinned by the blob length inside the [`BlobId`].
fn page_leaf(page: &[u8]) -> Fr {
    let mut hasher = Hasher::new(1 + poseidon2::packed_len(page.len()));
    hasher.absorb(TAG_PAGE);
    hasher.absorb_bytes(page);
    hasher.finish()
}

/// Hashes a blob identity into a blob-tree leaf.
fn blob_leaf(id: &BlobId) -> Fr {
    poseidon2::hash(&[TAG_LEAF, id.element()])
}

/// Folds `leaves` into every level of a depth-`D` tree padded with empty subtrees, leaves first
/// and the root last.
///
/// At most `2^D` leaves may be supplied; an empty slice folds to the all-empty tree, so the last
/// level always holds exactly one element.
fn build_levels<const D: usize>(leaves: Vec<Fr>) -> Vec<Vec<Fr>> {
    let mut level = if leaves.is_empty() {
        vec![EMPTY[0]]
    } else {
        leaves
    };
    let mut levels = Vec::with_capacity(D + 1);
    for depth in 0..D {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = pair.get(1).copied().unwrap_or(EMPTY[depth]);
            next.push(node(pair[0], right));
        }
        levels.push(level);
        level = next;
    }
    levels.push(level);
    levels
}

/// Collects the sibling digests on the path from leaf `index` to the root of `levels`.
fn path_from_levels<const D: usize>(levels: &[Vec<Fr>], index: usize) -> [Fr; D] {
    let mut siblings = [Fr::ZERO; D];
    let mut position = index;
    for (depth, sibling) in siblings.iter_mut().enumerate() {
        *sibling = levels[depth]
            .get(position ^ 1)
            .copied()
            .unwrap_or(EMPTY[depth]);
        position /= 2;
    }
    siblings
}

/// Recomputes the root implied by `leaf` at `index` and its sibling digests.
fn root_from_path<const D: usize>(index: usize, leaf: Fr, siblings: &[Fr; D]) -> Fr {
    let mut current = leaf;
    let mut position = index;
    for sibling in siblings {
        current = if position.is_multiple_of(2) {
            node(current, *sibling)
        } else {
            node(*sibling, current)
        };
        position /= 2;
    }
    current
}

/// The depth-8 tree over a batch's blob identities.
///
/// Folded once and then queried: a gateway that seals a batch of 256 blobs pays for one fold, not
/// one per opening.
#[derive(Clone, Debug)]
pub struct BlobTree {
    /// Every level, leaves at index 0 and the root alone at index [`BATCH_DEPTH`].
    levels: Vec<Vec<Fr>>,
}

impl BlobTree {
    /// Folds the tree over `ids`, rejecting a batch outside the permitted count range.
    pub fn build(ids: &[BlobId]) -> Result<Self, Error> {
        if ids.is_empty() || ids.len() > (1 << BATCH_DEPTH) {
            return Err(Error::BatchCount(ids.len()));
        }
        let leaves = ids.iter().map(blob_leaf).collect();
        Ok(Self {
            levels: build_levels::<BATCH_DEPTH>(leaves),
        })
    }

    /// Returns the blob-tree root.
    pub fn root(&self) -> Fr {
        self.levels[BATCH_DEPTH][0]
    }

    /// Returns the membership proof of the blob identity at `index`.
    pub fn prove(&self, index: usize) -> Result<BatchProof, Error> {
        if index >= self.levels[0].len() {
            return Err(Error::UnknownIndex(index));
        }
        Ok(BatchProof {
            index: index as u16,
            siblings: path_from_levels::<BATCH_DEPTH>(&self.levels, index),
        })
    }
}

/// The depth-7 tree over one blob's pages.
#[derive(Clone, Debug)]
pub struct PageTree {
    /// Every level, leaves at index 0 and the root alone at index [`PAGE_DEPTH`].
    levels: Vec<Vec<Fr>>,
}

impl PageTree {
    /// Folds the page tree of `blob`.
    ///
    /// Infallible: a [`Blob`] is size-checked on construction, so its page count is always between
    /// one and the tree's capacity.
    pub fn build(blob: &Blob) -> Self {
        let leaves = (0..page_count(blob.len()))
            .map(|index| page_leaf(page(blob, index).expect("page index is below the page count")))
            .collect();
        Self {
            levels: build_levels::<PAGE_DEPTH>(leaves),
        }
    }

    /// Returns the page-tree root, the value a [`BlobId`] commits to.
    pub fn root(&self) -> Fr {
        self.levels[PAGE_DEPTH][0]
    }

    /// Returns the membership proof of the page at `page`.
    pub fn prove(&self, page: usize) -> Result<PageProof, Error> {
        if page >= self.levels[0].len() {
            return Err(Error::UnknownIndex(page));
        }
        Ok(PageProof {
            index: page as u8,
            siblings: path_from_levels::<PAGE_DEPTH>(&self.levels, page),
        })
    }
}

/// A blob identity's membership in a blob tree.
///
/// Self-contained: it names the slot it was taken from, so a verifier cannot pair it with the
/// wrong index by accident.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchProof {
    /// Slot the identity occupies in the batch.
    index: u16,
    /// Sibling digests from leaf to root.
    siblings: [Fr; BATCH_DEPTH],
}

impl BatchProof {
    /// Returns the slot the proven identity occupies.
    pub const fn index(&self) -> u16 {
        self.index
    }

    /// Checks that `id` occupies this proof's slot of the blob tree with root `root`.
    pub fn verify(&self, root: &Fr, id: &BlobId) -> bool {
        let index = self.index as usize;
        index < (1 << BATCH_DEPTH) && root_from_path(index, blob_leaf(id), &self.siblings) == *root
    }
}

/// A page's membership in a blob's page tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageProof {
    /// Position the page occupies in the blob.
    index: u8,
    /// Sibling digests from leaf to root.
    siblings: [Fr; PAGE_DEPTH],
}

impl PageProof {
    /// Returns the position of the proven page.
    pub const fn index(&self) -> u8 {
        self.index
    }

    /// Checks that `page` occupies this proof's position of the page tree with root `page_root`.
    ///
    /// The caller is responsible for binding `page_root` to a [`BlobId`] (see
    /// [`BlobId::matches`](crate::types::BlobId::matches)) and for checking that the length of
    /// `page` is the one the blob length implies for that position; this only proves membership.
    pub fn verify(&self, page_root: &Fr, page: &[u8]) -> bool {
        let index = self.index as usize;
        index < (1 << PAGE_DEPTH)
            && root_from_path(index, page_leaf(page), &self.siblings) == *page_root
    }
}

/// Returns the number of pages a blob of `len` bytes occupies.
pub const fn page_count(len: usize) -> usize {
    len.div_ceil(BLOB_PAGE)
}

/// Returns page `index` of `blob`, or `None` if the blob has no such page.
///
/// The final page is returned unpadded; padding happens in the field, not in the bytes.
pub fn page(blob: &Blob, index: usize) -> Option<&[u8]> {
    let bytes = blob.as_ref();
    let start = index.checked_mul(BLOB_PAGE)?;
    (start < bytes.len()).then(|| &bytes[start..bytes.len().min(start + BLOB_PAGE)])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{MAX_BLOB_SIZE, MAX_BLOBS_PER_BATCH};
    use bytes::Bytes;

    /// Builds `count` distinct blobs, each `len` bytes.
    ///
    /// The filler is a linear congruential stream rather than a byte counter, so no two pages of a
    /// blob are equal; a repeating pattern would make page-order assertions vacuous.
    fn blobs(count: usize, len: usize) -> Vec<Blob> {
        (0..count)
            .map(|index| {
                let mut state = 0x1234_5678u32.wrapping_add(index as u32);
                let mut bytes = vec![0u8; len];
                for byte in &mut bytes {
                    state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                    *byte = (state >> 16) as u8;
                }
                Blob::new(Bytes::from(bytes)).expect("blob is within bounds")
            })
            .collect()
    }

    /// Positions to exercise for a tree with `occupied` leaves: every one while that is cheap, and
    /// the edges plus the middle once it is not.
    fn sampled(occupied: usize) -> Vec<usize> {
        if occupied <= 8 {
            return (0..occupied).collect();
        }
        let mut positions = vec![0, occupied / 2, occupied - 1];
        positions.dedup();
        positions
    }

    #[test]
    fn p1_blob_tree_membership_roundtrip() {
        for count in [1usize, 2, 3, 5, 8, 17, MAX_BLOBS_PER_BATCH] {
            let ids: Vec<BlobId> = blobs(count, 64).iter().map(Blob::id).collect();
            let tree = BlobTree::build(&ids).expect("count is within bounds");
            let root = tree.root();

            for index in sampled(count) {
                let id = &ids[index];
                let proof = tree.prove(index).expect("index is occupied");
                assert_eq!(proof.index(), index as u16);
                assert!(proof.verify(&root, id), "count {count} index {index}");

                // Wrong index, wrong identity, wrong root, and a tampered path all fail.
                let other = (index + 1) % count;
                if other != index {
                    let moved = BatchProof {
                        index: other as u16,
                        siblings: proof.siblings,
                    };
                    assert!(!moved.verify(&root, id));
                    assert!(!proof.verify(&root, &ids[other]));
                }
                assert!(!proof.verify(&(root + Fr::from(1u64)), id));
                let mut tampered = proof;
                tampered.siblings[0] += Fr::from(1u64);
                assert!(!tampered.verify(&root, id));
            }
        }
    }

    #[test]
    fn p1_blob_tree_padded_slots_are_not_members() {
        let ids: Vec<BlobId> = blobs(5, 64).iter().map(Blob::id).collect();
        let tree = BlobTree::build(&ids).expect("count is within bounds");
        let root = tree.root();

        // No proof exists for an unoccupied slot.
        assert!(matches!(tree.prove(5), Err(Error::UnknownIndex(5))));

        // And no identity can be planted in one: the padded siblings of slot 5 form the only path
        // that reaches the root there, and it commits to the empty leaf, not to a blob.
        let padded = BatchProof {
            index: 5,
            siblings: [
                EMPTY[0], EMPTY[1], EMPTY[2], EMPTY[3], EMPTY[4], EMPTY[5], EMPTY[6], EMPTY[7],
            ],
        };
        for id in &ids {
            assert!(!padded.verify(&root, id));
        }
    }

    #[test]
    fn p1_blob_tree_rejects_out_of_range_counts() {
        let ids: Vec<BlobId> = blobs(1, 64).iter().map(Blob::id).collect();
        assert!(matches!(BlobTree::build(&[]), Err(Error::BatchCount(0))));
        let tree = BlobTree::build(&ids).expect("count is within bounds");
        assert!(matches!(tree.prove(1), Err(Error::UnknownIndex(1))));

        let too_many = vec![ids[0]; MAX_BLOBS_PER_BATCH + 1];
        assert!(matches!(
            BlobTree::build(&too_many),
            Err(Error::BatchCount(257))
        ));
    }

    #[test]
    fn p1_blob_page_opening_roundtrip() {
        // A multi-page blob with a short final page, and one that is exactly page aligned.
        for len in [BLOB_PAGE * 3 + 17, BLOB_PAGE * 4, MAX_BLOB_SIZE] {
            let blob = blobs(1, len).remove(0);
            let tree = PageTree::build(&blob);
            let root = tree.root();
            let pages = page_count(len);
            assert_eq!(pages, len.div_ceil(BLOB_PAGE));

            for index in sampled(pages) {
                let bytes = page(&blob, index).expect("page index is occupied");
                let proof = tree.prove(index).expect("page index is occupied");
                assert_eq!(proof.index(), index as u8);
                assert!(proof.verify(&root, bytes), "len {len} page {index}");

                // A tampered window, a shifted window, and the wrong index all fail.
                let mut tampered = bytes.to_vec();
                tampered[0] ^= 1;
                assert!(!proof.verify(&root, &tampered));
                assert!(!proof.verify(&root, &bytes[1..]));
                if pages > 1 {
                    let moved = PageProof {
                        index: ((index + 1) % pages) as u8,
                        siblings: proof.siblings,
                    };
                    assert!(!moved.verify(&root, bytes));
                }
            }

            assert!(page(&blob, pages).is_none());
            assert!(matches!(tree.prove(pages), Err(Error::UnknownIndex(_))));
        }
    }

    #[test]
    fn p1_blob_page_tree_binds_page_order() {
        // Swapping two pages changes the root: the tree is positional, not a set commitment.
        let blob = blobs(1, BLOB_PAGE * 2).remove(0);
        let mut swapped = blob.as_ref().to_vec();
        let (left, right) = swapped.split_at_mut(BLOB_PAGE);
        left.swap_with_slice(right);
        let swapped = Blob::new(Bytes::from(swapped)).expect("blob is within bounds");
        assert_ne!(
            PageTree::build(&blob).root(),
            PageTree::build(&swapped).root()
        );
    }

    #[test]
    fn p1_blob_tree_empty_subtrees_are_distinct() {
        // Padding constants must not collide across levels, or a subtree could be moved.
        for level in 0..=BATCH_DEPTH {
            for other in (level + 1)..=BATCH_DEPTH {
                assert_ne!(EMPTY[level], EMPTY[other]);
            }
        }
    }
}
