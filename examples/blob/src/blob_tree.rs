//! Fixed-depth padded Poseidon2 Merkle trees over pages and over blob identities.
//!
//! Two trees, one shape. The **page tree** sits inside a blob: its leaves are the blob's 4 KiB
//! pages and its root is folded into the [`BlobId`]. The **blob tree** sits
//! over a batch: its leaves are the batch's blob identities and its root is what a gateway claims
//! inside a [`DaCert`](crate::types::DaCert).
//!
//! Both are binary, both are a fixed depth, and both pad missing slots with precomputed
//! empty-subtree digests. Fixed depth is the point: a membership path is always exactly
//! [`PAGE_DEPTH`] or [`BATCH_DEPTH`] field elements, so a Noir circuit verifying one has no
//! variable-length loop. `commonware_storage::bmt` is deliberately not used here, because its
//! depth follows the leaf count and its padding is a library detail rather than a wire constant.
//!
//! # Integrity tier
//!
//! Everything in this module is **derived**: any reader who holds the decoded batch recomputes
//! these roots and needs to trust nobody. Attestors cannot verify them from a single shard, which
//! is exactly why the batch root travels as a gateway *claim* rather than inside the attested
//! subject.

use crate::{
    constants::{BLOB_PAGE, MAX_BLOBS_PER_BATCH},
    poseidon2::{self, Fr, Hasher, TAG_EMPTY, TAG_LEAF, TAG_NODE, TAG_PAGE},
    types::{Blob, BlobId, Error},
};
use ark_ff::AdditiveGroup;
use std::sync::LazyLock;

/// Depth of the blob tree: `2^8 = 256 = MAX_BLOBS_PER_BATCH` leaves.
pub const BATCH_DEPTH: usize = 8;

/// Depth of the page tree: `2^7 = 128 = MAX_BLOB_SIZE / BLOB_PAGE` leaves.
pub const PAGE_DEPTH: usize = 7;

/// Membership path of a blob identity in the blob tree, sibling digests from leaf to root.
pub type BatchPath = [Fr; BATCH_DEPTH];

/// Membership path of a page in a blob's page tree, sibling digests from leaf to root.
pub type PagePath = [Fr; PAGE_DEPTH];

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

/// Folds `leaves` into the root of a depth-`D` tree padded with empty subtrees.
fn root_of<const D: usize>(leaves: &[Fr]) -> Fr {
    if leaves.is_empty() {
        return EMPTY[D];
    }
    let mut level = leaves.to_vec();
    for depth in 0..D {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = pair.get(1).copied().unwrap_or(EMPTY[depth]);
            next.push(node(pair[0], right));
        }
        level = next;
    }
    level[0]
}

/// Collects the sibling digests on the path from leaf `index` to the root.
fn path_of<const D: usize>(leaves: &[Fr], index: usize) -> [Fr; D] {
    let mut path = [Fr::ZERO; D];
    let mut level = leaves.to_vec();
    let mut position = index;
    for (depth, sibling) in path.iter_mut().enumerate() {
        *sibling = level.get(position ^ 1).copied().unwrap_or(EMPTY[depth]);
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = pair.get(1).copied().unwrap_or(EMPTY[depth]);
            next.push(node(pair[0], right));
        }
        level = next;
        position /= 2;
    }
    path
}

/// Recomputes the root implied by a leaf and its path.
fn root_from_path<const D: usize>(index: usize, leaf: Fr, path: &[Fr; D]) -> Fr {
    let mut current = leaf;
    let mut position = index;
    for sibling in path {
        current = if position.is_multiple_of(2) {
            node(current, *sibling)
        } else {
            node(*sibling, current)
        };
        position /= 2;
    }
    current
}

/// Returns the blob-tree root over a batch's identities.
pub fn root(ids: &[BlobId]) -> Result<Fr, Error> {
    if ids.is_empty() || ids.len() > MAX_BLOBS_PER_BATCH {
        return Err(Error::BatchCount(ids.len()));
    }
    let leaves: Vec<Fr> = ids.iter().map(blob_leaf).collect();
    Ok(root_of::<BATCH_DEPTH>(&leaves))
}

/// Returns the membership path of the blob at `index`.
pub fn prove(ids: &[BlobId], index: usize) -> Result<BatchPath, Error> {
    if ids.is_empty() || ids.len() > MAX_BLOBS_PER_BATCH {
        return Err(Error::BatchCount(ids.len()));
    }
    if index >= ids.len() {
        return Err(Error::UnknownIndex(index));
    }
    let leaves: Vec<Fr> = ids.iter().map(blob_leaf).collect();
    Ok(path_of::<BATCH_DEPTH>(&leaves, index))
}

/// Checks that `id` occupies `index` of the blob tree with root `root`.
pub fn verify(root: &Fr, index: usize, id: &BlobId, path: &BatchPath) -> bool {
    index < MAX_BLOBS_PER_BATCH && root_from_path(index, blob_leaf(id), path) == *root
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

/// Returns the page-tree root of a blob.
pub fn page_root(blob: &Blob) -> Fr {
    let leaves: Vec<Fr> = (0..page_count(blob.len()))
        .map(|index| page_leaf(page(blob, index).expect("page index is below the page count")))
        .collect();
    root_of::<PAGE_DEPTH>(&leaves)
}

/// Returns the membership path of page `index` within a blob's page tree.
pub fn prove_page(blob: &Blob, index: usize) -> Result<PagePath, Error> {
    if index >= page_count(blob.len()) {
        return Err(Error::UnknownIndex(index));
    }
    let leaves: Vec<Fr> = (0..page_count(blob.len()))
        .map(|index| page_leaf(page(blob, index).expect("page index is below the page count")))
        .collect();
    Ok(path_of::<PAGE_DEPTH>(&leaves, index))
}

/// Checks that `page` occupies `index` of the page tree with root `page_root`.
///
/// The caller is responsible for binding `page_root` to a [`BlobId`] (see
/// [`BlobId::matches`](crate::types::BlobId::matches)) and for checking that the length of `page`
/// is the one the blob length implies for that index; this function only proves membership.
pub fn verify_page(page_root: &Fr, index: usize, page: &[u8], path: &PagePath) -> bool {
    index < (1 << PAGE_DEPTH) && root_from_path(index, page_leaf(page), path) == *page_root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::MAX_BLOB_SIZE;
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
            let root = root(&ids).expect("count is within bounds");

            for index in sampled(count) {
                let id = &ids[index];
                let path = prove(&ids, index).expect("index is occupied");
                assert!(
                    verify(&root, index, id, &path),
                    "count {count} index {index}"
                );

                // Wrong index, wrong identity, wrong root, and a tampered path all fail.
                let other = (index + 1) % count;
                if other != index {
                    assert!(!verify(&root, other, id, &path));
                    assert!(!verify(&root, index, &ids[other], &path));
                }
                assert!(!verify(&(root + Fr::from(1u64)), index, id, &path));
                let mut tampered = path;
                tampered[0] += Fr::from(1u64);
                assert!(!verify(&root, index, id, &tampered));
            }
        }
    }

    #[test]
    fn p1_blob_tree_padded_slots_are_not_members() {
        let ids: Vec<BlobId> = blobs(5, 64).iter().map(Blob::id).collect();
        let root = root(&ids).expect("count is within bounds");

        // No path exists for an unoccupied slot.
        assert!(matches!(prove(&ids, 5), Err(Error::UnknownIndex(5))));

        // And no identity can be planted in one: the padded siblings of slot 5 form the only path
        // that reaches the root there, and it commits to the empty leaf, not to a blob.
        let padded: BatchPath = [
            EMPTY[0], EMPTY[1], EMPTY[2], EMPTY[3], EMPTY[4], EMPTY[5], EMPTY[6], EMPTY[7],
        ];
        for id in &ids {
            assert!(!verify(&root, 5, id, &padded));
        }
    }

    #[test]
    fn p1_blob_tree_rejects_out_of_range_counts() {
        let ids: Vec<BlobId> = blobs(1, 64).iter().map(Blob::id).collect();
        assert!(matches!(root(&[]), Err(Error::BatchCount(0))));
        assert!(matches!(prove(&ids, 1), Err(Error::UnknownIndex(1))));

        let too_many = vec![ids[0]; MAX_BLOBS_PER_BATCH + 1];
        assert!(matches!(root(&too_many), Err(Error::BatchCount(257))));
    }

    #[test]
    fn p1_blob_page_opening_roundtrip() {
        // A multi-page blob with a short final page, and one that is exactly page aligned.
        for len in [BLOB_PAGE * 3 + 17, BLOB_PAGE * 4, MAX_BLOB_SIZE] {
            let blob = blobs(1, len).remove(0);
            let root = page_root(&blob);
            let pages = page_count(len);
            assert_eq!(pages, len.div_ceil(BLOB_PAGE));

            for index in sampled(pages) {
                let bytes = page(&blob, index).expect("page index is occupied");
                let path = prove_page(&blob, index).expect("page index is occupied");
                assert!(
                    verify_page(&root, index, bytes, &path),
                    "len {len} page {index}"
                );

                // A tampered window, a shifted window, and the wrong index all fail.
                let mut tampered = bytes.to_vec();
                tampered[0] ^= 1;
                assert!(!verify_page(&root, index, &tampered, &path));
                assert!(!verify_page(&root, index, &bytes[1..], &path));
                if pages > 1 {
                    let other = (index + 1) % pages;
                    assert!(!verify_page(&root, other, bytes, &path));
                }
            }

            assert!(page(&blob, pages).is_none());
            assert!(matches!(
                prove_page(&blob, pages),
                Err(Error::UnknownIndex(_))
            ));
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
        assert_ne!(page_root(&blob), page_root(&swapped));
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
