//! The coding unit a gateway seals, and the bookkeeping that fills it.

use super::{Blob, BlobId, Error};
use crate::{
    blob_tree::BlobTree,
    constants::{MAX_BATCH_SIZE, MAX_BLOBS_PER_BATCH},
    poseidon2::Fr,
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write};
use std::collections::BTreeMap;

/// The coding unit: the sequence of blobs a gateway seals, encodes, and disperses.
///
/// Self-describing by design. Decoding the batch bytes alone recovers every blob, so a reader who
/// reconstructs from shards can rederive every identity and the blob-tree root without consulting
/// the gateway that built it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch(Vec<Blob>);

impl Batch {
    /// Wraps `blobs`, rejecting an empty batch, too many blobs, or too many encoded bytes.
    pub fn new(blobs: Vec<Blob>) -> Result<Self, Error> {
        if blobs.is_empty() || blobs.len() > MAX_BLOBS_PER_BATCH {
            return Err(Error::BatchCount(blobs.len()));
        }
        let bytes: usize = blobs.iter().map(Blob::encode_size).sum();
        if bytes > MAX_BATCH_SIZE {
            return Err(Error::BatchSize(bytes));
        }
        Ok(Self(blobs))
    }

    /// Returns the blobs in dispersal order.
    pub fn blobs(&self) -> &[Blob] {
        &self.0
    }

    /// Returns the number of blobs.
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Always false: a [`Batch`] cannot be constructed empty.
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Recomputes every blob identity, in tree-leaf order.
    pub fn ids(&self) -> Vec<BlobId> {
        self.0.iter().map(Blob::id).collect()
    }

    /// Recomputes the blob-tree root. Derived: this is the value a gateway's claim is checked
    /// against.
    pub fn root(&self) -> Result<Fr, Error> {
        Ok(BlobTree::build(&self.ids())?.root())
    }
}

impl Write for Batch {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl EncodeSize for Batch {
    fn encode_size(&self) -> usize {
        self.0.encode_size()
    }
}

impl Read for Batch {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        // Read blob by blob rather than deferring to `Vec<Blob>`, so a peer claiming 256 maximal
        // blobs cannot make us allocate 128 MiB before the total-size bound rejects it.
        let count = usize::read_cfg(buf, &RangeCfg::from(1..=MAX_BLOBS_PER_BATCH))?;
        let mut blobs = Vec::with_capacity(count.min(64));
        let mut bytes = 0usize;
        for _ in 0..count {
            let blob = Blob::read(buf)?;
            bytes += blob.encode_size();
            if bytes > MAX_BATCH_SIZE {
                return Err(CodecError::Invalid("blob::Batch", "batch too large"));
            }
            blobs.push(blob);
        }
        Self::new(blobs).map_err(|_| CodecError::Invalid("blob::Batch", "batch out of range"))
    }
}

/// A sealed batch and everything derived from it in one pass.
#[derive(Clone, Debug)]
pub struct Sealed {
    /// The batch, ready to encode.
    pub batch: Batch,
    /// Blob tree over the batch's identities, folded once so later openings do not refold it.
    pub tree: BlobTree,
    /// Position of each blob identity in the batch, for building membership proofs later.
    pub indexes: BTreeMap<BlobId, usize>,
}

impl Sealed {
    /// Returns the root of the sealed batch's blob tree.
    pub fn root(&self) -> Fr {
        self.tree.root()
    }
}

/// Accumulates client blobs until a batch is worth sealing.
///
/// Pure bookkeeping: the timer and the mailbox that drive it belong to the gateway actor. Caps are
/// enforced here as well as at decode, so a gateway cannot build a batch its peers would reject.
#[derive(Clone, Debug)]
pub struct BatchBuilder {
    /// Encoded-byte target at which the batch is worth sealing.
    target: usize,
    /// Blobs accepted so far, in arrival order.
    blobs: Vec<Blob>,
    /// Identity of each accepted blob, positionally aligned with `blobs`.
    ids: Vec<BlobId>,
    /// Running total of encoded blob bytes.
    bytes: usize,
}

impl BatchBuilder {
    /// Starts an empty batch that is worth sealing once it reaches `target` encoded bytes.
    pub fn new(target: usize) -> Self {
        Self {
            target: target.min(MAX_BATCH_SIZE),
            blobs: Vec::new(),
            ids: Vec::new(),
            bytes: 0,
        }
    }

    /// Accepts a blob, returning its identity.
    ///
    /// Rejects a blob that would breach a wire bound, and rejects a duplicate: two equal
    /// identities in one batch would make the index map ambiguous.
    pub fn push(&mut self, blob: Blob) -> Result<BlobId, Error> {
        if self.blobs.len() == MAX_BLOBS_PER_BATCH {
            return Err(Error::BatchCount(self.blobs.len() + 1));
        }
        let bytes = self.bytes + blob.encode_size();
        if bytes > MAX_BATCH_SIZE {
            return Err(Error::BatchSize(bytes));
        }
        let id = blob.id();
        if self.ids.contains(&id) {
            return Err(Error::DuplicateBlob(id));
        }
        self.blobs.push(blob);
        self.ids.push(id);
        self.bytes = bytes;
        Ok(id)
    }

    /// Reports whether the batch has reached its target or its blob-count bound.
    pub const fn is_full(&self) -> bool {
        self.bytes >= self.target || self.blobs.len() == MAX_BLOBS_PER_BATCH
    }

    /// Reports whether no blob has been accepted yet.
    pub const fn is_empty(&self) -> bool {
        self.blobs.is_empty()
    }

    /// Returns the number of blobs accepted so far.
    pub const fn len(&self) -> usize {
        self.blobs.len()
    }

    /// Returns the encoded blob bytes accepted so far.
    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    /// Seals the batch, returning it alongside its blob tree and index map.
    pub fn seal(self) -> Result<Sealed, Error> {
        let batch = Batch::new(self.blobs)?;
        let tree = BlobTree::build(&self.ids)?;
        let indexes = self
            .ids
            .into_iter()
            .enumerate()
            .map(|(index, id)| (id, index))
            .collect();
        Ok(Sealed {
            batch,
            tree,
            indexes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{BATCH_TARGET_SIM, BLOB_PAGE, MAX_BLOB_SIZE};
    use bytes::Bytes;
    use commonware_codec::{DecodeExt, Encode, FixedSize};

    /// Builds `count` distinct blobs of `len` bytes.
    fn blobs(count: usize, len: usize) -> Vec<Blob> {
        (0..count)
            .map(|index| {
                let mut bytes = vec![0u8; len];
                bytes[0] = index as u8;
                for (position, byte) in bytes.iter_mut().enumerate().skip(1) {
                    *byte = (position as u8).wrapping_mul(7) ^ (index as u8);
                }
                Blob::new(Bytes::from(bytes)).expect("blob is within bounds")
            })
            .collect()
    }

    #[test]
    fn p1_codec_batch_roundtrip() {
        for (count, len) in [(1usize, 1usize), (3, 4096), (5, BLOB_PAGE * 3 + 11)] {
            let batch = Batch::new(blobs(count, len)).expect("batch is within bounds");
            let encoded = batch.encode();
            let decoded = Batch::decode(encoded).expect("batch decodes");
            assert_eq!(batch, decoded);
            assert_eq!(batch.ids(), decoded.ids());
            assert_eq!(
                batch.root().expect("root is computable"),
                decoded.root().expect("root is computable")
            );
        }

        // Blob identities survive the wire, and reject a tampered version byte.
        let blob = blobs(1, 999).remove(0);
        let id = blob.id();
        let mut encoded = id.encode().to_vec();
        assert_eq!(encoded.len(), BlobId::SIZE);
        assert_eq!(BlobId::decode(encoded.as_slice()).expect("id decodes"), id);
        encoded[0] = 0x02;
        assert!(BlobId::decode(encoded.as_slice()).is_err());
    }

    #[test]
    fn p1_codec_batch_rejects_oversize() {
        let batch = Batch::new(blobs(3, 512)).expect("batch is within bounds");
        let encoded = batch.encode();

        // Truncation at every length must fail rather than produce a short batch.
        for cut in 0..encoded.len() {
            assert!(
                Batch::decode(&encoded[..cut]).is_err(),
                "truncation to {cut} bytes decoded"
            );
        }

        // Trailing garbage is rejected: `decode` demands the buffer be consumed.
        let mut extended = encoded.to_vec();
        extended.push(0);
        assert!(Batch::decode(extended.as_slice()).is_err());

        // A count above the bound is rejected before any blob is read.
        let mut over_count = Vec::new();
        (MAX_BLOBS_PER_BATCH + 1).write(&mut over_count);
        assert!(Batch::decode(over_count.as_slice()).is_err());

        // An empty batch is rejected.
        let mut empty = Vec::new();
        0usize.write(&mut empty);
        assert!(Batch::decode(empty.as_slice()).is_err());

        // An empty blob is rejected.
        let mut empty_blob = Vec::new();
        1usize.write(&mut empty_blob);
        Bytes::new().write(&mut empty_blob);
        assert!(Batch::decode(empty_blob.as_slice()).is_err());

        // A blob claiming more than the maximum size is rejected on its length prefix, without
        // the bytes ever arriving.
        let mut over_blob = Vec::new();
        1usize.write(&mut over_blob);
        (MAX_BLOB_SIZE + 1).write(&mut over_blob);
        assert!(Batch::decode(over_blob.as_slice()).is_err());

        // Constructors enforce the same bounds as the decoder.
        assert!(matches!(Blob::new(Bytes::new()), Err(Error::BlobSize(0))));
        assert!(matches!(
            Blob::new(Bytes::from(vec![0u8; MAX_BLOB_SIZE + 1])),
            Err(Error::BlobSize(_))
        ));
        assert!(matches!(Batch::new(Vec::new()), Err(Error::BatchCount(0))));
    }

    #[test]
    fn p1_batch_builder_enforces_caps() {
        let mut builder = BatchBuilder::new(BATCH_TARGET_SIM);
        assert!(builder.is_empty());
        assert!(!builder.is_full());

        let sample = blobs(4, 1024);
        let mut ids = Vec::new();
        for blob in &sample {
            ids.push(builder.push(blob.clone()).expect("blob is accepted"));
        }
        assert_eq!(builder.len(), 4);
        assert!(builder.bytes() >= 4 * 1024);

        // A repeat submission is refused, so the index map stays unambiguous.
        assert!(matches!(
            builder.push(sample[0].clone()),
            Err(Error::DuplicateBlob(_))
        ));

        let sealed = builder.seal().expect("batch is sealable");
        assert_eq!(sealed.batch.len(), 4);
        assert_eq!(sealed.indexes.len(), 4);
        for (index, id) in ids.iter().enumerate() {
            assert_eq!(sealed.indexes.get(id), Some(&index));
        }
        assert_eq!(
            sealed.root(),
            sealed.batch.root().expect("root is computable")
        );

        // The count cap is enforced by the builder, not just by the decoder.
        let mut builder = BatchBuilder::new(usize::MAX);
        for blob in blobs(MAX_BLOBS_PER_BATCH, 32) {
            builder.push(blob).expect("blob is accepted");
        }
        assert!(builder.is_full());
        assert!(matches!(
            builder.push(blobs(1, 33).remove(0)),
            Err(Error::BatchCount(_))
        ));
    }
}
