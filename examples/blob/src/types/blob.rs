//! A client's binary and the versioned identity that commits to it.

use super::Error;
use crate::{
    blob_tree::{PageTree, page_count},
    constants::MAX_BLOB_SIZE,
    poseidon2::{self, FR_SIZE, Fr, TAG_BLOB},
};
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{
    EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write,
};
use commonware_formatting::Hex;
use std::fmt::{Display, Formatter};

/// Versioned, circuit-native identity of a blob.
///
/// The wire form is a version byte followed by the canonical little-endian encoding of
/// `H(TAG_BLOB, len, page_root)`, where `page_root` is the root of the blob's depth-7 page tree.
/// Committing the length alongside the root is what makes the identity injective: 31-byte packing
/// zero-extends a trailing partial limb, so bytes alone do not determine the preimage.
///
/// This is the 4844 versioned blob hash analog. Because it is a Poseidon2 digest over a page tree,
/// a circuit can open a single 4 KiB window of the blob against it for a few dozen permutations
/// instead of rehashing the blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlobId {
    /// Field element committing to the blob's length and page root.
    element: Fr,
}

impl BlobId {
    /// Version of the identity scheme, and the first byte of the wire form.
    pub const VERSION: u8 = 0x01;

    /// Builds the identity of a blob of `len` bytes whose page tree has root `page_root`.
    pub fn new(len: usize, page_root: Fr) -> Self {
        Self {
            element: poseidon2::hash(&[TAG_BLOB, Fr::from(len as u64), page_root]),
        }
    }

    /// Returns the committed field element, the form the blob tree hashes.
    pub const fn element(&self) -> Fr {
        self.element
    }

    /// Reports whether this identity commits to `len` bytes under `page_root`.
    ///
    /// The check a reader runs after retrieving a blob: it closes the gap between an identity
    /// someone handed over and the bytes actually in hand.
    pub fn matches(&self, len: usize, page_root: Fr) -> bool {
        *self == Self::new(len, page_root)
    }
}

impl Display for BlobId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Hex(&poseidon2::to_bytes(&self.element)))
    }
}

impl Write for BlobId {
    fn write(&self, buf: &mut impl BufMut) {
        Self::VERSION.write(buf);
        buf.put_slice(&poseidon2::to_bytes(&self.element));
    }
}

impl FixedSize for BlobId {
    const SIZE: usize = u8::SIZE + FR_SIZE;
}

impl Read for BlobId {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let version = u8::read(buf)?;
        if version != Self::VERSION {
            return Err(CodecError::Invalid("blob::BlobId", "unsupported version"));
        }
        let encoded: [u8; FR_SIZE] = ReadExt::read(buf)?;
        let element = poseidon2::from_bytes(&encoded)
            .ok_or(CodecError::Invalid("blob::BlobId", "non-canonical element"))?;
        Ok(Self { element })
    }
}

/// A client-supplied binary, the unit a user submits and retrieves.
///
/// Bounded at both ends on construction and on decode: an empty blob has no pages to open, and
/// [`MAX_BLOB_SIZE`] is what keeps the page tree at depth 7.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Blob(Bytes);

impl Blob {
    /// Wraps `bytes`, rejecting anything outside the permitted size range.
    pub fn new(bytes: Bytes) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > MAX_BLOB_SIZE {
            return Err(Error::BlobSize(bytes.len()));
        }
        Ok(Self(bytes))
    }

    /// Returns the blob's length in bytes.
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Always false: a [`Blob`] cannot be constructed empty.
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Returns the number of pages the blob occupies.
    pub const fn pages(&self) -> usize {
        page_count(self.len())
    }

    /// Computes the blob's identity.
    ///
    /// Hashes every page, so callers that need it more than once should keep the result.
    pub fn id(&self) -> BlobId {
        BlobId::new(self.len(), PageTree::build(self).root())
    }
}

impl AsRef<[u8]> for Blob {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Write for Blob {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl EncodeSize for Blob {
    fn encode_size(&self) -> usize {
        self.0.encode_size()
    }
}

impl Read for Blob {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let bytes = Bytes::read_cfg(buf, &RangeCfg::from(1..=MAX_BLOB_SIZE))?;
        Self::new(bytes).map_err(|_| CodecError::Invalid("blob::Blob", "size out of range"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::DecodeExt;

    #[test]
    fn p1_codec_rejects_non_canonical_blob_id() {
        // The field modulus `r`, little-endian, is the smallest non-canonical encoding: it is one
        // past `r - 1`, whose low byte is zero.
        let modulus = {
            let mut encoded = poseidon2::to_bytes(&(Fr::from(0u64) - Fr::from(1u64)));
            assert_eq!(encoded[0], 0);
            encoded[0] = 1;
            encoded
        };

        let mut id = Vec::with_capacity(BlobId::SIZE);
        id.push(BlobId::VERSION);
        id.extend_from_slice(&modulus);
        assert!(BlobId::decode(id.as_slice()).is_err());
    }
}
