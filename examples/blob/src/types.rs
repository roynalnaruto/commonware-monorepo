//! Blobs, batches, and the objects that certify them.
//!
//! # Integrity tiers
//!
//! Three tiers appear throughout this example, and every field below belongs to exactly one:
//!
//! - **Attested**: covered by validator signatures. Only [`BatchHeader`] is, because it holds
//!   nothing a validator cannot check against its own shard.
//! - **Claimed**: asserted and signed by the gateway alone. [`ClaimedRoot`] is the whole of this
//!   tier: a false claim is attributable and provable, but it is not an availability statement.
//! - **Derived**: recomputed from decoded bytes by any reader, trusting nobody. [`BlobId`], the
//!   blob-tree root, and the batch contents live here.
//!
//! A [`DaCert`] carries one of each, which is why availability and structure can be reasoned about
//! separately.

use crate::{
    blob_tree,
    constants::{
        MAX_BATCH_SIZE, MAX_BLOB_SIZE, MAX_BLOBS_PER_BATCH, attest_namespace,
        gateway_root_namespace,
    },
    poseidon2::{self, FR_SIZE, Fr, TAG_BLOB},
};
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{
    Encode, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write,
};
use commonware_coding::Config;
use commonware_consensus::types::View;
use commonware_cryptography::{
    Signer, Verifier as _,
    bls12381::primitives::variant::MinSig,
    certificate::{self, Namespace as CertificateNamespace, Subject},
    ed25519,
    transcript::Summary,
};
use commonware_formatting::Hex;
use std::{
    collections::BTreeMap,
    fmt::{Display, Formatter},
};

/// Failures produced while building or validating blob-rail objects.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// A blob was empty or larger than [`MAX_BLOB_SIZE`].
    #[error("blob of {0} bytes is outside the permitted size range")]
    BlobSize(usize),
    /// A batch was empty or held more than [`MAX_BLOBS_PER_BATCH`] blobs.
    #[error("batch of {0} blobs is outside the permitted count range")]
    BatchCount(usize),
    /// A batch exceeded [`MAX_BATCH_SIZE`] encoded bytes.
    #[error("batch of {0} encoded bytes is over the permitted size")]
    BatchSize(usize),
    /// A tree index was not occupied.
    #[error("index {0} is not occupied")]
    UnknownIndex(usize),
    /// The same blob was offered to a batch twice.
    #[error("blob {0} is already in the batch")]
    DuplicateBlob(BlobId),
}

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
        blob_tree::page_count(self.len())
    }

    /// Computes the blob's identity.
    ///
    /// Hashes every page, so callers that need it more than once should keep the result.
    pub fn id(&self) -> BlobId {
        BlobId::new(self.len(), blob_tree::page_root(self))
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
        blob_tree::root(&self.ids())
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
    /// Root of the blob tree over the batch's identities.
    pub root: Fr,
    /// Position of each blob identity in the batch, for building membership paths later.
    pub indexes: BTreeMap<BlobId, usize>,
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

    /// Seals the batch, returning it alongside its blob-tree root and index map.
    pub fn seal(self) -> Result<Sealed, Error> {
        let batch = Batch::new(self.blobs)?;
        let root = blob_tree::root(&self.ids)?;
        let indexes = self
            .ids
            .into_iter()
            .enumerate()
            .map(|(index, id)| (id, index))
            .collect();
        Ok(Sealed {
            batch,
            root,
            indexes,
        })
    }
}

/// The subject validators attest to.
///
/// Attested tier. Every field is checkable by a validator holding one shard: the commitment binds
/// the encoded batch, the coding configuration says how the shards were cut, and the dispersal
/// view lets an attestor reject a stale or future dispersal. The blob-tree root is deliberately
/// absent, because no validator can derive it from a single shard.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BatchHeader {
    /// Version of the dispersal format.
    pub version: u8,
    /// ZODA transcript summary binding the encoded batch. The identifier of a batch on the rail.
    pub commitment: Summary,
    /// Coding parameters the batch was encoded with.
    pub config: Config,
    /// View the gateway claimed when dispersing.
    pub dispersal_view: View,
}

impl BatchHeader {
    /// Version of the dispersal format this build produces.
    pub const VERSION: u8 = 0x01;

    /// Builds a header at the current format version.
    pub const fn new(commitment: Summary, config: Config, dispersal_view: View) -> Self {
        Self {
            version: Self::VERSION,
            commitment,
            config,
            dispersal_view,
        }
    }
}

impl Write for BatchHeader {
    fn write(&self, buf: &mut impl BufMut) {
        self.version.write(buf);
        self.commitment.write(buf);
        self.config.write(buf);
        self.dispersal_view.write(buf);
    }
}

impl EncodeSize for BatchHeader {
    fn encode_size(&self) -> usize {
        self.version.encode_size()
            + self.commitment.encode_size()
            + self.config.encode_size()
            + self.dispersal_view.encode_size()
    }
}

impl Read for BatchHeader {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let version = u8::read(buf)?;
        if version != Self::VERSION {
            return Err(CodecError::Invalid(
                "blob::BatchHeader",
                "unsupported version",
            ));
        }
        Ok(Self {
            version,
            commitment: Summary::read(buf)?,
            config: Config::read(buf)?,
            dispersal_view: View::read(buf)?,
        })
    }
}

/// Pre-computed namespace for attestations over a [`BatchHeader`].
#[derive(Clone, Debug)]
pub struct Namespace(Vec<u8>);

impl CertificateNamespace for Namespace {
    fn derive(namespace: &[u8]) -> Self {
        Self(attest_namespace(namespace))
    }
}

impl Subject for &BatchHeader {
    type Namespace = Namespace;

    fn namespace<'a>(&self, derived: &'a Self::Namespace) -> &'a [u8] {
        &derived.0
    }

    fn message(&self) -> Bytes {
        self.encode()
    }
}

pub mod scheme {
    //! BLS12-381 multi-signature scheme over [`BatchHeader`].
    //!
    //! Attributable: a certificate names its signers, so a validator that attests to an
    //! unavailable batch can be identified. Shard index `i` is the `i`-th key of the scheme's
    //! ordered `participants()` set, which is ordered by ed25519 identity, so the same ordering
    //! drives p2p addressing and shard assignment.

    use super::{BatchHeader, Namespace};
    use commonware_cryptography::impl_certificate_bls12381_multisig;
    use commonware_utils::N3f1;

    impl_certificate_bls12381_multisig!(&'a BatchHeader, Namespace, N3f1);
}

/// The signing scheme attestors and gateways share.
///
/// `MinSig` keeps signatures small, which matters because certificates ride inside consensus
/// blocks.
pub type Scheme = scheme::Scheme<ed25519::PublicKey, MinSig>;

/// One validator's attestation over a [`BatchHeader`].
pub type Attestation = certificate::Attestation<Scheme>;

/// An aggregated quorum of attestations.
pub type Certificate = certificate::bls12381_multisig::Certificate<MinSig>;

/// The gateway's signed claim about a batch's structure.
///
/// Claimed tier, and outside the attested subject on purpose: attestors hold one shard each and
/// cannot recompute a hash tree over the whole batch, so this can only ever be an attributable
/// assertion. A gateway that signs a root that disagrees with the decoded bytes has produced
/// evidence against itself; what it cannot do is fake availability, which the attestations cover.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ClaimedRoot {
    /// The blob-tree root the gateway claims for the batch.
    pub root: Fr,
    /// Identity of the gateway making the claim.
    pub gateway: ed25519::PublicKey,
    /// Signature over `(commitment, root)`.
    pub signature: ed25519::Signature,
}

impl ClaimedRoot {
    /// Bytes the gateway signs: the batch commitment followed by the claimed root.
    fn message(commitment: &Summary, root: &Fr) -> Vec<u8> {
        let mut message = Vec::with_capacity(Summary::SIZE + FR_SIZE);
        message.extend_from_slice(commitment.as_ref());
        message.extend_from_slice(&poseidon2::to_bytes(root));
        message
    }

    /// Signs a claim under the base `namespace`.
    pub fn sign(
        namespace: &[u8],
        gateway: &ed25519::PrivateKey,
        commitment: &Summary,
        root: Fr,
    ) -> Self {
        let signature = gateway.sign(
            &gateway_root_namespace(namespace),
            &Self::message(commitment, &root),
        );
        Self {
            root,
            gateway: gateway.public_key(),
            signature,
        }
    }

    /// Checks the claim against the batch it is supposed to describe.
    ///
    /// Verifying this proves who made the claim, not that the claim is true. Truth is settled by
    /// decoding the batch and recomputing the root.
    pub fn verify(&self, namespace: &[u8], commitment: &Summary) -> bool {
        self.gateway.verify(
            &gateway_root_namespace(namespace),
            &Self::message(commitment, &self.root),
            &self.signature,
        )
    }
}

impl Write for ClaimedRoot {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&poseidon2::to_bytes(&self.root));
        self.gateway.write(buf);
        self.signature.write(buf);
    }
}

impl FixedSize for ClaimedRoot {
    const SIZE: usize = FR_SIZE + ed25519::PublicKey::SIZE + ed25519::Signature::SIZE;
}

impl Read for ClaimedRoot {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let encoded: [u8; FR_SIZE] = ReadExt::read(buf)?;
        let root = poseidon2::from_bytes(&encoded).ok_or(CodecError::Invalid(
            "blob::ClaimedRoot",
            "non-canonical root",
        ))?;
        Ok(Self {
            root,
            gateway: ed25519::PublicKey::read(buf)?,
            signature: ed25519::Signature::read(buf)?,
        })
    }
}

/// The availability proof, and the only blob-related object that enters consensus.
///
/// One object, three tiers: an attested [`BatchHeader`], a quorum [`Certificate`] over it, and a
/// gateway-[`ClaimedRoot`]. Holding a valid certificate means at least `2f + 1` validators custody
/// a shard, so at least `f + 1` honest ones do, which is more than the `minimum_shards` needed to
/// reconstruct.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DaCert {
    /// The attested subject.
    pub header: BatchHeader,
    /// Aggregated attestations from a quorum of validators.
    pub certificate: Certificate,
    /// The gateway's claim about the batch's structure.
    pub claimed_root: ClaimedRoot,
}

impl Write for DaCert {
    fn write(&self, buf: &mut impl BufMut) {
        self.header.write(buf);
        self.certificate.write(buf);
        self.claimed_root.write(buf);
    }
}

impl EncodeSize for DaCert {
    fn encode_size(&self) -> usize {
        self.header.encode_size() + self.certificate.encode_size() + self.claimed_root.encode_size()
    }
}

impl Read for DaCert {
    /// Number of participants in the signing set, which bounds the certificate's signer bitmap.
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, participants: &usize) -> Result<Self, CodecError> {
        Ok(Self {
            header: BatchHeader::read(buf)?,
            certificate: Certificate::read_cfg(buf, participants)?,
            claimed_root: ClaimedRoot::read(buf)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{BATCH_TARGET_SIM, BLOB_PAGE, NAMESPACE};
    use commonware_codec::{Decode, DecodeExt};
    use commonware_cryptography::{
        bls12381::certificate::multisig::mocks::fixture,
        certificate::{Scheme as _, Verifier as _},
    };
    use commonware_parallel::Sequential;
    use commonware_utils::{NZU16, test_rng};

    /// Participants in the certificate tests: `n = 10`, `f = 3`, quorum 7.
    const PARTICIPANTS: u32 = 10;

    /// The scheme is generic over a digest it never uses, since [`BatchHeader`] is not one; this
    /// pins that parameter.
    type Unused = commonware_cryptography::sha256::Digest;

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

    /// A header over a deterministic commitment.
    fn header_at(view: u64) -> BatchHeader {
        BatchHeader::new(
            Summary::decode([7u8; 32].as_slice()).expect("summary is 32 bytes"),
            Config {
                minimum_shards: NZU16!(4),
                extra_shards: NZU16!(6),
            },
            View::new(view),
        )
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
    fn p1_codec_rejects_non_canonical_field_elements() {
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

        let signer = ed25519::PrivateKey::from_seed(1);
        let claimed = ClaimedRoot::sign(
            NAMESPACE,
            &signer,
            &Summary::decode([3u8; 32].as_slice()).expect("summary is 32 bytes"),
            Fr::from(9u64),
        );
        let mut encoded = claimed.encode().to_vec();
        encoded[..FR_SIZE].copy_from_slice(&modulus);
        assert!(ClaimedRoot::decode(encoded.as_slice()).is_err());
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
            sealed.root,
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

    #[test]
    fn p1_cert_sign_verify_roundtrip() {
        let mut rng = test_rng();
        let fixture = fixture::<Scheme, MinSig, _>(
            &mut rng,
            NAMESPACE,
            PARTICIPANTS,
            Scheme::signer,
            Scheme::verifier,
        );
        let header = header_at(11);

        // A quorum of 7 of 10 assembles a certificate that verifies.
        let quorum: Vec<Attestation> = fixture.schemes[..7]
            .iter()
            .map(|scheme| scheme.sign::<Unused>(&header).expect("scheme can sign"))
            .collect();
        for attestation in &quorum {
            assert!(fixture.verifier.verify_attestation::<_, Unused>(
                &mut rng,
                &header,
                attestation,
                &Sequential
            ));
        }
        let certificate = fixture
            .verifier
            .assemble(quorum.clone(), &Sequential)
            .expect("quorum assembles");
        assert!(fixture.verifier.verify_certificate::<_, Unused>(
            &mut rng,
            &header,
            &certificate,
            &Sequential
        ));

        // One short of a quorum does not.
        let short: Vec<Attestation> = quorum[..6].to_vec();
        let assembled = fixture.verifier.assemble(short, &Sequential);
        assert!(assembled.is_none_or(|certificate| {
            !fixture.verifier.verify_certificate::<_, Unused>(
                &mut rng,
                &header,
                &certificate,
                &Sequential,
            )
        }));

        // A certificate is bound to its subject: a different dispersal view breaks it.
        assert!(!fixture.verifier.verify_certificate::<_, Unused>(
            &mut rng,
            &header_at(12),
            &certificate,
            &Sequential
        ));
    }

    #[test]
    fn p1_cert_codec_roundtrip() {
        let mut rng = test_rng();
        let fixture = fixture::<Scheme, MinSig, _>(
            &mut rng,
            NAMESPACE,
            PARTICIPANTS,
            Scheme::signer,
            Scheme::verifier,
        );
        let header = header_at(5);
        let attestations: Vec<Attestation> = fixture.schemes[..7]
            .iter()
            .map(|scheme| scheme.sign::<Unused>(&header).expect("scheme can sign"))
            .collect();
        let certificate = fixture
            .verifier
            .assemble(attestations, &Sequential)
            .expect("quorum assembles");
        let gateway = ed25519::PrivateKey::from_seed(2);
        let cert = DaCert {
            header: header.clone(),
            certificate,
            claimed_root: ClaimedRoot::sign(
                NAMESPACE,
                &gateway,
                &header.commitment,
                Fr::from(4242u64),
            ),
        };

        let encoded = cert.encode();
        let decoded =
            DaCert::decode_cfg(encoded.clone(), &(PARTICIPANTS as usize)).expect("cert decodes");
        assert_eq!(cert, decoded);

        // Every truncation fails, and so does a signer bitmap wider than the participant set.
        for cut in 0..encoded.len() {
            assert!(DaCert::decode_cfg(&encoded[..cut], &(PARTICIPANTS as usize)).is_err());
        }
        assert!(DaCert::decode_cfg(encoded, &1usize).is_err());
    }

    #[test]
    fn p1_cert_claimed_root_outside_attestation() {
        let mut rng = test_rng();
        let fixture = fixture::<Scheme, MinSig, _>(
            &mut rng,
            NAMESPACE,
            PARTICIPANTS,
            Scheme::signer,
            Scheme::verifier,
        );
        let header = header_at(9);
        let attestations: Vec<Attestation> = fixture.schemes[..7]
            .iter()
            .map(|scheme| scheme.sign::<Unused>(&header).expect("scheme can sign"))
            .collect();
        let certificate = fixture
            .verifier
            .assemble(attestations, &Sequential)
            .expect("quorum assembles");
        let gateway = ed25519::PrivateKey::from_seed(2);
        let mut cert = DaCert {
            header: header.clone(),
            certificate,
            claimed_root: ClaimedRoot::sign(
                NAMESPACE,
                &gateway,
                &header.commitment,
                Fr::from(1u64),
            ),
        };
        assert!(cert.claimed_root.verify(NAMESPACE, &cert.header.commitment));

        // Rewriting the claimed root leaves the attestations untouched, which is the whole point:
        // availability is attested, structure is only claimed.
        cert.claimed_root.root = Fr::from(2u64);
        assert!(fixture.verifier.verify_certificate::<_, Unused>(
            &mut rng,
            &cert.header,
            &cert.certificate,
            &Sequential
        ));
        assert!(!cert.claimed_root.verify(NAMESPACE, &cert.header.commitment));

        // The gateway signature is also bound to the commitment and the namespace.
        let honest = ClaimedRoot::sign(NAMESPACE, &gateway, &header.commitment, Fr::from(1u64));
        assert!(!honest.verify(
            NAMESPACE,
            &Summary::decode([8u8; 32].as_slice()).expect("summary is 32 bytes")
        ));
        assert!(!honest.verify(b"_COMMONWARE_OTHER", &header.commitment));

        // Rewriting the attested subject breaks the certificate.
        cert.header.dispersal_view = View::new(10);
        assert!(!fixture.verifier.verify_certificate::<_, Unused>(
            &mut rng,
            &cert.header,
            &cert.certificate,
            &Sequential
        ));
    }
}
