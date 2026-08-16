//! Messages exchanged on the data-availability and consensus rails.
//!
//! Each type carries its own decode bounds, and every `Read` here is bounded: a message arrives
//! from an untrusted peer, so nothing is sized by a number the peer chose. A length prefix is
//! never trusted to size an allocation, and a message that would exceed its bound is a decode
//! failure rather than a large allocation.
//!
//! # What travels where
//!
//! | Message | Channel | Direction |
//! |---|---|---|
//! | [`DisperseRequest`] / [`DisperseResponse`] | dispersal | gateway to attestor, and back |
//! | [`Payload`] | payload gossip | proposer to everyone |
//! | [`ClientRequest`] / [`ClientResponse`] | client rpc | client to validator, and back |
//!
//! Two things travel that are not defined here. A [`DaCert`] is gossiped as
//! itself, because it is a protocol object rather than an envelope, and a shard answering a
//! retrieval is a [`CustodyRecord`](crate::custody::CustodyRecord) encoded as opaque bytes,
//! because the resolver that carries it is generic over `Bytes` and the reader checks what it
//! decodes against the commitment regardless.

use crate::{
    constants::PAYLOAD_MAX_CERTS,
    types::{Attestation, Batch, BatchHeader, Blob, BlobId, DaCert},
};
use bytes::{Buf, BufMut};
use commonware_codec::{
    Encode, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write,
};
use commonware_coding::{CodecConfig, PhasedScheme, Zoda};
use commonware_consensus::types::View;
use commonware_cryptography::{
    Committable, Digestible, Hasher as _, Sha256, sha256, transcript::Summary,
};

/// The coding scheme the rail disperses with.
pub type Coder = Zoda<Sha256>;

/// One validator's slice of an encoded batch, including the data it needs to check itself.
pub type StrongShard = <Coder as PhasedScheme>::StrongShard;

/// A gateway asking one validator to custody one shard.
///
/// `index` is the validator's own position in the sorted participant set of the signing scheme.
/// The recipient cross-checks it against its own position before doing any work: a mismatched
/// index would have it check a shard against the wrong column of the commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisperseRequest {
    /// The subject the gateway wants attested.
    pub header: BatchHeader,
    /// Position of the recipient in the participant set, and of the shard in the encoding.
    pub index: u16,
    /// The shard to check and custody.
    pub shard: StrongShard,
}

impl Write for DisperseRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.header.write(buf);
        self.index.write(buf);
        self.shard.write(buf);
    }
}

impl EncodeSize for DisperseRequest {
    fn encode_size(&self) -> usize {
        self.header.encode_size() + self.index.encode_size() + self.shard.encode_size()
    }
}

impl Read for DisperseRequest {
    /// Bounds the shard's variable-length portion.
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, cfg: &CodecConfig) -> Result<Self, CodecError> {
        Ok(Self {
            header: BatchHeader::read(buf)?,
            index: u16::read(buf)?,
            shard: StrongShard::read_cfg(buf, cfg)?,
        })
    }
}

impl Committable for DisperseRequest {
    type Commitment = Summary;

    fn commitment(&self) -> Self::Commitment {
        self.header.commitment
    }
}

impl Digestible for DisperseRequest {
    type Digest = sha256::Digest;

    fn digest(&self) -> Self::Digest {
        Sha256::hash(&[self.encode().as_ref()])
    }
}

/// A validator's reply: it checked and custodied its shard, and here is the signature.
///
/// Shares [`Committable::Commitment`] and [`Digestible::Digest`] with [`DisperseRequest`], which
/// is what lets a `commonware_collector::Handler` pair them on one channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisperseResponse {
    /// The batch being attested, matching the request's commitment.
    pub commitment: Summary,
    /// The attestation over the request's header.
    pub attestation: Attestation,
}

impl Write for DisperseResponse {
    fn write(&self, buf: &mut impl BufMut) {
        self.commitment.write(buf);
        self.attestation.write(buf);
    }
}

impl EncodeSize for DisperseResponse {
    fn encode_size(&self) -> usize {
        self.commitment.encode_size() + self.attestation.encode_size()
    }
}

impl Read for DisperseResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            commitment: Summary::read(buf)?,
            attestation: Attestation::read(buf)?,
        })
    }
}

impl Committable for DisperseResponse {
    type Commitment = Summary;

    fn commitment(&self) -> Self::Commitment {
        self.commitment
    }
}

impl Digestible for DisperseResponse {
    type Digest = sha256::Digest;

    fn digest(&self) -> Self::Digest {
        Sha256::hash(&[self.encode().as_ref()])
    }
}

/// The consensus block body: a mini-block carrying certificates and no blob bytes.
///
/// `parent` and `view` sit inside the payload so its digest is unique to a fork position. That
/// makes ancestry reconstruction after a restart a matter of following parent links, with no side
/// channel, and it stops a payload from being replayed at a different height.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payload {
    /// Digest of the parent payload.
    pub parent: sha256::Digest,
    /// View this payload was proposed in.
    pub view: View,
    /// Availability certificates included by the proposer.
    pub certs: Vec<DaCert>,
}

impl Payload {
    /// The payload every chain starts from.
    ///
    /// Well known rather than agreed: its digest anchors the consensus floor, and every ancestry
    /// walk ends here. Nothing links to a parent of its own, so the zero digest stands in for one
    /// that does not exist and is never the digest of a real payload.
    pub fn genesis() -> Self {
        Self {
            parent: sha256::Digest::from([0u8; sha256::Digest::SIZE]),
            view: View::zero(),
            certs: Vec::new(),
        }
    }

    /// Returns the commitment of every certificate carried, in order.
    pub fn commitments(&self) -> impl Iterator<Item = Summary> + '_ {
        self.certs.iter().map(|cert| cert.header.commitment)
    }
}

impl Write for Payload {
    fn write(&self, buf: &mut impl BufMut) {
        self.parent.write(buf);
        self.view.write(buf);
        self.certs.write(buf);
    }
}

impl EncodeSize for Payload {
    fn encode_size(&self) -> usize {
        self.parent.encode_size() + self.view.encode_size() + self.certs.encode_size()
    }
}

impl Read for Payload {
    /// Number of participants in the signing set, needed to bound each certificate's bitmap.
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, participants: &usize) -> Result<Self, CodecError> {
        Ok(Self {
            parent: sha256::Digest::read(buf)?,
            view: View::read(buf)?,
            certs: Vec::<DaCert>::read_cfg(
                buf,
                &(RangeCfg::from(0..=PAYLOAD_MAX_CERTS), *participants),
            )?,
        })
    }
}

impl Digestible for Payload {
    type Digest = sha256::Digest;

    fn digest(&self) -> Self::Digest {
        Sha256::hash(&[self.encode().as_ref()])
    }
}

/// Where a submitted blob has got to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlobStatus {
    /// Accepted by a gateway, not yet in a certified batch.
    Pending,
    /// In a batch whose certificate exists but has not been included in a block.
    Certified(Summary),
    /// In a batch whose certificate was included in a finalized block.
    Included {
        /// Commitment of the batch carrying the blob.
        commitment: Summary,
        /// View of the block whose payload carried the certificate.
        view: View,
    },
    /// The batch failed to reach a quorum, and the blob must be resubmitted.
    Failed,
}

impl BlobStatus {
    /// Wire tag for [`BlobStatus::Pending`].
    const PENDING: u8 = 0;
    /// Wire tag for [`BlobStatus::Certified`].
    const CERTIFIED: u8 = 1;
    /// Wire tag for [`BlobStatus::Included`].
    const INCLUDED: u8 = 2;
    /// Wire tag for [`BlobStatus::Failed`].
    const FAILED: u8 = 3;
}

impl Write for BlobStatus {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Pending => Self::PENDING.write(buf),
            Self::Certified(commitment) => {
                Self::CERTIFIED.write(buf);
                commitment.write(buf);
            }
            Self::Included { commitment, view } => {
                Self::INCLUDED.write(buf);
                commitment.write(buf);
                view.write(buf);
            }
            Self::Failed => Self::FAILED.write(buf),
        }
    }
}

impl EncodeSize for BlobStatus {
    fn encode_size(&self) -> usize {
        u8::SIZE
            + match self {
                Self::Pending | Self::Failed => 0,
                Self::Certified(commitment) => commitment.encode_size(),
                Self::Included { commitment, view } => {
                    commitment.encode_size() + view.encode_size()
                }
            }
    }
}

impl Read for BlobStatus {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            Self::PENDING => Ok(Self::Pending),
            Self::CERTIFIED => Ok(Self::Certified(Summary::read(buf)?)),
            Self::INCLUDED => Ok(Self::Included {
                commitment: Summary::read(buf)?,
                view: View::read(buf)?,
            }),
            Self::FAILED => Ok(Self::Failed),
            _ => Err(CodecError::Invalid("blob::BlobStatus", "unknown variant")),
        }
    }
}

/// A request from a client to any validator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientRequest {
    /// Hand a blob to the receiving validator, acting as gateway.
    Submit(Blob),
    /// Ask where a previously submitted blob has got to.
    Status(BlobId),
    /// Ask for the bytes of a batch, to be verified by the client itself.
    GetBatch(Summary),
}

impl ClientRequest {
    /// Wire tag for [`ClientRequest::Submit`].
    const SUBMIT: u8 = 0;
    /// Wire tag for [`ClientRequest::Status`].
    const STATUS: u8 = 1;
    /// Wire tag for [`ClientRequest::GetBatch`].
    const GET_BATCH: u8 = 2;
}

impl Write for ClientRequest {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Submit(blob) => {
                Self::SUBMIT.write(buf);
                blob.write(buf);
            }
            Self::Status(id) => {
                Self::STATUS.write(buf);
                id.write(buf);
            }
            Self::GetBatch(commitment) => {
                Self::GET_BATCH.write(buf);
                commitment.write(buf);
            }
        }
    }
}

impl EncodeSize for ClientRequest {
    fn encode_size(&self) -> usize {
        u8::SIZE
            + match self {
                Self::Submit(blob) => blob.encode_size(),
                Self::Status(id) => id.encode_size(),
                Self::GetBatch(commitment) => commitment.encode_size(),
            }
    }
}

impl Read for ClientRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            Self::SUBMIT => Ok(Self::Submit(Blob::read(buf)?)),
            Self::STATUS => Ok(Self::Status(BlobId::read(buf)?)),
            Self::GET_BATCH => Ok(Self::GetBatch(Summary::read(buf)?)),
            _ => Err(CodecError::Invalid(
                "blob::ClientRequest",
                "unknown variant",
            )),
        }
    }
}

/// The outcome of a [`ClientRequest::GetBatch`].
///
/// A miss is named rather than left as an absent value, because the three of them mean different
/// things to a client: a batch nobody finalized may still be on its way, one past its window is
/// gone for good, and one that could not be gathered in time is worth asking another validator
/// for. None of them is a claim the client has to trust: the only answer it acts on is
/// [`BatchResult::Found`], and that one it re-derives from the bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BatchResult {
    /// The batch, and the certificate that says a quorum custodies it.
    Found {
        /// The reconstructed batch.
        batch: Batch,
        /// The certificate the responding validator holds over it.
        cert: Box<DaCert>,
    },
    /// No certificate over this commitment has been finalized, as far as this validator knows.
    Unknown,
    /// A certificate was finalized, but the batch is past its retrievability window.
    Expired,
    /// The certificate is live, but enough shards could not be gathered in time.
    Unavailable,
}

impl BatchResult {
    /// Wire tag for [`BatchResult::Found`].
    const FOUND: u8 = 0;
    /// Wire tag for [`BatchResult::Unknown`].
    const UNKNOWN: u8 = 1;
    /// Wire tag for [`BatchResult::Expired`].
    const EXPIRED: u8 = 2;
    /// Wire tag for [`BatchResult::Unavailable`].
    const UNAVAILABLE: u8 = 3;
}

impl Write for BatchResult {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Found { batch, cert } => {
                Self::FOUND.write(buf);
                batch.write(buf);
                cert.write(buf);
            }
            Self::Unknown => Self::UNKNOWN.write(buf),
            Self::Expired => Self::EXPIRED.write(buf),
            Self::Unavailable => Self::UNAVAILABLE.write(buf),
        }
    }
}

impl EncodeSize for BatchResult {
    fn encode_size(&self) -> usize {
        u8::SIZE
            + match self {
                Self::Found { batch, cert } => batch.encode_size() + cert.encode_size(),
                Self::Unknown | Self::Expired | Self::Unavailable => 0,
            }
    }
}

impl Read for BatchResult {
    /// Number of participants in the signing set, needed to bound the certificate's bitmap.
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, participants: &usize) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            Self::FOUND => Ok(Self::Found {
                batch: Batch::read(buf)?,
                cert: Box::new(DaCert::read_cfg(buf, participants)?),
            }),
            Self::UNKNOWN => Ok(Self::Unknown),
            Self::EXPIRED => Ok(Self::Expired),
            Self::UNAVAILABLE => Ok(Self::Unavailable),
            _ => Err(CodecError::Invalid("blob::BatchResult", "unknown variant")),
        }
    }
}

/// A validator's reply to a [`ClientRequest`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientResponse {
    /// The blob was accepted, and this is the identity to poll with.
    Ack {
        /// Identity of the accepted blob.
        id: BlobId,
    },
    /// Where the blob has got to, or `None` if this validator has no record of it.
    ///
    /// A validator only knows about blobs submitted to it: a client polling one gateway about a
    /// blob it gave to another gets `None`, which is also what it gets for a status the board has
    /// evicted.
    Status {
        /// The recorded status, if any.
        status: Option<BlobStatus>,
    },
    /// The batch bytes and the certificate over them, or why neither is on offer.
    ///
    /// The client verifies the bytes itself by re-encoding them and comparing the commitment, so
    /// a validator that returns the wrong batch gains nothing.
    Batch {
        /// The outcome of the query.
        result: BatchResult,
    },
}

impl ClientResponse {
    /// Wire tag for [`ClientResponse::Ack`].
    const ACK: u8 = 0;
    /// Wire tag for [`ClientResponse::Status`].
    const STATUS: u8 = 1;
    /// Wire tag for [`ClientResponse::Batch`].
    const BATCH: u8 = 2;
}

impl Write for ClientResponse {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Ack { id } => {
                Self::ACK.write(buf);
                id.write(buf);
            }
            Self::Status { status } => {
                Self::STATUS.write(buf);
                status.write(buf);
            }
            Self::Batch { result } => {
                Self::BATCH.write(buf);
                result.write(buf);
            }
        }
    }
}

impl EncodeSize for ClientResponse {
    fn encode_size(&self) -> usize {
        u8::SIZE
            + match self {
                Self::Ack { id } => id.encode_size(),
                Self::Status { status } => status.encode_size(),
                Self::Batch { result } => result.encode_size(),
            }
    }
}

impl Read for ClientResponse {
    /// Number of participants in the signing set, needed to bound a certificate's bitmap.
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, participants: &usize) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            Self::ACK => Ok(Self::Ack {
                id: BlobId::read(buf)?,
            }),
            Self::STATUS => Ok(Self::Status {
                status: Option::<BlobStatus>::read_cfg(buf, &())?,
            }),
            Self::BATCH => Ok(Self::Batch {
                result: BatchResult::read_cfg(buf, participants)?,
            }),
            _ => Err(CodecError::Invalid(
                "blob::ClientResponse",
                "unknown variant",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        constants::{MAX_SHARD_SIZE_SIM, NAMESPACE, coding_namespace},
        poseidon2::Fr,
        types::{ClaimedRoot, Scheme},
    };
    use bytes::Bytes;
    use commonware_codec::{Decode, DecodeExt};
    use commonware_coding::Config;
    use commonware_cryptography::{
        Signer as _,
        bls12381::{certificate::multisig::mocks::fixture, primitives::variant::MinSig},
        certificate::Scheme as _,
        ed25519,
    };
    use commonware_parallel::Sequential;
    use commonware_utils::{NZU16, test_rng};
    use rand_core::Rng as _;

    /// Participants in the wire tests.
    const PARTICIPANTS: u32 = 10;

    /// Random buffers fed to each decoder in the adversarial sweep.
    const GARBAGE_ROUNDS: usize = 32;

    /// Decode configuration for a dispersal request in a simulated deployment.
    fn shard_cfg() -> CodecConfig {
        CodecConfig {
            maximum_shard_size: MAX_SHARD_SIZE_SIM,
        }
    }

    /// Builds a certificate over `header` plus the gateway's claim, for reuse across tests.
    fn cert(header: &BatchHeader) -> DaCert {
        let mut rng = test_rng();
        let fixture = fixture::<Scheme, MinSig, _>(
            &mut rng,
            NAMESPACE,
            PARTICIPANTS,
            Scheme::signer,
            Scheme::verifier,
        );
        let attestations: Vec<Attestation> = fixture.schemes[..7]
            .iter()
            .map(|scheme| {
                scheme
                    .sign::<sha256::Digest>(header)
                    .expect("scheme can sign")
            })
            .collect();
        let certificate = fixture
            .verifier
            .assemble(attestations, &Sequential)
            .expect("quorum assembles");
        let gateway = ed25519::PrivateKey::from_seed(3);
        DaCert {
            header: header.clone(),
            certificate,
            claimed_root: ClaimedRoot::sign(
                NAMESPACE,
                &gateway,
                &header.commitment,
                Fr::from(77u64),
            ),
        }
    }

    /// Encodes a batch and shards it, returning the header and the shards.
    fn dispersal() -> (BatchHeader, Vec<StrongShard>) {
        let config = Config {
            minimum_shards: NZU16!(4),
            extra_shards: NZU16!(6),
        };
        let batch = Batch::new(vec![
            Blob::new(Bytes::from(vec![9u8; 4096])).expect("blob is within bounds"),
            Blob::new(Bytes::from(vec![11u8; 1024])).expect("blob is within bounds"),
        ])
        .expect("batch is within bounds");
        let (commitment, shards) = Coder::encode(
            &coding_namespace(NAMESPACE),
            &config,
            batch.encode(),
            &Sequential,
        )
        .expect("encode");
        (BatchHeader::new(commitment, config, View::new(3)), shards)
    }

    /// Compile-time proof that the pair satisfies [`commonware_collector::Handler`], which demands
    /// a shared commitment type and a shared digest type.
    fn assert_collector_bounds<H>()
    where
        H: commonware_collector::Handler<Request = DisperseRequest, Response = DisperseResponse>,
    {
    }

    #[test]
    fn codec_all_types_roundtrip() {
        let (header, shards) = dispersal();

        let request = DisperseRequest {
            header: header.clone(),
            index: 1,
            shard: shards[1].clone(),
        };
        let encoded = request.encode();
        assert_eq!(
            DisperseRequest::decode_cfg(encoded, &shard_cfg()).expect("request decodes"),
            request
        );
        assert_eq!(request.commitment(), header.commitment);

        let mut rng = test_rng();
        let fixture = fixture::<Scheme, MinSig, _>(
            &mut rng,
            NAMESPACE,
            PARTICIPANTS,
            Scheme::signer,
            Scheme::verifier,
        );
        let response = DisperseResponse {
            commitment: header.commitment,
            attestation: fixture.schemes[1]
                .sign::<sha256::Digest>(&header)
                .expect("scheme can sign"),
        };
        assert_eq!(
            DisperseResponse::decode(response.encode()).expect("response decodes"),
            response
        );
        assert_eq!(response.commitment(), request.commitment());

        let cert = cert(&header);
        let payload = Payload {
            parent: sha256::Digest::from([1u8; 32]),
            view: View::new(4),
            certs: vec![cert.clone(), cert.clone()],
        };
        let encoded = payload.encode();
        assert_eq!(
            Payload::decode_cfg(encoded, &(PARTICIPANTS as usize)).expect("payload decodes"),
            payload
        );
        assert_ne!(
            payload.digest(),
            Payload {
                view: View::new(5),
                ..payload
            }
            .digest()
        );

        let blob = Blob::new(Bytes::from(vec![3u8; 700])).expect("blob is within bounds");
        for request in [
            ClientRequest::Submit(blob.clone()),
            ClientRequest::Status(blob.id()),
            ClientRequest::GetBatch(header.commitment),
        ] {
            assert_eq!(
                ClientRequest::decode(request.encode()).expect("client request decodes"),
                request
            );
        }

        let batch = Batch::new(vec![blob.clone()]).expect("batch is within bounds");
        for response in [
            ClientResponse::Ack { id: blob.id() },
            ClientResponse::Status { status: None },
            ClientResponse::Status {
                status: Some(BlobStatus::Pending),
            },
            ClientResponse::Status {
                status: Some(BlobStatus::Certified(header.commitment)),
            },
            ClientResponse::Status {
                status: Some(BlobStatus::Included {
                    commitment: header.commitment,
                    view: View::new(8),
                }),
            },
            ClientResponse::Status {
                status: Some(BlobStatus::Failed),
            },
            ClientResponse::Batch {
                result: BatchResult::Unknown,
            },
            ClientResponse::Batch {
                result: BatchResult::Expired,
            },
            ClientResponse::Batch {
                result: BatchResult::Unavailable,
            },
            ClientResponse::Batch {
                result: BatchResult::Found {
                    batch,
                    cert: Box::new(cert),
                },
            },
        ] {
            assert_eq!(
                ClientResponse::decode_cfg(response.encode(), &(PARTICIPANTS as usize))
                    .expect("client response decodes"),
                response
            );
        }
    }

    #[test]
    fn codec_types_reject_garbage() {
        let (header, shards) = dispersal();
        let request = DisperseRequest {
            header,
            index: 0,
            shard: shards[0].clone(),
        };
        let encoded = request.encode();

        // Truncation anywhere fails.
        for cut in [0usize, 1, 16, encoded.len() / 2, encoded.len() - 1] {
            assert!(DisperseRequest::decode_cfg(&encoded[..cut], &shard_cfg()).is_err());
        }

        // A shard bound below the real shard size rejects the message instead of allocating.
        assert!(
            DisperseRequest::decode_cfg(
                encoded.clone(),
                &CodecConfig {
                    maximum_shard_size: 16,
                }
            )
            .is_err()
        );

        // An unsupported header version is rejected before anything else is read.
        let mut wrong_version = encoded.to_vec();
        wrong_version[0] = 0x02;
        assert!(DisperseRequest::decode_cfg(wrong_version.as_slice(), &shard_cfg()).is_err());

        // Unknown enum tags are rejected rather than defaulted.
        assert!(ClientRequest::decode([9u8].as_slice()).is_err());
        assert!(ClientResponse::decode_cfg([9u8].as_slice(), &(PARTICIPANTS as usize)).is_err());
        assert!(BlobStatus::decode([9u8].as_slice()).is_err());
        assert!(BatchResult::decode_cfg([9u8].as_slice(), &(PARTICIPANTS as usize)).is_err());

        // A payload claiming more certificates than the wire bound is rejected on the count.
        let mut over = Vec::new();
        sha256::Digest::from([0u8; 32]).write(&mut over);
        View::new(1).write(&mut over);
        (PAYLOAD_MAX_CERTS + 1).write(&mut over);
        assert!(Payload::decode_cfg(over.as_slice(), &(PARTICIPANTS as usize)).is_err());

        // Random bytes decode to nothing.
        assert!(Payload::decode_cfg([0xabu8; 64].as_slice(), &(PARTICIPANTS as usize)).is_err());
        assert!(DisperseResponse::decode([0xabu8; 64].as_slice()).is_err());
    }

    /// One encoded value, and a decoder that reports the canonical re-encoding of what it read.
    ///
    /// Re-encoding is what makes a decode checkable without knowing the type: a wire form that
    /// decodes to a value which encodes to different bytes is a second spelling of that value, and
    /// a peer that can choose between two spellings can choose between two digests.
    struct Case {
        name: &'static str,
        encoded: Vec<u8>,
        decode: Decoder,
    }

    /// Decodes bytes and re-encodes what it read, or reports that they were not a message.
    type Decoder = Box<dyn Fn(&[u8]) -> Option<Vec<u8>>>;

    /// Builds a [`Case`] for `value`, decoded under `cfg`.
    fn case<T>(name: &'static str, value: &T, cfg: T::Cfg) -> Case
    where
        T: Read + Encode,
        T::Cfg: Clone + 'static,
    {
        Case {
            name,
            encoded: value.encode().to_vec(),
            decode: Box::new(move |bytes: &[u8]| {
                T::decode_cfg(bytes, &cfg)
                    .ok()
                    .map(|decoded| decoded.encode().to_vec())
            }),
        }
    }

    /// Offsets a sweep visits in a message of `len` bytes.
    ///
    /// Every offset of a small message, and the framing plus a spread of the interior of a large
    /// one: a strong shard is a hundred kilobytes of field data, and flipping each of its bytes in
    /// turn would say nothing that flipping thirty of them does not.
    fn offsets(len: usize) -> Vec<usize> {
        if len <= 512 {
            return (0..len).collect();
        }
        let mut visited: Vec<usize> = (0..64).chain(len - 64..len).collect();
        visited.extend((0..32).map(|step| step * len / 32));
        visited.sort_unstable();
        visited.dedup();
        visited
    }

    #[test]
    fn codec_adversarial_sweep() {
        let mut rng = test_rng();
        let (header, shards) = dispersal();
        let cert = cert(&header);
        let blob = Blob::new(Bytes::from(vec![5u8; 700])).expect("blob is within bounds");
        let batch = Batch::new(vec![blob.clone()]).expect("batch is within bounds");
        let participants = PARTICIPANTS as usize;
        let request = DisperseRequest {
            header: header.clone(),
            index: 3,
            shard: shards[3].clone(),
        };
        let record = crate::custody::CustodyRecord {
            index: 3,
            shard: shards[3].clone(),
        };
        let response = DisperseResponse {
            commitment: header.commitment,
            attestation: fixture::<Scheme, MinSig, _>(
                &mut test_rng(),
                NAMESPACE,
                PARTICIPANTS,
                Scheme::signer,
                Scheme::verifier,
            )
            .schemes[3]
                .sign::<sha256::Digest>(&header)
                .expect("scheme can sign"),
        };
        let payload = Payload {
            parent: sha256::Digest::from([7u8; 32]),
            view: View::new(9),
            certs: vec![cert.clone()],
        };

        // Every type that crosses a wire or a storage boundary, each with the configuration a node
        // decodes it under. Two of them are not messages: a custody record is read back from disk
        // after a restart, and a shard key is chosen by whoever is asking for a shard.
        let cases = [
            case("BlobId", &blob.id(), ()),
            case("Blob", &blob, ()),
            case("Batch", &batch, ()),
            case("BatchHeader", &header, ()),
            case("ClaimedRoot", &cert.claimed_root, ()),
            case("DaCert", &cert, participants),
            case(
                "ShardKey",
                &crate::retrieval::ShardKey::new(header.commitment, 3),
                (),
            ),
            case("CustodyRecord", &record, shard_cfg()),
            case("DisperseRequest", &request, shard_cfg()),
            case("DisperseResponse", &response, ()),
            case("Payload", &payload, participants),
            case("BlobStatus::Pending", &BlobStatus::Pending, ()),
            case(
                "BlobStatus::Included",
                &BlobStatus::Included {
                    commitment: header.commitment,
                    view: View::new(9),
                },
                (),
            ),
            case(
                "ClientRequest::Submit",
                &ClientRequest::Submit(blob.clone()),
                (),
            ),
            case(
                "ClientRequest::Status",
                &ClientRequest::Status(blob.id()),
                (),
            ),
            case(
                "ClientRequest::GetBatch",
                &ClientRequest::GetBatch(header.commitment),
                (),
            ),
            case("BatchResult::Expired", &BatchResult::Expired, participants),
            case(
                "BatchResult::Found",
                &BatchResult::Found {
                    batch: batch.clone(),
                    cert: Box::new(cert.clone()),
                },
                participants,
            ),
            case(
                "ClientResponse::Ack",
                &ClientResponse::Ack { id: blob.id() },
                participants,
            ),
            case(
                "ClientResponse::Status",
                &ClientResponse::Status {
                    status: Some(BlobStatus::Certified(header.commitment)),
                },
                participants,
            ),
            case(
                "ClientResponse::Batch",
                &ClientResponse::Batch {
                    result: BatchResult::Unavailable,
                },
                participants,
            ),
        ];

        for Case {
            name,
            encoded,
            decode,
        } in &cases
        {
            // What a node writes, a node reads, and writes again identically.
            assert_eq!(
                decode(encoded).as_deref(),
                Some(encoded.as_slice()),
                "{name} does not round trip canonically"
            );

            // A message that ends early is never a shorter valid message. Nothing here is allowed
            // to treat a missing field as an absent one.
            for cut in offsets(encoded.len()) {
                assert!(
                    decode(&encoded[..cut]).is_none(),
                    "{name} decoded a {cut}-byte prefix of {} bytes",
                    encoded.len()
                );
            }

            // Trailing bytes are extra data rather than padding: a peer must not be able to append
            // to a message and have it mean the same thing.
            let mut extended = encoded.clone();
            extended.push(0);
            assert!(
                decode(&extended).is_none(),
                "{name} accepted a trailing byte"
            );

            // A flipped byte either fails or is a different message, canonically encoded. What it
            // must never be is accepted while re-encoding to something else.
            for offset in offsets(encoded.len()) {
                let mut mutated = encoded.clone();
                mutated[offset] ^= 0xff;
                if let Some(round) = decode(&mutated) {
                    assert_eq!(
                        round, mutated,
                        "{name} accepted a non-canonical encoding at byte {offset}"
                    );
                }
            }

            // And bytes that were never a message at all: the decoder is reached by anything a
            // peer cares to send, so it may reject but may not panic or normalize.
            for _ in 0..GARBAGE_ROUNDS {
                let mut noise = vec![0u8; encoded.len()];
                rng.fill_bytes(&mut noise);
                if let Some(round) = decode(&noise) {
                    assert_eq!(
                        round,
                        noise,
                        "{name} normalized {} random bytes",
                        noise.len()
                    );
                }
            }
        }

        // Bounds are the other half: a decoder that is handed a configuration smaller than the
        // message rejects it rather than allocating to fit.
        let narrow = CodecConfig {
            maximum_shard_size: 32,
        };
        assert!(crate::custody::CustodyRecord::decode_cfg(record.encode(), &narrow).is_err());
        assert!(DisperseRequest::decode_cfg(request.encode(), &narrow).is_err());
        for participants in [0usize, 1, PARTICIPANTS as usize - 1] {
            assert!(
                DaCert::decode_cfg(cert.encode(), &participants).is_err(),
                "a certificate decoded under a set of {participants}"
            );
            assert!(
                Payload::decode_cfg(payload.encode(), &participants).is_err(),
                "a payload decoded under a set of {participants}"
            );
            assert!(
                BatchResult::decode_cfg(
                    BatchResult::Found {
                        batch: batch.clone(),
                        cert: Box::new(cert.clone()),
                    }
                    .encode(),
                    &participants
                )
                .is_err(),
                "a batch result decoded under a set of {participants}"
            );
            assert!(
                ClientResponse::decode_cfg(
                    ClientResponse::Batch {
                        result: BatchResult::Found {
                            batch: batch.clone(),
                            cert: Box::new(cert.clone()),
                        },
                    }
                    .encode(),
                    &participants
                )
                .is_err(),
                "a client response decoded under a set of {participants}"
            );
        }

        // Unknown tags are rejected rather than defaulted. Each type is swept from one past its
        // last variant, so a variant added without a matching arm is caught here.
        for tag in 3u8..=0xff {
            assert!(
                ClientRequest::decode([tag].as_slice()).is_err(),
                "ClientRequest accepted tag {tag}"
            );
            assert!(
                ClientResponse::decode_cfg([tag].as_slice(), &participants).is_err(),
                "ClientResponse accepted tag {tag}"
            );
        }
        for tag in 4u8..=0xff {
            assert!(
                BlobStatus::decode([tag].as_slice()).is_err(),
                "BlobStatus accepted tag {tag}"
            );
            assert!(
                BatchResult::decode_cfg([tag].as_slice(), &participants).is_err(),
                "BatchResult accepted tag {tag}"
            );
        }

        // The version byte is a tag too: a dispersal from a build this one cannot speak to is
        // rejected before any of its fields are read.
        for version in 0u8..=0xff {
            if version == BatchHeader::VERSION {
                continue;
            }
            let mut wrong = header.encode().to_vec();
            wrong[0] = version;
            assert!(
                BatchHeader::decode(wrong.as_slice()).is_err(),
                "BatchHeader accepted version {version}"
            );
            let mut wrong = blob.id().encode().to_vec();
            wrong[0] = version;
            assert!(
                BlobId::decode(wrong.as_slice()).is_err(),
                "BlobId accepted version {version}"
            );
        }
    }

    #[test]
    fn collector_bounds_hold() {
        // The bound is checked when this instantiation is type-checked, not when it runs.
        assert_collector_bounds::<Pairing>();
    }

    /// Minimal handler used only to instantiate [`assert_collector_bounds`].
    #[derive(Clone)]
    struct Pairing;

    impl commonware_collector::Handler for Pairing {
        type PublicKey = ed25519::PublicKey;
        type Request = DisperseRequest;
        type Response = DisperseResponse;

        fn process(
            &mut self,
            _: Self::PublicKey,
            _: Self::Request,
            _: commonware_utils::channel::oneshot::Sender<Self::Response>,
        ) {
        }
    }
}
