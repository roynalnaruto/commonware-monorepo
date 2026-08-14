//! Messages exchanged on the data-availability and consensus rails.
//!
//! Each type carries its own decode bounds, and every `Read` here is bounded: a message arrives
//! from an untrusted peer, so nothing is sized by a number the peer chose.

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

/// A validator's reply to a [`ClientRequest`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientResponse {
    /// The blob was accepted, and this is the identity to poll with.
    Ack(BlobId),
    /// Where the blob has got to.
    Status(BlobStatus),
    /// The batch bytes, or `None` if the batch is unknown or has aged out of custody.
    ///
    /// The client verifies these bytes itself by re-encoding them and comparing the commitment,
    /// so a validator that returns the wrong batch gains nothing.
    Batch(Option<Batch>),
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
            Self::Ack(id) => {
                Self::ACK.write(buf);
                id.write(buf);
            }
            Self::Status(status) => {
                Self::STATUS.write(buf);
                status.write(buf);
            }
            Self::Batch(batch) => {
                Self::BATCH.write(buf);
                batch.write(buf);
            }
        }
    }
}

impl EncodeSize for ClientResponse {
    fn encode_size(&self) -> usize {
        u8::SIZE
            + match self {
                Self::Ack(id) => id.encode_size(),
                Self::Status(status) => status.encode_size(),
                Self::Batch(batch) => batch.encode_size(),
            }
    }
}

impl Read for ClientResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            Self::ACK => Ok(Self::Ack(BlobId::read(buf)?)),
            Self::STATUS => Ok(Self::Status(BlobStatus::read(buf)?)),
            Self::BATCH => Ok(Self::Batch(Option::<Batch>::read_cfg(buf, &())?)),
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
        constants::{MAX_SHARD_SIZE_SIM, NAMESPACE},
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

    /// Participants in the wire tests.
    const PARTICIPANTS: u32 = 10;

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
        let (commitment, shards) =
            Coder::encode(NAMESPACE, &config, batch.encode(), &Sequential).expect("encode");
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
    fn p1_codec_all_wire_types_roundtrip() {
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
            certs: vec![cert.clone(), cert],
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
            ClientResponse::Ack(blob.id()),
            ClientResponse::Status(BlobStatus::Pending),
            ClientResponse::Status(BlobStatus::Certified(header.commitment)),
            ClientResponse::Status(BlobStatus::Included {
                commitment: header.commitment,
                view: View::new(8),
            }),
            ClientResponse::Status(BlobStatus::Failed),
            ClientResponse::Batch(None),
            ClientResponse::Batch(Some(batch)),
        ] {
            assert_eq!(
                ClientResponse::decode(response.encode()).expect("client response decodes"),
                response
            );
        }
    }

    #[test]
    fn p1_codec_wire_types_reject_garbage() {
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
        assert!(ClientResponse::decode([9u8].as_slice()).is_err());
        assert!(BlobStatus::decode([9u8].as_slice()).is_err());

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

    #[test]
    fn p1_wire_collector_bounds_hold() {
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
