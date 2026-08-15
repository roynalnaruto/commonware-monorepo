//! Fixtures shared by the actor tests.
//!
//! Everything here builds the simulated deployment of the plan: ten validators, batches of a few
//! kilobytes, and shards produced by a real encode so that a test which claims a shard passes (or
//! fails) its coding check is claiming something about the coding scheme, not about a stub.

use crate::{
    assignment::coding_config,
    constants::{
        MAX_MESSAGE_SIZE_SIM, MAX_SHARD_SIZE_SIM, NAMESPACE, coding_namespace, consensus_namespace,
    },
    poseidon2::Fr,
    types::{Attestation, Batch, BatchHeader, Blob, ClaimedRoot, DaCert, Scheme},
    wire::{Coder, DisperseRequest, DisperseResponse, StrongShard},
};
use bytes::Bytes;
use commonware_actor::Feedback;
use commonware_broadcast::Broadcaster;
use commonware_codec::{Decode as _, DecodeExt as _, Encode as _};
use commonware_coding::{CodecConfig, PhasedScheme as _};
use commonware_consensus::types::View;
use commonware_cryptography::{
    Signer as _,
    bls12381::{
        certificate::multisig::mocks::fixture,
        primitives::{
            group::Private,
            ops::keypair,
            variant::{MinSig, Variant},
        },
    },
    certificate::{Scheme as _, mocks::Fixture},
    ed25519, sha256,
    transcript::Summary,
};
use commonware_p2p::{
    Channel, Manager as _, Receiver as _, Recipients, Sender as _,
    simulated::{Link, Network, Oracle, Receiver, Sender},
};
use commonware_parallel::Sequential;
use commonware_runtime::{Quota, Spawner as _, Supervisor as _, deterministic};
use commonware_utils::{
    NZU32, NZUsize, TryCollect as _,
    channel::{mpsc, oneshot},
    ordered::{BiMap, Set},
    sync::Mutex,
    test_rng,
};
use std::{sync::Arc, time::Duration};

/// Validators in the simulated deployment: `n = 10`, `f = 3`, quorum 7, minimum shards 4.
pub const PARTICIPANTS: u32 = 10;

/// The signing scheme is generic over a digest it never uses, because a
/// [`BatchHeader`](crate::types::BatchHeader) is not one; this pins that parameter.
pub type Unused = sha256::Digest;

/// Decode bounds for a shard in the simulated deployment.
pub fn shard_cfg() -> CodecConfig {
    CodecConfig {
        maximum_shard_size: MAX_SHARD_SIZE_SIM,
    }
}

/// Builds the signing fixture for the simulated deployment.
///
/// The fixture's `schemes[i]` signs as the holder of participant position `i`, and therefore of
/// shard `i`.
pub fn schemes() -> Fixture<Scheme> {
    let mut rng = test_rng();
    fixture::<Scheme, MinSig, _>(
        &mut rng,
        NAMESPACE,
        PARTICIPANTS,
        Scheme::signer,
        Scheme::verifier,
    )
}

/// Encodes a small batch, returning the header a gateway would disperse and one shard per
/// validator.
///
/// `filler` distinguishes batches: two calls with different fillers produce different commitments.
pub fn dispersal(view: u64, filler: u8) -> (BatchHeader, Vec<StrongShard>) {
    dispersal_among(PARTICIPANTS as usize, view, filler)
}

/// Encodes a small batch for a deployment of `participants` validators.
pub fn dispersal_among(
    participants: usize,
    view: u64,
    filler: u8,
) -> (BatchHeader, Vec<StrongShard>) {
    let config = coding_config(participants).expect("participant set can be coded");
    let batch = Batch::new(vec![
        Blob::new(Bytes::from(vec![filler; 4096])).expect("blob is within bounds"),
        Blob::new(Bytes::from(vec![filler ^ 0xff; 1024])).expect("blob is within bounds"),
    ])
    .expect("batch is within bounds");
    let (commitment, shards) = Coder::encode(
        &coding_namespace(NAMESPACE),
        &config,
        batch.encode(),
        &Sequential,
    )
    .expect("batch encodes");
    (
        BatchHeader::new(commitment, config, View::new(view)),
        shards,
    )
}

/// Attestations a certificate needs in the simulated deployment: `2f + 1`.
pub const QUORUM: usize = 7;

/// Rate limit high enough that no test is shaped by it.
const TEST_QUOTA: Quota = Quota::per_second(NZU32!(1_000_000));

/// Link between every pair of validators: fast, lossless, and slow enough that a node's own shard
/// always beats a peer's over the wire.
pub const LINK: Link = Link {
    latency: Duration::from_millis(10),
    jitter: Duration::from_millis(1),
    success_rate: 1.0,
};

/// Builds `count` distinct blobs of `len` bytes each, distinguished by `filler`.
pub fn blobs(count: usize, len: usize, filler: u8) -> Vec<Blob> {
    (0..count)
        .map(|index| {
            let mut bytes = vec![0u8; len];
            for (position, byte) in bytes.iter_mut().enumerate() {
                *byte = (position as u8).wrapping_mul(31).wrapping_add(index as u8) ^ filler;
            }
            Blob::new(Bytes::from(bytes)).expect("blob is within bounds")
        })
        .collect()
}

/// Starts a fully connected simulated network over `peers`.
///
/// Every peer is tracked as primary at set `0`, which is what lets them exchange messages at all
/// and what makes them eligible to buffer gossiped certificates.
pub async fn network(
    context: &deterministic::Context,
    peers: &[ed25519::PublicKey],
) -> Oracle<ed25519::PublicKey, deterministic::Context> {
    let (network, oracle) = Network::new(
        context.child("network"),
        commonware_p2p::simulated::Config {
            max_size: MAX_MESSAGE_SIZE_SIM as u32,
            max_peers_per_set: NZUsize!(peers.len()),
            disconnect_on_block: true,
            tracked_peer_sets: NZUsize!(1),
        },
    );
    network.start();
    for from in peers {
        for to in peers {
            if from != to {
                oracle
                    .add_link(from.clone(), to.clone(), LINK.clone())
                    .await
                    .expect("link is added");
            }
        }
    }
    oracle
        .manager()
        .track(0, Set::from_iter_dedup(peers.to_vec()));
    oracle
}

/// Registers one peer on one channel.
pub async fn register(
    oracle: &Oracle<ed25519::PublicKey, deterministic::Context>,
    peer: &ed25519::PublicKey,
    channel: Channel,
) -> (
    Sender<ed25519::PublicKey, deterministic::Context>,
    Receiver<ed25519::PublicKey>,
) {
    oracle
        .control(peer.clone())
        .register(channel, TEST_QUOTA)
        .await
        .expect("channel is registered")
}

/// How a validator answers dispersal requests in a test.
///
/// One handler type for all of them, because a collector engine is generic over its handler and a
/// deployment of mixed behaviours would otherwise be a deployment of mixed engine types.
#[derive(Clone)]
pub enum Attester {
    /// The real attestor: checks its shard, custodies it, and signs.
    Honest(crate::attestor::Mailbox),
    /// Hears every dispersal and answers none.
    ///
    /// Withholding is indistinguishable from a crash or a partition: the gateway simply never
    /// hears back.
    Silent,
    /// Answers with a well-formed signature over the wrong subject.
    ///
    /// Signs under its own position, so nothing short of checking the signature catches it: this
    /// is what the gateway's batch verification is for.
    Byzantine(Scheme),
}

impl commonware_collector::Handler for Attester {
    type PublicKey = ed25519::PublicKey;
    type Request = DisperseRequest;
    type Response = DisperseResponse;

    fn process(
        &mut self,
        origin: Self::PublicKey,
        request: Self::Request,
        responder: oneshot::Sender<Self::Response>,
    ) {
        match self {
            Self::Honest(attestor) => attestor.process(origin, request, responder),
            Self::Silent => {}
            Self::Byzantine(scheme) => {
                let mut lying = request.header.clone();
                lying.dispersal_view = View::new(lying.dispersal_view.get().wrapping_add(1));
                let Some(attestation) = scheme.sign::<Unused>(&lying) else {
                    return;
                };
                let _ = responder.send(DisperseResponse {
                    commitment: request.header.commitment,
                    attestation,
                });
            }
        }
    }
}

/// Who a validator hands collected responses to.
#[derive(Clone)]
pub enum Collected {
    /// The gateway's disperser.
    Gateway(crate::gateway::disperser::Mailbox),
    /// A validator that originates no dispersal, and so collects nothing.
    Deaf,
}

impl commonware_collector::Monitor for Collected {
    type PublicKey = ed25519::PublicKey;
    type Response = DisperseResponse;

    fn collected(&mut self, handler: Self::PublicKey, response: Self::Response, count: usize) {
        match self {
            Self::Gateway(disperser) => disperser.collected(handler, response, count),
            Self::Deaf => {}
        }
    }
}

/// Gossips certificates over a plain p2p channel.
///
/// The production path hands the gateway's disperser the application's mailbox, which pools the
/// certificate before forwarding it. Tests that run no application use this instead: it sends the
/// encoded certificate and nothing else, which is what the wire carries either way.
#[derive(Clone)]
pub struct Gossip {
    sender: Arc<Mutex<Sender<ed25519::PublicKey, deterministic::Context>>>,
}

impl Gossip {
    /// Wraps a registered sender.
    pub fn new(sender: Sender<ed25519::PublicKey, deterministic::Context>) -> Self {
        Self {
            sender: Arc::new(Mutex::new(sender)),
        }
    }
}

impl Broadcaster for Gossip {
    type Recipients = Recipients<ed25519::PublicKey>;
    type Message = DaCert;

    fn broadcast(&self, recipients: Self::Recipients, message: Self::Message) -> Feedback {
        self.sender.lock().send(recipients, message.encode(), false);
        Feedback::Ok
    }
}

/// Gossips certificates and keeps a copy for the test to inspect.
///
/// A certificate's digest covers its signer set, so a test cannot predict it; watching the
/// gateway's own broadcast is how a test learns which certificate to look for.
#[derive(Clone)]
pub struct Tee {
    /// The real gossip handle.
    pub inner: Gossip,
    /// Where the copy goes.
    pub seen: mpsc::UnboundedSender<DaCert>,
}

impl Broadcaster for Tee {
    type Recipients = Recipients<ed25519::PublicKey>;
    type Message = DaCert;

    fn broadcast(&self, recipients: Self::Recipients, message: Self::Message) -> Feedback {
        let _ = self.seen.send(message.clone());
        self.inner.broadcast(recipients, message)
    }
}

/// Drains a certificate-gossip channel into an unbounded queue a test can poll.
///
/// A node that runs no application still has to take messages off the channel, or the simulated
/// network blocks the sender; this is that node's whole certificate handling.
pub fn collect_certs(
    context: &deterministic::Context,
    mut receiver: Receiver<ed25519::PublicKey>,
    participants: usize,
) -> mpsc::UnboundedReceiver<DaCert> {
    let (sender, received) = mpsc::unbounded_channel();
    context.child("certs").spawn(move |_| async move {
        while let Ok((_, bytes)) = receiver.recv().await {
            let Ok(cert) = DaCert::decode_cfg(bytes.as_ref(), &participants) else {
                continue;
            };
            if sender.send(cert).is_err() {
                return;
            }
        }
    });
    received
}

/// Key material for a simulated deployment.
///
/// Every validator holds two keys: an ed25519 identity that names it on the network and a BLS
/// signing key it attests and votes with. The vectors are ordered by ed25519 identity, which is
/// the order the participant set imposes and therefore the order shard indices follow.
pub struct Keys {
    /// Identity private keys, sorted by public key.
    pub privates: Vec<ed25519::PrivateKey>,
    /// BLS signing keys, in the same order.
    pub bls: Vec<Private>,
    /// The participant set every scheme is built over.
    pub participants: BiMap<ed25519::PublicKey, <MinSig as Variant>::Public>,
}

/// Generates key material for `count` validators.
pub fn keys(count: usize) -> Keys {
    let mut rng = test_rng();
    let mut material: Vec<_> = (0..count)
        .map(|seed| {
            let identity = ed25519::PrivateKey::from_seed(seed as u64);
            let (private, public) = keypair::<_, MinSig>(&mut rng);
            (identity.public_key(), identity, private, public)
        })
        .collect();
    material.sort_by(|a, b| a.0.cmp(&b.0));
    let participants: BiMap<_, _> = material
        .iter()
        .map(|(identity, _, _, public)| (identity.clone(), *public))
        .try_collect()
        .expect("identities are unique");
    Keys {
        privates: material.iter().map(|(_, key, _, _)| key.clone()).collect(),
        bls: material.into_iter().map(|(_, _, key, _)| key).collect(),
        participants,
    }
}

/// Builds the attestation schemes for `keys`.
///
/// A [`Fixture`] rather than a bare vector so the certificate helpers here work the same over key
/// material a test generated and over key material the mocks did.
pub fn attesting(keys: &Keys) -> Fixture<Scheme> {
    Fixture {
        participants: keys.privates.iter().map(|key| key.public_key()).collect(),
        private_keys: keys.privates.clone(),
        schemes: keys
            .bls
            .iter()
            .map(|private| {
                Scheme::signer(NAMESPACE, keys.participants.clone(), private.clone())
                    .expect("signer is a participant")
            })
            .collect(),
        verifier: Scheme::verifier(NAMESPACE, keys.participants.clone()),
    }
}

/// Builds the consensus schemes for `keys`, over the same BLS material as [`attesting`].
pub fn voting(keys: &Keys) -> Fixture<crate::application::Scheme> {
    let namespace = consensus_namespace(NAMESPACE);
    Fixture {
        participants: keys.privates.iter().map(|key| key.public_key()).collect(),
        private_keys: keys.privates.clone(),
        schemes: keys
            .bls
            .iter()
            .map(|private| {
                crate::application::Scheme::signer(
                    &namespace,
                    keys.participants.clone(),
                    private.clone(),
                )
                .expect("signer is a participant")
            })
            .collect(),
        verifier: crate::application::Scheme::verifier(&namespace, keys.participants.clone()),
    }
}

/// A commitment distinguished only by `byte`.
pub fn summary(byte: u8) -> Summary {
    Summary::decode([byte; 32].as_slice()).expect("summary is 32 bytes")
}

/// A certificate whose header says what a test needs it to say.
///
/// The signatures are over a different header, so this is only usable where nothing checks them:
/// the payload store treats a certificate as an opaque commitment. Assembling the template costs a
/// signing fixture, so it is built once and cloned.
pub fn stub_cert(commitment: Summary, view: View) -> DaCert {
    static TEMPLATE: std::sync::OnceLock<DaCert> = std::sync::OnceLock::new();
    let mut cert = TEMPLATE
        .get_or_init(|| {
            let fixture = schemes();
            let (header, _) = dispersal(0, 0);
            genuine_cert(
                &fixture,
                &header,
                &ed25519::PrivateKey::from_seed(0),
                Fr::from(0u64),
                QUORUM,
            )
        })
        .clone();
    cert.header = BatchHeader::new(commitment, cert.header.config, view);
    cert
}

/// A certificate a verifier accepts: a real quorum over `header`, and a real gateway claim.
pub fn genuine_cert(
    fixture: &Fixture<Scheme>,
    header: &BatchHeader,
    gateway: &ed25519::PrivateKey,
    root: Fr,
    signers: usize,
) -> DaCert {
    let attestations: Vec<Attestation> = fixture.schemes[..signers]
        .iter()
        .map(|scheme| scheme.sign::<Unused>(header).expect("scheme can sign"))
        .collect();
    DaCert {
        header: header.clone(),
        certificate: fixture
            .verifier
            .assemble(attestations, &Sequential)
            .expect("quorum assembles"),
        claimed_root: ClaimedRoot::sign(NAMESPACE, gateway, &header.commitment, root),
    }
}

/// Flips one bit inside an encoded shard, returning a corrupt shard that still decodes.
///
/// Corrupting the bytes rather than the framing is the point: a shard that fails to decode is
/// caught by the codec, while this one is only caught by its coding check.
pub fn corrupt(shard: &StrongShard) -> StrongShard {
    let encoded = shard.encode();
    // The rows and the checksum matrix are written last, so scanning from the end corrupts the
    // shard data rather than its framing.
    for offset in (0..encoded.len()).rev() {
        let mut bytes = encoded.to_vec();
        bytes[offset] ^= 1;
        if let Ok(candidate) = StrongShard::decode_cfg(bytes.as_slice(), &shard_cfg())
            && &candidate != shard
        {
            return candidate;
        }
    }
    panic!("no byte of the shard could be flipped");
}
