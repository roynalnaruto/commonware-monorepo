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
    let batch = sample_batch(filler);
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

/// Encodes arbitrary bytes as a gateway would encode a batch.
///
/// A gateway chooses what it encodes, and attestors only ever check that a shard belongs to the
/// commitment, so bytes that are not a batch can reach a certificate. Tests about what happens
/// afterwards need to be able to produce that.
pub fn dispersal_of(view: u64, bytes: Bytes) -> (BatchHeader, Vec<StrongShard>) {
    let config = coding_config(PARTICIPANTS as usize).expect("participant set can be coded");
    let (commitment, shards) =
        Coder::encode(&coding_namespace(NAMESPACE), &config, bytes, &Sequential)
            .expect("bytes encode");
    (
        BatchHeader::new(commitment, config, View::new(view)),
        shards,
    )
}

/// The batch [`dispersal`] and [`dispersal_among`] encode, so a reader can compare against it.
pub fn sample_batch(filler: u8) -> Batch {
    Batch::new(vec![
        Blob::new(Bytes::from(vec![filler; 4096])).expect("blob is within bounds"),
        Blob::new(Bytes::from(vec![filler ^ 0xff; 1024])).expect("blob is within bounds"),
    ])
    .expect("batch is within bounds")
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
    network_linked(context, peers, |_, _| LINK.clone()).await
}

/// Starts a fully connected simulated network whose links are chosen per ordered pair.
///
/// `link` is given the positions of the sender and the receiver. Tests that need one peer's
/// answer to arrive before another's use this to say so, rather than relying on the order the
/// runtime happens to poll in.
pub async fn network_linked(
    context: &deterministic::Context,
    peers: &[ed25519::PublicKey],
    link: impl Fn(usize, usize) -> Link,
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
    for (from, sender) in peers.iter().enumerate() {
        for (to, receiver) in peers.iter().enumerate() {
            if from != to {
                oracle
                    .add_link(sender.clone(), receiver.clone(), link(from, to))
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

/// How a validator answers shard requests in a retrieval test.
///
/// One producer type for all of them, because a resolver engine is generic over its producer and
/// a deployment of mixed behaviours would otherwise be a deployment of mixed engine types.
pub enum Role<E: commonware_runtime::Metrics + commonware_runtime::Spawner> {
    /// The real producer: serves whatever this node custodies.
    Honest(crate::retrieval::Producer<E>),
    /// Hears every request and answers none.
    ///
    /// Indistinguishable from a crashed custodian or one whose shard has expired.
    Silent,
    /// Answers every request with the same fixed bytes, whatever was asked for.
    Forged(Bytes),
}

impl<E: commonware_runtime::Metrics + commonware_runtime::Spawner> Clone for Role<E> {
    fn clone(&self) -> Self {
        match self {
            Self::Honest(producer) => Self::Honest(producer.clone()),
            Self::Silent => Self::Silent,
            Self::Forged(bytes) => Self::Forged(bytes.clone()),
        }
    }
}

/// A [`Role`] that also counts the requests it was asked to serve.
///
/// The count is what makes cancellation observable: a request the resolver has given up on is a
/// request that never arrives, so a counter that stops growing is a fetch that stopped.
pub struct Serve<E: commonware_runtime::Metrics + commonware_runtime::Spawner> {
    role: Role<E>,
    requests: Arc<std::sync::atomic::AtomicUsize>,
}

impl<E: commonware_runtime::Metrics + commonware_runtime::Spawner> Clone for Serve<E> {
    fn clone(&self) -> Self {
        Self {
            role: self.role.clone(),
            requests: self.requests.clone(),
        }
    }
}

impl<E: commonware_runtime::Metrics + commonware_runtime::Spawner> Serve<E> {
    /// Wraps a role.
    pub fn new(role: Role<E>) -> Self {
        Self {
            role,
            requests: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// Returns how many requests this producer has been asked to serve.
    pub fn requests(&self) -> usize {
        self.requests.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl<E: commonware_runtime::Metrics + commonware_runtime::Spawner>
    commonware_resolver::p2p::Producer for Serve<E>
{
    type Key = crate::retrieval::ShardKey;

    fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes> {
        self.requests
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        match &mut self.role {
            Role::Honest(producer) => commonware_resolver::p2p::Producer::produce(producer, key),
            Role::Silent => oneshot::channel().1,
            Role::Forged(bytes) => {
                let (sender, receiver) = oneshot::channel();
                let _ = sender.send(bytes.clone());
                receiver
            }
        }
    }
}

/// A [`commonware_p2p::Blocker`] that records who it was asked to block.
#[derive(Clone)]
pub struct Watcher<B: commonware_p2p::Blocker> {
    inner: B,
    blocked: Arc<Mutex<Vec<B::PublicKey>>>,
}

impl<B: commonware_p2p::Blocker> Watcher<B> {
    /// Wraps a blocker.
    pub fn new(inner: B) -> Self {
        Self {
            inner,
            blocked: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Returns everyone this node has blocked, in order.
    pub fn blocked(&self) -> Vec<B::PublicKey> {
        self.blocked.lock().clone()
    }
}

impl<B: commonware_p2p::Blocker> commonware_p2p::Blocker for Watcher<B> {
    type PublicKey = B::PublicKey;

    #[allow(
        clippy::disallowed_methods,
        reason = "forwards a block another actor already decided on and logged"
    )]
    fn block(&mut self, peer: Self::PublicKey) -> Feedback {
        self.blocked.lock().push(peer.clone());
        self.inner.block(peer)
    }
}
