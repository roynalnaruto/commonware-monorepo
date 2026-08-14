//! Fixtures shared by the actor tests.
//!
//! Everything here builds the simulated deployment of the plan: ten validators, batches of a few
//! kilobytes, and shards produced by a real encode so that a test which claims a shard passes (or
//! fails) its coding check is claiming something about the coding scheme, not about a stub.

use crate::{
    assignment::coding_config,
    constants::{MAX_MESSAGE_SIZE_SIM, MAX_SHARD_SIZE_SIM, NAMESPACE, coding_namespace},
    types::{Batch, BatchHeader, Blob, DaCert, Scheme},
    wire::{Coder, DisperseRequest, DisperseResponse, StrongShard},
};
use bytes::Bytes;
use commonware_actor::Feedback;
use commonware_broadcast::{Broadcaster, buffered};
use commonware_codec::{Decode as _, Encode as _};
use commonware_coding::{CodecConfig, PhasedScheme as _};
use commonware_consensus::types::View;
use commonware_cryptography::{
    bls12381::{certificate::multisig::mocks::fixture, primitives::variant::MinSig},
    certificate::{Scheme as _, mocks::Fixture},
    ed25519, sha256,
};
use commonware_p2p::{
    Channel, Manager as _, Recipients,
    simulated::{Link, Network, Oracle, Receiver, Sender},
};
use commonware_parallel::Sequential;
use commonware_runtime::{Quota, Supervisor as _, deterministic};
use commonware_utils::{
    NZU32, NZUsize,
    channel::{mpsc, oneshot},
    ordered::Set,
    test_rng,
};
use std::time::Duration;

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
    let config = coding_config(PARTICIPANTS as usize).expect("participant set can be coded");
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

/// Gossips certificates and keeps a copy for the test to inspect.
///
/// A certificate's digest covers its signer set, so a test cannot predict it; watching the
/// gateway's own broadcast is how a test learns which certificate to look for.
#[derive(Clone)]
pub struct Tee {
    /// The real gossip mailbox.
    pub inner: buffered::Mailbox<ed25519::PublicKey, DaCert>,
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
