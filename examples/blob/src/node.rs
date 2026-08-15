//! Assembly: every actor a validator runs, wired to the channels it speaks on.
//!
//! A validator is seven actors and two rails. On the data-availability rail a [`Batcher`] takes
//! blobs from clients, a [`Disperser`] encodes and certifies them, a [`Attestor`] answers other
//! gateways' dispersals, and a [`Custody`] store keeps what it attested to. On the consensus rail
//! [`simplex`] orders payload digests, a [`buffered`] engine carries the payloads themselves, and
//! the [`Application`] decides what goes into a payload and what a payload has to satisfy.
//!
//! Wiring them by hand twice, once for tests and once for the binary, is how the two would drift
//! apart, so both go through here.
//!
//! # Two schemes, one key
//!
//! Consensus votes and blob attestations are signed with the same BLS key over the same
//! participant set, under namespaces that differ: a vote must never read as an attestation. The
//! ed25519 identity that orders the participant set is also the p2p identity and the gateway's
//! signing key for its claimed root, which is what makes shard index `i`, participant `i`, and
//! peer `i` the same validator everywhere.
//!
//! # Order of construction
//!
//! Two dependencies are circular and settle the order. A collector engine wants its monitor before
//! it hands back the originator its disperser needs, so the disperser's mailbox is built first and
//! the actor last. And a certificate reaches the gateway's own pool through the application's
//! mailbox, so the application exists before the disperser that gossips into it.

use crate::{
    application::{self, Application},
    assignment::coding_config,
    attestor::{self, Attestor, Watermark},
    constants::{
        ATTEST_SLACK, CERTIFICATION_TIMEOUT, CERTIFICATION_TIMEOUT_SIM, FETCH_TIMEOUT,
        FETCH_TIMEOUT_SIM, LEADER_TIMEOUT, LEADER_TIMEOUT_SIM, MAX_TRACKED_BLOBS, PAYLOAD_DEQUE,
        RETRIEVAL_TIMEOUT, RETRIEVAL_TIMEOUT_SIM, SHARD_FETCH_INITIAL, SHARD_FETCH_RETRY,
        SHARD_FETCH_RETRY_SIM, SHARD_FETCH_TIMEOUT, SHARD_FETCH_TIMEOUT_SIM, SKIP_TIMEOUT,
        SKIP_TIMEOUT_SIM, STATUS_TTL, TIMEOUT_RETRY, TIMEOUT_RETRY_SIM, VIEW_RETENTION,
        consensus_namespace,
    },
    custody::{self, Custody},
    gateway::{
        Batcher, Disperser, StatusBoard,
        batcher::{self},
        disperser::{self},
    },
    payload::{self, PayloadStore},
    registry::Registry,
    retrieval::{self, Coordinator},
    rpc,
    types::Scheme,
    wire::DisperseRequest,
};
use commonware_broadcast::buffered;
use commonware_coding::CodecConfig;
use commonware_collector::p2p as collector;
use commonware_consensus::{
    simplex,
    types::{Epoch, ViewDelta},
};
use commonware_cryptography::{
    Sha256, Signer as _,
    bls12381::primitives::{
        group::Private,
        variant::{MinSig, Variant},
    },
    ed25519,
};
use commonware_p2p::{Blocker, Provider, Receiver, Sender};
use commonware_parallel::Strategy;
use commonware_resolver::p2p as resolver;
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner, Storage, buffer::paged::CacheRef};
use commonware_utils::{NZU16, NZUsize, channel::mpsc, ordered::BiMap};
use rand_core::CryptoRng;
use std::{num::NonZeroUsize, time::Duration};

/// Sealed batches queued for dispersal before intake is held.
///
/// Small on purpose: the point of the queue is to let one batch encode while the next fills, not
/// to accumulate batches a gateway has no attestations for.
const SEALED_QUEUE: usize = 2;

/// Page size of the consensus journal's cache.
const PAGE_SIZE: std::num::NonZeroU16 = NZU16!(16_384);

/// Pages held by the consensus journal's cache.
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10_000);

/// Bytes buffered when replaying or writing the consensus journal.
const JOURNAL_BUFFER: NonZeroUsize = NZUsize!(1024 * 1024);

/// Failures that stop a node from starting.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The custody store failed to open.
    #[error("custody: {0}")]
    Custody(#[from] custody::Error),
    /// The payload store failed to open.
    #[error("payload store: {0}")]
    Payload(#[from] payload::Error),
    /// The attestor could not be built.
    #[error("attestor: {0}")]
    Attestor(#[from] attestor::Error),
    /// The participant set admits no coding configuration.
    #[error("participant set of {0} cannot be coded")]
    Participants(usize),
    /// The signing key does not belong to the participant set.
    #[error("signing key is not a participant")]
    Stranger,
}

/// Every timer a node runs on.
///
/// Grouped rather than passed one by one because they are only ever chosen together: a deployment
/// is either running against a real network or against a simulated one, and mixing the two gives
/// timings that make no sense on either.
#[derive(Clone, Copy, Debug)]
pub struct Timing {
    /// How long a gateway waits for more blobs before sealing an undersized batch.
    pub batch: Duration,
    /// How long a gateway waits for a quorum of attestations.
    pub disperse: Duration,
    /// How long a leader is given to propose.
    pub leader: Duration,
    /// How long a view waits for certification progress.
    pub certification: Duration,
    /// How long a stuck view waits before rebroadcasting its nullify.
    pub retry: Duration,
    /// How long a request for a missing consensus artifact waits.
    pub fetch: Duration,
    /// How long an inactive leader is tolerated.
    pub skip: Duration,
    /// Views below the finalized tip consensus keeps.
    pub retention: ViewDelta,
    /// How long a retrieval may take before it is abandoned.
    pub retrieval: Duration,
    /// How long one shard request waits on one custodian.
    pub shard: Duration,
    /// How long a shard request waits in the resolver's queue before it is retried.
    pub shard_retry: Duration,
}

impl Timing {
    /// Timers for a deployment on a real network.
    pub const fn production(batch: Duration, disperse: Duration) -> Self {
        Self {
            batch,
            disperse,
            leader: LEADER_TIMEOUT,
            certification: CERTIFICATION_TIMEOUT,
            retry: TIMEOUT_RETRY,
            fetch: FETCH_TIMEOUT,
            skip: SKIP_TIMEOUT,
            retention: VIEW_RETENTION,
            retrieval: RETRIEVAL_TIMEOUT,
            shard: SHARD_FETCH_TIMEOUT,
            shard_retry: SHARD_FETCH_RETRY,
        }
    }

    /// Timers for a simulated deployment, where nothing waits on a real network.
    pub const fn simulated(batch: Duration, disperse: Duration) -> Self {
        Self {
            batch,
            disperse,
            leader: LEADER_TIMEOUT_SIM,
            certification: CERTIFICATION_TIMEOUT_SIM,
            retry: TIMEOUT_RETRY_SIM,
            fetch: FETCH_TIMEOUT_SIM,
            skip: SKIP_TIMEOUT_SIM,
            retention: VIEW_RETENTION,
            retrieval: RETRIEVAL_TIMEOUT_SIM,
            shard: SHARD_FETCH_TIMEOUT_SIM,
            shard_retry: SHARD_FETCH_RETRY_SIM,
        }
    }
}

/// Configuration for a validator.
pub struct NodeConfig<B, P, T> {
    /// This validator's identity, which names it on the network and signs its gateway claims.
    pub signer: ed25519::PrivateKey,
    /// This validator's BLS key, which signs both its attestations and its consensus votes.
    pub bls: Private,
    /// The participant set, ordered by ed25519 identity.
    pub participants: BiMap<ed25519::PublicKey, <MinSig as Variant>::Public>,
    /// Base namespace of the deployment.
    pub namespace: Vec<u8>,
    /// Prefix of every storage partition this node owns.
    pub partition: String,
    /// Blocks misbehaving peers.
    pub blocker: B,
    /// Reports peer-set changes to the gossip layer.
    pub peers: P,
    /// Messages buffered before a mailbox spills to its overflow queue.
    pub mailbox_size: NonZeroUsize,
    /// Encoded batch bytes at which a gateway seals.
    pub batch_target: usize,
    /// Dispersals of a blob allowed before it is abandoned.
    pub attempts: u8,
    /// Decode bounds for a shard.
    pub shard: CodecConfig,
    /// Every timer the node runs on.
    pub timing: Timing,
    /// Parallelism for coding and signature verification.
    pub strategy: T,
}

/// The p2p channels a validator speaks on.
pub struct Channels<S, R> {
    /// Consensus votes.
    pub votes: (S, R),
    /// Consensus certificates.
    pub certificates: (S, R),
    /// Consensus block resolution.
    pub resolver: (S, R),
    /// Dispersal requests to attestors.
    pub disperse_req: (S, R),
    /// Attestations back to gateways.
    pub disperse_res: (S, R),
    /// Availability certificates.
    pub cert_gossip: (S, R),
    /// Consensus payloads, which bare simplex does not disseminate itself.
    pub payload_gossip: (S, R),
    /// Shard requests and the shards that answer them.
    pub retrieval: (S, R),
    /// Client submissions, status polls, and batch queries.
    pub client_rpc: (S, R),
}

/// A running validator.
///
/// Holding one keeps the node alive: the actors run on their own tasks, and the handles here are
/// what the outside world reaches them through.
pub struct Node<E: Clock + Metrics + Spawner> {
    /// Intake for blobs this node gateways.
    pub batcher: batcher::Mailbox<E>,
    /// Where every blob this node accepted has got to.
    pub board: StatusBoard<E>,
    /// The consensus-facing application, and the certificate pool behind it.
    pub application: application::Mailbox,
    /// The attestor, which owns this node's custody.
    pub attestor: attestor::Mailbox,
    /// Certificates this node has seen finalized, and the read path's entry point.
    pub registry: Registry,
    /// The retrieval coordinator, which gathers a batch from its custodians.
    pub retrieval: retrieval::Mailbox,
    /// The last finalized view, shared by everything that has a floor.
    pub watermark: Watermark,
    /// A live handle on the dispersal engine.
    ///
    /// Kept for its lifetime rather than its interface: the engine polls its mailbox and spins on
    /// a closed one, so dropping the last handle would starve every other task on the runtime.
    _originator: collector::Mailbox<ed25519::PublicKey, DisperseRequest>,
}

/// Starts every actor a validator runs and returns the handles onto them.
pub async fn start<E, B, P, S, R, T>(
    context: E,
    config: NodeConfig<B, P, T>,
    channels: Channels<S, R>,
) -> Result<Node<E>, Error>
where
    E: BufferPooler + Clock + CryptoRng + Metrics + Spawner + Storage,
    B: Blocker<PublicKey = ed25519::PublicKey>,
    P: Provider<PublicKey = ed25519::PublicKey>,
    S: Sender<PublicKey = ed25519::PublicKey>,
    R: Receiver<PublicKey = ed25519::PublicKey>,
    T: Strategy,
{
    let me = config.signer.public_key();
    let participants = config.participants.keys().len();
    let coding = coding_config(participants).ok_or(Error::Participants(participants))?;

    // One key, two claims. The namespaces differ, so neither signature can be replayed as the
    // other, and the participant ordering is shared, so signer index `i` means the same validator
    // in a certificate and in a vote.
    let attesting = Scheme::signer(
        &config.namespace,
        config.participants.clone(),
        config.bls.clone(),
    )
    .ok_or(Error::Stranger)?;
    let voting = application::Scheme::signer(
        &consensus_namespace(&config.namespace),
        config.participants,
        config.bls,
    )
    .ok_or(Error::Stranger)?;

    let watermark = Watermark::default();
    let registry = Registry::new();
    let board = StatusBoard::new(
        context.child("status"),
        NZUsize!(MAX_TRACKED_BLOBS),
        STATUS_TTL,
    );

    // Custody and the attestor that owns it.
    let custody = Custody::init(
        context.child("custody"),
        &config.partition,
        config.shard.clone(),
    )
    .await?;
    let (attestor, attestor_mailbox) = Attestor::new(
        context.child("attestor"),
        attestor::Config {
            scheme: attesting.clone(),
            namespace: config.namespace.clone(),
            watermark: watermark.clone(),
            slack: ATTEST_SLACK,
            mailbox_size: config.mailbox_size,
        },
        custody,
    )?;
    attestor.start();

    // Dispersal: the engine needs the disperser's monitor before it yields the originator the
    // disperser sends through, so the mailbox is built ahead of both.
    let (monitor, inbox) = disperser::mailbox(&context.child("disperser"), config.mailbox_size);
    let (dispersal, originator) = collector::Engine::new(
        context.child("collector"),
        collector::Config {
            blocker: config.blocker.clone(),
            monitor,
            handler: attestor_mailbox.clone(),
            mailbox_size: config.mailbox_size,
            priority_request: false,
            request_codec: config.shard.clone(),
            priority_response: false,
            response_codec: (),
        },
    );
    dispersal.start(channels.disperse_req, channels.disperse_res);

    // Payload dissemination, and the store that makes a payload answerable for after a restart.
    let (payload_gossip, payloads) = buffered::Engine::new(
        context.child("payload_gossip"),
        buffered::Config {
            public_key: me.clone(),
            mailbox_size: config.mailbox_size,
            deque_size: PAYLOAD_DEQUE,
            priority: false,
            codec_config: participants,
            peer_provider: config.peers.clone(),
        },
    );
    payload_gossip.start(channels.payload_gossip);
    let store = PayloadStore::init(
        context.child("payload_store"),
        &config.partition,
        participants,
    )
    .await?;
    let genesis = store.genesis();

    let (application, mailbox, reporter) = Application::new(
        context.child("application"),
        application::Config {
            scheme: attesting.clone(),
            namespace: config.namespace.clone(),
            store,
            payloads,
            board: board.clone(),
            registry: registry.clone(),
            watermark: watermark.clone(),
            attestor: attestor_mailbox.clone(),
            mailbox_size: config.mailbox_size,
            strategy: config.strategy.clone(),
        },
    );
    application.start(channels.cert_gossip);

    // The read path. Its engine needs the consumer that feeds the coordinator before it yields
    // the handle the coordinator fetches through, so the mailbox is built ahead of both, exactly
    // as the dispersal engine's is.
    let (retrieval_mailbox, consumer, shard_inbox) =
        retrieval::mailbox(&context.child("retrieval"), config.mailbox_size);
    let (shards, resolver_mailbox) = resolver::Engine::new(
        context.child("shards"),
        resolver::Config {
            peer_provider: config.peers,
            blocker: config.blocker.clone(),
            consumer,
            producer: retrieval::Producer::new(context.child("producer"), attestor_mailbox.clone()),
            mailbox_size: config.mailbox_size,
            me: Some(me.clone()),
            initial: SHARD_FETCH_INITIAL,
            timeout: config.timing.shard,
            fetch_retry_timeout: config.timing.shard_retry,
            priority_requests: false,
            priority_responses: false,
        },
    );
    shards.start(channels.retrieval);
    Coordinator::new(
        context.child("retrieval"),
        retrieval::Config {
            scheme: attesting.clone(),
            namespace: config.namespace.clone(),
            registry: registry.clone(),
            attestor: attestor_mailbox.clone(),
            shard: config.shard,
            timeout: config.timing.retrieval,
            mailbox_size: config.mailbox_size,
            strategy: config.strategy.clone(),
        },
        shard_inbox,
        resolver_mailbox,
    )
    .start();

    // The gateway: intake feeds dispersal over a bounded queue, and dispersal hands what it
    // certifies to the application, which pools it and puts it on the wire.
    let (sealed, batches) = mpsc::channel(SEALED_QUEUE);
    let (batcher, submit) = Batcher::new(
        context.child("batcher"),
        batcher::Config {
            target: config.batch_target,
            timeout: config.timing.batch,
            coding,
            watermark: watermark.clone(),
            board: board.clone(),
            mailbox_size: config.mailbox_size,
        },
        sealed,
    );
    batcher.start();
    Disperser::new(
        context.child("disperser"),
        disperser::Config {
            scheme: attesting,
            signer: config.signer,
            namespace: config.namespace,
            originator: originator.clone(),
            local: attestor_mailbox.clone(),
            gossip: mailbox.clone(),
            board: board.clone(),
            batcher: submit.clone(),
            timeout: config.timing.disperse,
            attempts: config.attempts,
            strategy: config.strategy.clone(),
            #[cfg(test)]
            fault: None,
        },
        inbox,
        batches,
    )
    .start();

    // What clients talk to. Nothing behind it is trusted by them: an acknowledgement names a
    // blob they can rehash, and a batch comes with the certificate they check it against.
    rpc::Server::new(
        context.child("rpc"),
        rpc::Config {
            batcher: submit.clone(),
            board: board.clone(),
            registry: registry.clone(),
            retrieval: retrieval_mailbox.clone(),
        },
    )
    .start(channels.client_rpc);

    // Consensus. The floor is the genesis payload's digest: every ancestry walk ends there, so
    // every chain starts there.
    let engine = simplex::Engine::new(
        context.child("consensus"),
        simplex::Config {
            scheme: voting,
            elector: simplex::elector::RoundRobin::<Sha256>::default(),
            blocker: config.blocker,
            automaton: mailbox.clone(),
            relay: mailbox.clone(),
            reporter,
            strategy: config.strategy,
            partition: format!("{}-consensus", config.partition),
            mailbox_size: config.mailbox_size,
            epoch: Epoch::zero(),
            floor: simplex::Floor::Genesis(genesis),
            replay_buffer: JOURNAL_BUFFER,
            write_buffer: JOURNAL_BUFFER,
            page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            leader_timeout: config.timing.leader,
            certification_timeout: config.timing.certification,
            timeout_retry: config.timing.retry,
            fetch_timeout: config.timing.fetch,
            view_retention: config.timing.retention,
            skip_timeout: config.timing.skip,
            forwarding: simplex::ForwardingPolicy::Disabled,
            track_historical_votes: false,
        },
    );
    engine.start(channels.votes, channels.certificates, channels.resolver);

    Ok(Node {
        batcher: submit,
        board,
        application: mailbox,
        attestor: attestor_mailbox,
        registry,
        retrieval: retrieval_mailbox,
        watermark,
        _originator: originator,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        constants::{
            BATCH_TARGET_SIM, BATCH_TIMEOUT_SIM, CERT_GOSSIP_CHANNEL, CERTIFICATE_CHANNEL,
            CLIENT_RPC_CHANNEL, DISPERSE_REQ_CHANNEL, DISPERSE_RES_CHANNEL, DISPERSE_TIMEOUT_SIM,
            MAX_DISPERSAL_ATTEMPTS, NAMESPACE, PAYLOAD_GOSSIP_CHANNEL, RESOLVER_CHANNEL,
            RETRIEVAL_CHANNEL, VOTE_CHANNEL,
        },
        poseidon2::Fr,
        test_util::{self, Keys},
        types::DaCert,
    };
    use commonware_broadcast::Broadcaster as _;
    use commonware_consensus::types::View;
    use commonware_cryptography::{certificate::mocks::Fixture, transcript::Summary};
    use commonware_p2p::{
        Recipients,
        simulated::{Oracle, Receiver as SimulatedReceiver, Sender as SimulatedSender},
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner, Supervisor as _, deterministic};
    use commonware_utils::{Faults as _, N3f1, NZUsize};

    /// Validators in the consensus deployment: `n = 5`, `f = 1`, quorum 4, minimum shards 2.
    ///
    /// Smaller than the data-availability tests use, because everything here runs a real consensus
    /// engine and the property under test is about ordering rather than about coding.
    const VALIDATORS: usize = 5;

    /// The validator a certificate is offered to first.
    const INJECTED: usize = 3;

    /// The validator it is offered to again, after it has already been included.
    const REPEATED: usize = 1;

    /// Views a certificate is given to reach a finalized block.
    ///
    /// Leadership rotates, so the validator holding it leads within [`VALIDATORS`] views; the rest
    /// is slack for the views it takes to finalize.
    const INCLUSION_BUDGET: u64 = 20;

    /// Views the repeat offer is watched over.
    const REPEAT_BUDGET: u64 = 10;

    /// How far ahead the postdated certificate claims to have been dispersed.
    ///
    /// Beyond anything this test finalizes, so it stays pooled for the whole run.
    const POSTDATED: u64 = 1_000;

    fn runner() -> deterministic::Runner {
        deterministic::Runner::timed(Duration::from_secs(300))
    }

    /// Registers every channel one validator speaks on.
    async fn channels(
        oracle: &Oracle<ed25519::PublicKey, deterministic::Context>,
        peer: &ed25519::PublicKey,
    ) -> Channels<
        SimulatedSender<ed25519::PublicKey, deterministic::Context>,
        SimulatedReceiver<ed25519::PublicKey>,
    > {
        Channels {
            votes: test_util::register(oracle, peer, VOTE_CHANNEL).await,
            certificates: test_util::register(oracle, peer, CERTIFICATE_CHANNEL).await,
            resolver: test_util::register(oracle, peer, RESOLVER_CHANNEL).await,
            disperse_req: test_util::register(oracle, peer, DISPERSE_REQ_CHANNEL).await,
            disperse_res: test_util::register(oracle, peer, DISPERSE_RES_CHANNEL).await,
            cert_gossip: test_util::register(oracle, peer, CERT_GOSSIP_CHANNEL).await,
            payload_gossip: test_util::register(oracle, peer, PAYLOAD_GOSSIP_CHANNEL).await,
            retrieval: test_util::register(oracle, peer, RETRIEVAL_CHANNEL).await,
            client_rpc: test_util::register(oracle, peer, CLIENT_RPC_CHANNEL).await,
        }
    }

    /// Starts [`VALIDATORS`] full nodes over one simulated network.
    async fn deploy(context: &deterministic::Context) -> (Vec<Node<deterministic::Context>>, Keys) {
        let keys = test_util::keys(VALIDATORS);
        let peers: Vec<_> = keys
            .privates
            .iter()
            .map(|private| private.public_key())
            .collect();
        let oracle = test_util::network(context, &peers).await;

        let mut nodes = Vec::new();
        for (index, peer) in peers.iter().enumerate() {
            let context = context.child("validator").with_attribute("index", index);
            let channels = channels(&oracle, peer).await;
            let node = start(
                context,
                NodeConfig {
                    signer: keys.privates[index].clone(),
                    bls: keys.bls[index].clone(),
                    participants: keys.participants.clone(),
                    namespace: NAMESPACE.to_vec(),
                    partition: format!("p4-node-{index}"),
                    blocker: oracle.control(peer.clone()),
                    peers: oracle.manager(),
                    mailbox_size: NZUsize!(256),
                    batch_target: BATCH_TARGET_SIM,
                    attempts: MAX_DISPERSAL_ATTEMPTS,
                    shard: test_util::shard_cfg(),
                    timing: Timing::simulated(BATCH_TIMEOUT_SIM, DISPERSE_TIMEOUT_SIM),
                    strategy: Sequential,
                },
                channels,
            )
            .await
            .expect("node starts");
            nodes.push(node);
        }
        (nodes, keys)
    }

    /// Waits until every node has finalized at least `target`, which is also the liveness check:
    /// views only advance if empty payloads keep finalizing.
    async fn advance(
        context: &deterministic::Context,
        nodes: &[Node<deterministic::Context>],
        target: View,
    ) {
        let deadline = context.current() + Duration::from_secs(120);
        while nodes.iter().any(|node| node.watermark.get() < target) {
            assert!(
                context.current() < deadline,
                "consensus stalled below view {}",
                target.get()
            );
            context.sleep(Duration::from_millis(50)).await;
        }
    }

    /// Builds a certificate a quorum of these validators really attested to.
    fn certify(
        attesting: &Fixture<crate::types::Scheme>,
        keys: &Keys,
        dispersed: View,
        filler: u8,
        quorum: usize,
    ) -> DaCert {
        let (header, _) = test_util::dispersal_among(VALIDATORS, dispersed.get(), filler);
        test_util::genuine_cert(
            attesting,
            &header,
            &keys.privates[0],
            Fr::from(u64::from(filler)),
            quorum,
        )
    }

    /// Returns how many payloads of each node's finalized chain carry `commitment`.
    async fn inclusions(
        nodes: &[Node<deterministic::Context>],
        commitment: &Summary,
    ) -> Vec<usize> {
        let mut counts = Vec::new();
        for node in nodes {
            let snapshot = node
                .application
                .inspect()
                .await
                .expect("application answers");
            counts.push(snapshot.inclusions(commitment));
        }
        counts
    }

    #[test]
    fn p4_e2e_cert_to_finalized_block() {
        runner().start(|context| async move {
            let (nodes, keys) = deploy(&context).await;

            // Empty blocks finalize on their own: the consensus rail does not wait on the
            // data-availability rail.
            advance(&context, &nodes, View::new(2)).await;

            // A certificate these very validators attested to, over a batch that was really
            // encoded, dispersed at a view that has already finalized.
            let attesting = test_util::attesting(&keys);
            let quorum = N3f1::quorum(VALIDATORS as u32) as usize;
            let dispersed = nodes[0].watermark.get();
            let cert: DaCert = certify(&attesting, &keys, dispersed, 0xb1, quorum);
            let commitment = cert.header.commitment;

            // Nobody has it, so nobody's chain carries it. One node hears about it, and nobody
            // else does: only the validator holding it can propose it.
            assert_eq!(
                inclusions(&nodes, &commitment).await,
                vec![0; VALIDATORS],
                "a certificate nobody holds was already on a chain"
            );
            assert!(
                nodes[INJECTED].application.certificate(cert.clone()),
                "pool accepted the certificate"
            );

            // It rides into a block, and every node agrees it rode exactly once.
            let deadline = View::new(dispersed.get() + INCLUSION_BUDGET);
            loop {
                let counts = inclusions(&nodes, &commitment).await;
                if counts.iter().all(|count| *count == 1) {
                    break;
                }
                assert!(counts.iter().all(|count| *count <= 1), "included twice");
                assert!(
                    nodes.iter().all(|node| node.watermark.get() < deadline),
                    "certificate was not included within {INCLUSION_BUDGET} views"
                );
                context.sleep(Duration::from_millis(50)).await;
            }
            let included_at = nodes[0].watermark.get();

            // Offering it again, to a validator that has already finalized it, changes nothing:
            // the pool rejects what is on the finalized chain, and a proposer would exclude it
            // even if the pool had not.
            assert!(
                nodes[REPEATED].application.certificate(cert),
                "the offer was accepted for processing, and rejected on its merits"
            );
            advance(
                &context,
                &nodes,
                View::new(included_at.get() + REPEAT_BUDGET),
            )
            .await;

            // The other path into a pool: a gateway assembles a certificate and gossips it, which
            // runs from this node's own pool onto the wire and into everybody else's. This one is
            // dispersed at a view the test never reaches, so it stays pooled everywhere instead
            // of racing consensus into a block: what is under test is the gossip, and, in
            // passing, that no proposer carries a certificate from the future.
            let ahead = View::new(nodes[0].watermark.get().get() + POSTDATED);
            let gossiped = certify(&attesting, &keys, ahead, 0xb2, quorum);
            let broadcast = gossiped.header.commitment;
            assert!(
                nodes[0]
                    .application
                    .broadcast(Recipients::All, gossiped)
                    .accepted()
            );
            let deadline = View::new(nodes[0].watermark.get().get() + INCLUSION_BUDGET);
            loop {
                let mut holders = 0;
                for node in &nodes {
                    let snapshot = node
                        .application
                        .inspect()
                        .await
                        .expect("application answers");
                    if snapshot.pool.contains(&broadcast) {
                        holders += 1;
                    }
                }
                if holders == VALIDATORS {
                    break;
                }
                assert!(
                    nodes.iter().all(|node| node.watermark.get() < deadline),
                    "gossiped certificate reached only {holders} of {VALIDATORS} pools"
                );
                context.sleep(Duration::from_millis(50)).await;
            }

            for (index, node) in nodes.iter().enumerate() {
                let snapshot = node
                    .application
                    .inspect()
                    .await
                    .expect("application answers");
                assert_eq!(
                    snapshot.inclusions(&commitment),
                    1,
                    "validator {index} did not finalize the certificate exactly once"
                );

                // The window the assertion covers really does still reach the block that carried
                // it, so "exactly once" is a statement about the chain rather than about pruning.
                assert!(
                    snapshot.horizon() <= dispersed,
                    "validator {index} pruned past the inclusion"
                );

                // And the views around it kept finalizing with nothing to carry.
                let empty = snapshot
                    .chain
                    .iter()
                    .filter(|(_, carried)| carried.is_empty())
                    .count();
                assert!(
                    empty >= REPEAT_BUDGET as usize,
                    "validator {index} finalized only {empty} empty payloads"
                );

                // The finalized certificate is spent rather than pooled, and the postdated one
                // is pooled rather than carried.
                assert_eq!(
                    snapshot.pool,
                    vec![broadcast],
                    "validator {index} pools the wrong certificates"
                );
                assert_eq!(
                    snapshot.inclusions(&broadcast),
                    0,
                    "validator {index} finalized a certificate from the future"
                );
                assert_eq!(node.watermark.get(), snapshot.finalized);
            }
        });
    }
}
