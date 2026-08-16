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
        ATTEST_SLACK, CERTIFICATION_TIMEOUT, FETCH_TIMEOUT, LEADER_TIMEOUT, MAX_TRACKED_BLOBS,
        PAYLOAD_DEQUE, RETRIEVAL_TIMEOUT, SHARD_FETCH_INITIAL, SHARD_FETCH_RETRY,
        SHARD_FETCH_TIMEOUT, SKIP_TIMEOUT, STATUS_TTL, TIMEOUT_RETRY, VIEW_RETENTION,
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
use commonware_runtime::{
    BufferPooler, Clock, Handle, Metrics, Spawner, Storage, buffer::paged::CacheRef,
};
use commonware_utils::{NZU16, NZUsize, channel::mpsc, ordered::BiMap};
use rand_core::CryptoRng;
use std::{future::Future, num::NonZeroUsize, time::Duration};

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
    #[cfg(test)]
    pub const fn simulated(batch: Duration, disperse: Duration) -> Self {
        use crate::constants::{
            CERTIFICATION_TIMEOUT_SIM, FETCH_TIMEOUT_SIM, LEADER_TIMEOUT_SIM,
            RETRIEVAL_TIMEOUT_SIM, SHARD_FETCH_RETRY_SIM, SHARD_FETCH_TIMEOUT_SIM,
            SKIP_TIMEOUT_SIM, TIMEOUT_RETRY_SIM,
        };

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

/// The tasks a node runs, as a group that lives and dies together.
///
/// A validator is only a validator with all of its actors: one that lost its attestor still votes
/// and still answers clients, and quietly stops custodying anything. So the group has one
/// lifetime, and the first task to stop ends it.
///
/// The group is what a caller waits on, not what it stops with. Aborting these handles would
/// leave the tasks an actor spawns from a context of its own -- a producer serving one shard
/// request, a batch being encoded -- running under a node that is otherwise gone. What stops a
/// node is dropping the task it was started beneath, which takes its whole subtree with it; that
/// is how the restart test stops one, and how a process exit stops one.
#[derive(Default)]
pub struct Handles(Vec<Handle<()>>);

impl Handles {
    /// Adds a task to the group.
    ///
    /// Public because the group is not only what a node started: the network it speaks over is
    /// started by whoever configured it, and a node without that is as much use as a node without
    /// an attestor.
    pub fn push(&mut self, handle: Handle<()>) {
        self.0.push(handle);
    }

    /// Waits until the first task stops, then aborts the rest.
    ///
    /// Returns what that task returned, which for a node that is running correctly is never:
    /// every actor here loops until its context is torn down.
    pub fn wait(self) -> impl Future<Output = Result<(), commonware_runtime::Error>> + Send {
        Handle::select(self.0)
    }
}

/// A running validator.
///
/// Holding one keeps the node alive: the actors run on their own tasks, and the handles here are
/// what the outside world reaches them through.
#[allow(
    dead_code,
    reason = "handles onto a running node, reached through by tests that drive one directly; the binary only runs it"
)]
pub struct Node {
    /// The tasks this node runs.
    ///
    /// Public so a caller can add its own before handing the group to [`Node::run`].
    pub handles: Handles,
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

impl Node {
    /// Runs until one of the node's tasks stops, and aborts the rest.
    ///
    /// Consumes the node rather than borrowing it, because the mailboxes it holds are what keep
    /// the actors behind them alive: the dispersal engine spins on a mailbox whose last handle has
    /// been dropped, and would starve everything else on the runtime.
    pub async fn run(mut self) -> Result<(), commonware_runtime::Error> {
        let handles = std::mem::take(&mut self.handles);
        let outcome = handles.wait().await;
        drop(self);
        outcome
    }
}

/// Starts every actor a validator runs and returns the handles onto them.
pub async fn start<E, B, P, S, R, T>(
    context: E,
    config: NodeConfig<B, P, T>,
    channels: Channels<S, R>,
) -> Result<Node, Error>
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
    let mut handles = Handles::default();
    handles.push(attestor.start());

    // Dispersal: the engine needs the disperser's monitor before it yields the originator the
    // disperser sends through, so the mailbox is built ahead of both.
    let disperser_context = context.child("disperser");
    let (monitor, inbox) = disperser::mailbox(&disperser_context, config.mailbox_size);
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
    handles.push(dispersal.start(channels.disperse_req, channels.disperse_res));

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
    handles.push(payload_gossip.start(channels.payload_gossip));
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
    handles.push(application.start(channels.cert_gossip));

    // The read path. Its engine needs the consumer that feeds the coordinator before it yields
    // the handle the coordinator fetches through, so the mailbox is built ahead of both, exactly
    // as the dispersal engine's is.
    let retrieval_context = context.child("retrieval");
    let (retrieval_mailbox, consumer, shard_inbox) =
        retrieval::mailbox(&retrieval_context, config.mailbox_size);
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
    handles.push(shards.start(channels.retrieval));
    let coordinator = Coordinator::new(
        context.child("retrieval"),
        retrieval::Config {
            scheme: attesting.clone(),
            namespace: config.namespace.clone(),
            registry: registry.clone(),
            attestor: attestor_mailbox.clone(),
            shard: config.shard,
            timeout: config.timing.retrieval,
            strategy: config.strategy.clone(),
        },
        shard_inbox,
        resolver_mailbox,
    );
    handles.push(coordinator.start());

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
    handles.push(batcher.start());
    let disperser = Disperser::new(
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
    );
    handles.push(disperser.start());

    // What clients talk to. Nothing behind it is trusted by them: an acknowledgement names a
    // blob they can rehash, and a batch comes with the certificate they check it against.
    let server = rpc::Server::new(
        context.child("rpc"),
        rpc::Config {
            batcher: submit,
            board: board.clone(),
            registry: registry.clone(),
            retrieval: retrieval_mailbox.clone(),
        },
    );
    handles.push(server.start(channels.client_rpc));

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
    handles.push(engine.start(channels.votes, channels.certificates, channels.resolver));

    Ok(Node {
        handles,
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
        application::Context,
        constants::{
            BATCH_TARGET_SIM, BATCH_TIMEOUT_SIM, CERT_GOSSIP_CHANNEL, CERTIFICATE_CHANNEL,
            CLIENT_RPC_CHANNEL, DISPERSE_REQ_CHANNEL, DISPERSE_RES_CHANNEL, DISPERSE_TIMEOUT_SIM,
            MAX_DISPERSAL_ATTEMPTS, NAMESPACE, PAYLOAD_GOSSIP_CHANNEL, RESOLVER_CHANNEL,
            RETRIEVAL_CHANNEL, VOTE_CHANNEL,
        },
        custody::CustodyRecord,
        poseidon2::Fr,
        test_util::{self, Keys},
        types::{BatchHeader, DaCert},
        wire::{Payload, StrongShard},
    };
    use commonware_broadcast::{Broadcaster as _, buffered};
    use commonware_consensus::{
        Automaton as _,
        types::{Round, View},
    };
    use commonware_cryptography::{
        Digestible as _, certificate::mocks::Fixture, sha256, transcript::Summary,
    };
    use commonware_p2p::{
        Recipients,
        simulated::{Oracle, Receiver as SimulatedReceiver, Sender as SimulatedSender},
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{Handle, Runner, Supervisor as _, deterministic};
    use commonware_utils::{Faults as _, N3f1, NZUsize, channel::oneshot};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

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
    async fn deploy(context: &deterministic::Context) -> (Vec<Node>, Keys) {
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
                    partition: format!("consensus-node-{index}"),
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
    async fn advance(context: &deterministic::Context, nodes: &[Node], target: View) {
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
    async fn inclusions(nodes: &[&Node], commitment: &Summary) -> Vec<usize> {
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

    /// Storage partitions of the restart deployment.
    ///
    /// A restarted node opens the same partitions under a different metric label, which is the
    /// whole of what "same node, new process" means here.
    fn partition(index: usize) -> String {
        format!("node-{index}")
    }

    /// The validator that is stopped and restarted.
    const RESTARTED: usize = 2;

    /// A validator that stays up throughout, and is asked what the chain looks like.
    const WITNESS: usize = 0;

    /// View both batches claim to have been dispersed at.
    ///
    /// Early, because custody has to be seeded before any node opens its store, and inclusion has
    /// to happen inside the freshness window of it.
    const DISPERSED: u64 = 1;

    /// Views the chain is left to advance while the node is away the second time.
    ///
    /// Long enough that it misses payloads it can never be given: bare simplex backfills none.
    const OUTAGE: u64 = 12;

    /// A view far above anything this test finalizes.
    ///
    /// A verification about a settled view is concluded rather than left open, so a request that
    /// is meant to stay pending has to be about a view consensus has not reached.
    const UNREACHED: u64 = 10_000;

    /// A running validator, and the one handle that stops all of it.
    struct Running {
        node: Node,
        /// The task every actor of this node was spawned beneath. Aborting it aborts the subtree,
        /// which is every task the node owns.
        handle: Handle<()>,
    }

    impl Running {
        /// Stops the node the way a crash does: every task at once, with nothing given a chance
        /// to flush. What the restart finds is what was already durable.
        fn stop(self) {
            self.handle.abort();
            drop(self.node);
        }
    }

    /// Starts one validator beneath a task of its own, under the metric label `role`.
    ///
    /// The label is what distinguishes a restarted instance from the one it replaces; the storage
    /// partition, which is what actually carries state across the restart, is the same either way.
    async fn spawn_node(
        context: &deterministic::Context,
        role: &'static str,
        index: usize,
        keys: &Keys,
        oracle: &Oracle<ed25519::PublicKey, deterministic::Context>,
    ) -> Running {
        let peer = keys.privates[index].public_key();
        let channels = channels(oracle, &peer).await;
        let config = NodeConfig {
            signer: keys.privates[index].clone(),
            bls: keys.bls[index].clone(),
            participants: keys.participants.clone(),
            namespace: NAMESPACE.to_vec(),
            partition: partition(index),
            blocker: oracle.control(peer.clone()),
            peers: oracle.manager(),
            mailbox_size: NZUsize!(256),
            batch_target: BATCH_TARGET_SIM,
            attempts: MAX_DISPERSAL_ATTEMPTS,
            shard: test_util::shard_cfg(),
            timing: Timing::simulated(BATCH_TIMEOUT_SIM, DISPERSE_TIMEOUT_SIM),
            strategy: Sequential,
        };
        let (ready, started) = oneshot::channel();
        let handle =
            context
                .child(role)
                .with_attribute("index", index)
                .spawn(move |context| async move {
                    let node = start(context.child("node"), config, channels)
                        .await
                        .expect("node starts");
                    let _ = ready.send(node);

                    // Never returns. Every actor was spawned from a context descended from this task,
                    // so this task's lifetime is the node's lifetime.
                    std::future::pending::<()>().await
                });
        Running {
            node: started.await.expect("node starts"),
            handle,
        }
    }

    /// Waits until every running node has finalized at least `target`.
    async fn reach(context: &deterministic::Context, nodes: &[&Running], target: View) {
        let deadline = context.current() + Duration::from_secs(120);
        while nodes.iter().any(|node| node.node.watermark.get() < target) {
            assert!(
                context.current() < deadline,
                "consensus stalled below view {}",
                target.get()
            );
            context.sleep(Duration::from_millis(50)).await;
        }
    }

    /// Asks the node to verify `payload` at `view` over `parent`, without waiting for a verdict.
    async fn ask(
        node: &Running,
        keys: &Keys,
        view: u64,
        parent: sha256::Digest,
        payload: &Payload,
    ) -> oneshot::Receiver<bool> {
        let mut mailbox = node.node.application.clone();
        mailbox
            .verify(
                Context {
                    round: Round::new(Epoch::zero(), View::new(view)),
                    leader: keys.privates[0].public_key(),
                    parent: (View::new(view.saturating_sub(1)), parent),
                },
                payload.digest(),
            )
            .await
    }

    #[test]
    fn restart_rebuilds_dedup_and_custody() {
        runner().start(|context| async move {
            let keys = test_util::keys(VALIDATORS);
            let attesting = test_util::attesting(&keys);

            // An extra peer that is no validator. It runs nothing but payload gossip, which is
            // how a test puts a specific payload in front of a specific node.
            let observer = ed25519::PrivateKey::from_seed(999).public_key();
            let mut peers: Vec<ed25519::PublicKey> = keys
                .privates
                .iter()
                .map(|private| private.public_key())
                .collect();
            peers.push(observer.clone());
            let oracle = test_util::network(&context, &peers).await;
            let (gossip, gossiped) = buffered::Engine::new(
                context.child("observer"),
                buffered::Config {
                    public_key: observer.clone(),
                    mailbox_size: NZUsize!(256),
                    deque_size: PAYLOAD_DEQUE,
                    priority: false,
                    codec_config: VALIDATORS,
                    peer_provider: oracle.manager(),
                },
            );
            gossip.start(test_util::register(&oracle, &observer, PAYLOAD_GOSSIP_CHANNEL).await);

            // Two batches this deployment really encoded, and the shard the restarted validator
            // would have custodied for each. Written before it opens the store, which is exactly
            // the state a dispersal leaves behind.
            let batches: Vec<(BatchHeader, Vec<StrongShard>)> = [0xc1u8, 0xc2]
                .into_iter()
                .map(|filler| test_util::dispersal_among(VALIDATORS, DISPERSED, filler))
                .collect();
            {
                let mut custody = Custody::init(
                    context.child("seed"),
                    &partition(RESTARTED),
                    test_util::shard_cfg(),
                )
                .await
                .expect("custody opens");
                for (header, shards) in &batches {
                    custody
                        .put(
                            header.dispersal_view,
                            header.commitment,
                            CustodyRecord {
                                index: RESTARTED as u16,
                                shard: shards[RESTARTED].clone(),
                            },
                        )
                        .await
                        .expect("shard stores");
                }
            }

            let mut nodes = Vec::new();
            for index in 0..VALIDATORS {
                nodes.push(spawn_node(&context, "validator", index, &keys, &oracle).await);
            }
            reach(&context, &nodes.iter().collect::<Vec<_>>(), View::new(2)).await;

            // Two certificates a quorum of these validators really attested to, offered to one
            // node's pool and left to ride into blocks.
            let quorum = N3f1::quorum(VALIDATORS as u32) as usize;
            let certs: Vec<DaCert> = batches
                .iter()
                .map(|(header, _)| {
                    test_util::genuine_cert(
                        &attesting,
                        header,
                        &keys.privates[0],
                        Fr::from(9u64),
                        quorum,
                    )
                })
                .collect();
            for cert in &certs {
                assert!(nodes[INJECTED].node.application.certificate(cert.clone()));
            }
            let deadline = View::new(DISPERSED + INCLUSION_BUDGET);
            loop {
                let mut carried = 0;
                for cert in &certs {
                    let counts = inclusions(
                        &nodes.iter().map(|node| &node.node).collect::<Vec<_>>(),
                        &cert.header.commitment,
                    )
                    .await;
                    assert!(counts.iter().all(|count| *count <= 1), "included twice");
                    carried += usize::from(counts.iter().all(|count| *count == 1));
                }
                if carried == certs.len() {
                    break;
                }
                assert!(
                    nodes
                        .iter()
                        .all(|node| node.node.watermark.get() < deadline),
                    "certificates were not included within {INCLUSION_BUDGET} views"
                );
                context.sleep(Duration::from_millis(50)).await;
            }

            // What the restarted node knew before it stopped: the chain it had finalized, and the
            // certificates on it.
            let before = nodes[RESTARTED]
                .node
                .application
                .inspect()
                .await
                .expect("application answers");
            for cert in &certs {
                assert_eq!(before.inclusions(&cert.header.commitment), 1);
            }

            // Stop it, and start it again from the same partitions.
            let stopped = nodes.remove(RESTARTED);
            let held = stopped.node.attestor.clone();
            stopped.stop();
            assert!(
                held.fetch(batches[0].0.commitment).await.is_none(),
                "a stopped attestor still answered"
            );
            let restarted = spawn_node(&context, "restarted", RESTARTED, &keys, &oracle).await;
            nodes.insert(RESTARTED, restarted);

            // Custody survived: the shards this validator attested to are still serveable, under
            // the index it signed for.
            for (header, shards) in &batches {
                let record = nodes[RESTARTED]
                    .node
                    .attestor
                    .fetch(header.commitment)
                    .await
                    .expect("custody replayed the shard");
                assert_eq!(record.index, RESTARTED as u16);
                assert_eq!(record.shard, shards[RESTARTED]);
            }

            // So did the payload archive, which is where ancestry comes from.
            assert!(
                nodes[RESTARTED]
                    .node
                    .application
                    .held(before.tip)
                    .await
                    .is_some(),
                "the payload archive did not replay"
            );

            // And so did dedup, which is the point of the archive: a certificate already on this
            // fork is refused at the position it would ride again, and an empty payload at the
            // same position is not, so the refusal is the duplicate rather than the restart.
            let view = before.finalized.get() + 1;
            let dup = Payload {
                parent: before.tip,
                view: View::new(view),
                certs: vec![certs[0].clone()],
            };
            let clean = Payload {
                parent: before.tip,
                view: View::new(view),
                certs: Vec::new(),
            };
            for payload in [&dup, &clean] {
                assert!(
                    gossiped
                        .broadcast(Recipients::All, (*payload).clone())
                        .accepted()
                );
            }
            assert!(
                !ask(&nodes[RESTARTED], &keys, view, before.tip, &dup)
                    .await
                    .await
                    .expect("verification concludes"),
                "a certificate already on this fork was accepted after the restart"
            );
            assert!(
                ask(&nodes[RESTARTED], &keys, view, before.tip, &clean)
                    .await
                    .await
                    .expect("verification concludes"),
                "a fresh payload was rejected after the restart"
            );

            // It is also still part of consensus: every node, this one included, keeps finalizing.
            let resumed = View::new(nodes[WITNESS].node.watermark.get().get() + 5);
            reach(&context, &nodes.iter().collect::<Vec<_>>(), resumed).await;

            // The rejoin limitation. Stop it again, let the chain run away from it, and start it
            // back up: the payloads it missed are gone for good, because bare simplex backfills
            // none of them.
            let stopped = nodes.remove(RESTARTED);
            stopped.stop();
            let others: Vec<&Running> = nodes.iter().collect();
            let away = View::new(nodes[WITNESS].node.watermark.get().get() + OUTAGE);
            reach(&context, &others, away).await;
            let missed = nodes[WITNESS]
                .node
                .application
                .inspect()
                .await
                .expect("application answers");
            let restarted = spawn_node(&context, "rejoined", RESTARTED, &keys, &oracle).await;
            nodes.insert(RESTARTED, restarted);

            // A payload finalized while it was away is one it never saw and can never be given.
            assert!(
                nodes[RESTARTED]
                    .node
                    .application
                    .held(missed.tip)
                    .await
                    .is_none(),
                "a payload from the outage was somehow held"
            );

            // Asked to verify a fork built on that payload, it stays pending: it has the bytes in
            // front of it and no way to place them. Not false, which would be a verdict it cannot
            // justify, and not a crash.
            let orphan = Payload {
                parent: missed.tip,
                view: View::new(UNREACHED),
                certs: Vec::new(),
            };
            let genesis = Payload::genesis().digest();
            let placeable = Payload {
                parent: genesis,
                view: View::new(UNREACHED),
                certs: Vec::new(),
            };
            for payload in [&orphan, &placeable] {
                assert!(
                    gossiped
                        .broadcast(Recipients::All, (*payload).clone())
                        .accepted()
                );
            }
            let mut pending = ask(&nodes[RESTARTED], &keys, UNREACHED, missed.tip, &orphan).await;
            context.sleep(Duration::from_secs(5)).await;
            assert!(
                matches!(pending.try_recv(), Err(oneshot::error::TryRecvError::Empty)),
                "verification of a fork with a missing parent concluded"
            );

            // The same node, the same moment, a parent it does hold: the wait is the missing
            // ancestor and nothing else about the restart.
            assert!(
                ask(&nodes[RESTARTED], &keys, UNREACHED, genesis, &placeable)
                    .await
                    .await
                    .expect("verification concludes"),
                "a payload over a parent this node holds was not verified"
            );
            assert!(
                matches!(pending.try_recv(), Err(oneshot::error::TryRecvError::Empty)),
                "the orphan concluded after all"
            );

            // And it is not wedged as a peer: it still hears the chain move, which is what makes
            // this a limitation of what it can verify rather than a node that has stopped.
            let heard = nodes[RESTARTED].node.watermark.get();
            assert!(heard >= away, "the rejoined node heard nothing");
        });
    }

    /// The validator that starts once the chain is already running.
    ///
    /// It opens an empty store, so nothing it is offered afterwards has a parent it can place: its
    /// verifications stay pending, and every block it finalizes is one it never checked itself.
    const LATE: usize = 4;

    /// Views the late validator is given to recover the block carrying the certificate.
    const RECOVERY_BUDGET: u64 = 30;

    #[test]
    fn finalized_payload_recovered_from_gossip_cache() {
        runner().start(|context| async move {
            let keys = test_util::keys(VALIDATORS);
            let attesting = test_util::attesting(&keys);
            let peers: Vec<ed25519::PublicKey> = keys
                .privates
                .iter()
                .map(|private| private.public_key())
                .collect();
            let oracle = test_util::network(&context, &peers).await;

            // A batch this deployment really encoded, custodied by every validator that signs the
            // certificate over it. Written before any node opens its store, which is the state a
            // dispersal leaves behind.
            let quorum = N3f1::quorum(VALIDATORS as u32) as usize;
            let (header, shards) = test_util::dispersal_among(VALIDATORS, DISPERSED, 0xd1);
            let commitment = header.commitment;
            for (index, shard) in shards.iter().enumerate().take(quorum) {
                let mut custody = Custody::init(
                    context.child("seed"),
                    &partition(index),
                    test_util::shard_cfg(),
                )
                .await
                .expect("custody opens");
                custody
                    .put(
                        header.dispersal_view,
                        commitment,
                        CustodyRecord {
                            index: index as u16,
                            shard: shard.clone(),
                        },
                    )
                    .await
                    .expect("shard stores");
            }

            // Everyone but one, running until the chain has left genesis behind. Four of five is
            // a quorum, so the fifth is not needed for progress.
            let mut nodes = Vec::new();
            for index in 0..VALIDATORS {
                if index == LATE {
                    continue;
                }
                nodes.push(spawn_node(&context, "validator", index, &keys, &oracle).await);
            }
            reach(&context, &nodes.iter().collect::<Vec<_>>(), View::new(2)).await;

            // The straggler joins. It receives every payload the gossip layer carries and hears
            // every finalization, and it can verify none of them: the parent of anything it is
            // offered is a block it was not there for.
            let late = spawn_node(&context, "late", LATE, &keys, &oracle).await;

            // A certificate a quorum of these validators really attested to, offered to one node
            // that was already running -- never to the straggler, whose pool never holds it.
            let cert = test_util::genuine_cert(
                &attesting,
                &header,
                &keys.privates[0],
                Fr::from(21u64),
                quorum,
            );
            const { assert!(INJECTED < LATE, "the injected validator is a running one") };
            assert!(nodes[INJECTED].node.application.certificate(cert));

            // It rides into a block, and the straggler learns of it from that block alone.
            let deadline = View::new(DISPERSED + RECOVERY_BUDGET);
            let (registered, included) = loop {
                if let Some(found) = late.node.registry.get(&commitment) {
                    break found;
                }
                assert!(
                    late.node.watermark.get() < deadline,
                    "the certificate never reached the straggler's registry"
                );
                context.sleep(Duration::from_millis(50)).await;
            };
            assert_eq!(registered.header, header);
            assert!(included <= late.node.watermark.get());

            // The payload behind it is stored rather than merely read out of the gossip cache, so
            // the block is on this node's chain like any other.
            assert_eq!(
                inclusions(&[&late.node], &commitment).await,
                vec![1],
                "the recovered block is not on the straggler's chain"
            );

            // And the read path is open on it. The straggler custodies no shard of this batch, so
            // every shard it decodes was gathered from the custodians the recovered certificate
            // names -- which is the whole point of recording it.
            assert!(
                late.node.attestor.fetch(commitment).await.is_none(),
                "the straggler custodied a shard of its own"
            );
            let (batch, returned) = late
                .node
                .retrieval
                .fetch(commitment)
                .await
                .expect("coordinator answers")
                .expect("batch is retrieved");
            assert_eq!(batch, test_util::sample_batch(0xd1));
            assert_eq!(returned.header, header);
        });
    }

    #[test]
    fn e2e_cert_to_finalized_block() {
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
                inclusions(&nodes.iter().collect::<Vec<_>>(), &commitment).await,
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
                let counts = inclusions(&nodes.iter().collect::<Vec<_>>(), &commitment).await;
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

    #[test]
    fn handles_stop_together() {
        runner().start(|context| async move {
            // What a node's task group promises the binary: it resolves when the first task
            // stops, and every other task is stopped with it. A validator missing one actor is
            // not a validator running with fewer, so the process ends rather than carries on.
            let stopped = Arc::new(AtomicUsize::new(0));
            let mut handles = Handles::default();
            for _ in 0..3 {
                let stopped = stopped.clone();
                handles.push(context.child("forever").spawn(move |_| async move {
                    let _guard = Counter(stopped);
                    std::future::pending::<()>().await
                }));
            }
            handles.push(context.child("returns").spawn(|_| async {}));

            assert!(handles.wait().await.is_ok());

            // Aborting is a request the runtime delivers the next time it polls each task, so
            // the group's tasks are gone once the runtime has run again rather than the instant
            // the wait returns.
            let deadline = context.current() + Duration::from_secs(10);
            while stopped.load(Ordering::Relaxed) < 3 {
                assert!(
                    context.current() < deadline,
                    "a task outlived the group it belongs to"
                );
                context.sleep(Duration::from_millis(1)).await;
            }
        });
    }

    /// Counts the tasks that were stopped rather than allowed to run on.
    struct Counter(Arc<AtomicUsize>);

    impl Drop for Counter {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
}
