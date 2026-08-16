//! The application actor: the certificate pool, the payload store, and the consensus decisions.

use super::{
    Context,
    ingress::{Mailbox, Message},
    reporter::Reporter,
};
use crate::{
    assignment::coding_config,
    attestor::{self, Watermark},
    constants::{FRESHNESS, MAX_POOL_CERTS, PAYLOAD_MAX_CERTS},
    gateway::StatusBoard,
    payload::{self, PayloadStore},
    registry::Registry,
    types::{DaCert, Scheme},
    wire::Payload,
};
use commonware_actor::mailbox::{self, Receiver, Sender};
use commonware_broadcast::buffered;
use commonware_coding::Config as CodingConfig;
use commonware_consensus::types::View;
use commonware_cryptography::{
    Digestible as _,
    certificate::{Scheme as _, Verifier as _},
    ed25519, sha256,
    transcript::Summary,
};
use commonware_macros::select_loop;
use commonware_p2p::{
    Recipients,
    utils::codec::{WrappedSender, wrap},
};
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner, Storage, spawn_cell,
};
use commonware_utils::channel::oneshot;
use rand_core::CryptoRng;
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    num::NonZeroUsize,
    sync::Arc,
};
use tracing::{debug, error, info, warn};

/// Certificates that have been gossiped but not yet included on the finalized chain.
///
/// Keyed by commitment, which is what inclusion is keyed by: two certificates over one batch are
/// interchangeable to a proposer, and only one of them can ever ride. Bounded, because how many
/// certificates arrive is decided by gateways rather than by this node; past the bound the oldest
/// is dropped, which is the one a proposer had the most chances to include already.
struct Pool {
    certs: HashMap<Summary, (u64, DaCert)>,
    order: BTreeMap<u64, Summary>,
    next: u64,
}

impl Pool {
    fn new() -> Self {
        Self {
            certs: HashMap::new(),
            order: BTreeMap::new(),
            next: 0,
        }
    }

    /// Pools `cert`, returning it, or `None` if its commitment is already held.
    fn insert(&mut self, cert: DaCert) -> Option<&DaCert> {
        let commitment = cert.header.commitment;
        if self.certs.contains_key(&commitment) {
            return None;
        }
        if self.certs.len() >= MAX_POOL_CERTS
            && let Some((sequence, evicted)) = self.order.pop_first()
        {
            debug!(
                ?evicted,
                sequence, "pool is full; dropping the oldest certificate"
            );
            self.certs.remove(&evicted);
        }
        let sequence = self.next;
        self.next += 1;
        self.order.insert(sequence, commitment);
        Some(&self.certs.entry(commitment).or_insert((sequence, cert)).1)
    }

    /// Drops the certificate over `commitment`, if one is held.
    fn remove(&mut self, commitment: &Summary) {
        if let Some((sequence, _)) = self.certs.remove(commitment) {
            self.order.remove(&sequence);
        }
    }

    /// Returns the certificates held, oldest first.
    fn iter(&self) -> impl Iterator<Item = &DaCert> {
        self.order
            .values()
            .filter_map(|commitment| self.certs.get(commitment).map(|(_, cert)| cert))
    }

    /// Returns the number of certificates held.
    fn len(&self) -> usize {
        self.certs.len()
    }
}

/// A verification held open until the payload's parent arrives.
struct Deferred {
    context: Context,
    payload: Arc<Payload>,
    response: oneshot::Sender<bool>,
}

/// A certification held open until the payload it is about arrives.
struct Pending {
    /// The view being certified, which is what makes the wait droppable once it is settled.
    view: View,
    response: oneshot::Sender<bool>,
}

/// What this node believes about the finalized chain and its certificate pool.
///
/// Diagnostic rather than protocol: nothing in the rail reads it, and it is a copy rather than a
/// handle, so what it says was true when it was taken.
#[derive(Clone, Debug)]
pub struct Snapshot {
    /// Latest finalized view.
    pub finalized: View,
    /// Digest of the latest finalized payload.
    pub tip: sha256::Digest,
    /// Commitments held in the pool, oldest first.
    pub pool: Vec<Summary>,
    /// The finalized chain as far as it is still retained, newest first.
    pub chain: Vec<(View, Vec<Summary>)>,
}

impl Snapshot {
    /// Returns how many payloads of the finalized chain carry `commitment`.
    ///
    /// One is the only healthy answer for a certificate that has been included: more would mean
    /// ancestry dedup failed, which would leave a future certificate registry keyed by commitment
    /// ambiguous.
    pub fn inclusions(&self, commitment: &Summary) -> usize {
        self.chain
            .iter()
            .filter(|(_, carried)| carried.contains(commitment))
            .count()
    }

    /// Returns the oldest view the retained chain reaches.
    pub fn horizon(&self) -> View {
        self.chain.last().map_or_else(View::zero, |(view, _)| *view)
    }
}

/// Configuration for an [`Application`].
pub struct Config<E: BufferPooler + Clock + Metrics + Spawner + Storage, T: Strategy> {
    /// The attestation scheme, which names the participant set and verifies certificates over it.
    pub scheme: Scheme,
    /// Base namespace of the deployment.
    pub namespace: Vec<u8>,
    /// Payload persistence and ancestry.
    pub store: PayloadStore<E>,
    /// Gossip that disseminates payloads, which bare simplex does not carry itself.
    pub payloads: buffered::Mailbox<ed25519::PublicKey, Payload>,
    /// Where the fate of each blob is recorded.
    pub board: StatusBoard<E>,
    /// Where finalized certificates are recorded for the read path.
    pub registry: Registry,
    /// The last finalized view, shared with the attestor and the batcher.
    pub watermark: Watermark,
    /// The attestor, which owns custody and therefore its expiry.
    pub attestor: attestor::Mailbox,
    /// Messages buffered before the mailbox spills to its overflow queue.
    pub mailbox_size: NonZeroUsize,
    /// Parallelism for signature verification.
    pub strategy: T,
}

/// The consensus-facing actor.
pub struct Application<
    E: BufferPooler + Clock + CryptoRng + Metrics + Spawner + Storage,
    T: Strategy,
> {
    context: ContextCell<E>,
    scheme: Scheme,
    namespace: Vec<u8>,
    participants: usize,
    /// Coding parameters this participant set implies, which every header must agree with.
    coding: Option<CodingConfig>,
    store: PayloadStore<E>,
    payloads: buffered::Mailbox<ed25519::PublicKey, Payload>,
    board: StatusBoard<E>,
    registry: Registry,
    watermark: Watermark,
    attestor: attestor::Mailbox,
    strategy: T,
    pool: Pool,
    /// Latest finalized view, and the payload that finalized there.
    finalized: View,
    tip: sha256::Digest,
    /// Verifications waiting on the payload keyed here, which is their parent.
    waiting: HashMap<sha256::Digest, Vec<Deferred>>,
    /// Certifications waiting on the payload keyed here.
    certifying: HashMap<sha256::Digest, Vec<Pending>>,
    sender: Sender<Message>,
    mailbox: Receiver<Message>,
}

impl<E: BufferPooler + Clock + CryptoRng + Metrics + Spawner + Storage, T: Strategy>
    Application<E, T>
{
    /// Builds the actor, returning it with the handle consensus drives it through and the observer
    /// consensus reports to.
    pub fn new(context: E, config: Config<E, T>) -> (Self, Mailbox, Reporter) {
        let (sender, receiver) = mailbox::new(context.child("mailbox"), config.mailbox_size);
        let tip = config.store.genesis();
        (
            Self {
                context: ContextCell::new(context),
                participants: config.scheme.participants().len(),
                coding: coding_config(config.scheme.participants().len()),
                scheme: config.scheme,
                namespace: config.namespace,
                store: config.store,
                payloads: config.payloads,
                board: config.board,
                registry: config.registry,
                watermark: config.watermark,
                attestor: config.attestor,
                strategy: config.strategy,
                pool: Pool::new(),
                finalized: View::zero(),
                tip,
                waiting: HashMap::new(),
                certifying: HashMap::new(),
                sender: sender.clone(),
                mailbox: receiver,
            },
            Mailbox::new(sender.clone()),
            Reporter::new(sender),
        )
    }

    /// Starts the actor over the certificate-gossip channel.
    ///
    /// Certificates ride a plain channel rather than the digest-addressed gossip payloads use: a
    /// pool has to hear about certificates it has never heard of, and cache-by-digest can only
    /// answer for a digest somebody already knows.
    pub fn start(
        mut self,
        cert_gossip: (
            impl commonware_p2p::Sender<PublicKey = ed25519::PublicKey>,
            impl commonware_p2p::Receiver<PublicKey = ed25519::PublicKey>,
        ),
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(cert_gossip))
    }

    async fn run(
        mut self,
        cert_gossip: (
            impl commonware_p2p::Sender<PublicKey = ed25519::PublicKey>,
            impl commonware_p2p::Receiver<PublicKey = ed25519::PublicKey>,
        ),
    ) {
        let (mut gossip, mut inbound) = wrap::<_, _, DaCert>(
            self.participants,
            self.context.network_buffer_pool().clone(),
            cert_gossip.0,
            cert_gossip.1,
        );
        select_loop! {
            self.context,
            on_stopped => {
                debug!(pool = self.pool.len(), "context shutdown, stopping application");
            },
            Some(message) = self.mailbox.recv() else break => {
                if let Err(err) = self.handle(message, &mut gossip).await {
                    // A payload this node cannot store is a payload it cannot honour a proposal
                    // or a verdict about, so it stops rather than answering from a store whose
                    // contents it no longer knows.
                    error!(?err, "payload store failed; application stopping");
                    break;
                }
            },
            Ok((peer, decoded)) = inbound.recv() else break => {
                match decoded {
                    Ok(cert) => {
                        self.admit(cert);
                    }
                    Err(err) => debug!(?peer, ?err, "undecodable certificate"),
                }
            },
        }
    }

    /// Runs one message to completion.
    ///
    /// `Err` means the payload store failed, which is fatal to this actor.
    async fn handle<S: commonware_p2p::Sender<PublicKey = ed25519::PublicKey>>(
        &mut self,
        message: Message,
        gossip: &mut WrappedSender<S, DaCert>,
    ) -> Result<(), payload::Error> {
        match message {
            Message::Propose { context, response } => {
                let parent = context.parent.1;
                let view = context.round.view();
                let certs = self.select(&parent, view);
                let payload = Arc::new(Payload {
                    parent,
                    view,
                    certs,
                });
                let digest = payload.digest();

                // Returning a digest commits this node to verifying the same bytes, including
                // after a restart, so the payload is durable before consensus hears about it.
                let carried = payload.certs.len();
                self.store.insert(payload).await?;
                debug!(view = view.get(), ?digest, carried, "proposed");
                let _ = response.send(digest);
                self.resume(digest).await?;
            }
            Message::Verify {
                context,
                payload,
                response,
            } => {
                // The payload may not have arrived, and may never. Waiting happens off this task
                // so the actor keeps serving, and the responder travels with the wait: holding it
                // is what leaves verification pending instead of concluding it.
                let subscription = self.payloads.subscribe(payload);
                let sender = self.sender.clone();
                self.context.child("fetch").spawn(move |_| async move {
                    let Ok(payload) = subscription.await else {
                        debug!(?payload, "payload gossip closed; verification abandoned");
                        return;
                    };
                    if !sender
                        .enqueue(Message::Fetched {
                            context,
                            payload,
                            response,
                        })
                        .accepted()
                    {
                        debug!("application is stopped; verification abandoned");
                    }
                });
            }
            Message::Fetched {
                context,
                payload,
                response,
            } => {
                if let Some(digest) = self.check(context, payload, response).await? {
                    self.resume(digest).await?;
                }
            }
            Message::Certify {
                round,
                payload,
                response,
            } => {
                // Certifying says a payload is safe to build on, which this node can only say of
                // one it checked. A payload it has not seen leaves the request pending; verifying
                // that same payload is what resolves it.
                if self.store.get(&payload).is_some() {
                    let _ = response.send(true);
                } else {
                    debug!(?payload, "certification waiting on the payload");
                    self.certifying.entry(payload).or_default().push(Pending {
                        view: round.view(),
                        response,
                    });
                }
            }
            Message::Relay {
                payload,
                recipients,
            } => {
                let Some(held) = self.store.get(&payload) else {
                    warn!(?payload, "asked to relay a payload this node does not hold");
                    return Ok(());
                };
                if !self.payloads.broadcast_shared(recipients, held).accepted() {
                    warn!(?payload, "payload gossip is stopped");
                }
            }
            Message::Certificate { cert, forward } => {
                if let Some(pooled) = self.admit(*cert)
                    && forward
                {
                    let _ = gossip.send_ref(Recipients::All, pooled, false);
                }
            }
            Message::Finalized { view, payload } => {
                // Finalizations are reported as they are recovered, which is not necessarily in
                // order. Every floor here only moves forward: one that moved back would prune
                // against a view this node has already passed and would hand the attestor a
                // watermark behind the dispersals it has already accepted.
                if view <= self.finalized {
                    debug!(view = view.get(), "finalization is not ahead of the tip");
                    return Ok(());
                }
                self.finalized = view;
                self.tip = payload;
                self.watermark.set(view);
                info!(
                    view = view.get(),
                    certs = self.store.get(&payload).map_or(0, |held| held.certs.len()),
                    "finalized"
                );

                // A certificate on the finalized chain is spent for consensus and born for
                // retrieval: it can never be included again, the blobs behind it have reached the
                // end of the write path, and the registry is now the only place the read path can
                // learn who custodies the batch. Recording happens before any floor moves, so
                // nothing is pruned out from under a reader that arrives in the same view.
                if let Some(finalized) = self.store.get(&payload) {
                    for cert in &finalized.certs {
                        let commitment = cert.header.commitment;
                        self.registry.record(cert.clone(), view);
                        self.pool.remove(&commitment);
                        self.board.included(&commitment, view);
                    }
                } else {
                    warn!(
                        view = view.get(),
                        ?payload,
                        "finalized a payload this node never held"
                    );
                }

                // A request about a settled view can no longer produce a useful verdict, and its
                // payload may never arrive. Dropping the responder concludes it, which is what
                // stops a chain of undelivered payloads from accumulating waiters.
                self.waiting.retain(|_, deferred| {
                    deferred.retain(|entry| entry.context.round.view() > view);
                    !deferred.is_empty()
                });
                self.certifying.retain(|_, pending| {
                    pending.retain(|entry| entry.view > view);
                    !pending.is_empty()
                });

                // Floors move on finalization and nowhere else: advancing them on a notarization
                // would let a fork that loses discard data the surviving fork still owes.
                self.store.prune(view).await?;
                self.attestor.prune(view);
                self.registry.prune(view);
            }
            Message::Held { digest, response } => {
                let _ = response.send(self.store.get(&digest));
            }
            Message::Inspect { response } => {
                let _ = response.send(Snapshot {
                    finalized: self.finalized,
                    tip: self.tip,
                    pool: self
                        .pool
                        .iter()
                        .map(|cert| cert.header.commitment)
                        .collect(),
                    chain: self
                        .store
                        .ancestry(&self.tip)
                        .into_iter()
                        .map(|payload| (payload.view, payload.commitments().collect()))
                        .collect(),
                });
            }
        }
        Ok(())
    }

    /// Chooses the certificates a proposal at `view` over `parent` may carry.
    fn select(&self, parent: &sha256::Digest, view: View) -> Vec<DaCert> {
        // A proposer that cannot see the parent cannot tell what is already on that fork, and a
        // duplicate is a permanent rejection for every verifier. An empty payload is always valid,
        // so that is what an unseen parent gets.
        if self.store.get(parent).is_none() {
            warn!(?parent, "proposing over an unknown parent");
            return Vec::new();
        }
        let floor = view.saturating_sub(FRESHNESS);
        let mut certs = Vec::new();
        for cert in self.pool.iter() {
            if certs.len() >= PAYLOAD_MAX_CERTS {
                break;
            }
            let dispersed = cert.header.dispersal_view;
            if dispersed > view || dispersed < floor {
                continue;
            }
            if self.store.included(parent, &cert.header.commitment) {
                continue;
            }
            certs.push(cert.clone());
        }
        certs
    }

    /// Checks a fetched payload at the position consensus offered it.
    ///
    /// Returns the digest of a payload that was accepted and stored, so its dependents can be
    /// resumed. A rejection is permanent; missing data is not a rejection.
    async fn check(
        &mut self,
        context: Context,
        payload: Arc<Payload>,
        response: oneshot::Sender<bool>,
    ) -> Result<Option<sha256::Digest>, payload::Error> {
        let view = context.round.view();
        let parent = context.parent.1;

        // A payload names the fork position it was built for, so one offered at any other
        // position is a different payload's bytes wearing this digest's position.
        if payload.parent != parent || payload.view != view {
            debug!(
                view = view.get(),
                claimed = payload.view.get(),
                "payload is not bound to this position"
            );
            let _ = response.send(false);
            return Ok(None);
        }

        // Without the parent there is no ancestry, and a certificate that looks fresh may already
        // be on this fork. That is missing data rather than a wrong payload, so the request stays
        // pending until the parent arrives. Bare simplex backfills no payloads, so a parent that
        // never arrives leaves it pending forever, which is the documented limitation.
        if self.store.get(&parent).is_none() {
            debug!(?parent, "verification waiting on the parent payload");
            self.waiting.entry(parent).or_default().push(Deferred {
                context,
                payload,
                response,
            });
            return Ok(None);
        }

        if let Err(reason) = self.admissible(&payload, view, &parent) {
            debug!(view = view.get(), reason, "payload rejected");
            let _ = response.send(false);
            return Ok(None);
        }

        let digest = payload.digest();
        self.store.insert(payload).await?;
        let _ = response.send(true);
        Ok(Some(digest))
    }

    /// Checks every certificate a payload carries, in cost order.
    fn admissible(
        &mut self,
        payload: &Payload,
        view: View,
        parent: &sha256::Digest,
    ) -> Result<(), &'static str> {
        let floor = view.saturating_sub(FRESHNESS);
        let mut seen = HashSet::with_capacity(payload.certs.len());
        for cert in &payload.certs {
            let commitment = cert.header.commitment;
            let dispersed = cert.header.dispersal_view;
            if !seen.insert(commitment) {
                return Err("payload carries a certificate twice");
            }
            if dispersed > view {
                return Err("certificate was dispersed in the future");
            }
            if dispersed < floor {
                return Err("certificate is past its freshness");
            }
            // The coding parameters are a function of the participant set, so a header claiming
            // any others describes a batch nobody here is a custodian of. Honest attestors reject
            // such a header, so no quorum should form over one, but a certificate is checked on
            // what it says rather than on what its signers are assumed to have done.
            if Some(cert.header.config) != self.coding {
                return Err("coding configuration does not match the participant set");
            }
            if self.store.included(parent, &commitment) {
                return Err("certificate is already on this fork");
            }
            if !cert.claimed_root.verify(&self.namespace, &commitment) {
                return Err("gateway claim does not verify");
            }
            if !self.scheme.verify_certificate::<_, sha256::Digest>(
                self.context.as_mut(),
                &cert.header,
                &cert.certificate,
                &self.strategy,
            ) {
                return Err("certificate does not verify");
            }
        }
        Ok(())
    }

    /// Resolves everything that was waiting on `digest`, and on whatever that unblocks.
    ///
    /// Iterative rather than recursive: accepting a payload can release a child, whose acceptance
    /// can release a grandchild, and a chain of them must not be a chain of stack frames.
    async fn resume(&mut self, digest: sha256::Digest) -> Result<(), payload::Error> {
        let mut released = VecDeque::from([digest]);
        while let Some(digest) = released.pop_front() {
            for pending in self.certifying.remove(&digest).unwrap_or_default() {
                let _ = pending.response.send(true);
            }
            for deferred in self.waiting.remove(&digest).unwrap_or_default() {
                let Deferred {
                    context,
                    payload,
                    response,
                } = deferred;
                if let Some(accepted) = self.check(context, payload, response).await? {
                    released.push_back(accepted);
                }
            }
        }
        Ok(())
    }

    /// Takes a certificate into the pool, returning it if it was pooled.
    ///
    /// Everything offered here is adversarial: a peer chooses what it gossips, and a gateway is
    /// untrusted by design. Cheap checks come first so that noise costs a signature verification
    /// only when it has survived everything free.
    fn admit(&mut self, cert: DaCert) -> Option<&DaCert> {
        let commitment = cert.header.commitment;

        // A certificate too old to be included at any view this chain will reach again is not
        // worth holding, whoever sent it.
        if cert.header.dispersal_view < self.finalized.saturating_sub(FRESHNESS) {
            debug!(?commitment, "certificate is past its freshness");
            return None;
        }
        if Some(cert.header.config) != self.coding {
            debug!(
                ?commitment,
                "coding configuration does not match the participant set"
            );
            return None;
        }
        if self.store.included(&self.tip, &commitment) {
            debug!(?commitment, "certificate is already on the finalized chain");
            return None;
        }
        if !cert.claimed_root.verify(&self.namespace, &commitment) {
            warn!(?commitment, "gateway claim does not verify");
            return None;
        }
        if !self.scheme.verify_certificate::<_, sha256::Digest>(
            self.context.as_mut(),
            &cert.header,
            &cert.certificate,
            &self.strategy,
        ) {
            warn!(?commitment, "certificate does not verify");
            return None;
        }
        let pooled = self.pool.insert(cert);
        if pooled.is_none() {
            debug!(?commitment, "certificate is already pooled");
        }
        pooled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        attestor::Attestor,
        constants::{
            ATTEST_SLACK, CERT_GOSSIP_CHANNEL, MAX_TRACKED_BLOBS, NAMESPACE, PAYLOAD_DEQUE,
            PAYLOAD_GOSSIP_CHANNEL, STATUS_TTL,
        },
        custody::{Custody, CustodyRecord},
        poseidon2::Fr,
        test_util::{self, Keys, PARTICIPANTS, QUORUM},
        types::DaCert,
        wire::BlobStatus,
    };
    use commonware_broadcast::Broadcaster as _;
    use commonware_consensus::{
        Automaton as _, Reporter as _,
        simplex::types::{Activity, Finalization, Finalize, Proposal},
        types::{Epoch, Round},
    };
    use commonware_cryptography::{Signer as _, certificate::mocks::Fixture};
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner, Supervisor as _, deterministic};
    use commonware_utils::{NZU16, NZUsize, channel::oneshot};
    use std::time::Duration;

    /// Partition prefix shared by every store in these tests.
    const PREFIX: &str = "p4";

    /// Mailbox depth, comfortably above anything a test enqueues.
    const MAILBOX: NonZeroUsize = NZUsize!(64);

    /// The view the fixture ancestry is built at.
    ///
    /// Above [`FRESHNESS`] on purpose: staleness is only expressible on a chain old enough for a
    /// certificate to have aged out of it.
    const ANCESTOR: u64 = 40;

    fn runner() -> deterministic::Runner {
        deterministic::Runner::timed(Duration::from_secs(60))
    }

    /// A node under test, and the peer whose gossip it depends on.
    struct Harness {
        keys: Keys,
        attesting: Fixture<Scheme>,
        app: Mailbox,
        reporter: Reporter,
        board: StatusBoard<deterministic::Context>,
        watermark: Watermark,
        /// The peer's payload gossip, which is the only way a payload reaches the node.
        peer: buffered::Mailbox<ed25519::PublicKey, Payload>,
        genesis: sha256::Digest,
        /// Drains the peer's certificate channel; dropping it would stall a forwarding send.
        _certs: commonware_utils::channel::mpsc::UnboundedReceiver<DaCert>,
    }

    /// Starts the node under test and one peer beside it.
    async fn deploy(context: &deterministic::Context) -> Harness {
        let keys = test_util::keys(PARTICIPANTS as usize);
        let attesting = test_util::attesting(&keys);
        let peers: Vec<_> = keys.privates[..2]
            .iter()
            .map(|key| key.public_key())
            .collect();
        let oracle = test_util::network(context, &peers).await;

        // The node under test: custody and its attestor, payload gossip, the store, and the
        // application over all three.
        let node = context.child("node");
        let custody = Custody::init(node.child("custody"), PREFIX, test_util::shard_cfg())
            .await
            .expect("custody opens");
        let watermark = Watermark::default();
        let (attestor, attestor_mailbox) = Attestor::new(
            node.child("attestor"),
            crate::attestor::Config {
                scheme: attesting.schemes[0].clone(),
                namespace: NAMESPACE.to_vec(),
                watermark: watermark.clone(),
                slack: ATTEST_SLACK,
                mailbox_size: MAILBOX,
            },
            custody,
        )
        .expect("attestor builds");
        attestor.start();
        let (gossip, payloads) = buffered::Engine::new(
            node.child("payload_gossip"),
            buffered::Config {
                public_key: peers[0].clone(),
                mailbox_size: MAILBOX,
                deque_size: PAYLOAD_DEQUE,
                priority: false,
                codec_config: PARTICIPANTS as usize,
                peer_provider: oracle.manager(),
            },
        );
        gossip.start(test_util::register(&oracle, &peers[0], PAYLOAD_GOSSIP_CHANNEL).await);
        let store = PayloadStore::init(node.child("store"), PREFIX, PARTICIPANTS as usize)
            .await
            .expect("store opens");
        let genesis = store.genesis();
        let board = StatusBoard::new(
            node.child("status"),
            NZUsize!(MAX_TRACKED_BLOBS),
            STATUS_TTL,
        );
        let registry = Registry::new();
        let (application, app, reporter) = Application::new(
            node.child("application"),
            Config {
                scheme: attesting.schemes[0].clone(),
                namespace: NAMESPACE.to_vec(),
                store,
                payloads,
                board: board.clone(),
                registry: registry.clone(),
                watermark: watermark.clone(),
                attestor: attestor_mailbox,
                mailbox_size: MAILBOX,
                strategy: Sequential,
            },
        );
        application.start(test_util::register(&oracle, &peers[0], CERT_GOSSIP_CHANNEL).await);

        // The peer: gossip enough to hand the node a payload, and a drain for anything the node
        // gossips back.
        let other = context.child("peer");
        let (gossip, peer) = buffered::Engine::new(
            other.child("payload_gossip"),
            buffered::Config {
                public_key: peers[1].clone(),
                mailbox_size: MAILBOX,
                deque_size: PAYLOAD_DEQUE,
                priority: false,
                codec_config: PARTICIPANTS as usize,
                peer_provider: oracle.manager(),
            },
        );
        gossip.start(test_util::register(&oracle, &peers[1], PAYLOAD_GOSSIP_CHANNEL).await);
        let certs = test_util::collect_certs(
            &other,
            test_util::register(&oracle, &peers[1], CERT_GOSSIP_CHANNEL)
                .await
                .1,
            PARTICIPANTS as usize,
        );

        Harness {
            keys,
            attesting,
            app,
            reporter,
            board,
            watermark,
            peer,
            genesis,
            _certs: certs,
        }
    }

    /// A certificate a verifier accepts, over a batch nothing else in the test uses.
    fn cert(harness: &Harness, seed: u8, dispersed: u64) -> DaCert {
        let (header, _) = test_util::dispersal(dispersed, seed);
        test_util::genuine_cert(
            &harness.attesting,
            &header,
            &harness.keys.privates[0],
            Fr::from(u64::from(seed)),
            QUORUM,
        )
    }

    /// Consensus metadata for a proposal at `view` built on `parent`.
    fn at(harness: &Harness, view: u64, parent: (u64, sha256::Digest)) -> Context {
        Context {
            round: Round::new(Epoch::zero(), View::new(view)),
            leader: harness.keys.privates[0].public_key(),
            parent: (View::new(parent.0), parent.1),
        }
    }

    /// Hands `payload` to the node the way a proposer would, and returns it.
    fn offer(harness: &Harness, parent: sha256::Digest, view: u64, certs: Vec<DaCert>) -> Payload {
        let payload = Payload {
            parent,
            view: View::new(view),
            certs,
        };
        assert!(
            harness
                .peer
                .broadcast(Recipients::All, payload.clone())
                .accepted(),
            "payload gossip accepted the broadcast"
        );
        payload
    }

    /// Asks the node to verify `payload` at `context` and waits for its verdict.
    async fn verdict(harness: &mut Harness, context: Context, payload: &Payload) -> bool {
        harness
            .app
            .verify(context, payload.digest())
            .await
            .await
            .expect("verification concludes")
    }

    #[test]
    fn p4_propose_drains_pool_excludes_dups_and_stale() {
        runner().start(|context| async move {
            let mut harness = deploy(&context).await;

            // The parent block already carries one certificate, which is what makes it a
            // duplicate rather than merely an old one.
            let included = cert(&harness, 1, ANCESTOR - 1);
            let ancestor = offer(&harness, harness.genesis, ANCESTOR, vec![included.clone()]);
            let parent = at(&harness, ANCESTOR, (0, harness.genesis));
            assert!(verdict(&mut harness, parent, &ancestor).await);

            // Four certificates reach the pool, and only one of them may ride at view 41: the
            // second is already on this fork, the third aged out, and the fourth claims a
            // dispersal that has not happened yet.
            let view = ANCESTOR + 1;
            let fresh = cert(&harness, 2, view);
            let stale = cert(&harness, 3, 5);
            let future = cert(&harness, 4, view + 9);
            for offered in [&fresh, &included, &stale, &future] {
                assert!(harness.app.certificate(offered.clone()));
            }

            let context = at(&harness, view, (ANCESTOR, ancestor.digest()));
            let digest = harness
                .app
                .propose(context)
                .await
                .await
                .expect("proposal is made");
            let proposed = harness
                .app
                .held(digest)
                .await
                .expect("the proposer stores what it proposes");
            assert_eq!(proposed.parent, ancestor.digest());
            assert_eq!(proposed.view, View::new(view));
            assert_eq!(
                proposed.certs,
                vec![fresh.clone()],
                "proposal carried something other than the one includable certificate"
            );

            // Nothing was consumed: a proposal that never finalizes must not cost the pool the
            // certificates it carried.
            let snapshot = harness.app.inspect().await.expect("application answers");
            assert_eq!(snapshot.pool.len(), 4);

            // And the proposal is one this node would accept from somebody else.
            assert!(
                harness
                    .app
                    .held(proposed.digest())
                    .await
                    .is_some_and(|held| *held == *proposed)
            );
        });
    }

    #[test]
    fn p4_verify_missing_payload_stays_pending_then_true() {
        runner().start(|context| async move {
            let mut harness = deploy(&context).await;
            let carried = cert(&harness, 7, ANCESTOR - 1);
            let payload = Payload {
                parent: harness.genesis,
                view: View::new(ANCESTOR),
                certs: vec![carried],
            };

            // Consensus knows the digest; the bytes are not gossiped yet.
            let context_at = at(&harness, ANCESTOR, (0, harness.genesis));
            let mut receiver = harness.app.verify(context_at, payload.digest()).await;
            context.sleep(Duration::from_secs(5)).await;
            assert!(
                matches!(
                    receiver.try_recv(),
                    Err(oneshot::error::TryRecvError::Empty)
                ),
                "verification concluded without the payload"
            );

            // The payload arrives late, and the verdict follows it.
            assert!(
                harness
                    .peer
                    .broadcast(Recipients::All, payload.clone())
                    .accepted()
            );
            assert!(receiver.await.expect("verification concludes"));
            assert!(harness.app.held(payload.digest()).await.is_some());
        });
    }

    #[test]
    fn p4_verify_rejects_dup_in_ancestry() {
        runner().start(|context| async move {
            let mut harness = deploy(&context).await;
            let carried = cert(&harness, 11, ANCESTOR - 1);
            let ancestor = offer(&harness, harness.genesis, ANCESTOR, vec![carried.clone()]);
            let context_at = at(&harness, ANCESTOR, (0, harness.genesis));
            assert!(verdict(&mut harness, context_at, &ancestor).await);

            // The same certificate one block later is a permanent rejection: inclusion is keyed
            // by the commitment, which is what makes a future registry over it well defined.
            let child = offer(&harness, ancestor.digest(), ANCESTOR + 1, vec![carried]);
            let context_at = at(&harness, ANCESTOR + 1, (ANCESTOR, ancestor.digest()));
            assert!(!verdict(&mut harness, context_at, &child).await);
        });
    }

    #[test]
    fn p6_dup_cert_in_later_block_rejected() {
        runner().start(|context| async move {
            let mut harness = deploy(&context).await;

            // A chain deep enough that the duplicate sits several blocks below the tip: the
            // ancestry walk has to follow parent links rather than glance at the parent, and it
            // has to keep following them right down to the freshness horizon.
            let depth = FRESHNESS.get() - 1;
            let carried = cert(&harness, 41, ANCESTOR - 1);
            let commitment = carried.header.commitment;
            let mut parent = harness.genesis;
            let mut parent_view = 0;
            let mut tip = harness.genesis;
            for offset in 0..depth {
                let view = ANCESTOR + offset;
                // Only the first block carries the certificate; every block after it is empty,
                // so the walk cannot find it without descending.
                let certs = if offset == 0 {
                    vec![carried.clone()]
                } else {
                    Vec::new()
                };
                let block = offer(&harness, parent, view, certs);
                let context_at = at(&harness, view, (parent_view, parent));
                assert!(
                    verdict(&mut harness, context_at, &block).await,
                    "block at view {view} was rejected"
                );
                parent = block.digest();
                parent_view = view;
                tip = block.digest();
            }

            // The same certificate offered again, `depth` blocks later on the same chain and
            // still inside its freshness window. Inclusion is keyed by the commitment, so a
            // second ride would leave a registry over commitments ambiguous.
            let view = ANCESTOR + depth;
            let repeat = offer(&harness, tip, view, vec![carried.clone()]);
            let context_at = at(&harness, view, (parent_view, tip));
            assert!(
                !verdict(&mut harness, context_at.clone(), &repeat).await,
                "a certificate already on this chain rode a second time"
            );

            // A different certificate at the same position is accepted, so the rejection is the
            // duplicate rather than the depth of the walk or the age of the chain.
            let other = cert(&harness, 43, ANCESTOR - 1);
            assert_ne!(other.header.commitment, commitment);
            let fresh = offer(&harness, tip, view, vec![other]);
            assert!(verdict(&mut harness, context_at, &fresh).await);
        });
    }

    #[test]
    fn p6_verify_rejects_mismatched_coding_config() {
        runner().start(|context| async move {
            let mut harness = deploy(&context).await;
            let view = ANCESTOR;

            // A certificate a real quorum signed, over a header whose coding parameters are not
            // the ones this participant set implies. The signatures verify, because the signers
            // signed exactly these bytes; what does not hold is the claim itself.
            let honest = cert(&harness, 47, view - 1);
            let mut header = honest.header.clone();
            header.config = CodingConfig {
                minimum_shards: NZU16!(2),
                extra_shards: NZU16!(3),
            };
            assert_ne!(
                header.config,
                coding_config(PARTICIPANTS as usize).expect("participant set can be coded")
            );
            let forged = test_util::genuine_cert(
                &harness.attesting,
                &header,
                &harness.keys.privates[0],
                Fr::from(47u64),
                QUORUM,
            );

            let payload = offer(&harness, harness.genesis, view, vec![forged.clone()]);
            let context_at = at(&harness, view, (0, harness.genesis));
            assert!(
                !verdict(&mut harness, context_at.clone(), &payload).await,
                "a certificate over a foreign coding configuration was accepted"
            );

            // The pool refuses it for the same reason, so a proposer never sees it either.
            assert!(harness.app.certificate(forged.clone()));
            context.sleep(Duration::from_secs(1)).await;
            let snapshot = harness.app.inspect().await.expect("application answers");
            assert!(
                snapshot.pool.is_empty(),
                "a certificate over a foreign coding configuration was pooled"
            );

            // The same certificate over the configuration this set implies is accepted, so the
            // rejection is the configuration and nothing else about the fixture.
            assert!(harness.app.certificate(honest.clone()));
            context.sleep(Duration::from_secs(1)).await;
            let snapshot = harness.app.inspect().await.expect("application answers");
            assert_eq!(snapshot.pool, vec![honest.header.commitment]);
            let accepted = offer(&harness, harness.genesis, view, vec![honest]);
            assert!(verdict(&mut harness, context_at, &accepted).await);
        });
    }

    #[test]
    fn p4_verify_rejects_same_cert_two_forks_dedup_per_fork() {
        runner().start(|context| async move {
            let mut harness = deploy(&context).await;
            let carried = cert(&harness, 13, ANCESTOR - 1);

            // Fork A carries the certificate, so its child may not.
            let a1 = offer(&harness, harness.genesis, ANCESTOR, vec![carried.clone()]);
            let context_at = at(&harness, ANCESTOR, (0, harness.genesis));
            assert!(verdict(&mut harness, context_at, &a1).await);
            let a2 = offer(&harness, a1.digest(), ANCESTOR + 1, vec![carried.clone()]);
            let context_at = at(&harness, ANCESTOR + 1, (ANCESTOR, a1.digest()));
            assert!(!verdict(&mut harness, context_at, &a2).await);

            // Fork B branches from genesis and has never seen it, so the same certificate is as
            // includable there as it ever was. Dedup is per fork, not per node.
            let b1 = offer(&harness, harness.genesis, ANCESTOR + 1, vec![carried]);
            let context_at = at(&harness, ANCESTOR + 1, (0, harness.genesis));
            assert!(verdict(&mut harness, context_at, &b1).await);
        });
    }

    #[test]
    fn p4_verify_rejects_stale_and_future_dispersal() {
        runner().start(|context| async move {
            let mut harness = deploy(&context).await;
            let view = ANCESTOR + 1;

            // Older than the freshness rule allows: the shards behind it may already have been
            // pruned by the validators that hold them.
            let stale = offer(&harness, harness.genesis, view, vec![cert(&harness, 17, 5)]);
            let context_at = at(&harness, view, (0, harness.genesis));
            assert!(!verdict(&mut harness, context_at.clone(), &stale).await);

            // Dispersed at a view that has not happened: accepting it would extend the life of a
            // batch past the window custody promises.
            let future = offer(
                &harness,
                harness.genesis,
                view,
                vec![cert(&harness, 19, view + 1)],
            );
            assert!(!verdict(&mut harness, context_at.clone(), &future).await);

            // The boundaries themselves are fine: dispersed exactly at the inclusion view, and
            // exactly at the freshness horizon.
            let edge = offer(
                &harness,
                harness.genesis,
                view,
                vec![
                    cert(&harness, 23, view),
                    cert(&harness, 29, view - FRESHNESS.get()),
                ],
            );
            assert!(verdict(&mut harness, context_at, &edge).await);
        });
    }

    #[test]
    fn p4_verify_rejects_wrong_parent_binding() {
        runner().start(|context| async move {
            let mut harness = deploy(&context).await;

            // A payload built on a different parent than consensus offered. Its bytes may be
            // perfectly valid somewhere else, which is exactly why the binding is checked.
            let stranger = Payload {
                parent: sha256::Digest::from([9u8; 32]),
                view: View::new(ANCESTOR),
                certs: Vec::new(),
            };
            assert!(
                harness
                    .peer
                    .broadcast(Recipients::All, stranger.clone())
                    .accepted()
            );
            let context_at = at(&harness, ANCESTOR, (0, harness.genesis));
            assert!(!verdict(&mut harness, context_at, &stranger).await);

            // And a payload that names a different view than the one it was offered at.
            let mistimed = offer(&harness, harness.genesis, ANCESTOR, Vec::new());
            let context_at = at(&harness, ANCESTOR + 1, (0, harness.genesis));
            assert!(!verdict(&mut harness, context_at, &mistimed).await);

            // The same bytes at the position they were built for are accepted.
            let context_at = at(&harness, ANCESTOR, (0, harness.genesis));
            assert!(verdict(&mut harness, context_at, &mistimed).await);
        });
    }

    #[test]
    fn p4_reporter_advances_floors_and_evicts_pool() {
        runner().start(|context| async move {
            // Custody is seeded before the node opens it, so the attestor replays two shards: one
            // old enough to expire at the view this test finalizes, and one that is not.
            let expired = {
                let mut custody =
                    Custody::init(context.child("seed"), PREFIX, test_util::shard_cfg())
                        .await
                        .expect("custody opens");
                let (old, shards) = test_util::dispersal(5, 0xa1);
                custody
                    .put(
                        old.dispersal_view,
                        old.commitment,
                        CustodyRecord {
                            index: 0,
                            shard: shards[0].clone(),
                        },
                    )
                    .await
                    .expect("shard stores");
                let (live, shards) = test_util::dispersal(150, 0xa2);
                custody
                    .put(
                        live.dispersal_view,
                        live.commitment,
                        CustodyRecord {
                            index: 0,
                            shard: shards[0].clone(),
                        },
                    )
                    .await
                    .expect("shard stores");
                (old.commitment, live.commitment)
            };

            let mut harness = deploy(&context).await;
            let carried = cert(&harness, 31, ANCESTOR - 1);
            let commitment = carried.header.commitment;

            // A blob the gateway certified under that batch, so the board has something to move.
            let blob = test_util::blobs(1, 256, 0x4b).remove(0).id();
            harness.board.pending(blob);
            harness.board.certified(blob, commitment);

            // The block that finalizes, and the pool that still holds its certificate.
            let finalized = offer(&harness, harness.genesis, ANCESTOR, vec![carried.clone()]);
            let context_at = at(&harness, ANCESTOR, (0, harness.genesis));
            assert!(verdict(&mut harness, context_at, &finalized).await);
            assert!(harness.app.certificate(carried));
            assert_eq!(
                harness
                    .app
                    .inspect()
                    .await
                    .expect("application answers")
                    .pool,
                vec![commitment]
            );

            // One finalization, reported the way consensus reports it.
            let voting = test_util::voting(&harness.keys);
            let proposal = Proposal::new(
                Round::new(Epoch::zero(), View::new(200)),
                View::new(199),
                finalized.digest(),
            );
            let finalizes: Vec<_> = voting.schemes[..QUORUM]
                .iter()
                .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("scheme can sign"))
                .collect();
            let finalization =
                Finalization::from_owned_finalizes(&voting.verifier, finalizes, &Sequential)
                    .expect("quorum assembles");
            assert!(
                harness
                    .reporter
                    .report(Activity::Finalization(finalization))
                    .accepted()
            );
            context.sleep(Duration::from_secs(1)).await;

            // The watermark every floor is measured from.
            assert_eq!(harness.watermark.get(), View::new(200));

            // The pool dropped what can never be included again, and the chain says why.
            let snapshot = harness.app.inspect().await.expect("application answers");
            assert!(
                snapshot.pool.is_empty(),
                "included certificate still pooled"
            );
            assert_eq!(snapshot.finalized, View::new(200));

            // The payload floor moved: a block that far below the horizon is no longer held.
            assert!(
                harness.app.held(finalized.digest()).await.is_none(),
                "payload below the freshness horizon was kept"
            );

            // The custody floor moved with it, through the attestor that owns the store.
            let audit = Custody::init(context.child("audit"), PREFIX, test_util::shard_cfg())
                .await
                .expect("custody opens");
            assert_eq!(
                audit.get(&expired.0).await.expect("custody is readable"),
                None,
                "expired shard was kept"
            );
            assert!(
                audit
                    .get(&expired.1)
                    .await
                    .expect("custody is readable")
                    .is_some(),
                "live shard was dropped"
            );

            // And the client sees where its blob got to.
            assert_eq!(
                harness.board.get(&blob).expect("blob is tracked").status,
                BlobStatus::Included {
                    commitment,
                    view: View::new(200)
                }
            );
        });
    }
}
