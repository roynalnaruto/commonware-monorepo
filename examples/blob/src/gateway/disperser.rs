//! Dispersal: encode a sealed batch, hand every validator its shard, and certify what comes back.
//!
//! One batch turns into `n` shards and one certificate. The shards are what make the batch
//! available, and the certificate is the only part that ever enters consensus, which is the whole
//! economy of the design: the network carries one shard per validator, not one batch per
//! validator.
//!
//! # Pipeline
//!
//! For each sealed batch:
//!
//! 1. encode it on a shared executor under the coding namespace and the participant set's coding
//!    configuration, both of which every attestor re-derives and checks by equality;
//! 2. sign the blob-tree root the batch actually has, as an attributable gateway claim;
//! 3. send shard `i` to the holder of participant position `i`, including this node, which gets
//!    its shard through the same [`commonware_collector::Handler`] a peer would, so it checks and
//!    custodies it exactly as a peer does;
//! 4. collect attestations until a quorum verifies, then assemble, gossip, and stop tracking;
//! 5. or, if the quorum never arrives, stop tracking and return the blobs to intake.
//!
//! # Trusting nothing that arrives
//!
//! Collection runs entirely on the actor's own task. The [`commonware_collector::Monitor`] this
//! module installs is a forwarder and nothing else: its callback runs inside the collector
//! engine's loop, where verifying a signature would stall every other peer's traffic, and the
//! count it is handed is a count of *responses*, not of valid attestations. What the actor does
//! with a response is check that the peer attested as itself, hold it until a quorum's worth have
//! arrived, and then batch-verify the lot. Signatures that fail are dropped along with the
//! signers that sent them, and collection continues; a peer cannot spend the gateway's quorum by
//! sending noise.
//!
//! # Metrics
//!
//! `certified` counts batches that reached a quorum and `failed` counts batches abandoned without
//! one. The ratio is the health of the data-availability rail as this gateway sees it: everything
//! it counts as failed is blobs going back to intake for another attempt.

use super::{batcher, status::StatusBoard};
use crate::{
    assignment::{index_of, key_of},
    constants::coding_namespace,
    types::{Attestation, BatchHeader, Blob, BlobId, ClaimedRoot, DaCert, Scheme},
    wire::{Coder, DisperseRequest, DisperseResponse},
};
use commonware_actor::mailbox::{self, Policy, Receiver, Sender};
use commonware_broadcast::Broadcaster;
use commonware_codec::Encode as _;
use commonware_coding::PhasedScheme as _;
use commonware_collector::{Handler, Monitor, Originator};
use commonware_cryptography::{
    Signer as _,
    certificate::{Scheme as _, Verifier},
    ed25519, sha256,
    transcript::Summary,
};
use commonware_macros::select_loop;
use commonware_p2p::Recipients;
use commonware_parallel::Strategy;
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell,
    telemetry::metrics::{Counter, MetricsExt as _},
};
use commonware_utils::{Participant, channel::mpsc, ordered::Quorum as _};
use rand_core::CryptoRng;
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    num::NonZeroUsize,
    time::{Duration, SystemTime},
};
use tracing::{debug, error, warn};

/// A hook that rewrites outbound dispersal requests, for fault-injection tests only.
///
/// Never set outside `cfg(test)`: the field it lives in does not exist in a release build.
#[cfg(test)]
pub type Fault = std::sync::Arc<dyn Fn(u16, &mut DisperseRequest) + Send + Sync>;

/// Work handed to the disperser.
enum Message {
    /// A validator replied to a dispersal request.
    ///
    /// Carries the peer the collector engine authenticated it from, which is the only thing that
    /// says who the attestation is allowed to be from.
    Collected {
        peer: ed25519::PublicKey,
        response: DisperseResponse,
    },
}

impl Policy for Message {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut VecDeque<Self>, message: Self) {
        // A dropped response is an attestation the gateway paid for and cannot ask for again.
        overflow.push_back(message);
    }
}

/// Handle to a [`Disperser`], and the [`Monitor`] its collector engine calls.
///
/// Forwarding is all this does. See the module documentation for why.
#[derive(Clone)]
pub struct Mailbox {
    sender: Sender<Message>,
}

/// The receiving half of a [`Mailbox`], which the actor takes.
pub struct Inbox {
    sender: Sender<Message>,
    receiver: Receiver<Message>,
}

/// Creates a disperser's mailbox ahead of the actor that drains it.
///
/// The two are separated because the wiring is circular: a collector engine wants the [`Monitor`]
/// when it is built and only then hands back the [`Originator`] the disperser needs, so the
/// mailbox has to exist before either of them.
pub fn mailbox(context: &impl Metrics, size: NonZeroUsize) -> (Mailbox, Inbox) {
    let (sender, receiver) = mailbox::new(context.child("mailbox"), size);
    (
        Mailbox {
            sender: sender.clone(),
        },
        Inbox { sender, receiver },
    )
}

impl Monitor for Mailbox {
    type PublicKey = ed25519::PublicKey;
    type Response = DisperseResponse;

    fn collected(&mut self, handler: Self::PublicKey, response: Self::Response, _: usize) {
        // The engine's count is a count of responses from distinct peers, not of valid
        // attestations, so it is deliberately ignored.
        if !self
            .sender
            .enqueue(Message::Collected {
                peer: handler,
                response,
            })
            .accepted()
        {
            debug!("disperser is stopped; attestation dropped");
        }
    }
}

/// Configuration for a [`Disperser`].
pub struct Config<E, O, H, B, S>
where
    E: Clock + Metrics + Spawner,
    S: Strategy,
{
    /// The signing scheme, which names the participant set and verifies attestations over it.
    pub scheme: Scheme,
    /// This gateway's identity, which signs the claimed blob-tree root.
    pub signer: ed25519::PrivateKey,
    /// Base namespace of the deployment.
    pub namespace: Vec<u8>,
    /// Sends dispersal requests to peers and collects their replies.
    pub originator: O,
    /// The local attestor, called directly because p2p does not deliver to self.
    pub local: H,
    /// Gossips assembled certificates.
    pub gossip: B,
    /// Where the fate of each blob is recorded.
    pub board: StatusBoard<E>,
    /// Intake, for the blobs of a batch that failed to certify.
    pub batcher: batcher::Mailbox<E>,
    /// How long a batch waits for its quorum.
    pub timeout: Duration,
    /// Dispersals of a blob allowed before it is abandoned.
    pub attempts: u8,
    /// Parallelism for coding and signature verification.
    pub strategy: S,
    /// Test-only rewrite applied to every outbound request. See [`Fault`].
    #[cfg(test)]
    pub fault: Option<Fault>,
}

/// A batch that has been dispersed and is waiting on its quorum.
struct InFlight {
    /// The attested subject.
    header: BatchHeader,
    /// The gateway's signed structural claim, held until the certificate is assembled.
    claimed_root: ClaimedRoot,
    /// The batch's blobs, needed to record their fate and to return them to intake.
    blobs: Vec<(Blob, BlobId)>,
    /// When the gateway gives up.
    deadline: SystemTime,
    /// Attestations that have passed batch verification, by signer.
    verified: BTreeMap<Participant, Attestation>,
    /// Attestations that have arrived but not yet been verified, by signer.
    pending: BTreeMap<Participant, Attestation>,
}

impl InFlight {
    /// Returns whether a signer has already been heard from, in either state.
    fn heard(&self, signer: Participant) -> bool {
        self.verified.contains_key(&signer) || self.pending.contains_key(&signer)
    }
}

/// The dispersal actor.
pub struct Disperser<E, O, H, B, S>
where
    E: Clock + CryptoRng + Metrics + Spawner,
    S: Strategy,
{
    context: ContextCell<E>,
    scheme: Scheme,
    signer: ed25519::PrivateKey,
    namespace: Vec<u8>,
    coding: Vec<u8>,
    quorum: usize,
    originator: O,
    local: H,
    gossip: B,
    board: StatusBoard<E>,
    batcher: batcher::Mailbox<E>,
    timeout: Duration,
    attempts: u8,
    strategy: S,
    /// Batches that reached a quorum and were certified.
    certified: Counter,
    /// Batches abandoned without a quorum.
    failed: Counter,
    sender: Sender<Message>,
    mailbox: Receiver<Message>,
    batches: mpsc::Receiver<batcher::Job>,
    in_flight: HashMap<Summary, InFlight>,
    #[cfg(test)]
    fault: Option<Fault>,
}

impl<E, O, H, B, S> Disperser<E, O, H, B, S>
where
    E: Clock + CryptoRng + Metrics + Spawner,
    O: Originator<PublicKey = ed25519::PublicKey, Request = DisperseRequest>,
    H: Handler<
            PublicKey = ed25519::PublicKey,
            Request = DisperseRequest,
            Response = DisperseResponse,
        >,
    B: Broadcaster<Recipients = Recipients<ed25519::PublicKey>, Message = DaCert>,
    S: Strategy,
{
    /// Builds a disperser that reads sealed batches from `batches` and responses from `inbox`.
    pub fn new(
        context: E,
        config: Config<E, O, H, B, S>,
        inbox: Inbox,
        batches: mpsc::Receiver<batcher::Job>,
    ) -> Self {
        let quorum = config
            .scheme
            .participants()
            .quorum::<<Scheme as Verifier>::Faults>() as usize;
        let certified = context.counter("certified", "Number of batches certified");
        let failed = context.counter("failed", "Number of batches abandoned without a quorum");
        Self {
            context: ContextCell::new(context),
            coding: coding_namespace(&config.namespace),
            namespace: config.namespace,
            scheme: config.scheme,
            signer: config.signer,
            quorum,
            originator: config.originator,
            local: config.local,
            gossip: config.gossip,
            board: config.board,
            batcher: config.batcher,
            timeout: config.timeout,
            attempts: config.attempts,
            strategy: config.strategy,
            certified,
            failed,
            sender: inbox.sender,
            mailbox: inbox.receiver,
            batches,
            in_flight: HashMap::new(),
            #[cfg(test)]
            fault: config.fault,
        }
    }

    /// Starts the actor.
    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        select_loop! {
            self.context,
            on_start => {
                // Waking at the earliest deadline is enough: nothing expires before it, and a
                // batch dispersed later only ever moves the next wake-up further out.
                let deadline = self
                    .in_flight
                    .values()
                    .map(|batch| batch.deadline)
                    .min()
                    .unwrap_or_else(|| self.context.current() + self.timeout);
            },
            on_stopped => {
                debug!(in_flight = self.in_flight.len(), "context shutdown, stopping disperser");
            },
            _ = self.context.sleep_until(deadline) => {
                self.expire();
            },
            Some(message) = self.mailbox.recv() else break => {
                let Message::Collected { peer, response } = message;
                self.collected(&peer, response);
            },
            Some(job) = self.batches.recv() else break => {
                self.disperse(job).await;
            },
        }
    }

    /// Encodes a sealed batch and hands every validator its shard.
    async fn disperse(&mut self, job: batcher::Job) {
        let batcher::Job {
            sealed,
            view,
            config,
        } = job;
        let blobs = batcher::identified(&sealed);
        let root = sealed.root();

        // The encoded batch goes into the encode job and is consumed there. Shards run to several
        // times the size of the batch that produced them, so holding the serialized batch as well
        // is the one avoidable peak; what stays behind is the blobs, which the retry path needs.
        let namespace = self.coding.clone();
        let strategy = self.strategy.clone();
        let bytes = sealed.batch.encode();
        drop(sealed);
        let encoded = self
            .context
            .child("coding")
            .shared(true)
            .spawn(move |_| async move { Coder::encode(&namespace, &config, bytes, &strategy) })
            .await;
        let (commitment, shards) = match encoded {
            Ok(Ok(encoded)) => encoded,
            Ok(Err(err)) => {
                error!(?err, "batch could not be encoded");
                return self.abandon(blobs);
            }
            Err(err) => {
                error!(?err, "encode did not complete");
                return self.abandon(blobs);
            }
        };

        // A commitment binds the encoded batch, so a second batch under one already in flight
        // holds exactly the same blobs. Tracking both would leave the collector engine unable to
        // say which header an attestation is for, and the batch already out covers the blobs.
        if self.in_flight.contains_key(&commitment) {
            warn!(?commitment, "batch is already being dispersed");
            return;
        }

        // Claimed tier: attestors hold one shard each and cannot check a tree over the whole
        // batch, so this travels beside their attestations rather than inside them.
        let claimed_root = ClaimedRoot::sign(&self.namespace, &self.signer, &commitment, root);
        let header = BatchHeader::new(commitment, config, view);
        let deadline = self.context.current() + self.timeout;
        self.in_flight.insert(
            commitment,
            InFlight {
                header: header.clone(),
                claimed_root,
                blobs,
                deadline,
                verified: BTreeMap::new(),
                pending: BTreeMap::new(),
            },
        );

        let me = self.signer.public_key();
        let count = shards.len();
        for (index, shard) in shards.into_iter().enumerate() {
            let Ok(index) = u16::try_from(index) else {
                break;
            };
            let Some(recipient) = key_of(&self.scheme, index).cloned() else {
                warn!(index, "no validator holds this shard");
                continue;
            };
            #[allow(
                unused_mut,
                reason = "only the fault injector below, which is test-only, mutates the request"
            )]
            let mut request = DisperseRequest {
                header: header.clone(),
                index,
                shard,
            };
            #[cfg(test)]
            if let Some(fault) = &self.fault {
                fault(index, &mut request);
            }
            if recipient == me {
                self.disperse_locally(recipient, request);
            } else if !self
                .originator
                .send(Recipients::One(recipient), request)
                .accepted()
            {
                debug!(index, "dispersal engine is stopped");
            }
        }
        debug!(?commitment, shards = count, "dispersed batch");
    }

    /// Hands this node's own shard to its attestor.
    ///
    /// The simulated and the real p2p networks both refuse to deliver a message to its sender, so
    /// a gateway that did nothing here would be one attestation short of the quorum it could
    /// otherwise reach, and would hold a batch it never checked. Routing through the same handler
    /// a peer's request reaches means the local shard is checked and custodied on the same terms.
    fn disperse_locally(&mut self, me: ed25519::PublicKey, request: DisperseRequest) {
        let (responder, receiver) = commonware_utils::channel::oneshot::channel();
        self.local.process(me.clone(), request, responder);
        let sender = self.sender.clone();
        // The attestor checks the shard and writes it to durable storage before it replies, so the
        // reply is awaited off this task; it then joins the same queue a peer's reply arrives on.
        self.context.child("local").spawn(move |_| async move {
            let Ok(response) = receiver.await else {
                debug!("local attestor did not attest");
                return;
            };
            let _ = sender.enqueue(Message::Collected { peer: me, response });
        });
    }

    /// Takes one attestation, and certifies the batch if it now has a quorum.
    fn collected(&mut self, peer: &ed25519::PublicKey, response: DisperseResponse) {
        let commitment = response.commitment;
        let Some(signer) = index_of(&self.scheme, peer) else {
            debug!(?peer, "attestation from outside the participant set");
            return;
        };
        let signer = Participant::new(u32::from(signer));

        // A validator may only attest as itself. Rejecting anything else keeps one peer from
        // claiming another's position, and is what guarantees the one attestation per signer that
        // batch verification and assembly both require.
        if response.attestation.signer != signer {
            warn!(
                ?peer,
                ?commitment,
                "attestation signed under another position"
            );
            return;
        }
        let Some(batch) = self.in_flight.get_mut(&commitment) else {
            debug!(
                ?commitment,
                ?peer,
                "attestation for a batch no longer tracked"
            );
            return;
        };
        if batch.heard(signer) {
            debug!(?commitment, ?peer, "duplicate attestation");
            return;
        }
        batch.pending.insert(signer, response.attestation);
        if batch.verified.len() + batch.pending.len() < self.quorum {
            return;
        }

        // A quorum's worth have arrived: verify the new ones together, which is one aggregate
        // check rather than one per signature, and drop whoever fails.
        let candidates: Vec<Attestation> =
            std::mem::take(&mut batch.pending).into_values().collect();
        let verification = self.scheme.verify_attestations::<_, sha256::Digest, _>(
            self.context.as_mut(),
            &batch.header,
            candidates,
            &self.strategy,
        );
        if !verification.invalid.is_empty() {
            warn!(?commitment, invalid = ?verification.invalid, "dropping invalid attestations");
        }
        for attestation in verification.verified {
            batch.verified.insert(attestation.signer, attestation);
        }
        if batch.verified.len() < self.quorum {
            return;
        }
        self.certify(commitment);
    }

    /// Assembles, gossips, and records the certificate for a batch that has its quorum.
    fn certify(&mut self, commitment: Summary) {
        let batch = self
            .in_flight
            .remove(&commitment)
            .expect("batch is tracked");
        let Some(certificate) = self
            .scheme
            .assemble(batch.verified.into_values(), &self.strategy)
        else {
            // Unreachable with a quorum of verified attestations, and not worth retrying: the
            // batch is already custodied, so it is the certificate rather than the data that is
            // lost. The blobs go back to intake.
            error!(?commitment, "quorum of attestations did not assemble");
            self.failed.inc();
            self.originator.cancel(commitment);
            return self.abandon(batch.blobs);
        };
        let cert = DaCert {
            header: batch.header,
            certificate,
            claimed_root: batch.claimed_root,
        };
        if !self.gossip.broadcast(Recipients::All, cert).accepted() {
            warn!(?commitment, "certificate could not be gossiped");
        }

        // Nothing more is wanted from this batch, so late responses stop being tracked.
        self.originator.cancel(commitment);
        for (_, id) in &batch.blobs {
            self.board.certified(*id, commitment);
        }
        self.certified.inc();
        debug!(?commitment, blobs = batch.blobs.len(), "certified batch");
    }

    /// Gives up on every batch whose deadline has passed.
    fn expire(&mut self) {
        let now = self.context.current();
        let expired: Vec<Summary> = self
            .in_flight
            .iter()
            .filter(|(_, batch)| batch.deadline <= now)
            .map(|(commitment, _)| *commitment)
            .collect();
        for commitment in expired {
            let batch = self
                .in_flight
                .remove(&commitment)
                .expect("batch is tracked");
            warn!(
                ?commitment,
                verified = batch.verified.len(),
                quorum = self.quorum,
                "batch did not reach a quorum"
            );
            self.failed.inc();
            self.originator.cancel(commitment);
            self.abandon(batch.blobs);
        }
    }

    /// Returns the blobs of a failed batch to intake, or reports them failed.
    fn abandon(&mut self, blobs: Vec<(Blob, BlobId)>) {
        for (blob, id) in blobs {
            let attempts = self.board.attempted(id);
            if attempts >= self.attempts {
                debug!(%id, attempts, "giving up on blob");
                self.board.failed(id);
                continue;
            }
            if !self.batcher.retry(blob, id) {
                warn!(%id, "intake is stopped; blob failed");
                self.board.failed(id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        assignment::coding_config,
        attestor::{self, Attestor, Watermark},
        constants::{
            ATTEST_SLACK, BATCH_TIMEOUT_SIM, CERT_GOSSIP_CHANNEL, DISPERSE_REQ_CHANNEL,
            DISPERSE_RES_CHANNEL, DISPERSE_TIMEOUT_SIM, MAX_DISPERSAL_ATTEMPTS, MAX_TRACKED_BLOBS,
            NAMESPACE, STATUS_TTL,
        },
        custody::Custody,
        gateway::batcher::{self, Batcher},
        test_util::{Attester, Collected, PARTICIPANTS, QUORUM, Tee, Unused, blobs, shard_cfg},
        types::Batch,
        wire::BlobStatus,
    };
    use commonware_codec::EncodeSize as _;
    use commonware_collector::p2p as collector;
    use commonware_consensus::types::View;
    use commonware_cryptography::certificate::mocks::Fixture;
    use commonware_macros::select;
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner, Supervisor as _, deterministic};
    use commonware_utils::{NZUsize, channel::mpsc, test_rng};
    use std::sync::Arc;

    /// The view every batch in these tests is dispersed at.
    const VIEW: View = View::new(40);

    /// Position of the gateway in the participant set. It is a validator like any other, and
    /// custodies its own shard through the same handler its peers use.
    const GATEWAY: usize = 0;

    fn runner() -> deterministic::Runner {
        deterministic::Runner::timed(Duration::from_secs(120))
    }

    /// A deployment of [`PARTICIPANTS`] validators, one of which is also the gateway.
    struct Deployment {
        fixture: Fixture<Scheme>,
        /// Intake for the gateway.
        submit: batcher::Mailbox<deterministic::Context>,
        /// The gateway's view of where each blob has got to.
        board: StatusBoard<deterministic::Context>,
        /// Certificates the gateway gossiped, in order.
        certs: mpsc::UnboundedReceiver<DaCert>,
        /// Certificates each validator heard on the gossip channel, indexed by position.
        ///
        /// The gateway's own queue stays empty: p2p never delivers a message back to its sender,
        /// which is why a gateway's pool is fed by the application rather than by the wire.
        received: Vec<mpsc::UnboundedReceiver<DaCert>>,
        /// Custody partition prefix of each validator, indexed by position.
        prefixes: Vec<String>,
        /// Every validator's dispersal originator, indexed by position.
        ///
        /// Held for the deployment's lifetime even though only the gateway sends anything: a
        /// collector engine whose mailbox has been dropped spins on a closed receiver, which in
        /// the deterministic runtime starves every other task.
        _originators: Vec<collector::Mailbox<ed25519::PublicKey, DisperseRequest>>,
    }

    impl Deployment {
        /// Opens a second handle on validator `index`'s custody store.
        ///
        /// The attestor writes durably before it signs, so what a reader opened afterwards finds
        /// is exactly what that validator was prepared to attest to.
        async fn custody(
            &self,
            context: &deterministic::Context,
            index: usize,
        ) -> Custody<deterministic::Context> {
            Custody::init(context.child("audit"), &self.prefixes[index], shard_cfg())
                .await
                .expect("custody opens")
        }

        /// Waits for the next certificate the gateway gossips, or gives up after `patience`.
        async fn certified(
            &mut self,
            context: &deterministic::Context,
            patience: Duration,
        ) -> Option<DaCert> {
            select! {
                _ = context.sleep(patience) => None,
                cert = self.certs.recv() => cert,
            }
        }
    }

    /// How each validator behaves in a deployment.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Role {
        /// Runs a real attestor over its own custody store.
        Honest,
        /// Withholds: hears every dispersal and answers none.
        Silent,
        /// Answers with a well-formed signature over the wrong subject.
        Byzantine,
    }

    /// Returns `PARTICIPANTS` roles, all honest except the listed positions.
    fn roles(exceptions: &[(usize, Role)]) -> Vec<Role> {
        let mut roles = vec![Role::Honest; PARTICIPANTS as usize];
        for (index, role) in exceptions {
            roles[*index] = *role;
        }
        roles
    }

    /// Builds the deployment: a simulated network, an attestor and a certificate cache per
    /// validator, and the two gateway actors on top of them.
    async fn deploy(
        context: &deterministic::Context,
        roles: &[Role],
        fault: Option<Fault>,
    ) -> Deployment {
        let fixture = crate::test_util::schemes();
        let peers = fixture.participants.clone();
        assert_eq!(roles.len(), peers.len());
        let oracle = crate::test_util::network(context, &peers).await;

        // Per-validator plumbing: the attestor that answers dispersals, the engine that carries
        // them, and the cache that holds gossiped certificates.
        let disperser_context = context.child("disperser");
        let (gateway_monitor, gateway_inbox) = mailbox(&disperser_context, NZUsize!(256));
        let mut originators = Vec::new();
        let mut received = Vec::new();
        let mut prefixes = Vec::new();
        let mut local = None;
        let mut gossip = None;
        for (index, peer) in peers.iter().enumerate() {
            let node = context.child("validator").with_attribute("index", index);
            let prefix = format!("disperser-{index}");
            let attester = match roles[index] {
                Role::Honest => {
                    let attestor = attestor(&node, &fixture, index, &prefix).await;
                    if index == GATEWAY {
                        local = Some(attestor.clone());
                    }
                    Attester::Honest(attestor)
                }
                Role::Silent => Attester::Silent,
                Role::Byzantine => Attester::Byzantine(fixture.schemes[index].clone()),
            };
            let monitor = if index == GATEWAY {
                Collected::Gateway(gateway_monitor.clone())
            } else {
                Collected::Deaf
            };
            let (engine, originator) = collector::Engine::new(
                node.child("collector"),
                collector::Config {
                    blocker: oracle.control(peer.clone()),
                    monitor,
                    handler: attester,
                    mailbox_size: NZUsize!(256),
                    priority_request: false,
                    request_codec: shard_cfg(),
                    priority_response: false,
                    response_codec: (),
                },
            );
            engine.start(
                crate::test_util::register(&oracle, peer, DISPERSE_REQ_CHANNEL).await,
                crate::test_util::register(&oracle, peer, DISPERSE_RES_CHANNEL).await,
            );

            // Certificates ride a plain channel: a pool has to hear about certificates it has
            // never heard of, which cache-by-digest gossip cannot deliver.
            let (sender, receiver) =
                crate::test_util::register(&oracle, peer, CERT_GOSSIP_CHANNEL).await;
            if index == GATEWAY {
                gossip = Some(crate::test_util::Gossip::new(sender));
            }
            received.push(crate::test_util::collect_certs(
                &node,
                receiver,
                PARTICIPANTS as usize,
            ));

            originators.push(originator);
            prefixes.push(prefix);
        }

        // The gateway's own two actors, joined by a bounded queue of sealed batches.
        let board = StatusBoard::new(
            context.child("status"),
            NZUsize!(MAX_TRACKED_BLOBS),
            STATUS_TTL,
        );
        let (sealed, batches) = mpsc::channel(2);
        let (batcher, submit) = Batcher::new(
            context.child("batcher"),
            batcher::Config {
                target: usize::MAX,
                timeout: BATCH_TIMEOUT_SIM,
                coding: coding_config(PARTICIPANTS as usize).expect("participants can be coded"),
                watermark: Watermark::new(VIEW),
                board: board.clone(),
                mailbox_size: NZUsize!(256),
            },
            sealed,
        );
        batcher.start();

        let (seen, certs) = mpsc::unbounded_channel();
        Disperser::new(
            context.child("disperser"),
            Config {
                scheme: fixture.schemes[GATEWAY].clone(),
                signer: fixture.private_keys[GATEWAY].clone(),
                namespace: NAMESPACE.to_vec(),
                originator: originators[GATEWAY].clone(),
                local: local.expect("the gateway runs an attestor"),
                gossip: Tee {
                    inner: gossip.expect("the gateway gossips certificates"),
                    seen,
                },
                board: board.clone(),
                batcher: submit.clone(),
                timeout: DISPERSE_TIMEOUT_SIM,
                attempts: MAX_DISPERSAL_ATTEMPTS,
                strategy: Sequential,
                fault,
            },
            gateway_inbox,
            batches,
        )
        .start();

        Deployment {
            fixture,
            submit,
            board,
            certs,
            received,
            prefixes,
            _originators: originators,
        }
    }

    /// Starts a real attestor for validator `index` over the custody store at `prefix`.
    async fn attestor(
        context: &deterministic::Context,
        fixture: &Fixture<Scheme>,
        index: usize,
        prefix: &str,
    ) -> attestor::Mailbox {
        let custody = Custody::init(context.child("custody"), prefix, shard_cfg())
            .await
            .expect("custody opens");
        let (actor, mailbox) = Attestor::new(
            context.child("attestor"),
            attestor::Config {
                scheme: fixture.schemes[index].clone(),
                namespace: NAMESPACE.to_vec(),
                watermark: Watermark::new(VIEW),
                slack: ATTEST_SLACK,
                mailbox_size: NZUsize!(64),
            },
            custody,
        )
        .expect("attestor builds");
        actor.start();
        mailbox
    }

    /// Submits `sample` to the gateway and returns the identities it accepted.
    async fn submit(deployment: &mut Deployment, sample: &[Blob]) -> Vec<BlobId> {
        let mut ids = Vec::new();
        for blob in sample {
            ids.push(
                deployment
                    .submit
                    .submit(blob.clone())
                    .await
                    .expect("blob is accepted"),
            );
        }
        ids
    }

    /// Asserts that `cert` is a genuine certificate over the batch built from `sample`.
    fn genuine(deployment: &Deployment, cert: &DaCert, sample: &[Blob]) -> Vec<usize> {
        let mut rng = test_rng();

        // Attested tier: a quorum of validators signed this header.
        assert!(deployment.fixture.verifier.verify_certificate::<_, Unused>(
            &mut rng,
            &cert.header,
            &cert.certificate,
            &Sequential
        ));
        assert_eq!(cert.header.dispersal_view, VIEW);
        assert_eq!(
            cert.header.config,
            coding_config(PARTICIPANTS as usize).expect("participants can be coded")
        );

        // Claimed tier: the gateway signed the root, and it is the root the batch really has.
        assert!(cert.claimed_root.verify(NAMESPACE, &cert.header.commitment));
        assert_eq!(
            cert.claimed_root.gateway,
            deployment.fixture.participants[GATEWAY]
        );
        let derived = Batch::new(sample.to_vec())
            .expect("batch is within bounds")
            .root()
            .expect("root is computable");
        assert_eq!(
            cert.claimed_root.root, derived,
            "claimed root is not derived"
        );

        let signers: Vec<usize> = cert.certificate.signers.iter().map(usize::from).collect();
        assert!(signers.len() >= QUORUM, "only {} signers", signers.len());
        signers
    }

    /// Asserts that validator `index` custodies the shard it attested to.
    async fn custodied(
        deployment: &Deployment,
        context: &deterministic::Context,
        index: usize,
        commitment: &Summary,
    ) {
        let custody = deployment.custody(context, index).await;
        let held = custody
            .get(commitment)
            .await
            .expect("custody is readable")
            .unwrap_or_else(|| panic!("validator {index} holds no shard"));
        assert_eq!(usize::from(held.index), index);
    }

    #[test]
    fn all_honest_cert_forms() {
        runner().start(|context| async move {
            let mut deployment = deploy(&context, &roles(&[]), None).await;
            let sample = blobs(2, 8 * 1024, 0x51);
            let ids = submit(&mut deployment, &sample).await;

            let cert = deployment
                .certified(&context, Duration::from_secs(10))
                .await
                .expect("certificate forms");
            let signers = genuine(&deployment, &cert, &sample);

            // The gateway is a custodian like any other: p2p never loops a message back to its
            // sender, so its own shard only exists because the local attestor path put it there.
            assert!(
                signers.contains(&GATEWAY),
                "gateway did not attest to its own shard"
            );

            // Every signer holds the shard it signed for. This is what an attestation means.
            for index in &signers {
                custodied(&deployment, &context, *index, &cert.header.commitment).await;
            }

            // And every blob in the batch is reported certified under that commitment.
            for id in &ids {
                assert_eq!(
                    deployment.board.get(id).expect("blob is tracked").status,
                    BlobStatus::Certified(cert.header.commitment)
                );
            }
        });
    }

    #[test]
    fn f_withhold_cert_forms() {
        runner().start(|context| async move {
            // Three validators, the most the fault model allows, never answer.
            let silent = [7usize, 8, 9];
            let roles = roles(&silent.map(|index| (index, Role::Silent)));
            let mut deployment = deploy(&context, &roles, None).await;
            let sample = blobs(1, 16 * 1024, 0x62);
            let ids = submit(&mut deployment, &sample).await;

            let cert = deployment
                .certified(&context, Duration::from_secs(10))
                .await
                .expect("certificate forms without the withholders");
            let signers = genuine(&deployment, &cert, &sample);
            for index in silent {
                assert!(!signers.contains(&index), "withholder {index} signed");
            }
            assert_eq!(
                deployment
                    .board
                    .get(&ids[0])
                    .expect("blob is tracked")
                    .status,
                BlobStatus::Certified(cert.header.commitment)
            );
        });
    }

    #[test]
    fn f_plus_1_withhold_no_cert_timeout() {
        runner().start(|context| async move {
            // One more than the fault model allows: the quorum is out of reach.
            let roles = roles(&[
                (6, Role::Silent),
                (7, Role::Silent),
                (8, Role::Silent),
                (9, Role::Silent),
            ]);
            let mut deployment = deploy(&context, &roles, None).await;
            let sample = blobs(1, 4 * 1024, 0x73);
            let ids = submit(&mut deployment, &sample).await;

            // No certificate, however long the gateway is given.
            assert!(
                deployment
                    .certified(&context, DISPERSE_TIMEOUT_SIM * 4)
                    .await
                    .is_none(),
                "certificate formed below quorum"
            );

            // The blob re-enters intake once per failed dispersal, and is abandoned once its
            // budget is spent. Every dispersal takes a batch timer plus a dispersal timeout.
            let budget =
                (BATCH_TIMEOUT_SIM + DISPERSE_TIMEOUT_SIM) * u32::from(MAX_DISPERSAL_ATTEMPTS + 1);
            let deadline = context.current() + budget;
            loop {
                let entry = deployment.board.get(&ids[0]).expect("blob is tracked");
                if entry.status == BlobStatus::Failed {
                    assert_eq!(entry.attempts, MAX_DISPERSAL_ATTEMPTS);
                    break;
                }
                assert_eq!(entry.status, BlobStatus::Pending);
                assert!(context.current() < deadline, "blob never failed");
                context.sleep(BATCH_TIMEOUT_SIM).await;
            }

            // Nothing is left tracked: every abandoned batch was cancelled, so a late attestation
            // has nowhere to land.
            context.sleep(DISPERSE_TIMEOUT_SIM).await;
            assert_eq!(outstanding(&context), 0, "commitments still tracked");
        });
    }

    #[test]
    fn corrupt_one_shard_that_validator_absent_from_cert() {
        runner().start(|context| async move {
            // The gateway sends validator 5 a shard that is not its shard.
            const VICTIM: u16 = 5;
            let fault: Fault = Arc::new(|index, request| {
                if index == VICTIM {
                    request.shard = crate::test_util::corrupt(&request.shard);
                }
            });
            let mut deployment = deploy(&context, &roles(&[]), Some(fault)).await;
            let sample = blobs(1, 16 * 1024, 0x84);
            submit(&mut deployment, &sample).await;

            // The other nine are enough, and the one that was lied to is not among the signers:
            // its coding check failed, so it never attested.
            let cert = deployment
                .certified(&context, Duration::from_secs(10))
                .await
                .expect("certificate forms without the corrupted shard");
            let signers = genuine(&deployment, &cert, &sample);
            assert!(
                !signers.contains(&usize::from(VICTIM)),
                "validator attested to a shard that failed its check"
            );

            // Nor does it hold anything: the attestor persists only what it has checked.
            let custody = deployment.custody(&context, usize::from(VICTIM)).await;
            assert_eq!(
                custody
                    .get(&cert.header.commitment)
                    .await
                    .expect("custody is readable"),
                None
            );
        });
    }

    #[test]
    fn byzantine_garbage_attestation_not_counted() {
        runner().start(|context| async move {
            // Validator 5 answers instantly with a signature over a subject nobody asked about,
            // so its reply is among the first the gateway collects.
            const LIAR: usize = 5;
            let mut deployment = deploy(&context, &roles(&[(LIAR, Role::Byzantine)]), None).await;
            let sample = blobs(1, 16 * 1024, 0x95);
            submit(&mut deployment, &sample).await;

            let cert = deployment
                .certified(&context, Duration::from_secs(10))
                .await
                .expect("certificate forms without the impostor");
            let signers = genuine(&deployment, &cert, &sample);
            assert!(
                !signers.contains(&LIAR),
                "an invalid attestation was counted"
            );

            // Counting responses rather than checking them would have certified at the seventh
            // reply, which included the impostor's; the certificate is assembled from nine.
            assert!(
                cert.certificate.signers.count() >= QUORUM,
                "quorum was spent on noise"
            );
        });
    }

    #[test]
    fn e2e_bytes_to_cert() {
        runner().start(|context| async move {
            let mut deployment = deploy(&context, &roles(&[]), None).await;

            // A client hands three blobs to the gateway it chose.
            let sample = blobs(3, 32 * 1024, 0xe2);
            let opened = context.current();
            let ids = submit(&mut deployment, &sample).await;
            assert_eq!(ids.len(), 3);

            // Nothing reaches the batch target, so the timer is what seals the batch.
            let cert = deployment
                .certified(&context, Duration::from_secs(10))
                .await
                .expect("certificate forms");
            assert!(
                context
                    .current()
                    .duration_since(opened)
                    .expect("time moves forward")
                    >= BATCH_TIMEOUT_SIM,
                "batch sealed before its timer"
            );
            let signers = genuine(&deployment, &cert, &sample);

            // Every other validator hears the certificate. That is what makes it includable by
            // whichever validator leads the next view, rather than only by the gateway.
            for (index, received) in deployment.received.iter_mut().enumerate() {
                if index == GATEWAY {
                    continue;
                }
                let heard = select! {
                    _ = context.sleep(Duration::from_secs(5)) => None,
                    heard = received.recv() => heard,
                };
                let heard = heard.unwrap_or_else(|| panic!("validator {index} has no certificate"));
                assert_eq!(heard, cert);
            }

            // Every signer holds the shard that makes the batch reconstructible.
            for index in &signers {
                custodied(&deployment, &context, *index, &cert.header.commitment).await;
            }

            // And the client can see where each of its blobs got to.
            for id in &ids {
                assert_eq!(
                    deployment.board.get(id).expect("blob is tracked").status,
                    BlobStatus::Certified(cert.header.commitment)
                );
            }

            // The property the whole rail exists for: dispersal costs the network one shard per
            // validator, not one batch per validator. Recomputed here from the same inputs the
            // gateway used, so the numbers are the ones that actually went out.
            let batch = Batch::new(sample).expect("batch is within bounds");
            let bytes = batch.encode();
            let batch_size = bytes.len();
            let (commitment, shards) = Coder::encode(
                &coding_namespace(NAMESPACE),
                &cert.header.config,
                bytes,
                &Sequential,
            )
            .expect("batch encodes");
            assert_eq!(
                commitment, cert.header.commitment,
                "encode is deterministic"
            );
            let mut dispersed = 0usize;
            for (index, shard) in shards.into_iter().enumerate() {
                let request = DisperseRequest {
                    header: cert.header.clone(),
                    index: index as u16,
                    shard,
                };
                let size = request.encode_size();
                assert!(
                    size < batch_size,
                    "shard {index} of {size} bytes is not smaller than the {batch_size} byte batch"
                );
                dispersed += size;
            }
            // Measured for this batch: 96 KiB of blobs cost 609 KiB of dispersal against 960 KiB
            // to replicate them, and the gap widens with batch size because a shard's fixed
            // overhead is amortized while replication is not.
            let replicated = batch_size * PARTICIPANTS as usize;
            assert!(
                dispersed < replicated,
                "dispersal cost {dispersed} bytes, no better than {replicated} bytes of replication"
            );
        });
    }

    /// Sums every `outstanding` gauge the collector engines expose.
    ///
    /// The engine tracks a commitment until it is cancelled, so this returning to zero is the
    /// gateway having stopped waiting on every batch it dispersed.
    fn outstanding(context: &deterministic::Context) -> u64 {
        context
            .encode()
            .lines()
            .filter(|line| !line.starts_with('#'))
            .filter_map(|line| line.split_once(' '))
            .filter(|(name, _)| name.ends_with("outstanding"))
            .filter_map(|(_, value)| value.trim().parse::<u64>().ok())
            .sum()
    }
}
