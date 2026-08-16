//! The validator side of dispersal: check one shard, keep it, and say so.
//!
//! An attestation is a narrow claim. It says that this validator checked the shard it was sent
//! against the batch commitment at its own position, wrote that shard to durable custody, and is
//! prepared to serve it for as long as the retrievability window lasts. It says nothing about the
//! contents of the batch, which no holder of a single shard can see.
//!
//! # Ordering
//!
//! The pipeline in [`Attestor::attest`] is normative, and the last two steps especially so: the
//! shard is persisted before the header is signed. The opposite order admits a validator that
//! attests to a batch it then loses, which is the one failure a custodian can rule out by
//! construction. Every rejection short of a storage failure drops the responder rather than
//! replying, because there is no useful "no" to send: a gateway that hears nothing simply fails to
//! reach its quorum.
//!
//! A storage failure is different. It is fatal to the custody store, so the actor stops rather
//! than continuing to answer requests it can no longer honour; its mailbox then reports itself
//! closed and later requests are dropped unanswered.
//!
//! # Metrics
//!
//! Because every refusal is silent on the wire, the counters are the only place an operator sees
//! one: `attested` counts dispersals attested to, and `rejected` counts refusals by `reason`
//! (`View`, `Config`, `Index`, `Check`, `Conflict`, `Sign`). A gateway that never reaches a quorum
//! and a validator that refuses everything look identical from the outside and are told apart
//! here.

use crate::{
    assignment::{coding_config, my_index},
    constants::coding_namespace,
    custody::{self, Custody, CustodyRecord},
    types::{BatchHeader, Scheme},
    wire::{Coder, DisperseRequest, DisperseResponse, StrongShard},
};
use commonware_actor::mailbox::{self, Policy, Receiver, Sender};
use commonware_coding::{Config as CodingConfig, PhasedScheme as _};
use commonware_consensus::types::{View, ViewDelta};
use commonware_cryptography::{certificate::Scheme as _, ed25519, sha256, transcript::Summary};
use commonware_runtime::{
    BufferPooler, ContextCell, Handle, Metrics, Spawner, Storage, spawn_cell,
    telemetry::metrics::{
        Counter, CounterFamily, EncodeLabelSet, EncodeLabelValue, MetricsExt as _,
    },
};
use commonware_utils::channel::oneshot;
use std::{
    collections::VecDeque,
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tracing::{debug, error, warn};

/// The last finalized view this node has observed.
///
/// Shared rather than passed along: the attestor reads it on every request while the consensus
/// reporter advances it, and neither should have to wait for the other. Views only move forward in
/// the reporter's hands, but nothing here depends on that.
#[derive(Clone, Debug, Default)]
pub struct Watermark(Arc<AtomicU64>);

impl Watermark {
    /// Creates a watermark at `view`.
    #[cfg(test)]
    pub fn new(view: View) -> Self {
        Self(Arc::new(AtomicU64::new(view.get())))
    }

    /// Returns the current view.
    pub fn get(&self) -> View {
        View::new(self.0.load(Ordering::Relaxed))
    }

    /// Records `view` as the latest observed.
    pub fn set(&self, view: View) {
        self.0.store(view.get(), Ordering::Relaxed);
    }
}

/// Failures that stop an attestor from being built or from continuing.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The scheme holds no position in the participant set, so this node custodies no shard.
    #[error("scheme holds no shard index")]
    NoShardIndex,
    /// The participant set admits no coding configuration.
    #[error("participant set of {0} cannot be coded")]
    Participants(usize),
    /// The custody store failed, which is fatal to it.
    #[error("custody: {0}")]
    Custody(#[from] custody::Error),
}

/// Why a dispersal was refused.
///
/// Every one of these is a silent rejection on the wire, so the counter is the only place a
/// gateway's mistake or an attacker's probing becomes visible to an operator.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
enum Refusal {
    /// Dispersal view outside the accepted band.
    View,
    /// Coding configuration disagreed with the participant set.
    Config,
    /// Addressed to another validator's shard index.
    Index,
    /// Shard failed its coding check.
    Check,
    /// A different shard is already held under this commitment.
    Conflict,
    /// The scheme could not sign.
    Sign,
}

/// Label set for [`Counters::rejected`].
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct Rejected {
    reason: Refusal,
}

/// What an operator can see of the attestation path.
struct Counters {
    /// Dispersals attested to.
    attested: Counter,
    /// Dispersals refused, by reason.
    rejected: CounterFamily<Rejected>,
}

impl Counters {
    /// Registers the counters with `context`.
    fn init(context: &impl Metrics) -> Self {
        Self {
            attested: context.counter("attested", "Number of dispersals attested to"),
            rejected: context.family("rejected", "Number of dispersals refused by reason"),
        }
    }

    /// Records a refusal.
    fn reject(&self, reason: Refusal) {
        self.rejected.get_or_create(&Rejected { reason }).inc();
    }
}

/// Work handed to the attestor.
enum Message {
    /// A gateway asked this validator to custody a shard.
    ///
    /// The request is boxed because it dwarfs everything else in this enum, and every queued
    /// message would otherwise be sized by it.
    Disperse {
        origin: ed25519::PublicKey,
        request: Box<DisperseRequest>,
        responder: oneshot::Sender<DisperseResponse>,
    },
    /// A block finalized, so shards older than the retention window can go.
    Prune {
        /// The latest finalized view.
        finalized: View,
    },
    /// A reader wants the shard this node holds for a batch.
    Fetch {
        /// Commitment of the batch.
        commitment: Summary,
        /// Where the record goes, dropped if nothing is held.
        response: oneshot::Sender<CustodyRecord>,
    },
}

impl Policy for Message {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut VecDeque<Self>, message: Self) {
        // A dispersal is worth keeping under load: the gateway is waiting on a quorum, and a
        // request dropped here costs it one of the attestations it needs. A dropped prune would
        // leave custody holding shards nobody can ask for until the next finalization. A read is
        // kept too, but it is the one message whose caller can cope with being dropped: a reader
        // that hears nothing simply fetches the shard from a peer instead.
        overflow.push_back(message);
    }
}

/// Handle to an [`Attestor`].
///
/// This is the [`commonware_collector::Handler`] the dispersal engine calls. Handling is a
/// synchronous callback, so it only enqueues: the checking, the write, and the signature all
/// happen on the actor's own task.
#[derive(Clone)]
pub struct Mailbox {
    sender: Sender<Message>,
}

impl Mailbox {
    /// Reports the latest finalized view, so custody can drop what it no longer owes.
    ///
    /// Expiry is routed through the actor rather than applied by the reporter directly: the
    /// custody store has one owner, and a second writer could prune a shard out from under an
    /// attestation being signed. Returns whether the attestor accepted the report.
    pub fn prune(&self, finalized: View) -> bool {
        self.sender.enqueue(Message::Prune { finalized }).accepted()
    }

    /// Returns the shard this node custodies for `commitment`, if it holds one.
    ///
    /// The read side of the same single-owner rule pruning follows: custody has one owner, and a
    /// second handle on the store would read shards a prune is part-way through dropping. The
    /// attestor sits on no consensus path, so the hop costs a message.
    ///
    /// `None` covers every way there is nothing to serve -- never attested, already expired, the
    /// store failed, or the attestor has stopped -- because a reader does the same thing in all
    /// of them: ask a peer instead.
    pub async fn fetch(&self, commitment: Summary) -> Option<CustodyRecord> {
        let (response, receiver) = oneshot::channel();
        if !self
            .sender
            .enqueue(Message::Fetch {
                commitment,
                response,
            })
            .accepted()
        {
            debug!(?commitment, "attestor is stopped; shard read dropped");
            return None;
        }
        receiver.await.ok()
    }
}

impl commonware_collector::Handler for Mailbox {
    type PublicKey = ed25519::PublicKey;
    type Request = DisperseRequest;
    type Response = DisperseResponse;

    fn process(
        &mut self,
        origin: Self::PublicKey,
        request: Self::Request,
        responder: oneshot::Sender<Self::Response>,
    ) {
        // `origin` is not an authorization decision here: the collector engine only delivers
        // requests from authenticated peers, and any peer may act as a gateway. It is carried for
        // tracing and for the reply address the engine already holds.
        if !self
            .sender
            .enqueue(Message::Disperse {
                origin,
                request: Box::new(request),
                responder,
            })
            .accepted()
        {
            // The message, and with it the responder, is dropped: the gateway gets no reply.
            debug!("attestor is stopped; dispersal dropped");
        }
    }
}

/// Configuration for an [`Attestor`].
pub struct Config {
    /// The signing scheme, which also names the participant set.
    pub scheme: Scheme,
    /// Base namespace of the deployment.
    pub namespace: Vec<u8>,
    /// The last finalized view, shared with the consensus reporter.
    pub watermark: Watermark,
    /// Views either side of the watermark within which a dispersal is accepted.
    pub slack: ViewDelta,
    /// Requests buffered before the mailbox spills to its overflow queue.
    pub mailbox_size: NonZeroUsize,
}

/// The attestation actor.
pub struct Attestor<E: BufferPooler + Metrics + Spawner + Storage> {
    context: ContextCell<E>,
    scheme: Scheme,
    custody: Custody<E>,
    watermark: Watermark,
    coding: Vec<u8>,
    config: CodingConfig,
    index: u16,
    slack: ViewDelta,
    counters: Counters,
    mailbox: Receiver<Message>,
}

impl<E: BufferPooler + Metrics + Spawner + Storage> Attestor<E> {
    /// Builds an attestor over `custody`, returning it with the handle a dispersal engine calls.
    ///
    /// The shard index and the coding configuration are settled here, from the participant set,
    /// rather than per request: they are properties of the deployment, and a node that cannot
    /// derive them has nothing to attest to.
    pub fn new(context: E, config: Config, custody: Custody<E>) -> Result<(Self, Mailbox), Error> {
        let participants = config.scheme.participants().len();
        let index = my_index(&config.scheme).ok_or(Error::NoShardIndex)?;
        let coding = coding_config(participants).ok_or(Error::Participants(participants))?;
        let (sender, receiver) = mailbox::new(context.child("mailbox"), config.mailbox_size);
        let counters = Counters::init(&context);
        Ok((
            Self {
                context: ContextCell::new(context),
                scheme: config.scheme,
                custody,
                watermark: config.watermark,
                coding: coding_namespace(&config.namespace),
                config: coding,
                index,
                slack: config.slack,
                counters,
                mailbox: receiver,
            },
            Mailbox { sender },
        ))
    }

    /// Starts the actor.
    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        while let Some(message) = self.mailbox.recv().await {
            match message {
                Message::Disperse {
                    origin,
                    request,
                    responder,
                } => match self.attest(&origin, *request).await {
                    Ok(Some(response)) => {
                        let _ = responder.send(response);
                    }
                    // Dropping the responder is the rejection.
                    Ok(None) => {}
                    Err(err) => {
                        error!(?err, "custody failed; attestor stopping");
                        return;
                    }
                },
                Message::Prune { finalized } => {
                    if let Err(err) = self.custody.prune(finalized).await {
                        error!(?err, "custody failed; attestor stopping");
                        return;
                    }
                }
                Message::Fetch {
                    commitment,
                    response,
                } => {
                    // A read that fails is not fatal the way a write is: nothing has been claimed
                    // on the strength of it, and the reader has other custodians to ask. Dropping
                    // the responder is the whole of the answer.
                    match self.custody.get(&commitment).await {
                        Ok(Some(record)) => {
                            let _ = response.send(record);
                        }
                        Ok(None) => debug!(?commitment, "no shard held"),
                        Err(err) => warn!(?commitment, ?err, "custody read failed"),
                    }
                }
            }
        }
    }

    /// Runs one dispersal through the pipeline.
    ///
    /// `Ok(None)` rejects the request. `Err` means custody failed and this attestor is finished.
    async fn attest(
        &mut self,
        origin: &ed25519::PublicKey,
        request: DisperseRequest,
    ) -> Result<Option<DisperseResponse>, Error> {
        let DisperseRequest {
            header,
            index,
            shard,
        } = request;
        let commitment = header.commitment;
        let view = header.dispersal_view;

        // A dispersal far from the views this node believes are current is either stale, in which
        // case its certificate could no longer be included, or post-dated, in which case attesting
        // would extend the life of a batch beyond the freshness rule.
        let watermark = self.watermark.get();
        if view < watermark.saturating_sub(self.slack)
            || view > watermark.saturating_add(self.slack)
        {
            debug!(
                ?origin,
                ?commitment,
                view = view.get(),
                watermark = watermark.get(),
                "dispersal view outside the accepted band"
            );
            self.counters.reject(Refusal::View);
            return Ok(None);
        }

        // The coding configuration is a function of the participant set, so a header that claims a
        // different one describes a batch this node cannot be a custodian of.
        if header.config != self.config {
            debug!(
                ?origin,
                ?commitment,
                "coding configuration does not match the participant set"
            );
            self.counters.reject(Refusal::Config);
            return Ok(None);
        }

        // A shard checks out against exactly one column of the commitment. If the gateway
        // addressed someone else, this node is not that column's custodian.
        if index != self.index {
            debug!(
                ?origin,
                ?commitment,
                index,
                mine = self.index,
                "dispersal addressed to another validator"
            );
            self.counters.reject(Refusal::Index);
            return Ok(None);
        }

        // The cryptographic step: the shard is bound to this commitment at this index, or it is
        // not a shard of this batch at all.
        if !self.checked(&header, shard.clone()).await {
            self.counters.reject(Refusal::Check);
            return Ok(None);
        }

        // A different shard under the same commitment is a claim this node will not make: the
        // record already written is the one it can actually serve.
        let record = CustodyRecord { index, shard };
        if let Some(held) = self.custody.get(&commitment).await?
            && held != record
        {
            warn!(
                ?origin,
                ?commitment,
                "dispersal conflicts with the shard already held"
            );
            self.counters.reject(Refusal::Conflict);
            return Ok(None);
        }

        // A gateway that never heard the reply retries the same dispersal, and that costs nothing:
        // the record is already stored under this view. The same batch dispersed at a later view
        // is a new claim, and custody is written again so that it outlives the certificate this
        // attestation lets the gateway assemble.
        if self.custody.has_at(view, &commitment).await? {
            debug!(
                ?origin,
                ?commitment,
                "re-attesting to a dispersal already held"
            );
        } else {
            self.custody.put(view, commitment, record).await?;
        }

        // Only now, with the shard durable, is the header signed. The scheme is generic over a
        // digest type it never uses, since the subject is a header rather than a digest.
        let Some(attestation) = self.scheme.sign::<sha256::Digest>(&header) else {
            error!(?commitment, "scheme cannot sign");
            self.counters.reject(Refusal::Sign);
            return Ok(None);
        };
        self.counters.attested.inc();
        Ok(Some(DisperseResponse {
            commitment,
            attestation,
        }))
    }

    /// Returns whether `shard` is this node's shard of the batch `header` describes.
    async fn checked(&self, header: &BatchHeader, shard: StrongShard) -> bool {
        let namespace = self.coding.clone();
        let config = header.config;
        let commitment = header.commitment;
        let index = self.index;
        // Milliseconds of field arithmetic on a large batch, so it does not run on the actor's own
        // task. The checking data and weak shard it yields are dropped here; retrieval is what
        // needs them.
        let handle = self
            .context
            .child("coding")
            .shared(true)
            .spawn(move |_| async move {
                Coder::weaken(&namespace, &config, &commitment, index, shard).map(|_| ())
            });
        match handle.await {
            Ok(Ok(())) => true,
            Ok(Err(err)) => {
                debug!(?commitment, ?err, "shard failed its coding check");
                false
            }
            Err(err) => {
                warn!(?commitment, ?err, "coding check did not complete");
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        constants::{ATTEST_SLACK, NAMESPACE},
        test_util::{PARTICIPANTS, Unused, corrupt, dispersal, schemes, shard_cfg},
    };
    use commonware_collector::Handler as _;
    use commonware_cryptography::{Signer as _, certificate::mocks::Fixture};
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner, Supervisor as _, deterministic};
    use commonware_utils::{NZU16, NZUsize, test_rng};
    use std::time::Duration;

    /// Partition prefix shared by every store in these tests.
    const PREFIX: &str = "attestor";

    /// Position this node holds in every test below.
    const INDEX: u16 = 2;

    fn runner() -> deterministic::Runner {
        deterministic::Runner::timed(Duration::from_secs(60))
    }

    /// A peer identity for the gateway side of a dispersal.
    fn gateway() -> ed25519::PublicKey {
        ed25519::PrivateKey::from_seed(99).public_key()
    }

    /// Opens a custody store under the shared prefix.
    async fn custody(
        context: &deterministic::Context,
        label: &'static str,
    ) -> Custody<deterministic::Context> {
        Custody::init(context.child(label), PREFIX, shard_cfg())
            .await
            .expect("custody opens")
    }

    /// Starts an attestor holding shard [`INDEX`] at `watermark`.
    fn start(
        context: &deterministic::Context,
        scheme: Scheme,
        custody: Custody<deterministic::Context>,
        watermark: View,
    ) -> (Mailbox, Handle<()>) {
        let (attestor, mailbox) = Attestor::new(
            context.child("attestor"),
            Config {
                scheme,
                namespace: NAMESPACE.to_vec(),
                watermark: Watermark::new(watermark),
                slack: ATTEST_SLACK,
                mailbox_size: NZUsize!(8),
            },
            custody,
        )
        .expect("attestor builds");
        (mailbox, attestor.start())
    }

    /// Hands one request to the attestor, returning its reply if it sent one.
    async fn dispatch(mailbox: &mut Mailbox, request: DisperseRequest) -> Option<DisperseResponse> {
        let (responder, receiver) = oneshot::channel();
        mailbox.process(gateway(), request, responder);
        receiver.await.ok()
    }

    /// Stops the attestor and reopens its custody store to inspect what it kept.
    async fn stopped(
        context: &deterministic::Context,
        mailbox: Mailbox,
        handle: Handle<()>,
    ) -> Custody<deterministic::Context> {
        drop(mailbox);
        handle.await.expect("attestor exits");
        custody(context, "reopened").await
    }

    /// The request an honest gateway would send this node.
    fn request(header: &BatchHeader, shards: &[StrongShard]) -> DisperseRequest {
        DisperseRequest {
            header: header.clone(),
            index: INDEX,
            shard: shards[usize::from(INDEX)].clone(),
        }
    }

    /// Asserts that the response carries a valid attestation over `header`.
    fn verifies(fixture: &Fixture<Scheme>, header: &BatchHeader, response: &DisperseResponse) {
        let mut rng = test_rng();
        assert_eq!(response.commitment, header.commitment);
        assert!(fixture.verifier.verify_attestation::<_, Unused>(
            &mut rng,
            header,
            &response.attestation,
            &Sequential
        ));
    }

    #[test]
    fn valid_shard_attests() {
        runner().start(|context| async move {
            let fixture = schemes();
            let scheme = fixture.schemes[usize::from(INDEX)].clone();
            assert_eq!(
                my_index(&scheme),
                Some(INDEX),
                "fixture order is positional"
            );
            let (header, shards) = dispersal(50, 1);

            let custody = custody(&context, "custody").await;
            let (mut mailbox, handle) = start(&context, scheme, custody, View::new(50));
            let response = dispatch(&mut mailbox, request(&header, &shards))
                .await
                .expect("attestation returned");
            verifies(&fixture, &header, &response);

            // The shard it attested to is the shard it kept.
            let custody = stopped(&context, mailbox, handle).await;
            assert_eq!(
                custody.get(&header.commitment).await.expect("lookup"),
                Some(CustodyRecord {
                    index: INDEX,
                    shard: shards[usize::from(INDEX)].clone(),
                })
            );
        });
    }

    #[test]
    fn corrupt_shard_no_reply() {
        runner().start(|context| async move {
            let fixture = schemes();
            let (header, shards) = dispersal(50, 2);
            let mut request = request(&header, &shards);
            request.shard = corrupt(&request.shard);

            let custody = custody(&context, "custody").await;
            let (mut mailbox, handle) = start(
                &context,
                fixture.schemes[usize::from(INDEX)].clone(),
                custody,
                View::new(50),
            );
            assert!(dispatch(&mut mailbox, request).await.is_none());

            let custody = stopped(&context, mailbox, handle).await;
            assert_eq!(custody.get(&header.commitment).await.expect("lookup"), None);
        });
    }

    #[test]
    fn counts_attestations_and_refusals() {
        runner().start(|context| async move {
            let fixture = schemes();
            let (header, shards) = dispersal(50, 9);
            let custody = custody(&context, "custody").await;
            let (mut mailbox, handle) = start(
                &context,
                fixture.schemes[usize::from(INDEX)].clone(),
                custody,
                View::new(50),
            );

            // One dispersal this node attests to, and one of each refusal an operator would
            // otherwise never hear about, because every rejection is silent on the wire.
            assert!(
                dispatch(&mut mailbox, request(&header, &shards))
                    .await
                    .is_some()
            );
            let mut corrupted = request(&header, &shards);
            corrupted.shard = corrupt(&corrupted.shard);
            assert!(dispatch(&mut mailbox, corrupted).await.is_none());
            let (stale, stale_shards) = dispersal(1, 10);
            assert!(
                dispatch(&mut mailbox, request(&stale, &stale_shards))
                    .await
                    .is_none()
            );
            let mut misaddressed = request(&header, &shards);
            misaddressed.index = INDEX + 1;
            assert!(dispatch(&mut mailbox, misaddressed).await.is_none());

            let encoded = context.encode();
            for expected in [
                "attested_total 1",
                "rejected_total{reason=\"Check\"} 1",
                "rejected_total{reason=\"View\"} 1",
                "rejected_total{reason=\"Index\"} 1",
            ] {
                assert!(
                    encoded.contains(expected),
                    "metrics do not report `{expected}`:\n{encoded}"
                );
            }
            drop(mailbox);
            handle.await.expect("attestor exits");
        });
    }

    #[test]
    fn wrong_index_no_reply() {
        runner().start(|context| async move {
            let fixture = schemes();
            let (header, shards) = dispersal(50, 3);
            // A gateway that addressed the neighbour's shard to this node.
            let other = usize::from(INDEX) + 1;
            let request = DisperseRequest {
                header: header.clone(),
                index: u16::try_from(other).expect("index fits"),
                shard: shards[other].clone(),
            };

            let custody = custody(&context, "custody").await;
            let (mut mailbox, handle) = start(
                &context,
                fixture.schemes[usize::from(INDEX)].clone(),
                custody,
                View::new(50),
            );
            assert!(dispatch(&mut mailbox, request).await.is_none());

            let custody = stopped(&context, mailbox, handle).await;
            assert_eq!(custody.get(&header.commitment).await.expect("lookup"), None);
        });
    }

    #[test]
    fn bad_config_no_reply() {
        runner().start(|context| async move {
            let fixture = schemes();
            let (header, shards) = dispersal(50, 4);
            // Ten shards still, but cut so that six of them would be needed to reconstruct.
            let mut request = request(&header, &shards);
            request.header.config = CodingConfig {
                minimum_shards: NZU16!(6),
                extra_shards: NZU16!(4),
            };

            let custody = custody(&context, "custody").await;
            let (mut mailbox, handle) = start(
                &context,
                fixture.schemes[usize::from(INDEX)].clone(),
                custody,
                View::new(50),
            );
            assert!(dispatch(&mut mailbox, request).await.is_none());

            let custody = stopped(&context, mailbox, handle).await;
            assert_eq!(custody.get(&header.commitment).await.expect("lookup"), None);
        });
    }

    #[test]
    fn stale_and_future_view_no_reply() {
        runner().start(|context| async move {
            let fixture = schemes();
            let watermark = View::new(100);
            let slack = ATTEST_SLACK.get();

            let custody = custody(&context, "custody").await;
            let (mut mailbox, handle) = start(
                &context,
                fixture.schemes[usize::from(INDEX)].clone(),
                custody,
                watermark,
            );

            // A distinct batch per view, so each dispersal stands on its own commitment.
            let outside = [
                (watermark.get() - slack - 1, 11),
                (watermark.get() + slack + 1, 12),
            ];
            let edges = [(watermark.get() - slack, 13), (watermark.get() + slack, 14)];

            // One view too old, and one view too new.
            for (view, filler) in outside {
                let (header, shards) = dispersal(view, filler);
                assert!(
                    dispatch(&mut mailbox, request(&header, &shards))
                        .await
                        .is_none(),
                    "view {view} is outside the band"
                );
            }

            // The edges of the band are inside it.
            for (view, filler) in edges {
                let (header, shards) = dispersal(view, filler);
                let response = dispatch(&mut mailbox, request(&header, &shards))
                    .await
                    .expect("edge of the band is accepted");
                verifies(&fixture, &header, &response);
            }

            // Only the accepted dispersals were kept.
            let custody = stopped(&context, mailbox, handle).await;
            for (view, filler) in edges {
                let (header, _) = dispersal(view, filler);
                assert!(
                    custody
                        .get(&header.commitment)
                        .await
                        .expect("lookup")
                        .is_some(),
                    "view {view} was kept"
                );
            }
            for (view, filler) in outside {
                let (header, _) = dispersal(view, filler);
                assert_eq!(
                    custody.get(&header.commitment).await.expect("lookup"),
                    None,
                    "view {view} wrote nothing"
                );
            }
        });
    }

    #[test]
    fn persists_before_signing() {
        runner().start(|context| async move {
            let fixture = schemes();
            let (kept, kept_shards) = dispersal(50, 7);
            let (dropped, dropped_shards) = dispersal(50, 8);
            let mut corrupted = request(&dropped, &dropped_shards);
            corrupted.shard = corrupt(&corrupted.shard);

            let custody = custody(&context, "custody").await;
            let (mut mailbox, handle) = start(
                &context,
                fixture.schemes[usize::from(INDEX)].clone(),
                custody,
                View::new(50),
            );
            let response = dispatch(&mut mailbox, request(&kept, &kept_shards))
                .await
                .expect("attestation returned");
            verifies(&fixture, &kept, &response);
            assert!(dispatch(&mut mailbox, corrupted).await.is_none());

            // A reply implies a record, and no reply implies no record: an attestation is never
            // signed over a shard that was not written first.
            let custody = stopped(&context, mailbox, handle).await;
            assert_eq!(
                custody.get(&kept.commitment).await.expect("lookup"),
                Some(CustodyRecord {
                    index: INDEX,
                    shard: kept_shards[usize::from(INDEX)].clone(),
                })
            );
            assert_eq!(
                custody.get(&dropped.commitment).await.expect("lookup"),
                None
            );
        });
    }

    #[test]
    fn duplicate_dispersal_idempotent() {
        runner().start(|context| async move {
            let fixture = schemes();
            let (header, shards) = dispersal(50, 9);

            let custody = custody(&context, "custody").await;
            let (mut mailbox, handle) = start(
                &context,
                fixture.schemes[usize::from(INDEX)].clone(),
                custody,
                View::new(50),
            );

            // A gateway that missed the first reply sends the same request again.
            for _ in 0..2 {
                let response = dispatch(&mut mailbox, request(&header, &shards))
                    .await
                    .expect("attestation returned");
                verifies(&fixture, &header, &response);
            }

            // Both replies attest to one stored shard, not two.
            let custody = stopped(&context, mailbox, handle).await;
            assert_eq!(
                custody
                    .get_all(header.dispersal_view)
                    .await
                    .expect("lookup"),
                Some(vec![CustodyRecord {
                    index: INDEX,
                    shard: shards[usize::from(INDEX)].clone(),
                }])
            );
        });
    }

    #[test]
    fn same_batch_new_view_recustodies() {
        runner().start(|context| async move {
            let fixture = schemes();
            let (header, shards) = dispersal(50, 15);
            // The same batch, dispersed again later: identical commitment, a new claimed view.
            let later = BatchHeader::new(header.commitment, header.config, View::new(60));

            let custody = custody(&context, "custody").await;
            let (mut mailbox, handle) = start(
                &context,
                fixture.schemes[usize::from(INDEX)].clone(),
                custody,
                View::new(55),
            );
            let first = dispatch(&mut mailbox, request(&header, &shards))
                .await
                .expect("attestation returned");
            verifies(&fixture, &header, &first);
            let second = dispatch(&mut mailbox, request(&later, &shards))
                .await
                .expect("attestation returned");
            verifies(&fixture, &later, &second);

            // Held under both views, so custody outlives the later certificate rather than
            // expiring on the earlier dispersal's schedule.
            let custody = stopped(&context, mailbox, handle).await;
            let expected = Some(vec![CustodyRecord {
                index: INDEX,
                shard: shards[usize::from(INDEX)].clone(),
            }]);
            assert_eq!(
                custody.get_all(View::new(50)).await.expect("lookup"),
                expected
            );
            assert_eq!(
                custody.get_all(View::new(60)).await.expect("lookup"),
                expected
            );
        });
    }

    #[test]
    fn equivocating_dispersal_no_reply() {
        runner().start(|context| async move {
            let fixture = schemes();
            let (header, shards) = dispersal(50, 10);

            // Custody already holds a different shard under this commitment, whatever put it
            // there. The genuine dispersal cannot displace it.
            let mut custody = custody(&context, "custody").await;
            let held = CustodyRecord {
                index: INDEX,
                shard: shards[usize::from(INDEX) + 1].clone(),
            };
            custody
                .put(header.dispersal_view, header.commitment, held.clone())
                .await
                .expect("conflicting record stores");

            let (mut mailbox, handle) = start(
                &context,
                fixture.schemes[usize::from(INDEX)].clone(),
                custody,
                View::new(50),
            );
            assert!(
                dispatch(&mut mailbox, request(&header, &shards))
                    .await
                    .is_none()
            );

            let custody = stopped(&context, mailbox, handle).await;
            assert_eq!(
                custody.get(&header.commitment).await.expect("lookup"),
                Some(held)
            );
        });
    }

    #[test]
    fn rejects_verifier_only_scheme() {
        runner().start(|context| async move {
            let fixture = schemes();
            let custody = custody(&context, "custody").await;
            let built = Attestor::new(
                context.child("attestor"),
                Config {
                    scheme: fixture.verifier.clone(),
                    namespace: NAMESPACE.to_vec(),
                    watermark: Watermark::default(),
                    slack: ATTEST_SLACK,
                    mailbox_size: NZUsize!(8),
                },
                custody,
            );
            assert!(matches!(built, Err(Error::NoShardIndex)));
            assert_eq!(fixture.verifier.participants().len(), PARTICIPANTS as usize);
        });
    }
}
