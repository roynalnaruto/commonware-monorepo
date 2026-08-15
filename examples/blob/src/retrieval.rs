//! The read path: gather `minimum_shards` from the validators that certified a batch, and decode.
//!
//! A certificate says at least `2f + 1` validators custody a shard, so at least `f + 1` honest
//! ones do, and `f + 1` is exactly `minimum_shards`. That counting argument is what makes
//! retrieval targeted: one request per *signer*, addressed to that signer, rather than a broadcast
//! anyone may answer. A validator that never signed may hold nothing, and asking it would only
//! spend a round trip.
//!
//! # One phase
//!
//! Custodians serve the strong shard they stored, and the reader runs
//! [`weaken`](commonware_coding::PhasedScheme::weaken) on it. `weaken` validates *any* strong shard
//! against the commitment at the index it claims, not only one's own, so a reader needs no prior
//! checking data and no second round of shard exchange: bytes in, [`CheckedShard`] out, and
//! `minimum_shards` of those decode the batch. Weak shards therefore never appear on this wire.
//! They would save little in any case — at batch scale a weak shard is within a percent of a
//! strong one.
//!
//! # Trust
//!
//! Every byte here is adversarial. A custodian may serve garbage, another validator's shard, or
//! its shard under the wrong index; all three fail `weaken` against `(commitment, index)`, and the
//! resolver blocks the peer that sent them. What no custodian can do is make the reader accept
//! bytes that decode to something other than the committed batch, because the commitment binds the
//! encoding: shards that pass their check reconstruct the batch or they reconstruct nothing.

use crate::{
    assignment, attestor,
    constants::{MAX_CONCURRENT_SHARD_SERVES, coding_namespace},
    custody::CustodyRecord,
    registry::{Lookup, Registry},
    types::{Batch, DaCert, Scheme},
    wire::Coder,
};
use bytes::Bytes;
use commonware_actor::{
    Feedback,
    mailbox::{self, Policy, Receiver, Sender},
};
use commonware_codec::{
    Decode as _, DecodeExt as _, Encode as _, Error as CodecError, FixedSize, Read, ReadExt as _,
    Write,
};
use commonware_coding::{CodecConfig, Config as CodingConfig, PhasedScheme as _};
use commonware_cryptography::{ed25519, transcript::Summary};
use commonware_formatting::Hex;
use commonware_macros::select_loop;
use commonware_parallel::Strategy;
use commonware_resolver::{Delivery, Outcome, TargetedResolver};
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell,
    telemetry::metrics::{
        Counter, MetricsExt as _,
        status::{self, Status},
    },
};
use commonware_utils::{
    Span,
    channel::oneshot,
    concurrency::{Limiter, Reservation},
    vec::NonEmptyVec,
};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    fmt::{Display, Formatter},
    num::{NonZeroU32, NonZeroUsize},
    sync::Arc,
    time::Duration,
};
use tracing::{debug, warn};

/// Data derived from one strong shard, used to check others and to decode.
type CheckingData = <Coder as commonware_coding::PhasedScheme>::CheckingData;

/// A shard that has been bound to the commitment at its index.
type CheckedShard = <Coder as commonware_coding::PhasedScheme>::CheckedShard;

/// What retrieval asks a peer for: one validator's shard of one batch.
///
/// Fixed size and self-describing, which is what the resolver requires of a key: it is the whole
/// of what a peer sees, and validity of a response is decided against it alone. The index is not
/// redundant with the peer's identity — a custodian is asked for the shard it signed for, and
/// serving any other one is caught by the check rather than by trust in the addressing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShardKey {
    /// Commitment of the batch the shard belongs to.
    pub commitment: Summary,
    /// Position of the shard in the encoding, and of its custodian in the participant set.
    pub index: u16,
}

impl ShardKey {
    /// Names the shard `index` of the batch committed to by `commitment`.
    pub const fn new(commitment: Summary, index: u16) -> Self {
        Self { commitment, index }
    }
}

impl Display for ShardKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", Hex(self.commitment.as_ref()), self.index)
    }
}

impl Write for ShardKey {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.commitment.write(buf);
        self.index.write(buf);
    }
}

impl FixedSize for ShardKey {
    const SIZE: usize = Summary::SIZE + u16::SIZE;
}

impl Read for ShardKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            commitment: Summary::read(buf)?,
            index: u16::read(buf)?,
        })
    }
}

impl Span for ShardKey {}

/// Why a retrieval did not produce a batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// No certificate over this commitment has been finalized, as far as this node knows.
    #[error("no finalized certificate over this commitment")]
    Unknown,
    /// A certificate was finalized, but the batch is past its retrievability window.
    #[error("batch is past its retrievability window")]
    Expired,
    /// Not enough shards were gathered before the deadline.
    #[error("retrieval timed out")]
    Timeout,
    /// Enough shards were gathered, but they did not reconstruct a batch.
    ///
    /// Two failures share this name, and neither is worth retrying. Reconstruction itself failing
    /// is unreachable: every shard counted was bound to the commitment by
    /// [`weaken`](commonware_coding::PhasedScheme::weaken), and `minimum_shards` such shards
    /// reconstruct the committed bytes or the commitment did not bind them. What is reachable is
    /// the second step: the committed bytes are whatever the gateway chose to encode, and nothing
    /// on the write path checks that they parse as a batch. Gathering more shards would only
    /// reproduce the same bytes.
    #[error("gathered shards did not decode to a batch")]
    Decode,
    /// The coordinator, or work it delegated, stopped before the retrieval finished.
    #[error("retrieval coordinator is stopped")]
    Internal,
}

/// Work handed to the [`Coordinator`].
enum Message {
    /// Somebody wants the batch behind a commitment.
    Fetch {
        commitment: Summary,
        response: oneshot::Sender<Result<(Batch, DaCert), Error>>,
    },
    /// A peer answered a shard request.
    Deliver {
        key: ShardKey,
        value: Bytes,
        outcome: oneshot::Sender<Outcome>,
    },
    /// This node's own custody answered.
    Local {
        commitment: Summary,
        gather: u64,
        record: Box<CustodyRecord>,
    },
    /// A shard finished its coding check.
    ///
    /// Boxed because checking data and a checked shard together dwarf every other message.
    Checked {
        commitment: Summary,
        gather: u64,
        index: u16,
        checked: Option<Box<(CheckingData, CheckedShard)>>,
    },
    /// A decode finished.
    Decoded {
        commitment: Summary,
        gather: u64,
        bytes: Option<Vec<u8>>,
    },
    /// A retrieval ran out of time.
    Expire { commitment: Summary, gather: u64 },
}

impl Policy for Message {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut VecDeque<Self>, message: Self) {
        // Nothing here can be recovered by dropping it: a fetch is a caller waiting, a delivery
        // owes the resolver an outcome, and the rest are results of work already done.
        overflow.push_back(message);
    }
}

/// Handle to a [`Coordinator`].
#[derive(Clone)]
pub struct Mailbox {
    sender: Sender<Message>,
}

impl Mailbox {
    /// Asks for the batch behind `commitment`.
    ///
    /// Resolves once the batch has been reconstructed, or with the reason it could not be. Several
    /// callers may ask for the same batch: they share one gather and are all answered by it.
    pub fn fetch(&self, commitment: Summary) -> oneshot::Receiver<Result<(Batch, DaCert), Error>> {
        let (response, receiver) = oneshot::channel();
        if !self
            .sender
            .enqueue(Message::Fetch {
                commitment,
                response,
            })
            .accepted()
        {
            // The responder went with the dropped message, so the caller sees a closed channel;
            // saying so here is what turns that into a reason.
            debug!(?commitment, "retrieval coordinator is stopped");
        }
        receiver
    }
}

/// Serves this node's custodied shards to other readers.
///
/// Custody belongs to the attestor, which is the only writer of it, so serving goes through the
/// attestor's mailbox rather than through a second handle on the store. The attestor sits on no
/// consensus path, so the extra hop costs a message and buys a single owner.
///
/// # Bounded
///
/// How many shards are asked for at once is decided by peers, and each answer is a custody read
/// and an encode of up to a whole shard. At most [`MAX_CONCURRENT_SHARD_SERVES`] of them run
/// together; past that a request is answered with nothing, which the resolver reads as "no data
/// here" and retries later against the same custodian. Shedding is a delay rather than a loss:
/// the shard exists nowhere else, so nobody else was going to answer instead.
pub struct Producer<E: Metrics + Spawner> {
    context: Arc<E>,
    attestor: attestor::Mailbox,
    /// Serves in flight, shared by every clone of this producer.
    inflight: Arc<Limiter>,
    /// Serves, by whether they answered, found nothing, or were shed.
    served: status::Counter,
}

impl<E: Metrics + Spawner> Clone for Producer<E> {
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
            attestor: self.attestor.clone(),
            inflight: self.inflight.clone(),
            served: self.served.clone(),
        }
    }
}

impl<E: Metrics + Spawner> Producer<E> {
    /// Builds a producer that serves out of `attestor`'s custody.
    pub fn new(context: E, attestor: attestor::Mailbox) -> Self {
        let served = context.family("served", "Number of shard requests served by outcome");
        let limit = NonZeroU32::new(MAX_CONCURRENT_SHARD_SERVES as u32)
            .expect("the serve bound is not zero");
        Self {
            context: Arc::new(context),
            attestor,
            inflight: Arc::new(Limiter::new(limit)),
            served,
        }
    }
}

impl<E: Metrics + Spawner> commonware_resolver::p2p::Producer for Producer<E> {
    type Key = ShardKey;

    fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes> {
        let (response, receiver) = oneshot::channel();
        let Some(permit) = self.inflight.try_acquire() else {
            debug!(%key, "shard serves are at their bound; request shed");
            self.served.inc(Status::Dropped);
            return receiver;
        };
        let attestor = self.attestor.clone();
        let served = self.served.clone();
        self.context.child("serve").spawn(move |_| async move {
            // Held for the whole answer, so the bound counts work in flight rather than requests
            // accepted.
            let _permit: Reservation = permit;

            // Dropping the responder is how "I do not have this" is said: the requester is told
            // there is no data and tries again later, and nobody is blamed for it.
            let Some(record) = attestor.fetch(key.commitment).await else {
                debug!(%key, "no shard held for this key");
                served.inc(Status::Failure);
                return;
            };
            if record.index != key.index {
                debug!(%key, held = record.index, "held shard is for another index");
                served.inc(Status::Failure);
                return;
            }
            let _ = response.send(record.encode());
            served.inc(Status::Success);
        });
        receiver
    }
}

/// Hands shard responses to the [`Coordinator`].
///
/// The resolver decides what to do with a peer from the outcome this returns, so an outcome is
/// always sent: a dropped responder is read as invalid data and would block a peer that did
/// nothing wrong.
#[derive(Clone)]
pub struct Consumer {
    sender: Sender<Message>,
}

impl commonware_resolver::Consumer for Consumer {
    type Key = ShardKey;
    type Value = Bytes;
    type Subscriber = ();
    type Outcome = Outcome;

    fn deliver(
        &mut self,
        delivery: Delivery<Self::Key, Self::Subscriber>,
        value: Self::Value,
    ) -> oneshot::Receiver<Self::Outcome> {
        let (outcome, receiver) = oneshot::channel();
        let key = delivery.key;
        let message = Message::Deliver {
            key,
            value,
            outcome,
        };
        if self.sender.enqueue(message) == Feedback::Closed {
            // The enqueue took the responder with it. A resolver that hears nothing treats the
            // response as invalid and blocks the peer, so a stopped coordinator would punish
            // whoever answered last; answer for it instead.
            debug!(%key, "retrieval coordinator is stopped; response ignored");
            return closed();
        }
        receiver
    }
}

/// A receiver already resolved to [`Outcome::Ignored`].
fn closed() -> oneshot::Receiver<Outcome> {
    let (sender, receiver) = oneshot::channel();
    let _ = sender.send(Outcome::Ignored);
    receiver
}

/// Configuration for a [`Coordinator`].
pub struct Config<T: Strategy> {
    /// The attestation scheme, which names the participant set a signer index points into.
    pub scheme: Scheme,
    /// Base namespace of the deployment.
    pub namespace: Vec<u8>,
    /// Certificates this node has seen finalized.
    pub registry: Registry,
    /// The attestor, which owns this node's custody.
    pub attestor: attestor::Mailbox,
    /// Decode bounds for a shard served by a peer.
    pub shard: CodecConfig,
    /// How long a retrieval may take before it is abandoned.
    pub timeout: Duration,
    /// Messages buffered before the mailbox spills to its overflow queue.
    pub mailbox_size: NonZeroUsize,
    /// Parallelism for decoding.
    pub strategy: T,
}

/// Builds the coordinator's mailbox ahead of the actor.
///
/// The resolver engine needs the [`Consumer`] before it yields the handle the coordinator fetches
/// through, so the mailbox is built first and the actor last.
pub fn mailbox(context: &impl Metrics, size: NonZeroUsize) -> (Mailbox, Consumer, Inbox) {
    let (sender, receiver) = mailbox::new(context.child("mailbox"), size);
    (
        Mailbox {
            sender: sender.clone(),
        },
        Consumer {
            sender: sender.clone(),
        },
        Inbox { sender, receiver },
    )
}

/// The receiving half of a [`mailbox()`] pair, and the handle the actor answers itself through.
pub struct Inbox {
    sender: Sender<Message>,
    receiver: Receiver<Message>,
}

/// Where a shard about to be checked came from.
enum Source {
    /// Served by a peer, so it still has to be decoded and is owed a verdict.
    Served(Bytes),
    /// Read out of this node's own custody.
    Held(CustodyRecord),
}

/// One retrieval in progress.
struct Gather {
    /// The certificate the retrieval is against, returned with the batch.
    cert: DaCert,
    /// Coding parameters, taken from the attested header rather than from any peer.
    config: CodingConfig,
    /// Checking data from the first shard that passed, which is what decoding runs against.
    checking: Option<CheckingData>,
    /// Checked shards, keyed by index so one custodian cannot count twice.
    shards: BTreeMap<u16, CheckedShard>,
    /// Callers waiting on this batch.
    waiters: Vec<oneshot::Sender<Result<(Batch, DaCert), Error>>>,
    /// Whether a decode has already been started.
    decoding: bool,
    /// Identifies this gather, so results of an abandoned one are not applied to its successor.
    id: u64,
}

/// The retrieval actor.
pub struct Coordinator<E: Clock + Metrics + Spawner, R: TargetedResolver, T: Strategy> {
    context: ContextCell<E>,
    scheme: Scheme,
    coding: Vec<u8>,
    registry: Registry,
    attestor: attestor::Mailbox,
    resolver: R,
    shard: CodecConfig,
    timeout: Duration,
    strategy: T,
    /// Batches reconstructed, by whether they were returned, timed out, or would not decode.
    gathered: status::Counter,
    /// Shards that failed their coding check.
    invalid: Counter,
    /// This node's own position, whose shard comes from custody rather than the network.
    index: Option<u16>,
    gathers: HashMap<Summary, Gather>,
    next: u64,
    sender: Sender<Message>,
    mailbox: Receiver<Message>,
}

impl<E, R, T> Coordinator<E, R, T>
where
    E: Clock + Metrics + Spawner,
    R: TargetedResolver<Key = ShardKey, Subscriber = (), PublicKey = ed25519::PublicKey>,
    T: Strategy,
{
    /// Builds the coordinator over the receiving half of a [`mailbox()`] pair.
    pub fn new(context: E, config: Config<T>, inbox: Inbox, resolver: R) -> Self {
        let index = assignment::my_index(&config.scheme);
        let gathered = context.family("gathered", "Number of retrievals by outcome");
        let invalid = context.counter("invalid", "Number of shards that failed their coding check");
        Self {
            context: ContextCell::new(context),
            coding: coding_namespace(&config.namespace),
            scheme: config.scheme,
            registry: config.registry,
            attestor: config.attestor,
            resolver,
            shard: config.shard,
            timeout: config.timeout,
            strategy: config.strategy,
            gathered,
            invalid,
            index,
            gathers: HashMap::new(),
            next: 0,
            sender: inbox.sender,
            mailbox: inbox.receiver,
        }
    }

    /// Starts the actor.
    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        select_loop! {
            self.context,
            on_stopped => {
                debug!(gathers = self.gathers.len(), "context shutdown, stopping coordinator");
            },
            Some(message) = self.mailbox.recv() else break => {
                self.handle(message);
            },
        }
    }

    /// Runs one message to completion.
    fn handle(&mut self, message: Message) {
        match message {
            Message::Fetch {
                commitment,
                response,
            } => self.open(commitment, response),
            Message::Deliver {
                key,
                value,
                outcome,
            } => {
                // A response for a batch this node is no longer gathering is neither valid nor
                // invalid: it is unwanted, and the peer that served it should not be judged on
                // bytes nobody will look at.
                let Some(gather) = self.gathers.get(&key.commitment) else {
                    debug!(%key, "response for a retrieval that is no longer open");
                    let _ = outcome.send(Outcome::Ignored);
                    return;
                };
                if gather.shards.contains_key(&key.index) {
                    let _ = outcome.send(Outcome::Ignored);
                    return;
                }
                let (id, config) = (gather.id, gather.config);
                self.verify(key, id, config, Source::Served(value), Some(outcome));
            }
            Message::Local {
                commitment,
                gather,
                record,
            } => {
                let Some(open) = self.gathers.get(&commitment) else {
                    return;
                };
                if open.id != gather || open.shards.contains_key(&record.index) {
                    return;
                }
                let (config, key) = (open.config, ShardKey::new(commitment, record.index));
                self.verify(key, gather, config, Source::Held(*record), None);
            }
            Message::Checked {
                commitment,
                gather,
                index,
                checked,
            } => self.collect(commitment, gather, index, checked),
            Message::Decoded {
                commitment,
                gather,
                bytes,
            } => self.finish(commitment, gather, bytes),
            Message::Expire { commitment, gather } => {
                let Some(open) = self.gathers.get(&commitment) else {
                    return;
                };
                if open.id != gather {
                    return;
                }
                let held = open.shards.len();
                warn!(
                    ?commitment,
                    held, "retrieval did not gather enough shards in time"
                );
                self.retire(&commitment, Err(Error::Timeout));
            }
        }
    }

    /// Starts a retrieval, or attaches the caller to one already running.
    fn open(
        &mut self,
        commitment: Summary,
        response: oneshot::Sender<Result<(Batch, DaCert), Error>>,
    ) {
        if let Some(gather) = self.gathers.get_mut(&commitment) {
            gather.waiters.push(response);
            return;
        }
        let cert = match self.registry.lookup(&commitment) {
            Lookup::Live { cert, .. } => *cert,
            Lookup::Expired => {
                let _ = response.send(Err(Error::Expired));
                return;
            }
            Lookup::Unknown => {
                let _ = response.send(Err(Error::Unknown));
                return;
            }
        };

        let id = self.next;
        self.next += 1;
        let config = cert.header.config;
        let signers: Vec<u16> = cert
            .certificate
            .signers
            .iter()
            .filter_map(|participant| u16::try_from(participant.get()).ok())
            .collect();
        self.gathers.insert(
            commitment,
            Gather {
                cert,
                config,
                checking: None,
                shards: BTreeMap::new(),
                waiters: vec![response],
                decoding: false,
                id,
            },
        );

        // The shard this node custodies itself, if it has one, costs no round trip. It is checked
        // the same way as any other: custody is durable storage, not a source of truth about
        // coding.
        let sender = self.sender.clone();
        let attestor = self.attestor.clone();
        self.context.child("custody").spawn(move |_| async move {
            let Some(record) = attestor.fetch(commitment).await else {
                return;
            };
            let _ = sender.enqueue(Message::Local {
                commitment,
                gather: id,
                record: Box::new(record),
            });
        });

        // One request per signer, addressed to that signer. Signers are the only validators a
        // certificate promises anything about, and the promise is per index, so a request that
        // could be answered by anyone would be a request nothing backs.
        let mut keys = Vec::with_capacity(signers.len());
        for index in signers {
            if Some(index) == self.index {
                continue;
            }
            let Some(custodian) = assignment::key_of(&self.scheme, index) else {
                continue;
            };
            keys.push((
                ShardKey::new(commitment, index),
                NonEmptyVec::new(custodian.clone()),
            ));
        }
        let targets = keys.len();
        if !self.resolver.fetch_all_targeted(keys).accepted() {
            warn!(?commitment, "resolver is stopped");
            self.retire(&commitment, Err(Error::Internal));
            return;
        }
        debug!(?commitment, targets, "retrieval opened");

        // One deadline for the whole gather. The resolver retries individual custodians on its
        // own; what this bounds is the caller's wait.
        let sender = self.sender.clone();
        let timeout = self.timeout;
        self.context
            .child("deadline")
            .spawn(move |context| async move {
                context.sleep(timeout).await;
                let _ = sender.enqueue(Message::Expire {
                    commitment,
                    gather: id,
                });
            });
    }

    /// Checks a shard against `key`, on the shared executor, and reports the result both ways.
    ///
    /// `outcome` is present when the shard came off the wire, because then a peer is waiting to
    /// be judged on it; the shard this node custodies itself owes nobody a verdict.
    fn verify(
        &mut self,
        key: ShardKey,
        gather: u64,
        config: CodingConfig,
        source: Source,
        outcome: Option<oneshot::Sender<Outcome>>,
    ) {
        let bound = self.shard.clone();
        let namespace = self.coding.clone();
        let sender = self.sender.clone();
        // Decoding a shard and weakening it are both milliseconds of work on a large batch, so
        // neither runs on the actor's task.
        self.context
            .child("weaken")
            .shared(true)
            .spawn(move |_| async move {
                let checked = match source {
                    Source::Held(record) => run(&namespace, &config, &key, record),
                    Source::Served(value) => {
                        match CustodyRecord::decode_cfg(value.as_ref(), &bound) {
                            // The index a peer served under has to be the index it was asked
                            // for; anything else is a shard of this batch aimed at somebody else,
                            // and weakening it under the wrong index would fail anyway.
                            Ok(record) if record.index == key.index => {
                                run(&namespace, &config, &key, record)
                            }
                            Ok(record) => {
                                debug!(%key, served = record.index, "served shard is for another index");
                                None
                            }
                            Err(err) => {
                                debug!(%key, ?err, "served bytes are not a custody record");
                                None
                            }
                        }
                    }
                };
                if let Some(outcome) = outcome {
                    let _ = outcome.send(if checked.is_some() {
                        Outcome::Complete
                    } else {
                        Outcome::Invalid
                    });
                }
                let _ = sender.enqueue(Message::Checked {
                    commitment: key.commitment,
                    gather,
                    index: key.index,
                    checked,
                });
            });
    }

    /// Takes a checked shard, and decodes once there are enough of them.
    fn collect(
        &mut self,
        commitment: Summary,
        gather: u64,
        index: u16,
        checked: Option<Box<(CheckingData, CheckedShard)>>,
    ) {
        let Some(open) = self.gathers.get_mut(&commitment) else {
            return;
        };
        if open.id != gather {
            return;
        }
        let Some(checked) = checked else {
            debug!(?commitment, index, "shard failed its coding check");
            self.invalid.inc();
            return;
        };
        let (checking, shard) = *checked;
        open.checking.get_or_insert(checking);
        open.shards.insert(index, shard);
        let held = open.shards.len();
        let needed = usize::from(open.config.minimum_shards.get());
        if open.decoding || held < needed {
            debug!(?commitment, held, needed, "shard checked");
            return;
        }
        open.decoding = true;

        // Enough shards. Decoding is the expensive half of retrieval, measured near half a second
        // for an 8 MiB batch, so it goes to the shared executor.
        let config = open.config;
        let checking = open
            .checking
            .clone()
            .expect("a checked shard sets checking");
        let shards: Vec<CheckedShard> = open.shards.values().cloned().collect();
        let strategy = self.strategy.clone();
        let sender = self.sender.clone();
        self.context
            .child("decode")
            .shared(true)
            .spawn(move |_| async move {
                let bytes = Coder::decode(&config, &commitment, checking, shards.iter(), &strategy)
                    .map_err(|err| debug!(?commitment, ?err, "decode failed"))
                    .ok();
                let _ = sender.enqueue(Message::Decoded {
                    commitment,
                    gather,
                    bytes,
                });
            });
    }

    /// Turns decoded bytes back into a batch and answers the callers.
    fn finish(&mut self, commitment: Summary, gather: u64, bytes: Option<Vec<u8>>) {
        let Some(open) = self.gathers.get(&commitment) else {
            return;
        };
        if open.id != gather {
            return;
        }
        // The batch is self-describing: the decoded bytes alone carry every blob, which is what
        // lets a reader rederive identities and the blob tree without asking the gateway. It is
        // also where a gateway that certified bytes which are not a batch is found out, and the
        // gather is retired rather than reopened: see [`Error::Decode`].
        let result = bytes.map_or(Err(Error::Decode), |bytes| {
            Batch::decode(bytes.as_slice()).map_err(|err| {
                warn!(?commitment, ?err, "decoded bytes are not a batch");
                Error::Decode
            })
        });
        self.retire(&commitment, result);
    }

    /// Answers every caller waiting on `commitment` and cancels its outstanding requests.
    fn retire(&mut self, commitment: &Summary, result: Result<Batch, Error>) {
        let Some(gather) = self.gathers.remove(commitment) else {
            return;
        };
        self.gathered.inc(match result {
            Ok(_) => Status::Success,
            Err(Error::Timeout) => Status::Timeout,
            Err(_) => Status::Failure,
        });
        for waiter in gather.waiters {
            let _ = waiter.send(result.clone().map(|batch| (batch, gather.cert.clone())));
        }

        // Whatever is still outstanding for this batch is no longer worth a peer's bandwidth.
        // Every other retrieval's keys are kept, which is what makes concurrent fetches
        // independent.
        let commitment = *commitment;
        if !self
            .resolver
            .retain(move |key, ()| key.commitment != commitment)
            .accepted()
        {
            debug!(?commitment, "resolver is stopped; nothing to cancel");
        }
    }
}

/// Checks `record` against the commitment at the index `key` names.
///
/// Returns the checking data and the checked shard, or `None` if the bytes are not that shard.
fn run(
    namespace: &[u8],
    config: &CodingConfig,
    key: &ShardKey,
    record: CustodyRecord,
) -> Option<Box<(CheckingData, CheckedShard)>> {
    match Coder::weaken(namespace, config, &key.commitment, key.index, record.shard) {
        Ok((checking, checked, _)) => Some(Box::new((checking, checked))),
        Err(err) => {
            debug!(%key, ?err, "shard is not this batch's shard at this index");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        attestor::{Attestor, Watermark},
        constants::{
            ATTEST_SLACK, NAMESPACE, RETRIEVAL_CHANNEL, RETRIEVAL_TIMEOUT_SIM, SHARD_FETCH_INITIAL,
            SHARD_FETCH_RETRY_SIM, SHARD_FETCH_TIMEOUT_SIM,
        },
        custody::Custody,
        poseidon2::Fr,
        test_util::{self, Keys, LINK, PARTICIPANTS, QUORUM, Role, Serve, Watcher},
        types::BatchHeader,
        wire::StrongShard,
    };
    use commonware_consensus::types::View;
    use commonware_cryptography::{Signer as _, certificate::mocks::Fixture};
    use commonware_p2p::simulated::{Control, Link};
    use commonware_parallel::Sequential;
    use commonware_resolver::p2p as shards;
    use commonware_runtime::{Runner, Supervisor as _, deterministic};
    use commonware_utils::NZUsize;
    use std::time::Duration;

    /// Partition prefix shared by every store in these tests.
    const PREFIX: &str = "p5";

    /// View every batch in these tests is dispersed at.
    const VIEW: u64 = 40;

    /// Shards needed to reconstruct at `n = 10`: `f + 1`.
    const MINIMUM: usize = 4;

    /// The validator that reads. Deliberately outside the signer set, so it holds no shard of its
    /// own and every shard it uses came off the wire.
    const READER: usize = 9;

    /// The mailbox a resolver engine is driven through.
    type Shards = shards::Mailbox<ShardKey, ed25519::PublicKey, ()>;

    /// A blocker that records who a node blocked.
    type Blocker = Watcher<Control<ed25519::PublicKey, deterministic::Context>>;

    fn runner() -> deterministic::Runner {
        deterministic::Runner::timed(Duration::from_secs(120))
    }

    /// What each validator does when asked for a shard.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Behaviour {
        /// Serves whatever it custodies.
        Honest,
        /// Answers nothing.
        Silent,
        /// Answers with a shard that is not the one asked for.
        Forged,
    }

    /// Returns `PARTICIPANTS` behaviours, all honest except the listed positions.
    fn behaviours(exceptions: &[(usize, Behaviour)]) -> Vec<Behaviour> {
        let mut roles = vec![Behaviour::Honest; PARTICIPANTS as usize];
        for (index, role) in exceptions {
            roles[*index] = *role;
        }
        roles
    }

    /// A deployment of custodians and readers over one simulated network.
    struct Deployment {
        keys: Keys,
        fixture: Fixture<Scheme>,
        /// Every validator's retrieval handle, indexed by position.
        coordinators: Vec<Mailbox>,
        /// Every validator's finalized-certificate registry, indexed by position.
        registries: Vec<Registry>,
        /// Every validator's blocker, indexed by position.
        blockers: Vec<Blocker>,
        /// Every validator's producer, indexed by position, for its request count.
        serves: Vec<Serve<deterministic::Context>>,
        /// Held for the deployment's lifetime: a resolver engine whose mailbox has been dropped
        /// stops, and a stopped engine serves nobody.
        _resolvers: Vec<Shards>,
    }

    /// Builds the deployment: one custody, attestor, resolver engine and coordinator per
    /// validator, over a network whose links `link` decides.
    async fn deploy(
        context: &deterministic::Context,
        batches: &[(&BatchHeader, &[StrongShard])],
        holders: &[usize],
        roles: &[Behaviour],
        link: impl Fn(usize, usize) -> Link,
    ) -> Deployment {
        let keys = test_util::keys(PARTICIPANTS as usize);
        let fixture = test_util::attesting(&keys);
        let peers: Vec<ed25519::PublicKey> = keys
            .privates
            .iter()
            .map(|private| private.public_key())
            .collect();
        let oracle = test_util::network_linked(context, &peers, link).await;

        let mut coordinators = Vec::new();
        let mut registries = Vec::new();
        let mut blockers = Vec::new();
        let mut serves = Vec::new();
        let mut resolvers = Vec::new();
        for (index, peer) in peers.iter().enumerate() {
            let node = context.child("validator").with_attribute("index", index);

            // Custody, holding this validator's shard if the test says it kept one. Written
            // before the attestor takes ownership, which is the same state a restart would leave.
            let mut custody = Custody::init(
                node.child("custody"),
                &format!("{PREFIX}-{index}"),
                test_util::shard_cfg(),
            )
            .await
            .expect("custody opens");
            if holders.contains(&index) {
                for (header, shards) in batches {
                    custody
                        .put(
                            header.dispersal_view,
                            header.commitment,
                            CustodyRecord {
                                index: index as u16,
                                shard: shards[index].clone(),
                            },
                        )
                        .await
                        .expect("shard stores");
                }
            }
            let (attestor, attestor_mailbox) = Attestor::new(
                node.child("attestor"),
                crate::attestor::Config {
                    scheme: fixture.schemes[index].clone(),
                    namespace: NAMESPACE.to_vec(),
                    watermark: Watermark::new(View::new(VIEW)),
                    slack: ATTEST_SLACK,
                    mailbox_size: NZUsize!(64),
                },
                custody,
            )
            .expect("attestor builds");
            attestor.start();

            let serve = Serve::new(match roles[index] {
                Behaviour::Honest => Role::Honest(Producer::new(
                    node.child("producer"),
                    attestor_mailbox.clone(),
                )),
                Behaviour::Silent => Role::Silent,
                // A record that decodes cleanly and carries the index that was asked for, so
                // nothing short of the coding check catches it.
                Behaviour::Forged => Role::Forged(
                    CustodyRecord {
                        index: index as u16,
                        shard: test_util::corrupt(&batches[0].1[index]),
                    }
                    .encode(),
                ),
            });
            serves.push(serve.clone());

            let blocker = Watcher::new(oracle.control(peer.clone()));
            blockers.push(blocker.clone());
            let registry = Registry::new();
            registries.push(registry.clone());

            let retrieval_context = node.child("retrieval");
            let (mailbox, consumer, inbox) = mailbox(&retrieval_context, NZUsize!(256));
            let (engine, resolver) = shards::Engine::new(
                node.child("shards"),
                shards::Config {
                    peer_provider: oracle.manager(),
                    blocker,
                    consumer,
                    producer: serve,
                    mailbox_size: NZUsize!(256),
                    me: Some(peer.clone()),
                    initial: SHARD_FETCH_INITIAL,
                    timeout: SHARD_FETCH_TIMEOUT_SIM,
                    fetch_retry_timeout: SHARD_FETCH_RETRY_SIM,
                    priority_requests: false,
                    priority_responses: false,
                },
            );
            engine.start(test_util::register(&oracle, peer, RETRIEVAL_CHANNEL).await);
            Coordinator::new(
                node.child("coordinator"),
                Config {
                    scheme: fixture.schemes[index].clone(),
                    namespace: NAMESPACE.to_vec(),
                    registry,
                    attestor: attestor_mailbox,
                    shard: test_util::shard_cfg(),
                    timeout: RETRIEVAL_TIMEOUT_SIM,
                    mailbox_size: NZUsize!(256),
                    strategy: Sequential,
                },
                inbox,
                resolver.clone(),
            )
            .start();

            coordinators.push(mailbox);
            resolvers.push(resolver);
        }
        Deployment {
            keys,
            fixture,
            coordinators,
            registries,
            blockers,
            serves,
            _resolvers: resolvers,
        }
    }

    /// A certificate a quorum of `signers` really attested to, over `header`.
    fn certify(deployment: &Deployment, header: &BatchHeader, signers: usize) -> DaCert {
        test_util::genuine_cert(
            &deployment.fixture,
            header,
            &deployment.keys.privates[0],
            Fr::from(7u64),
            signers,
        )
    }

    #[test]
    fn p5_retrieval_roundtrip_f_plus_1_of_signers() {
        runner().start(|context| async move {
            let (header, shards) = test_util::dispersal(VIEW, 0x11);
            let expected = test_util::sample_batch(0x11);

            // Seven validators signed, so seven custody a shard. Only the first four answer;
            // the rest are as good as crashed. Four is `minimum_shards`, so four is enough.
            let holders: Vec<usize> = (0..QUORUM).collect();
            let silent: Vec<(usize, Behaviour)> = (MINIMUM..QUORUM)
                .map(|index| (index, Behaviour::Silent))
                .collect();
            let deployment = deploy(
                &context,
                &[(&header, &shards)],
                &holders,
                &behaviours(&silent),
                |_, _| LINK.clone(),
            )
            .await;

            let cert = certify(&deployment, &header, QUORUM);
            deployment.registries[READER].record(cert.clone(), View::new(VIEW + 1));

            let (batch, returned) = deployment.coordinators[READER]
                .fetch(header.commitment)
                .await
                .expect("coordinator answers")
                .expect("batch is retrieved");
            assert_eq!(batch, expected);
            assert_eq!(returned, cert);

            // The reader is not a signer and custodies nothing, so every shard it used came off
            // the wire, and only the four that answered could have supplied one.
            for index in MINIMUM..QUORUM {
                assert!(
                    deployment.serves[index].requests() > 0,
                    "validator {index} was never asked"
                );
            }
            assert!(deployment.blockers[READER].blocked().is_empty());
        });
    }

    #[test]
    fn p5_retrieval_rejects_forged_shard() {
        runner().start(|context| async move {
            let (header, shards) = test_util::dispersal(VIEW, 0x22);
            let expected = test_util::sample_batch(0x22);

            // Every signer holds its shard; the first one serves a corrupted copy of it.
            let holders: Vec<usize> = (0..QUORUM).collect();
            let deployment = deploy(
                &context,
                &[(&header, &shards)],
                &holders,
                &behaviours(&[(0, Behaviour::Forged)]),
                // The forger answers first. Otherwise the honest shards could complete the
                // gather before the forgery is even looked at, and the test would be asserting
                // about scheduling rather than about validation.
                |from, to| {
                    if from == 0 && to == READER {
                        Link {
                            latency: Duration::from_millis(5),
                            jitter: Duration::ZERO,
                            success_rate: 1.0,
                        }
                    } else {
                        Link {
                            latency: Duration::from_millis(150),
                            jitter: Duration::ZERO,
                            success_rate: 1.0,
                        }
                    }
                },
            )
            .await;

            let cert = certify(&deployment, &header, QUORUM);
            deployment.registries[READER].record(cert, View::new(VIEW + 1));

            let (batch, _) = deployment.coordinators[READER]
                .fetch(header.commitment)
                .await
                .expect("coordinator answers")
                .expect("batch is retrieved from the honest custodians");
            assert_eq!(batch, expected, "a forged shard changed the batch");

            // The forger is named, and nobody else is.
            let forger = deployment.keys.privates[0].public_key();
            assert_eq!(
                deployment.blockers[READER].blocked(),
                vec![forger],
                "the forged shard did not cost its sender anything"
            );
        });
    }

    #[test]
    fn p5_coordinator_completes_at_threshold_cancels_rest() {
        runner().start(|context| async move {
            let (header, shards) = test_util::dispersal(VIEW, 0x33);

            // Four custodians answer and three never will. The three are what the cancellation
            // is measured on: without it the resolver retries them until the deadline.
            let holders: Vec<usize> = (0..MINIMUM).collect();
            let silent: Vec<(usize, Behaviour)> = (MINIMUM..QUORUM)
                .map(|index| (index, Behaviour::Silent))
                .collect();
            let deployment = deploy(
                &context,
                &[(&header, &shards)],
                &holders,
                &behaviours(&silent),
                |_, _| LINK.clone(),
            )
            .await;

            let cert = certify(&deployment, &header, QUORUM);
            deployment.registries[READER].record(cert, View::new(VIEW + 1));
            deployment.coordinators[READER]
                .fetch(header.commitment)
                .await
                .expect("coordinator answers")
                .expect("batch is retrieved");

            // Whatever the silent custodians had been asked for by the time the batch arrived,
            // they are asked for nothing more: the fetches were retained away.
            let settled: Vec<usize> = (MINIMUM..QUORUM)
                .map(|index| deployment.serves[index].requests())
                .collect();
            context.sleep(RETRIEVAL_TIMEOUT_SIM * 3).await;
            let after: Vec<usize> = (MINIMUM..QUORUM)
                .map(|index| deployment.serves[index].requests())
                .collect();
            assert_eq!(settled, after, "outstanding requests were not cancelled");

            // A second retrieval of the same batch still works, so cancelling did not poison
            // anything: it retired keys rather than the coordinator.
            deployment.coordinators[READER]
                .fetch(header.commitment)
                .await
                .expect("coordinator answers")
                .expect("batch is retrieved again");
        });
    }

    #[test]
    fn p5_coordinator_times_out_cleanly_when_unavailable() {
        runner().start(|context| async move {
            let (header, shards) = test_util::dispersal(VIEW, 0x44);

            // One custodian short of what reconstruction needs, and nothing else on offer.
            let holders: Vec<usize> = (0..MINIMUM - 1).collect();
            let silent: Vec<(usize, Behaviour)> = (MINIMUM - 1..QUORUM)
                .map(|index| (index, Behaviour::Silent))
                .collect();
            let deployment = deploy(
                &context,
                &[(&header, &shards)],
                &holders,
                &behaviours(&silent),
                |_, _| LINK.clone(),
            )
            .await;

            let cert = certify(&deployment, &header, QUORUM);
            deployment.registries[READER].record(cert, View::new(VIEW + 1));

            let started = context.current();
            let outcome = deployment.coordinators[READER]
                .fetch(header.commitment)
                .await
                .expect("coordinator answers");
            assert_eq!(outcome.unwrap_err(), Error::Timeout);
            assert!(
                context.current() >= started + RETRIEVAL_TIMEOUT_SIM,
                "gave up before the deadline"
            );

            // Nobody is blamed: a custodian that says nothing has not misbehaved.
            assert!(deployment.blockers[READER].blocked().is_empty());

            // And the coordinator is still serving, which is the difference between a timeout
            // and a failure.
            assert_eq!(
                deployment.coordinators[READER]
                    .fetch(test_util::summary(0xaa))
                    .await
                    .expect("coordinator answers")
                    .unwrap_err(),
                Error::Unknown
            );
        });
    }

    #[test]
    fn p6_producer_bounds_concurrent_serves() {
        runner().start(|context| async move {
            // An attestor whose actor is never started: its mailbox takes reads and nothing on
            // the other side completes them, so every serve this producer starts stays in flight.
            let custody = Custody::init(
                context.child("custody"),
                &format!("{PREFIX}-bound"),
                test_util::shard_cfg(),
            )
            .await
            .expect("custody opens");
            let fixture = test_util::attesting(&test_util::keys(PARTICIPANTS as usize));
            let (idle, mailbox) = Attestor::new(
                context.child("attestor"),
                crate::attestor::Config {
                    scheme: fixture.schemes[0].clone(),
                    namespace: NAMESPACE.to_vec(),
                    watermark: Watermark::new(View::new(VIEW)),
                    slack: ATTEST_SLACK,
                    mailbox_size: NZUsize!(64),
                },
                custody,
            )
            .expect("attestor builds");
            let mut producer = Producer::new(context.child("producer"), mailbox);

            // The bound is taken before the work is spawned, so saturating it needs no scheduling
            // and no clock: the requests are simply outstanding.
            let commitment = test_util::summary(0x77);
            let held: Vec<_> = (0..MAX_CONCURRENT_SHARD_SERVES)
                .map(|index| {
                    commonware_resolver::p2p::Producer::produce(
                        &mut producer,
                        ShardKey::new(commitment, index as u16),
                    )
                })
                .collect();

            // One past it is answered with nothing, which is what the resolver reads as "no data
            // here" and retries later. Shedding blames nobody and loses nothing.
            let shed = commonware_resolver::p2p::Producer::produce(
                &mut producer,
                ShardKey::new(commitment, MAX_CONCURRENT_SHARD_SERVES as u16),
            );
            assert!(
                shed.await.is_err(),
                "a request past the bound was taken on anyway"
            );
            let encoded = context.encode();
            assert!(
                encoded.contains("served_total{status=\"Dropped\"} 1"),
                "the shed request was not counted:\n{encoded}"
            );

            // Releasing the outstanding serves lets the next request through, so the bound counts
            // work in flight rather than requests ever made.
            drop(idle);
            for receiver in held {
                assert!(receiver.await.is_err(), "an idle attestor answered");
            }
            context.sleep(Duration::from_millis(10)).await;
            let after = commonware_resolver::p2p::Producer::produce(
                &mut producer,
                ShardKey::new(commitment, 1),
            );
            assert!(after.await.is_err(), "an idle attestor answered");
            let encoded = context.encode();
            assert!(
                encoded.contains("served_total{status=\"Dropped\"} 1"),
                "a request inside the bound was shed:\n{encoded}"
            );
        });
    }

    #[test]
    fn p6_retrieval_rejects_certified_non_batch() {
        runner().start(|context| async move {
            // A gateway chooses what it encodes. Attestors check that a shard belongs to the
            // commitment and nothing more, so a quorum can certify bytes that are not a batch.
            let (header, shards) = test_util::dispersal_of(VIEW, Bytes::from(vec![0xffu8; 2048]));
            let holders: Vec<usize> = (0..QUORUM).collect();
            let deployment = deploy(
                &context,
                &[(&header, &shards)],
                &holders,
                &behaviours(&[]),
                |_, _| LINK.clone(),
            )
            .await;
            let cert = certify(&deployment, &header, QUORUM);
            deployment.registries[READER].record(cert, View::new(VIEW + 1));

            // Reconstruction succeeds and parsing does not, which is the one way this error is
            // reachable. It is reported rather than retried: more shards would rebuild the same
            // bytes.
            let result = deployment.coordinators[READER]
                .fetch(header.commitment)
                .await
                .expect("coordinator answers");
            assert_eq!(result.err(), Some(Error::Decode));

            // Nobody is blamed for it. Every custodian served the shard it signed for, so the
            // fault is the gateway's and it is not a reason to block a peer.
            assert!(deployment.blockers[READER].blocked().is_empty());

            // And the gather was retired rather than wedged: asking again opens a fresh one and
            // reaches the same conclusion, instead of attaching to a gather that never ends.
            assert_eq!(
                deployment.coordinators[READER]
                    .fetch(header.commitment)
                    .await
                    .expect("coordinator answers")
                    .err(),
                Some(Error::Decode),
                "a second request did not run to its own conclusion"
            );
        });
    }

    #[test]
    fn p5_retrieval_after_expiry_fails_cleanly() {
        runner().start(|context| async move {
            let (header, shards) = test_util::dispersal(VIEW, 0x55);
            let (orphan, _) = test_util::dispersal(VIEW, 0x56);

            // Every signer answers, and none of them holds anything: their custody has been
            // pruned even though the certificate has not aged out of the registry yet.
            let deployment = deploy(
                &context,
                &[(&header, &shards)],
                &[],
                &behaviours(&[]),
                |_, _| LINK.clone(),
            )
            .await;
            let registry = &deployment.registries[READER];
            let coordinator = &deployment.coordinators[READER];

            // A batch nobody ever finalized is unknown, and no request is sent for it.
            assert_eq!(
                coordinator
                    .fetch(orphan.commitment)
                    .await
                    .expect("coordinator answers")
                    .unwrap_err(),
                Error::Unknown
            );

            // A live certificate whose shards are gone times out rather than answering wrongly.
            let cert = certify(&deployment, &header, QUORUM);
            registry.record(cert, View::new(VIEW + 1));
            assert_eq!(
                coordinator
                    .fetch(header.commitment)
                    .await
                    .expect("coordinator answers")
                    .unwrap_err(),
                Error::Timeout
            );

            // The horizon itself, `D + FRESHNESS + WINDOW`, is not quite the end: custody drops
            // whole sections and the registry follows it, so a batch part-way into a section is
            // still promised because its shards are still on disk.
            registry.prune(View::new(VIEW + 32 + 64 + 1));
            assert_eq!(
                coordinator
                    .fetch(header.commitment)
                    .await
                    .expect("coordinator answers")
                    .unwrap_err(),
                Error::Timeout
            );

            // A section further on, custody has let go and so has the registry, and the answer
            // becomes immediate.
            registry.prune(View::new(
                VIEW + 32 + 64 + crate::constants::ITEMS_PER_SECTION.get(),
            ));
            assert_eq!(
                coordinator
                    .fetch(header.commitment)
                    .await
                    .expect("coordinator answers")
                    .unwrap_err(),
                Error::Expired
            );
            assert!(deployment.blockers[READER].blocked().is_empty());
        });
    }

    #[test]
    fn p5_retrieval_serves_concurrent_commitments() {
        runner().start(|context| async move {
            let (first, first_shards) = test_util::dispersal(VIEW, 0x66);
            let (second, second_shards) = test_util::dispersal(VIEW, 0x67);
            assert_ne!(first.commitment, second.commitment);

            // Both batches are custodied by the same validators, so the two gathers share every
            // peer and only the keys tell them apart.
            let holders: Vec<usize> = (0..QUORUM).collect();
            let deployment = deploy(
                &context,
                &[(&first, &first_shards), (&second, &second_shards)],
                &holders,
                &behaviours(&[]),
                |_, _| LINK.clone(),
            )
            .await;

            for header in [&first, &second] {
                let cert = certify(&deployment, header, QUORUM);
                deployment.registries[READER].record(cert, View::new(VIEW + 1));
            }

            // Both in flight at once, and neither cancels the other: `fetch` enqueues and
            // returns, so the second gather starts before the first is awaited.
            let a = deployment.coordinators[READER].fetch(first.commitment);
            let b = deployment.coordinators[READER].fetch(second.commitment);
            let (a, b) = (a.await, b.await);
            assert_eq!(
                a.expect("coordinator answers").expect("first is retrieved"),
                (
                    test_util::sample_batch(0x66),
                    certify(&deployment, &first, QUORUM)
                )
            );
            assert_eq!(
                b.expect("coordinator answers")
                    .expect("second is retrieved")
                    .0,
                test_util::sample_batch(0x67)
            );
        });
    }
}
