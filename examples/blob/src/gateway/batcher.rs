//! Intake: turn a stream of client blobs into sealed batches.
//!
//! A batch seals when it reaches its byte target or when its timer runs out, whichever comes
//! first. The timer starts with the first blob of a batch, so an idle gateway does not seal empty
//! batches and a busy one never holds a blob longer than the timeout.
//!
//! # Hashing off the loop
//!
//! A [`BlobId`] is a Poseidon2 digest over the whole blob, which is by far the most expensive part
//! of accepting one: measured serially, a full batch of them takes longer than the batch timer
//! itself. [`Mailbox::submit`] therefore computes the identity on a shared executor and hands the
//! actor the blob and its identity together. The loop never hashes, so intake never stalls behind
//! a submission, and sealing is left with the tree fold and the header.
//!
//! # Backpressure
//!
//! Sealed batches go to the disperser over a bounded channel. When the disperser is behind, the
//! send waits, and the batcher stops draining its mailbox while it does. Submissions queue, the
//! timer keeps running, and the batch that eventually forms is larger. That is the behavior worth
//! having: under load the gateway makes fewer, fuller batches rather than more, smaller ones.

use super::status::StatusBoard;
use crate::{
    attestor::Watermark,
    types::{BatchBuilder, Blob, BlobId, Error, Sealed},
};
use commonware_actor::mailbox::{self, Policy, Receiver, Sender};
use commonware_coding::Config as CodingConfig;
use commonware_consensus::types::View;
use commonware_macros::select_loop;
use commonware_runtime::{Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell};
use commonware_utils::channel::mpsc;
use std::{collections::VecDeque, num::NonZeroUsize, sync::Arc, time::Duration};
use tracing::{debug, warn};

/// A sealed batch on its way to the disperser.
///
/// Carries the two header fields that are known at seal time. The third, the commitment, does not
/// exist until the batch has been encoded, so the disperser is what completes the header.
pub struct Job {
    /// The batch, its blob tree, and the position of each identity in it.
    pub sealed: Sealed,
    /// View the gateway is dispersing at, read from the shared watermark when the batch sealed.
    pub view: View,
    /// Coding parameters the batch will be encoded with.
    pub config: CodingConfig,
}

/// Work handed to the batcher.
enum Message {
    /// A client submitted a blob, whose identity the submit path has already computed.
    Submit { blob: Blob, id: BlobId },
    /// A blob whose batch failed to certify, returning for another dispersal.
    Retry { blob: Blob, id: BlobId },
}

impl Policy for Message {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut VecDeque<Self>, message: Self) {
        // Both kinds are worth keeping: a dropped submission is a blob a client believes was
        // accepted, and a dropped retry is a blob already counted against its attempt budget.
        overflow.push_back(message);
    }
}

/// Handle to a [`Batcher`].
pub struct Mailbox<E: Metrics + Spawner> {
    context: Arc<E>,
    sender: Sender<Message>,
}

impl<E: Metrics + Spawner> Clone for Mailbox<E> {
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
            sender: self.sender.clone(),
        }
    }
}

impl<E: Metrics + Spawner> Mailbox<E> {
    /// Submits a blob, returning the identity a client polls its status with.
    ///
    /// Returns `None` if the batcher has stopped. Acceptance into a batch is decided by the actor
    /// and shows up on the status board; a blob already in the open batch is dropped there.
    pub async fn submit(&mut self, blob: Blob) -> Option<BlobId> {
        // The one CPU-bound step of intake, kept off both this task and the actor's.
        let hashed = blob.clone();
        let id = self
            .context
            .child("blob_id")
            .shared(true)
            .spawn(move |_| async move { hashed.id() })
            .await
            .ok()?;
        self.sender
            .enqueue(Message::Submit { blob, id })
            .accepted()
            .then_some(id)
    }

    /// Returns a blob to intake after the batch carrying it failed to certify.
    ///
    /// Cheaper than [`Mailbox::submit`] and not async: the identity is already known, so there is
    /// nothing to hash. Enqueueing never waits, which is what keeps the disperser from deadlocking
    /// against a batcher that is itself waiting to hand over a sealed batch.
    pub fn retry(&self, blob: Blob, id: BlobId) -> bool {
        self.sender.enqueue(Message::Retry { blob, id }).accepted()
    }
}

/// Configuration for a [`Batcher`].
pub struct Config<E: Clock> {
    /// Encoded batch bytes at which a batch is worth sealing.
    pub target: usize,
    /// How long an undersized batch waits for more blobs.
    pub timeout: Duration,
    /// Coding parameters, derived from the participant set.
    pub coding: CodingConfig,
    /// The last finalized view, shared with the attestor and the consensus reporter.
    pub watermark: Watermark,
    /// Where accepted blobs are recorded.
    pub board: StatusBoard<E>,
    /// Submissions buffered before the mailbox spills to its overflow queue.
    pub mailbox_size: NonZeroUsize,
}

/// The intake actor.
pub struct Batcher<E: Clock + Metrics + Spawner> {
    context: ContextCell<E>,
    target: usize,
    timeout: Duration,
    coding: CodingConfig,
    watermark: Watermark,
    board: StatusBoard<E>,
    mailbox: Receiver<Message>,
    batches: mpsc::Sender<Job>,
}

impl<E: Clock + Metrics + Spawner> Batcher<E> {
    /// Builds a batcher that hands sealed batches to `batches`, returning it with its handle.
    pub fn new(context: E, config: Config<E>, batches: mpsc::Sender<Job>) -> (Self, Mailbox<E>) {
        let (sender, receiver) = mailbox::new(context.child("mailbox"), config.mailbox_size);
        let mailbox = Mailbox {
            context: Arc::new(context.child("submit")),
            sender,
        };
        (
            Self {
                context: ContextCell::new(context),
                target: config.target,
                timeout: config.timeout,
                coding: config.coding,
                watermark: config.watermark,
                board: config.board,
                mailbox: receiver,
                batches,
            },
            mailbox,
        )
    }

    /// Starts the actor.
    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        let mut builder = BatchBuilder::new(self.target);
        // Absolute rather than a duration so the timer survives being recreated on every pass of
        // the loop; it is only moved forward when a batch seals or when it expires empty.
        let mut deadline = self.context.current() + self.timeout;
        select_loop! {
            self.context,
            on_stopped => {
                debug!(open = builder.len(), "context shutdown, stopping batcher");
            },
            Some(message) = self.mailbox.recv() else break => {
                // The two arrivals differ only in where the identity came from: a submission had
                // it computed off this task, a retry already knew it. From here they are alike.
                let (Message::Submit { blob, id } | Message::Retry { blob, id }) = message;
                if builder.is_empty() {
                    deadline = self.context.current() + self.timeout;
                }

                // A blob the open batch has no room for is not a rejection: seal what is there
                // and let the blob open the next batch. A blob always fits an empty batch, so the
                // second attempt only fails if something is badly wrong. Only a duplicate is
                // refused outright, because a batch holding one identity twice has an ambiguous
                // index map.
                match builder.push(blob.clone(), id) {
                    Ok(()) => {}
                    Err(Error::DuplicateBlob(_)) => {
                        debug!(%id, "blob is already in the open batch");
                        continue;
                    }
                    Err(_) => {
                        builder = self.seal(builder).await;
                        deadline = self.context.current() + self.timeout;
                        if let Err(err) = builder.push(blob, id) {
                            warn!(%id, ?err, "blob fits no batch at all");
                            continue;
                        }
                    }
                }
                self.board.pending(id);
                if builder.is_full() {
                    builder = self.seal(builder).await;
                    deadline = self.context.current() + self.timeout;
                }
            },
            _ = self.context.sleep_until(deadline) => {
                if !builder.is_empty() {
                    builder = self.seal(builder).await;
                }
                deadline = self.context.current() + self.timeout;
            },
        }
    }

    /// Seals the open batch and hands it to the disperser, returning a fresh builder.
    ///
    /// Waits for room in the disperser's queue, which is the backpressure described in the module
    /// documentation.
    async fn seal(&mut self, builder: BatchBuilder) -> BatchBuilder {
        let blobs = builder.len();
        let sealed = match builder.seal() {
            Ok(sealed) => sealed,
            Err(err) => {
                // The builder enforces every bound `seal` re-checks, so this is unreachable
                // short of a bug; drop the batch rather than retry it into the same failure.
                warn!(blobs, ?err, "open batch could not be sealed");
                return BatchBuilder::new(self.target);
            }
        };
        let job = Job {
            // Stamped now rather than at dispersal so the view an attestor checks is the view the
            // gateway believed was current when it committed to the batch.
            view: self.watermark.get(),
            config: self.coding,
            sealed,
        };
        debug!(blobs, view = job.view.get(), "sealed batch");
        if self.batches.send(job).await.is_err() {
            debug!("disperser is gone; sealed batch dropped");
        }
        BatchBuilder::new(self.target)
    }
}

/// Returns the blobs of a sealed batch paired with their identities, in batch order.
///
/// The identities are the ones the builder accepted, so nothing is rehashed. Used by the
/// disperser, which needs them to write the status board and to return blobs to intake.
pub fn identified(sealed: &Sealed) -> Vec<(Blob, BlobId)> {
    let blobs = sealed.batch.blobs();
    let mut paired = Vec::with_capacity(blobs.len());
    for (id, index) in &sealed.indexes {
        if let Some(blob) = blobs.get(*index) {
            paired.push((*index, blob.clone(), *id));
        }
    }
    paired.sort_by_key(|(index, _, _)| *index);
    paired.into_iter().map(|(_, blob, id)| (blob, id)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        assignment::coding_config,
        constants::{BATCH_TIMEOUT_SIM, MAX_BLOBS_PER_BATCH, MAX_TRACKED_BLOBS, STATUS_TTL},
        test_util::{PARTICIPANTS, blobs},
        wire::BlobStatus,
    };
    use commonware_codec::EncodeSize as _;
    use commonware_runtime::{Runner, Supervisor as _, deterministic};
    use commonware_utils::{NZUsize, channel::mpsc};

    /// Bytes at which the batches in these tests seal, small enough to reach with a few blobs.
    const TARGET: usize = 8 * 1024;

    fn runner() -> deterministic::Runner {
        deterministic::Runner::timed(Duration::from_secs(30))
    }

    /// Starts a batcher with a queue of `capacity` sealed batches.
    #[allow(clippy::type_complexity)]
    fn start(
        context: &deterministic::Context,
        target: usize,
        timeout: Duration,
        capacity: usize,
    ) -> (
        Mailbox<deterministic::Context>,
        StatusBoard<deterministic::Context>,
        mpsc::Receiver<Job>,
        Handle<()>,
    ) {
        let board = StatusBoard::new(
            context.child("status"),
            NZUsize!(MAX_TRACKED_BLOBS),
            STATUS_TTL,
        );
        let (sender, receiver) = mpsc::channel(capacity);
        let (batcher, mailbox) = Batcher::new(
            context.child("batcher"),
            Config {
                target,
                timeout,
                coding: coding_config(PARTICIPANTS as usize).expect("participants can be coded"),
                watermark: Watermark::new(View::new(7)),
                board: board.clone(),
                mailbox_size: NZUsize!(64),
            },
            sender,
        );
        (mailbox, board, receiver, batcher.start())
    }

    #[test]
    fn p3_batcher_flush_on_size() {
        runner().start(|context| async move {
            let (mut mailbox, board, mut batches, _handle) =
                start(&context, TARGET, BATCH_TIMEOUT_SIM, 4);

            // Four blobs of a quarter of the target each: the fourth crosses it.
            let sample = blobs(4, TARGET / 4, 0xa1);
            let mut ids = Vec::new();
            for blob in &sample {
                ids.push(
                    mailbox
                        .submit(blob.clone())
                        .await
                        .expect("blob is accepted"),
                );
            }

            // Sealing happened on size, well inside the timer.
            let sealed_at = context.current();
            let job = batches.recv().await.expect("batch is sealed");
            assert!(
                context
                    .current()
                    .duration_since(sealed_at)
                    .expect("time moves forward")
                    < BATCH_TIMEOUT_SIM
            );
            assert_eq!(job.sealed.batch.len(), 4);
            assert_eq!(job.view, View::new(7));
            assert_eq!(job.config.minimum_shards.get(), 4);

            // The identities the actor accepted are the ones the submit path computed, and each
            // blob is pending as soon as it is accepted.
            for (index, id) in ids.iter().enumerate() {
                assert_eq!(job.sealed.indexes.get(id), Some(&index));
                assert_eq!(
                    board.get(id).expect("blob is tracked").status,
                    BlobStatus::Pending
                );
            }
            assert_eq!(job.sealed.root(), job.sealed.batch.root().expect("root"));
        });
    }

    #[test]
    fn p3_batcher_flush_on_timeout() {
        runner().start(|context| async move {
            let (mut mailbox, _board, mut batches, _handle) =
                start(&context, TARGET, BATCH_TIMEOUT_SIM, 4);

            // One small blob, nowhere near the target.
            let blob = blobs(1, 512, 0xb2).remove(0);
            let start = context.current();
            let id = mailbox.submit(blob).await.expect("blob is accepted");

            // The timer, not the target, is what seals it.
            let job = batches.recv().await.expect("batch is sealed");
            let waited = context
                .current()
                .duration_since(start)
                .expect("time moves forward");
            assert!(waited >= BATCH_TIMEOUT_SIM, "sealed after {waited:?}");
            assert_eq!(job.sealed.batch.len(), 1);
            assert_eq!(job.sealed.indexes.get(&id), Some(&0));

            // An idle gateway seals nothing: the timer keeps expiring with an empty builder.
            let idle = context.current();
            let mut sleep = Box::pin(context.sleep(BATCH_TIMEOUT_SIM * 4));
            commonware_macros::select! {
                _ = &mut sleep => {},
                job = batches.recv() => panic!("empty batch sealed: {:?}", job.is_some()),
            }
            assert!(
                context
                    .current()
                    .duration_since(idle)
                    .expect("time moves forward")
                    >= BATCH_TIMEOUT_SIM * 4
            );
        });
    }

    #[test]
    fn p3_batcher_bounds_batch() {
        runner().start(|context| async move {
            // A target no batch can reach and a timer no test outlives, so only the count bound
            // is left to seal one. Hashing a blob is real work, and the deterministic clock
            // advances while a submission waits on it, so the timer has to be generous.
            let (mut mailbox, _board, mut batches, _handle) =
                start(&context, usize::MAX, Duration::from_secs(5), 4);
            let sample = blobs(MAX_BLOBS_PER_BATCH + 8, 64, 0xc3);
            for blob in &sample {
                mailbox
                    .submit(blob.clone())
                    .await
                    .expect("blob is accepted");
            }

            let job = batches.recv().await.expect("batch is sealed");
            assert_eq!(job.sealed.batch.len(), MAX_BLOBS_PER_BATCH);
            assert!(job.sealed.batch.encode_size() <= crate::constants::MAX_BATCH_SIZE);

            // The blobs that did not fit opened the next batch rather than being lost.
            let job = batches.recv().await.expect("second batch is sealed");
            assert_eq!(job.sealed.batch.len(), 8);
        });
    }

    #[test]
    fn p3_batcher_duplicate_rejected() {
        runner().start(|context| async move {
            let (mut mailbox, board, mut batches, _handle) =
                start(&context, usize::MAX, BATCH_TIMEOUT_SIM, 4);
            let blob = blobs(1, 1024, 0xd4).remove(0);

            // The same bytes submitted twice have the same identity, and a batch holds it once.
            let first = mailbox
                .submit(blob.clone())
                .await
                .expect("blob is accepted");
            let second = mailbox
                .submit(blob.clone())
                .await
                .expect("blob is accepted");
            assert_eq!(first, second);

            let job = batches.recv().await.expect("batch is sealed");
            assert_eq!(job.sealed.batch.len(), 1);
            assert_eq!(job.sealed.indexes.len(), 1);
            assert_eq!(board.len(), 1);
            assert_eq!(
                board.get(&first).expect("blob is tracked").status,
                BlobStatus::Pending
            );

            // A blob returning from a failed dispersal joins the next batch without rehashing.
            assert!(mailbox.retry(blob, first));
            let job = batches.recv().await.expect("second batch is sealed");
            assert_eq!(job.sealed.indexes.get(&first), Some(&0));
        });
    }
}
