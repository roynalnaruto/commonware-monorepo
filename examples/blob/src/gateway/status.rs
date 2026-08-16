//! Where every blob a gateway accepted has got to.
//!
//! One shared, bounded map from [`BlobId`] to a [`BlobStatus`] and the number of dispersals the
//! blob has already survived. The batcher marks a blob pending when it accepts one, the disperser
//! moves it on when its batch certifies or gives up, the consensus reporter marks it included, and
//! the client server reads it. All of them hold the same handle, so nobody has to ask anybody else.
//!
//! # Bounds
//!
//! Clients decide how many blobs to submit, so the map has to be bounded rather than left to grow
//! with submissions. Two rules keep it small, and both run on the write path, so there is no
//! sweeper task to schedule:
//!
//! - a terminal entry ([`BlobStatus::Certified`], [`BlobStatus::Included`], or
//!   [`BlobStatus::Failed`]) is dropped once it is older than the configured age, checked in a
//!   pass taken every [`SWEEP_WRITES`] writes rather than on each one;
//! - past the configured capacity, the oldest terminal entry is evicted, and only if nothing
//!   terminal remains is the oldest live entry dropped.
//!
//! Evicting an entry loses its attempt count as well as its status, which is why live entries go
//! last: a gateway under enough pressure to evict them will redisperse a blob it has already
//! given up on. A client that polls and finds nothing treats it exactly like a status it never
//! recorded, which is what it must do anyway for a blob submitted to a gateway that has since
//! restarted.

use crate::{types::BlobId, wire::BlobStatus};
use commonware_consensus::types::View;
use commonware_cryptography::transcript::Summary;
use commonware_runtime::Clock;
use commonware_utils::sync::Mutex;
use std::{
    collections::HashMap,
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, SystemTime},
};

/// What the board knows about one blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Where the blob has got to.
    pub status: BlobStatus,
    /// Dispersals of this blob that have already failed to reach a quorum.
    pub attempts: u8,
}

/// An [`Entry`] with the bookkeeping eviction needs.
#[derive(Clone, Debug)]
struct Tracked {
    entry: Entry,
    /// When the status was last written, for the terminal-entry age rule.
    written: SystemTime,
    /// Write order, so eviction can find the oldest entry without scanning by time.
    sequence: u64,
}

/// Writes between full passes over the map to apply the terminal-entry age rule.
const SWEEP_WRITES: u64 = 64;

/// Reports whether a status can still change.
const fn terminal(status: &BlobStatus) -> bool {
    !matches!(status, BlobStatus::Pending)
}

/// State behind the shared handle.
struct State {
    entries: HashMap<BlobId, Tracked>,
    next: u64,
}

/// The shared status map.
///
/// Cheap to clone: every clone is a handle onto the same map.
pub struct StatusBoard<E: Clock> {
    context: Arc<E>,
    capacity: usize,
    ttl: Duration,
    state: Arc<Mutex<State>>,
}

impl<E: Clock> Clone for StatusBoard<E> {
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
            capacity: self.capacity,
            ttl: self.ttl,
            state: self.state.clone(),
        }
    }
}

impl<E: Clock> StatusBoard<E> {
    /// Creates an empty board holding at most `capacity` entries and retaining a terminal entry
    /// for `ttl`.
    pub fn new(context: E, capacity: NonZeroUsize, ttl: Duration) -> Self {
        Self {
            context: Arc::new(context),
            capacity: capacity.get(),
            ttl,
            state: Arc::new(Mutex::new(State {
                entries: HashMap::new(),
                next: 0,
            })),
        }
    }

    /// Records that a gateway has accepted `id` into a batch it has not yet dispersed.
    ///
    /// Leaves the attempt count alone, so a blob returning from a failed dispersal keeps its
    /// history.
    pub fn pending(&self, id: BlobId) {
        self.write(id, BlobStatus::Pending);
    }

    /// Records that the batch carrying `id` reached a quorum of attestations.
    pub fn certified(&self, id: BlobId, commitment: Summary) {
        self.write(id, BlobStatus::Certified(commitment));
    }

    /// Records that the certificate over `commitment` was included in a finalized block at `view`.
    ///
    /// Takes the batch rather than the blob because that is what a finalized payload names: the
    /// consensus rail never learns which blobs a batch held. Every blob the board has certified
    /// under that commitment moves on, which is a scan of a map bounded by [`Self::new`]'s
    /// capacity and happens once per finalized certificate.
    pub fn included(&self, commitment: &Summary, view: View) {
        let now = self.context.current();
        let mut state = self.state.lock();
        for tracked in state.entries.values_mut() {
            if tracked.entry.status != BlobStatus::Certified(*commitment) {
                continue;
            }
            tracked.entry.status = BlobStatus::Included {
                commitment: *commitment,
                view,
            };
            tracked.written = now;
        }
    }

    /// Records that a gateway has given up on `id`.
    pub fn failed(&self, id: BlobId) {
        self.write(id, BlobStatus::Failed);
    }

    /// Records one more failed dispersal of `id` and returns the new count.
    ///
    /// The status is left as it is: whether the blob is redispersed or abandoned is the caller's
    /// decision, and it reports the outcome with [`StatusBoard::pending`] or
    /// [`StatusBoard::failed`]. A saturating count cannot wrap back under the retry bound.
    pub fn attempted(&self, id: BlobId) -> u8 {
        let now = self.context.current();
        let mut state = self.state.lock();
        let Some(tracked) = state.entries.get_mut(&id) else {
            // The entry was evicted, so its history is gone; see the module bounds.
            return 0;
        };
        tracked.entry.attempts = tracked.entry.attempts.saturating_add(1);
        tracked.written = now;
        tracked.entry.attempts
    }

    /// Returns what the board knows about `id`, if anything.
    pub fn get(&self, id: &BlobId) -> Option<Entry> {
        self.state.lock().entries.get(id).map(|t| t.entry.clone())
    }

    /// Returns the number of entries held.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.state.lock().entries.len()
    }

    /// Writes `status` for `id`.
    ///
    /// A new entry starts with no attempts; an existing one keeps the count it had, because the
    /// count is a property of the blob rather than of the batch it is currently in.
    fn write(&self, id: BlobId, status: BlobStatus) {
        let now = self.context.current();
        let mut state = self.state.lock();
        let sequence = state.next;
        state.next += 1;
        let tracked = state.entries.entry(id).or_insert_with(|| Tracked {
            entry: Entry {
                status: BlobStatus::Pending,
                attempts: 0,
            },
            written: now,
            sequence,
        });
        tracked.entry.status = status;
        tracked.written = now;
        tracked.sequence = sequence;
        self.evict(&mut state, now);
    }

    /// Applies both bounds.
    ///
    /// The age rule needs a pass over every entry, so it runs once every [`SWEEP_WRITES`] writes
    /// rather than on each one, and whenever the capacity rule is about to bite anyway. Between
    /// sweeps the map can hold terminal entries past their age but never more than its capacity.
    fn evict(&self, state: &mut State, now: SystemTime) {
        let full = state.entries.len() > self.capacity;
        if full || state.next.is_multiple_of(SWEEP_WRITES) {
            let ttl = self.ttl;
            state.entries.retain(|_, tracked| {
                !terminal(&tracked.entry.status)
                    || now
                        .duration_since(tracked.written)
                        .is_ok_and(|age| age < ttl)
            });
        }
        while state.entries.len() > self.capacity {
            // Prefer a terminal entry, and among equals the one written longest ago. Nothing is
            // ever certain to be terminal, so a board full of pending blobs still shrinks.
            let Some(victim) = state
                .entries
                .iter()
                .min_by_key(|(_, tracked)| (!terminal(&tracked.entry.status), tracked.sequence))
                .map(|(id, _)| *id)
            else {
                break;
            };
            state.entries.remove(&victim);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{poseidon2::Fr, test_util::blobs};
    use commonware_codec::DecodeExt as _;
    use commonware_runtime::{Runner, Supervisor as _, deterministic};
    use commonware_utils::NZUsize;

    /// A distinct identity per `seed`, without hashing a blob for each one.
    fn id(seed: u64) -> BlobId {
        BlobId::new(seed as usize, Fr::from(seed))
    }

    fn commitment(byte: u8) -> Summary {
        Summary::decode([byte; 32].as_slice()).expect("summary is 32 bytes")
    }

    fn runner() -> deterministic::Runner {
        deterministic::Runner::timed(Duration::from_secs(30))
    }

    #[test]
    fn transitions() {
        runner().start(|context| async move {
            let ttl = Duration::from_secs(10);
            let board = StatusBoard::new(context.child("status"), NZUsize!(4), ttl);

            // An identity nobody submitted is unknown, which is what a client sees for a blob a
            // restarted gateway has forgotten.
            assert_eq!(board.get(&id(1)), None);

            // The ordinary path: accepted, then certified.
            let blob = blobs(1, 256, 0x11).remove(0).id();
            board.pending(blob);
            assert_eq!(
                board.get(&blob),
                Some(Entry {
                    status: BlobStatus::Pending,
                    attempts: 0
                })
            );
            board.certified(blob, commitment(7));
            assert_eq!(
                board.get(&blob),
                Some(Entry {
                    status: BlobStatus::Certified(commitment(7)),
                    attempts: 0
                })
            );
            board.included(&commitment(7), View::new(42));
            assert_eq!(
                board.get(&blob).expect("blob is tracked").status,
                BlobStatus::Included {
                    commitment: commitment(7),
                    view: View::new(42)
                }
            );

            // The retry path: attempts accumulate across dispersals and survive a status write,
            // because they are a property of the blob rather than of the batch carrying it.
            let retried = id(2);
            board.pending(retried);
            assert_eq!(board.attempted(retried), 1);
            board.pending(retried);
            assert_eq!(board.attempted(retried), 2);
            assert_eq!(
                board.get(&retried),
                Some(Entry {
                    status: BlobStatus::Pending,
                    attempts: 2
                })
            );
            board.failed(retried);
            assert_eq!(
                board.get(&retried),
                Some(Entry {
                    status: BlobStatus::Failed,
                    attempts: 2
                })
            );

            // An unknown identity cannot accumulate attempts, so a blob whose entry was evicted
            // starts its budget again rather than reporting someone else's history.
            assert_eq!(board.attempted(id(99)), 0);
            assert_eq!(board.get(&id(99)), None);
        });
    }

    #[test]
    fn bounded() {
        runner().start(|context| async move {
            let ttl = Duration::from_secs(10);
            let board = StatusBoard::new(context.child("status"), NZUsize!(4), ttl);

            // Past the capacity, terminal entries go first: the two pending blobs survive while
            // the failed ones are dropped.
            let live = [id(1), id(2)];
            for id in live {
                board.pending(id);
            }
            for seed in 10..20 {
                board.failed(id(seed));
            }
            assert_eq!(board.len(), 4);
            for id in live {
                assert_eq!(
                    board.get(&id).expect("live blob is kept").status,
                    BlobStatus::Pending
                );
            }

            // With nothing terminal left to drop, the capacity is still honoured: the oldest live
            // entry goes, which is the bound the module documents.
            for seed in 20..30 {
                board.pending(id(seed));
            }
            assert_eq!(board.len(), 4);
            assert_eq!(board.get(&id(1)), None);
            assert_eq!(board.get(&id(29)).expect("newest is kept").attempts, 0);

            // A terminal entry ages out on its own, even under the capacity.
            let board = StatusBoard::new(context.child("aging"), NZUsize!(256), ttl);
            board.failed(id(1));
            board.pending(id(2));
            assert_eq!(board.len(), 2);
            context.sleep(ttl * 2).await;
            // The sweep runs on the write path, so it takes a write to observe it.
            for seed in 100..(100 + SWEEP_WRITES) {
                board.pending(id(seed));
            }
            assert_eq!(board.get(&id(1)), None, "aged-out failure is evicted");
            assert_eq!(
                board.get(&id(2)).expect("pending blob is kept").status,
                BlobStatus::Pending
            );
        });
    }
}
