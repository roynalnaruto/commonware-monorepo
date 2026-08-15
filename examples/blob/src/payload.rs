//! Consensus payloads: durable storage, and the ancestry that makes a certificate includable once.
//!
//! Bare simplex orders digests. Everything a node needs in order to decide whether a payload is
//! valid at the position consensus offers it lives here: the payload itself, so a child's parent
//! link can be followed, and the set of commitments each payload carries, so a certificate already
//! on this fork is not carried twice.
//!
//! # Two structures, one truth
//!
//! Payloads are written to a prunable archive keyed by view, which is what survives a restart, and
//! are indexed in memory by digest, which is what an ancestry walk follows. The in-memory index is
//! rebuilt from the archive at startup, so the two never disagree about anything that matters: a
//! payload absent from the archive is absent from the index of the next run.
//!
//! Forks share views, so the archive is written with `put_multi`: a plain put would keep the first
//! payload proposed at a view and silently discard every competing one, which is exactly the case
//! ancestry has to reason about.
//!
//! # Dedup horizon
//!
//! An ancestry walk is bounded by [`FRESHNESS`]. A certificate dispersed at view `D` may only be
//! included at a view `H` with `D <= H <= D + FRESHNESS`, so a certificate fresh enough to be
//! included now cannot have been included in a payload more than `FRESHNESS` views below the tip.
//! Walking further would cost more and decide nothing.
//!
//! # Ownership
//!
//! [`prunable::Archive`] is move-through, so [`PayloadStore`] holds it in an [`Option`] and rebinds
//! after every mutation, exactly as [`Custody`](crate::custody::Custody) does. A failed mutation
//! leaves the slot empty and every later call returns [`Error::Poisoned`]: a store whose contents
//! are unknown cannot be allowed to answer questions about what this node has already accepted.

use crate::{
    constants::{FRESHNESS, ITEMS_PER_SECTION},
    wire::Payload,
};
use commonware_consensus::types::View;
use commonware_cryptography::{Digestible as _, sha256, transcript::Summary};
use commonware_runtime::{BufferPooler, Metrics, Storage, buffer::paged::CacheRef};
use commonware_storage::{
    archive::{
        Archive as _, Error as ArchiveError, MultiArchive as _,
        prunable::{self, Archive},
    },
    translator::TwoCap,
};
use commonware_utils::{NZU16, NZUsize};
use std::{
    collections::{HashMap, HashSet},
    num::{NonZeroU16, NonZeroUsize},
    sync::Arc,
};

/// Page size of the key journal's cache.
const PAGE_SIZE: NonZeroU16 = NZU16!(1024);

/// Pages held by the key journal's cache.
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(16);

/// Bytes buffered before a journal write reaches storage.
const IO_BUFFER_SIZE: NonZeroUsize = NZUsize!(4096);

/// Failures of the payload store.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The archive itself failed.
    #[error("archive: {0}")]
    Archive(#[from] ArchiveError),
    /// A previous mutation failed, so the store no longer holds an archive.
    #[error("payload store was poisoned by a failed mutation")]
    Poisoned,
}

/// One payload and the certificates it carries.
struct Node {
    payload: Arc<Payload>,
    /// Commitments carried, for membership tests that do not touch the certificates themselves.
    certs: HashSet<Summary>,
}

impl Node {
    fn new(payload: Arc<Payload>) -> Self {
        let certs = payload.commitments().collect();
        Self { payload, certs }
    }
}

/// Payloads this node has accepted, and their ancestry.
pub struct PayloadStore<E: BufferPooler + Metrics + Storage> {
    archive: Option<Archive<TwoCap, E, sha256::Digest, Payload>>,
    nodes: HashMap<sha256::Digest, Node>,
    genesis: sha256::Digest,
}

impl<E: BufferPooler + Metrics + Storage> PayloadStore<E> {
    /// Opens the store, rebuilding the ancestry index from whatever a previous run left behind.
    ///
    /// `prefix` names the partitions, so two stores sharing a prefix share their contents.
    /// `participants` bounds the signer bitmap of every certificate read back.
    pub async fn init(context: E, prefix: &str, participants: usize) -> Result<Self, Error> {
        let cfg = prunable::Config {
            translator: TwoCap,
            key_partition: format!("{prefix}-payload-key"),
            key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            value_partition: format!("{prefix}-payload-value"),
            compression: None,
            codec_config: participants,
            items_per_section: ITEMS_PER_SECTION,
            key_write_buffer: IO_BUFFER_SIZE,
            value_write_buffer: IO_BUFFER_SIZE,
            replay_buffer: IO_BUFFER_SIZE,
        };
        let archive: Archive<TwoCap, E, sha256::Digest, Payload> =
            Archive::init(context, cfg).await?;

        // Replay every retained view. The ranges are collected first because walking them borrows
        // the archive that the reads below also borrow.
        let ranges: Vec<(u64, u64)> = archive.ranges().collect();
        let mut nodes = HashMap::new();
        for (start, end) in ranges {
            for index in start..=end {
                let Some(payloads) = archive.get_all(index).await? else {
                    continue;
                };
                for payload in payloads {
                    let payload = Arc::new(payload);
                    nodes.insert(payload.digest(), Node::new(payload));
                }
            }
        }

        // Genesis is well known rather than stored: every walk ends at it, including the first
        // walk of a chain that has finalized nothing.
        let genesis = Arc::new(Payload::genesis());
        let digest = genesis.digest();
        nodes.entry(digest).or_insert_with(|| Node::new(genesis));
        Ok(Self {
            archive: Some(archive),
            nodes,
            genesis: digest,
        })
    }

    /// Returns the digest of the genesis payload, which anchors the consensus floor.
    pub const fn genesis(&self) -> sha256::Digest {
        self.genesis
    }

    /// Stores `payload`, indexed by its digest and archived at its view.
    ///
    /// Idempotent: a payload already held is not written again, which is what lets a proposer
    /// store what it is about to propose and then store it again when consensus asks it to be
    /// verified. Returns only once the write is durable, because returning a digest to consensus
    /// commits this node to verifying the same bytes after a restart.
    pub async fn insert(&mut self, payload: Arc<Payload>) -> Result<(), Error> {
        let digest = payload.digest();
        if self.nodes.contains_key(&digest) {
            return Ok(());
        }
        let archive = self.archive.take().ok_or(Error::Poisoned)?;
        self.archive = Some(
            archive
                .put_multi_sync(payload.view.get(), digest, (*payload).clone())
                .await?,
        );
        self.nodes.insert(digest, Node::new(payload));
        Ok(())
    }

    /// Returns the payload with `digest`, if this node holds it.
    pub fn get(&self, digest: &sha256::Digest) -> Option<Arc<Payload>> {
        self.nodes.get(digest).map(|node| node.payload.clone())
    }

    /// Returns whether the fork ending at `tip` already carries `commitment`.
    ///
    /// The walk stops at genesis, at the freshness horizon below `tip`, or at a parent this node
    /// does not hold. The last case answers "not included", which is the only answer a node
    /// without the ancestry can give; a caller that must not guess checks [`PayloadStore::get`]
    /// on the parent first.
    pub fn included(&self, tip: &sha256::Digest, commitment: &Summary) -> bool {
        let Some(mut current) = self.nodes.get(tip) else {
            return false;
        };
        let floor = current.payload.view.saturating_sub(FRESHNESS);
        loop {
            if current.certs.contains(commitment) {
                return true;
            }
            if current.payload.view <= floor {
                return false;
            }
            let Some(parent) = self.nodes.get(&current.payload.parent) else {
                return false;
            };
            // Views strictly decrease along parent links, which is what bounds this walk. A pair
            // that says otherwise is not ancestry and is not followed.
            if parent.payload.view >= current.payload.view {
                return false;
            }
            current = parent;
        }
    }

    /// Returns the fork ending at `tip`, newest first.
    ///
    /// Unlike [`PayloadStore::included`] this is not bounded by the freshness horizon: it walks as
    /// far as the store still holds, which is as far as the last [`PayloadStore::prune`] left.
    pub fn ancestry(&self, tip: &sha256::Digest) -> Vec<Arc<Payload>> {
        let mut chain = Vec::new();
        let mut cursor = self.nodes.get(tip);
        while let Some(current) = cursor {
            chain.push(current.payload.clone());
            if current.payload.view.is_zero() {
                break;
            }
            cursor = self
                .nodes
                .get(&current.payload.parent)
                .filter(|parent| parent.payload.view < current.payload.view);
        }
        chain
    }

    /// Drops every payload that can no longer take part in a dedup decision.
    ///
    /// A certificate includable at a view at or above `finalized` was dispersed no earlier than
    /// `finalized - FRESHNESS`, so a payload below that view can neither be an ancestor worth
    /// walking nor carry a certificate worth remembering. Genesis is kept regardless: it costs one
    /// entry and it terminates every walk.
    pub async fn prune(&mut self, finalized: View) -> Result<(), Error> {
        let floor = finalized.saturating_sub(FRESHNESS);
        let archive = self.archive.take().ok_or(Error::Poisoned)?;
        self.archive = Some(archive.prune(floor.get()).await?);
        let genesis = self.genesis;
        self.nodes
            .retain(|digest, node| *digest == genesis || node.payload.view >= floor);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{PARTICIPANTS, stub_cert, summary};
    use commonware_runtime::{Runner, Supervisor as _, deterministic};
    use std::time::Duration;

    /// Partition prefix shared by every store in these tests.
    const PREFIX: &str = "p4";

    fn runner() -> deterministic::Runner {
        deterministic::Runner::timed(Duration::from_secs(30))
    }

    /// Builds a payload carrying one certificate per commitment byte.
    fn payload(parent: sha256::Digest, view: u64, certs: &[u8]) -> Arc<Payload> {
        Arc::new(Payload {
            parent,
            view: View::new(view),
            certs: certs
                .iter()
                .map(|byte| stub_cert(summary(*byte), View::new(view)))
                .collect(),
        })
    }

    #[test]
    fn p4_payload_roundtrip_and_rebuild() {
        let runner = runner();
        let (expected, checkpoint) = runner.start_and_recover(|context| async move {
            let mut store =
                PayloadStore::init(context.child("store"), PREFIX, PARTICIPANTS as usize)
                    .await
                    .expect("store opens");
            let genesis = store.genesis();

            // Two forks that share every view: same parent at view 1, then one payload each at
            // views 2 and 3. A plain put would keep one payload per view and lose the other.
            let a1 = payload(genesis, 1, &[1]);
            let b1 = payload(genesis, 1, &[2]);
            let a2 = payload(a1.digest(), 2, &[3]);
            let b2 = payload(b1.digest(), 2, &[4]);
            let a3 = payload(a2.digest(), 3, &[5]);
            let b3 = payload(b2.digest(), 3, &[1]);
            for entry in [&a1, &b1, &a2, &b2, &a3, &b3] {
                store.insert(entry.clone()).await.expect("payload stores");
            }

            // Storing the same payload twice is not an error and does not change what is held.
            store.insert(a1.clone()).await.expect("payload stores");
            assert_eq!(store.get(&a1.digest()).as_deref(), Some(a1.as_ref()));

            // Each fork sees only its own certificates. Commitment 1 is on both, at opposite ends.
            assert!(store.included(&a3.digest(), &summary(1)));
            assert!(store.included(&a3.digest(), &summary(5)));
            assert!(!store.included(&a3.digest(), &summary(2)));
            assert!(!store.included(&a3.digest(), &summary(4)));
            assert!(store.included(&b3.digest(), &summary(1)));
            assert!(store.included(&b3.digest(), &summary(4)));
            assert!(!store.included(&b3.digest(), &summary(3)));

            // A tip nobody stored has no ancestry at all.
            assert!(!store.included(&payload(genesis, 9, &[7]).digest(), &summary(7)));

            vec![a3.digest(), b3.digest()]
        });

        // A restart rebuilds the index from the archive alone, and answers identically.
        deterministic::Runner::from(checkpoint).start(|context| async move {
            let store =
                PayloadStore::init(context.child("restarted"), PREFIX, PARTICIPANTS as usize)
                    .await
                    .expect("store reopens");
            let (a3, b3) = (expected[0], expected[1]);
            for byte in [1u8, 3, 5] {
                assert!(store.included(&a3, &summary(byte)), "fork a lost {byte}");
            }
            for byte in [2u8, 4] {
                assert!(!store.included(&a3, &summary(byte)), "fork a gained {byte}");
            }
            for byte in [1u8, 2, 4] {
                assert!(store.included(&b3, &summary(byte)), "fork b lost {byte}");
            }
            for byte in [3u8, 5] {
                assert!(!store.included(&b3, &summary(byte)), "fork b gained {byte}");
            }
            assert_eq!(store.ancestry(&a3).len(), 4, "genesis terminates the walk");
        });
    }

    #[test]
    fn p4_payload_prune_respects_freshness_horizon() {
        runner().start(|context| async move {
            let mut store =
                PayloadStore::init(context.child("store"), PREFIX, PARTICIPANTS as usize)
                    .await
                    .expect("store opens");

            // A chain long enough that its oldest payloads sit below the horizon of its tip.
            let horizon = FRESHNESS.get();
            let mut parent = store.genesis();
            let mut chain = Vec::new();
            for view in 1..=(horizon * 2) {
                let byte = u8::try_from(view % 251).expect("byte fits");
                let entry = payload(parent, view, &[byte]);
                store.insert(entry.clone()).await.expect("payload stores");
                parent = entry.digest();
                chain.push(entry);
            }
            let tip = chain.last().expect("chain is not empty").digest();

            // Before pruning, everything is held, but the walk still stops at the horizon: a
            // certificate that old could not be included here anyway.
            let oldest = &chain[0];
            assert!(store.get(&oldest.digest()).is_some());
            assert!(!store.included(&tip, &summary(1)));
            let inside = u8::try_from(horizon + 1).expect("byte fits");
            assert!(store.included(&tip, &summary(inside)));

            // Pruning at the tip drops exactly what the horizon already ignored.
            let finalized = View::new(horizon * 2);
            store.prune(finalized).await.expect("prune runs");
            assert!(store.get(&oldest.digest()).is_none(), "stale payload kept");
            assert!(store.get(&tip).is_some(), "live payload dropped");
            assert!(store.get(&store.genesis()).is_some(), "genesis dropped");
            assert!(
                store.included(&tip, &summary(inside)),
                "live cert forgotten"
            );

            // A floor below what has already been pruned is a no-op rather than an error.
            store.prune(View::zero()).await.expect("prune runs");
            assert!(store.get(&tip).is_some());
        });
    }
}
