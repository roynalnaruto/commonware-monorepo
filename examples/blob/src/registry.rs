//! The certificates this node has seen finalized, keyed by the batch they cover.
//!
//! A [`DaCert`] is the answer to "who custodies this batch, and under what coding". Retrieval
//! needs both, and so does a client's verification, but neither is carried by anything the read
//! path already holds: consensus keeps payloads, custody keeps shards, and the certificate pool
//! only holds what has *not* been included yet. The registry is what remains once a certificate
//! has ridden into a finalized block.
//!
//! Written by the consensus reporter at finalization, before anything is pruned, and read by the
//! retrieval coordinator and the client-facing server. It is deliberately the process-local
//! precursor of the enshrined `commitment -> {root, gateway, dispersal view, inclusion view}` map
//! a future execution layer would expose: because ancestry dedup is keyed by the commitment, at
//! most one certificate per commitment is ever finalized on one chain, so the mapping is
//! well defined rather than a matter of who wrote last.
//!
//! # Expiry
//!
//! An entry lives until the batch behind it is past its retrievability window, the same horizon
//! custody prunes at: `D + FRESHNESS + WINDOW`. Past it the certificate is dropped but the
//! commitment is remembered, so a client asking for a batch that has aged out is told so instead
//! of being told the batch never existed. Those tombstones are bounded by
//! [`MAX_EXPIRED_CERTS`]; past the bound the oldest is
//! forgotten and the answer degrades to [`Lookup::Unknown`], which is what a node that never saw
//! the certificate would have said.

use crate::{
    constants::{FRESHNESS, ITEMS_PER_SECTION, MAX_EXPIRED_CERTS, WINDOW},
    types::DaCert,
};
use commonware_consensus::types::View;
use commonware_cryptography::transcript::Summary;
use commonware_utils::sync::Mutex;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
};
use tracing::debug;

/// What the registry knows about a commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// A certificate was finalized and the batch should still be retrievable.
    Live {
        /// The finalized certificate.
        cert: Box<DaCert>,
        /// View of the block whose payload carried it.
        included: View,
    },
    /// A certificate was finalized, but the batch is past its retrievability window.
    Expired,
    /// Nothing has been finalized under this commitment, as far as this node knows.
    Unknown,
}

/// One live entry.
struct Record {
    cert: DaCert,
    included: View,
}

/// State behind the shared handle.
struct State {
    live: HashMap<Summary, Record>,
    /// Commitments whose batches have expired, and the order they expired in.
    expired: HashSet<Summary>,
    order: VecDeque<Summary>,
    /// Section the last expiry reached, so a floor that has not left it costs nothing.
    pruned: Option<u64>,
}

/// The finalized-certificate registry.
///
/// Cheap to clone: every clone is a handle onto the same map.
#[derive(Clone)]
pub struct Registry {
    state: Arc<Mutex<State>>,
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl Registry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                live: HashMap::new(),
                expired: HashSet::new(),
                order: VecDeque::new(),
                pruned: None,
            })),
        }
    }

    /// Records that `cert` was carried by a block finalized at `included`.
    ///
    /// The first record for a commitment wins. A later one would have to come from a competing
    /// certificate over the same batch, which cannot be included on the same chain, so it is
    /// either a replay of the same fact or a fork this node has already left behind; either way
    /// what is already recorded is what the finalized chain says.
    pub fn record(&self, cert: DaCert, included: View) {
        let commitment = cert.header.commitment;
        let mut state = self.state.lock();
        if state.expired.contains(&commitment) || state.live.contains_key(&commitment) {
            debug!(?commitment, "certificate is already registered");
            return;
        }
        state.live.insert(commitment, Record { cert, included });
    }

    /// Returns the certificate finalized under `commitment` and the view it was included at.
    pub fn get(&self, commitment: &Summary) -> Option<(DaCert, View)> {
        let state = self.state.lock();
        state
            .live
            .get(commitment)
            .map(|record| (record.cert.clone(), record.included))
    }

    /// Returns what this node knows about `commitment`, distinguishing expired from unknown.
    pub fn lookup(&self, commitment: &Summary) -> Lookup {
        let state = self.state.lock();
        if let Some(record) = state.live.get(commitment) {
            return Lookup::Live {
                cert: Box::new(record.cert.clone()),
                included: record.included,
            };
        }
        if state.expired.contains(commitment) {
            return Lookup::Expired;
        }
        Lookup::Unknown
    }

    /// Expires every certificate whose batch can no longer be owed to anyone.
    ///
    /// The floor is custody's, down to the same rounding: a certificate dispersed at `D` is
    /// includable until `D + FRESHNESS` and retrievable for `WINDOW` views after that, and custody
    /// drops whole sections, so the floor is rounded down to a section boundary here too. Both
    /// halves of that matter. Expiring on the same rule rather than a looser one is what keeps the
    /// answer honest, because a registry that outlived custody would promise batches no validator
    /// still holds; rounding the same way is what stops it from disowning batches whose shards are
    /// still on disk.
    ///
    /// Called on every finalization, and a scan only happens when the floor crosses a boundary:
    /// within one section there is nothing new to expire.
    pub fn prune(&self, finalized: View) {
        let floor = finalized.saturating_sub(FRESHNESS).saturating_sub(WINDOW);
        let section = floor.get() / ITEMS_PER_SECTION.get();
        let mut state = self.state.lock();
        if state.pruned == Some(section) {
            return;
        }
        state.pruned = Some(section);
        let floor = section * ITEMS_PER_SECTION.get();
        let stale: Vec<Summary> = state
            .live
            .iter()
            .filter(|(_, record)| record.cert.header.dispersal_view.get() < floor)
            .map(|(commitment, _)| *commitment)
            .collect();
        for commitment in stale {
            state.live.remove(&commitment);
            if state.expired.insert(commitment) {
                state.order.push_back(commitment);
            }
        }
        while state.order.len() > MAX_EXPIRED_CERTS {
            let Some(forgotten) = state.order.pop_front() else {
                break;
            };
            state.expired.remove(&forgotten);
        }
    }

    /// Returns the number of live certificates held.
    pub fn len(&self) -> usize {
        self.state.lock().live.len()
    }

    /// Returns whether any certificate is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{stub_cert, summary};
    use commonware_codec::DecodeExt as _;

    /// Builds a certificate over a distinct commitment, dispersed at `view`.
    fn cert(byte: u8, view: u64) -> DaCert {
        stub_cert(summary(byte), View::new(view))
    }

    /// A commitment distinguished only by `index`, for filling the tombstone queue.
    fn numbered(index: usize) -> Summary {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&(index as u64).to_le_bytes());
        Summary::decode(bytes.as_slice()).expect("summary is 32 bytes")
    }

    #[test]
    fn p5_registry_records_and_prunes_at_horizon() {
        let registry = Registry::new();
        assert!(registry.is_empty());

        // Nothing is known about a commitment nobody finalized.
        let unseen = summary(0xee);
        assert_eq!(registry.lookup(&unseen), Lookup::Unknown);
        assert_eq!(registry.get(&unseen), None);

        // Two certificates, dispersed 100 views apart, both included well after.
        let old = cert(1, 10);
        let new = cert(2, 110);
        registry.record(old.clone(), View::new(20));
        registry.record(new.clone(), View::new(120));
        assert_eq!(registry.len(), 2);
        assert_eq!(
            registry.get(&old.header.commitment),
            Some((old.clone(), View::new(20)))
        );
        assert_eq!(
            registry.lookup(&new.header.commitment),
            Lookup::Live {
                cert: Box::new(new.clone()),
                included: View::new(120),
            }
        );

        // A repeat of what is already registered changes nothing.
        registry.record(old.clone(), View::new(999));
        assert_eq!(
            registry.get(&old.header.commitment),
            Some((old.clone(), View::new(20)))
        );

        // The horizon is D + FRESHNESS + WINDOW = D + 96. Finalizing view 100 puts the floor at
        // 4, below both dispersals, so neither expires.
        registry.prune(View::new(100));
        assert_eq!(registry.len(), 2);

        // Finalizing view 110 puts the raw floor at 14, past the older dispersal -- but only
        // part-way into the section holding it. Custody drops whole sections, so those shards are
        // still on disk and the registry still says the batch is live. Every finalization inside
        // one section is this same no-op.
        for finalized in [110u64, 111, 115] {
            registry.prune(View::new(finalized));
            assert_eq!(registry.len(), 2, "expired inside a section at {finalized}");
            assert!(matches!(
                registry.lookup(&old.header.commitment),
                Lookup::Live { .. }
            ));
        }

        // Finalizing view 116 puts the floor a whole section past the older batch, which is when
        // custody lets go of it too.
        registry.prune(View::new(116));
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.lookup(&old.header.commitment), Lookup::Expired);
        assert_eq!(registry.get(&old.header.commitment), None);
        assert!(matches!(
            registry.lookup(&new.header.commitment),
            Lookup::Live { .. }
        ));

        // An expired certificate is not resurrected by a late report of the same finalization.
        registry.record(old.clone(), View::new(20));
        assert_eq!(registry.lookup(&old.header.commitment), Lookup::Expired);

        // Past its own horizon the newer one goes the same way, and a young chain prunes nothing.
        registry.prune(View::new(216));
        assert!(registry.is_empty());
        assert_eq!(registry.lookup(&new.header.commitment), Lookup::Expired);
        registry.prune(View::zero());
        assert_eq!(registry.lookup(&new.header.commitment), Lookup::Expired);
    }

    #[test]
    fn p5_registry_bounds_expired_commitments() {
        let registry = Registry::new();

        // More expiries than the tombstone bound, each over its own commitment.
        let overflow = MAX_EXPIRED_CERTS + 8;
        let mut commitments = Vec::with_capacity(overflow);
        // Each expiry needs its own section: within one the scan is skipped, because there is
        // nothing new below a floor that has not moved.
        for index in 0..overflow {
            let cert = stub_cert(numbered(index), View::new(1));
            commitments.push(cert.header.commitment);
            registry.record(cert, View::new(2));
            registry.prune(View::new(200 + index as u64 * ITEMS_PER_SECTION.get()));
        }
        assert!(registry.is_empty());

        // The newest are remembered as expired; the oldest have been forgotten entirely, which
        // is the same answer a node that never saw them would give.
        assert_eq!(
            registry.lookup(commitments.last().unwrap()),
            Lookup::Expired
        );
        assert_eq!(registry.lookup(&commitments[0]), Lookup::Unknown);
        assert_eq!(
            commitments
                .iter()
                .filter(|commitment| registry.lookup(commitment) == Lookup::Expired)
                .count(),
            MAX_EXPIRED_CERTS
        );
    }
}
