//! How the participant set determines who holds which shard.
//!
//! # Consensus-critical
//!
//! Shard `i` belongs to the validator holding the `i`-th key of the signing scheme's ordered
//! [`participants`](commonware_cryptography::certificate::Scheme::participants) set, which is
//! ordered by ed25519 identity. Every node derives the mapping from that set alone, so every node
//! derives the same mapping: the order a configuration file, a command line, or a peer listed the
//! validators in never reaches this module. A node that disagreed about the order would check its
//! shard against the wrong column of the commitment and reject every honest dispersal.
//!
//! The coding configuration is derived the same way, from the size of that set, so a gateway and
//! its attestors agree on how a batch was cut without negotiating it.

use crate::types::Scheme;
use commonware_coding::Config;
use commonware_cryptography::{certificate::Scheme as _, ed25519};
use commonware_utils::{Faults as _, N3f1};
use std::num::NonZeroU16;

/// Returns this node's own shard index, or `None` if it does not hold one.
///
/// A verifier-only scheme has no position, and a participant set larger than [`u16::MAX`] cannot
/// be coded at all: both are reported as "no index" rather than guessed at.
pub fn my_index(scheme: &Scheme) -> Option<u16> {
    u16::try_from(scheme.me()?.get()).ok()
}

/// Returns the identity that holds shard `index`.
pub fn key_of(scheme: &Scheme, index: u16) -> Option<&ed25519::PublicKey> {
    scheme.participants().get(usize::from(index))
}

/// Returns the shard index held by `key`.
pub fn index_of(scheme: &Scheme, key: &ed25519::PublicKey) -> Option<u16> {
    u16::try_from(scheme.participants().position(key)?).ok()
}

/// Returns the coding configuration for a set of `participants`.
///
/// One shard per validator, and `f + 1` of them reconstruct the batch: reconstruction only needs
/// the honest custodians that a quorum of `2f + 1` attestations guarantees. Returns `None` for a
/// participant set that cannot be coded, which is one whose size does not fit a `u16` or that is
/// too small to have any redundancy at all.
pub fn coding_config(participants: usize) -> Option<Config> {
    let total = u16::try_from(participants).ok()?;
    if total == 0 {
        return None;
    }
    let faults = u16::try_from(N3f1::max_faults(total)).ok()?;
    let minimum = faults.checked_add(1)?;
    let extra = total.checked_sub(minimum)?;
    Some(Config {
        minimum_shards: NonZeroU16::new(minimum)?,
        extra_shards: NonZeroU16::new(extra)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{constants::NAMESPACE, test_util::PARTICIPANTS};
    use commonware_cryptography::{
        Signer as _,
        bls12381::primitives::{group::Private, ops::keypair, variant::MinSig},
    };
    use commonware_utils::{NZU16, TryCollect as _, ordered::BiMap, test_rng};

    #[test]
    fn p2_assignment_order_matches_participants_sorted() {
        // Key material a configuration file could list in any order.
        let mut rng = test_rng();
        let mut identities = Vec::new();
        let mut privates: Vec<Private> = Vec::new();
        let mut pairs = Vec::new();
        for seed in 0..u64::from(PARTICIPANTS) {
            let identity = ed25519::PrivateKey::from_seed(seed).public_key();
            let (private, public) = keypair::<_, MinSig>(&mut rng);
            identities.push(identity.clone());
            privates.push(private);
            pairs.push((identity, public));
        }

        // Build the same scheme twice, offering the participants in opposite orders.
        let signer = 3;
        let forward: BiMap<_, _> = pairs
            .clone()
            .into_iter()
            .try_collect()
            .expect("identities are unique");
        let backward: BiMap<_, _> = pairs
            .clone()
            .into_iter()
            .rev()
            .try_collect()
            .expect("identities are unique");
        let a =
            Scheme::signer(NAMESPACE, forward, privates[signer].clone()).expect("signer is known");
        let b =
            Scheme::signer(NAMESPACE, backward, privates[signer].clone()).expect("signer is known");

        // Both schemes agree on the whole mapping, in both directions.
        assert_eq!(my_index(&a), my_index(&b));
        assert_eq!(my_index(&a), index_of(&a, &identities[signer]));
        let mut sorted = identities.clone();
        sorted.sort();
        for (index, identity) in sorted.iter().enumerate() {
            let index = u16::try_from(index).expect("index fits");
            assert_eq!(key_of(&a, index), Some(identity));
            assert_eq!(key_of(&b, index), Some(identity));
            assert_eq!(index_of(&a, identity), Some(index));
            assert_eq!(index_of(&b, identity), Some(index));
        }

        // Positions outside the set have no holder.
        assert_eq!(key_of(&a, PARTICIPANTS as u16), None);
        let stranger = ed25519::PrivateKey::from_seed(u64::from(PARTICIPANTS)).public_key();
        assert_eq!(index_of(&a, &stranger), None);
    }

    #[test]
    fn p2_assignment_coding_config_tracks_faults() {
        // n = 10 is the simulated deployment: f = 3, so 4 of 10 shards reconstruct.
        assert_eq!(
            coding_config(10),
            Some(Config {
                minimum_shards: NZU16!(4),
                extra_shards: NZU16!(6),
            })
        );
        // n = 4 is the demo deployment: f = 1, so 2 of 4 shards reconstruct.
        assert_eq!(
            coding_config(4),
            Some(Config {
                minimum_shards: NZU16!(2),
                extra_shards: NZU16!(2),
            })
        );
        // Sets with no redundancy, and sets too large to index, cannot be coded.
        assert_eq!(coding_config(0), None);
        assert_eq!(coding_config(1), None);
        assert_eq!(coding_config(usize::from(u16::MAX) + 1), None);
    }
}
