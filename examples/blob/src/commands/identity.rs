//! Demo identities, and the arguments that name them.
//!
//! A validator holds two keys: the ed25519 identity that names it on the network, orders the
//! participant set, and signs its gateway claims, and the BLS key that signs its attestations and
//! its consensus votes. Both are derived here from one `u64` seed, so a command line that lists
//! seeds names the whole deployment and every node derives the same participant set from it.
//!
//! # Not a key-distribution scheme
//!
//! Seed-derived keys are a demo convenience and nothing more: anyone who can read the command line
//! holds every private key in the deployment. A real deployment reads its own key from disk and
//! its peers' public keys from a genesis file.

use commonware_cryptography::{
    Signer as _,
    bls12381::primitives::{
        group::Private,
        ops::{keypair, sign_proof_of_possession, verify_proof_of_possession},
        variant::{MinSig, Variant},
    },
    ed25519,
};
use commonware_utils::{TestRng, TryCollect as _, ordered::BiMap};
use std::net::SocketAddr;

/// A participant's two keys, both derived from one seed.
pub struct Identity {
    /// The network identity, which also orders the participant set and signs gateway claims.
    pub signer: ed25519::PrivateKey,
    /// The signing key for attestations and consensus votes.
    pub bls: Private,
    /// The public half of [`Identity::bls`].
    pub public: <MinSig as Variant>::Public,
}

impl Identity {
    /// Derives the pair belonging to `seed`.
    ///
    /// Both halves are deterministic in `seed` alone, which is what lets a node that was given
    /// nothing but a list of seeds reconstruct every peer's public keys.
    pub fn from_seed(seed: u64) -> Self {
        let signer = ed25519::PrivateKey::from_seed(seed);
        let (bls, public) = keypair::<_, MinSig>(&mut TestRng::new(seed));
        Self {
            signer,
            bls,
            public,
        }
    }

    /// Returns the network identity's public key.
    pub fn key(&self) -> ed25519::PublicKey {
        self.signer.public_key()
    }
}

/// Builds the participant set named by `seeds`.
///
/// The map is ordered by ed25519 identity when it is built, so the order the seeds were listed in
/// never reaches shard assignment or signer indexing.
pub fn participants(
    seeds: &[u64],
) -> Option<BiMap<ed25519::PublicKey, <MinSig as Variant>::Public>> {
    if seeds.is_empty() {
        return None;
    }
    seeds
        .iter()
        .map(|seed| {
            let identity = Identity::from_seed(*seed);
            (identity.key(), identity.public)
        })
        .try_collect()
        .ok()
}

/// Checks that every participant holds the key it claims, and reports the first that does not.
///
/// # Vacuous here, and deliberately so
///
/// This deployment derives both halves of every pair itself, so the proof this verifies is one it
/// just produced: it can only pass. The startup check is the deliverable rather than its verdict.
/// A deployment whose participants publish their own public keys runs exactly this loop over
/// proofs their holders produced, and it is what stops a rogue-key registration -- a public key
/// chosen as a function of the others, so that an aggregate over the set verifies under a
/// signature its owner never contributed to -- from ever reaching the participant set.
pub fn verify_possession(seeds: &[u64], namespace: &[u8]) -> Result<(), u64> {
    for seed in seeds {
        let identity = Identity::from_seed(*seed);
        let proof = sign_proof_of_possession::<MinSig>(&identity.bls, namespace);
        verify_proof_of_possession::<MinSig>(&identity.public, namespace, &proof)
            .map_err(|_| *seed)?;
    }
    Ok(())
}

/// Splits `<left>@<right>` into its two halves.
fn split(value: &str) -> Option<(&str, &str)> {
    let (left, right) = value.split_once('@')?;
    (!left.is_empty() && !right.is_empty()).then_some((left, right))
}

/// Parses `<seed>@<port>`, the form a node names itself with.
pub fn parse_local(value: &str) -> Option<(u64, u16)> {
    let (seed, port) = split(value)?;
    Some((seed.parse().ok()?, port.parse().ok()?))
}

/// Parses `<seed>@<ip:port>`, the form a node names a peer it can dial with.
pub fn parse_remote(value: &str) -> Option<(u64, SocketAddr)> {
    let (seed, address) = split(value)?;
    Some((seed.parse().ok()?, address.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::NAMESPACE;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn seeds_are_deterministic_and_distinct() {
        let a = Identity::from_seed(7);
        let again = Identity::from_seed(7);
        let b = Identity::from_seed(8);

        // The whole demo rests on this: two processes given the same seed derive the same
        // identity, and two given different seeds derive different ones.
        assert_eq!(a.key(), again.key());
        assert_eq!(a.public, again.public);
        assert_ne!(a.key(), b.key());
        assert_ne!(a.public, b.public);
    }

    #[test]
    fn participants_order_by_key() {
        let seeds = [3u64, 1, 2, 0];
        let set = participants(&seeds).expect("seeds are distinct");
        let mut expected: Vec<_> = seeds
            .iter()
            .map(|seed| Identity::from_seed(*seed).key())
            .collect();
        expected.sort();
        assert_eq!(set.keys().iter().cloned().collect::<Vec<_>>(), expected);

        // Neither a repeated seed nor an empty list is a participant set.
        assert!(participants(&[1, 1]).is_none());
        assert!(participants(&[]).is_none());
    }

    #[test]
    fn possession_holds_for_every_participant() {
        assert_eq!(verify_possession(&[0, 1, 2, 3], NAMESPACE), Ok(()));
    }

    #[test]
    fn parses_addresses() {
        assert_eq!(parse_local("3@3003"), Some((3, 3003)));
        assert_eq!(
            parse_remote("0@127.0.0.1:3000"),
            Some((0, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3000)))
        );

        // Every malformed shape is rejected rather than guessed at.
        for malformed in ["3", "@3003", "3@", "x@3003", "3@70000", "3@3003@1"] {
            assert_eq!(parse_local(malformed), None, "accepted {malformed:?}");
        }
        for malformed in [
            "0@127.0.0.1",
            "0@:3000",
            "@127.0.0.1:3000",
            "x@127.0.0.1:3000",
            "0@127.0.0.1:70000",
        ] {
            assert_eq!(parse_remote(malformed), None, "accepted {malformed:?}");
        }
    }
}
