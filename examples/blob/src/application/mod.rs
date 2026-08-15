//! The consensus rail: what a validator proposes, and what it will accept.
//!
//! Blocks on this chain carry availability certificates and nothing else. The application is what
//! decides which certificates go into the block it proposes, whether somebody else's block is one
//! it can accept, and what happens to the rest of the node when a block finalizes.
//!
//! # Two rails, one meeting point
//!
//! The data-availability rail runs asynchronously to consensus: gateways batch, disperse, and
//! certify on their own schedule, and a certificate lands in the pool here. The rails meet exactly
//! once, when a leader drains that pool into a payload. Everything downstream of that meeting is
//! ordinary consensus, and everything upstream of it is ordinary dispersal.
//!
//! # What the actor guarantees
//!
//! - **Nothing is proposed that this node has not stored.** A digest returned to consensus commits
//!   the proposer to verifying the same bytes later, so the payload is durable first.
//! - **Missing data is never a rejection.** A payload that has not arrived leaves verification
//!   pending; only a payload that is wrong at the position offered is answered `false`, and that
//!   answer is permanent.
//! - **A certificate rides at most once per fork.** Inclusion is keyed by the batch commitment and
//!   checked against the ancestry of the parent, so the same certificate can be included on two
//!   competing forks but never twice on one.
//!
//! # Files
//!
//! The split follows the shape of the other actors in this crate: [`ingress`] holds the mailbox and
//! the consensus traits it satisfies, [`actor`] holds the state and the loop, and [`reporter`]
//! turns consensus activity into the one event the rest of the node reacts to.

mod actor;
mod ingress;
mod reporter;

// Named in the signatures above them rather than reached through this module by anything inside
// the binary yet: the reporter is handed straight to consensus, and a snapshot is only ever read
// by whoever asked for one.
#[allow(unused_imports)]
pub use self::{
    actor::{Application, Config, Snapshot},
    ingress::Mailbox,
    reporter::Reporter,
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519, sha256};

/// The scheme consensus votes with.
///
/// The same BLS key material the data-availability rail attests with, under a namespace of its
/// own: a vote and an attestation are different claims, and a signature over one must never read
/// as a signature over the other.
pub type Scheme =
    commonware_consensus::simplex::scheme::bls12381_multisig::Scheme<ed25519::PublicKey, MinSig>;

/// Consensus activity this node observes.
pub type Activity = commonware_consensus::simplex::types::Activity<Scheme, sha256::Digest>;

/// Metadata consensus hands the application for a proposal.
pub type Context =
    commonware_consensus::simplex::types::Context<sha256::Digest, ed25519::PublicKey>;
