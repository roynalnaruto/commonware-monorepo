//! The gateway role: client blobs in, availability certificates out.
//!
//! Any validator plays it, for whichever clients chose it, and none of it is trusted. A gateway
//! that batches badly, disperses a corrupt shard, or claims a blob-tree root the batch does not
//! have produces a batch that fails to certify, or a claim that a reader disproves; what it cannot
//! do is make an unavailable batch look available, because the attestations that settle that are
//! signed by validators who each checked their own shard.
//!
//! Two actors, pipelined over a bounded channel:
//!
//! - [`Batcher`] accepts blobs and seals batches on size or on a timer;
//! - [`Disperser`] encodes a sealed batch, hands out its shards, and certifies it.
//!
//! Splitting them is what lets the next batch fill while the current one is still out for
//! attestation, and the channel between them is bounded so a gateway that cannot keep up makes
//! fewer, larger batches instead of an unbounded queue of small ones.
//!
//! [`StatusBoard`] is the third piece: the shared, bounded record of where each accepted blob has
//! got to, written by both actors and read by whatever answers clients.

pub mod batcher;
pub mod disperser;
pub mod status;

// The sealed-batch handoff is named by the actors on either side of it rather than by anything
// outside this module.
#[allow(unused_imports)]
pub use self::{
    batcher::{Batcher, Job},
    disperser::Disperser,
    status::StatusBoard,
};
