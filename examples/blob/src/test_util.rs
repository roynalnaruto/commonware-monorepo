//! Fixtures shared by the actor tests.
//!
//! Everything here builds the simulated deployment of the plan: ten validators, batches of a few
//! kilobytes, and shards produced by a real encode so that a test which claims a shard passes (or
//! fails) its coding check is claiming something about the coding scheme, not about a stub.

use crate::{
    assignment::coding_config,
    constants::{MAX_SHARD_SIZE_SIM, NAMESPACE, coding_namespace},
    types::{Batch, BatchHeader, Blob, Scheme},
    wire::{Coder, StrongShard},
};
use bytes::Bytes;
use commonware_codec::Encode as _;
use commonware_coding::{CodecConfig, PhasedScheme as _};
use commonware_consensus::types::View;
use commonware_cryptography::{
    bls12381::{certificate::multisig::mocks::fixture, primitives::variant::MinSig},
    certificate::mocks::Fixture,
    sha256,
};
use commonware_parallel::Sequential;
use commonware_utils::test_rng;

/// Validators in the simulated deployment: `n = 10`, `f = 3`, quorum 7, minimum shards 4.
pub const PARTICIPANTS: u32 = 10;

/// The signing scheme is generic over a digest it never uses, because a
/// [`BatchHeader`](crate::types::BatchHeader) is not one; this pins that parameter.
pub type Unused = sha256::Digest;

/// Decode bounds for a shard in the simulated deployment.
pub fn shard_cfg() -> CodecConfig {
    CodecConfig {
        maximum_shard_size: MAX_SHARD_SIZE_SIM,
    }
}

/// Builds the signing fixture for the simulated deployment.
///
/// The fixture's `schemes[i]` signs as the holder of participant position `i`, and therefore of
/// shard `i`.
pub fn schemes() -> Fixture<Scheme> {
    let mut rng = test_rng();
    fixture::<Scheme, MinSig, _>(
        &mut rng,
        NAMESPACE,
        PARTICIPANTS,
        Scheme::signer,
        Scheme::verifier,
    )
}

/// Encodes a small batch, returning the header a gateway would disperse and one shard per
/// validator.
///
/// `filler` distinguishes batches: two calls with different fillers produce different commitments.
pub fn dispersal(view: u64, filler: u8) -> (BatchHeader, Vec<StrongShard>) {
    let config = coding_config(PARTICIPANTS as usize).expect("participant set can be coded");
    let batch = Batch::new(vec![
        Blob::new(Bytes::from(vec![filler; 4096])).expect("blob is within bounds"),
        Blob::new(Bytes::from(vec![filler ^ 0xff; 1024])).expect("blob is within bounds"),
    ])
    .expect("batch is within bounds");
    let (commitment, shards) = Coder::encode(
        &coding_namespace(NAMESPACE),
        &config,
        batch.encode(),
        &Sequential,
    )
    .expect("batch encodes");
    (
        BatchHeader::new(commitment, config, View::new(view)),
        shards,
    )
}
