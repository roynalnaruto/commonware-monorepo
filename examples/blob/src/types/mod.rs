//! Blobs, batches, and the objects that certify them.
//!
//! # Integrity tiers
//!
//! Three tiers appear throughout this example, and every field below belongs to exactly one:
//!
//! - **Attested**: covered by validator signatures. Only [`BatchHeader`] is, because it holds
//!   nothing a validator cannot check against its own shard.
//! - **Claimed**: asserted and signed by the gateway alone. [`ClaimedRoot`] is the whole of this
//!   tier: a false claim is attributable and provable, but it is not an availability statement.
//! - **Derived**: recomputed from decoded bytes by any reader, trusting nobody. [`BlobId`], the
//!   blob-tree root, and the batch contents live here.
//!
//! A [`DaCert`] carries one of each, which is why availability and structure can be reasoned about
//! separately.

mod batch;
mod blob;
mod cert;
mod error;
mod header;
#[cfg(test)]
mod test_util;

// The vocabulary is defined ahead of the actors that consume it, so some of these names have no
// caller inside this binary yet.
#[allow(unused_imports)]
pub use self::{
    batch::{Batch, BatchBuilder, Sealed},
    blob::{Blob, BlobId},
    cert::{ClaimedRoot, DaCert},
    error::Error,
    header::{Attestation, BatchHeader, Certificate, Namespace, Scheme, scheme},
};
