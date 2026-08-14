//! The error type every fallible constructor on the rail returns.

use super::BlobId;

/// Failures produced while building or validating blob-rail objects.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// A blob was empty or larger than [`MAX_BLOB_SIZE`](crate::constants::MAX_BLOB_SIZE).
    #[error("blob of {0} bytes is outside the permitted size range")]
    BlobSize(usize),
    /// A batch was empty or held more than
    /// [`MAX_BLOBS_PER_BATCH`](crate::constants::MAX_BLOBS_PER_BATCH) blobs.
    #[error("batch of {0} blobs is outside the permitted count range")]
    BatchCount(usize),
    /// A batch exceeded [`MAX_BATCH_SIZE`](crate::constants::MAX_BATCH_SIZE) encoded bytes.
    #[error("batch of {0} encoded bytes is over the permitted size")]
    BatchSize(usize),
    /// A tree index was not occupied.
    #[error("index {0} is not occupied")]
    UnknownIndex(usize),
    /// The same blob was offered to a batch twice.
    #[error("blob {0} is already in the batch")]
    DuplicateBlob(BlobId),
}
