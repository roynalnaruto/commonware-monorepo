//! Fixtures shared by the header and certificate tests.

use super::BatchHeader;
use commonware_codec::DecodeExt;
use commonware_coding::Config;
use commonware_consensus::types::View;
use commonware_cryptography::transcript::Summary;
use commonware_utils::NZU16;

/// Participants in the certificate tests: `n = 10`, `f = 3`, quorum 7.
pub(super) const PARTICIPANTS: u32 = 10;

/// The scheme is generic over a digest it never uses, since [`BatchHeader`] is not one; this
/// pins that parameter.
pub(super) type Unused = commonware_cryptography::sha256::Digest;

/// A header over a deterministic commitment.
pub(super) fn header_at(view: u64) -> BatchHeader {
    BatchHeader::new(
        Summary::decode([7u8; 32].as_slice()).expect("summary is 32 bytes"),
        Config {
            minimum_shards: NZU16!(4),
            extra_shards: NZU16!(6),
        },
        View::new(view),
    )
}
