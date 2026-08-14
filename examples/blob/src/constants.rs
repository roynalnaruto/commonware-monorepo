//! Protocol constants: namespaces, p2p channel identifiers, size caps, and view accounting.
//!
//! Values here fall into two groups, and the distinction matters. **Wire bounds** (`MAX_*`) are
//! part of the format: every `Read` implementation enforces them, so changing one is a breaking
//! change that every peer must adopt at once. **Policy targets** (`*_TARGET`, `*_TIMEOUT`, the
//! `*_SIM` variants) are local choices a node can change unilaterally; they only ever sit at or
//! below the wire bounds.

use commonware_consensus::types::ViewDelta;
use commonware_utils::union;
use std::time::Duration;

/// Globally unique namespace for every signature this example produces.
///
/// Suffixes are appended with [`union`] rather than nested, matching the pattern in
/// `commonware_consensus::aggregation`.
pub const NAMESPACE: &[u8] = b"_COMMONWARE_EXAMPLES_BLOB";

/// Suffix for the attestor signature over a [`BatchHeader`](crate::types::BatchHeader).
pub const ATTEST_SUFFIX: &[u8] = b"_DA_ATTEST";

/// Suffix for the gateway signature over `(commitment, blob-tree root)`.
pub const GATEWAY_ROOT_SUFFIX: &[u8] = b"_GATEWAY_ROOT";

/// Suffix for the domain separator a batch is erasure-coded under.
pub const CODING_SUFFIX: &[u8] = b"_DA_CODING";

/// Returns the namespace attestors sign batch headers under.
pub fn attest_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, ATTEST_SUFFIX)
}

/// Returns the namespace a gateway signs its claimed blob-tree root under.
///
/// Distinct from [`attest_namespace`] on purpose: the claimed root is an attributable gateway
/// claim, not an attestation, and the two must never be confusable.
pub fn gateway_root_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, GATEWAY_ROOT_SUFFIX)
}

/// Returns the namespace batches are erasure-coded under.
///
/// A gateway passes this to `encode` and every attestor passes it to `weaken`. The two must
/// agree: under a different namespace a shard fails its check even though the bytes are intact.
pub fn coding_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, CODING_SUFFIX)
}

/// Consensus votes.
pub const VOTE_CHANNEL: u64 = 0;

/// Consensus certificates.
pub const CERTIFICATE_CHANNEL: u64 = 1;

/// Consensus block resolution.
pub const RESOLVER_CHANNEL: u64 = 2;

/// Client blob submissions to a gateway.
pub const SUBMIT_CHANNEL: u64 = 3;

/// Gateway to attestor shard dispersal.
pub const DISPERSE_REQ_CHANNEL: u64 = 4;

/// Attestor to gateway attestations.
pub const DISPERSE_RES_CHANNEL: u64 = 5;

/// Gossip of assembled availability certificates.
pub const CERT_GOSSIP_CHANNEL: u64 = 6;

/// Gossip of consensus payloads, which bare simplex does not disseminate itself.
pub const PAYLOAD_GOSSIP_CHANNEL: u64 = 7;

/// Shard retrieval requests.
pub const RETRIEVAL_REQ_CHANNEL: u64 = 8;

/// Shard retrieval responses.
pub const RETRIEVAL_RES_CHANNEL: u64 = 9;

/// Client status and batch queries.
pub const CLIENT_RPC_CHANNEL: u64 = 10;

/// Bytes per page of a blob, the unit of the page tree and of an in-circuit opening.
pub const BLOB_PAGE: usize = 4096;

/// Largest blob a client may submit. Wire bound.
///
/// `MAX_BLOB_SIZE / BLOB_PAGE = 128 = 2^PAGE_DEPTH`, so the page tree stays exactly depth 7.
pub const MAX_BLOB_SIZE: usize = 512 * 1024;

/// Largest number of blobs in a batch. Wire bound.
///
/// Equals `2^BATCH_DEPTH`, so the blob tree stays exactly depth 8 and membership paths are
/// constant size in a circuit.
pub const MAX_BLOBS_PER_BATCH: usize = 256;

/// Largest encoded batch payload. Wire bound.
///
/// A batch seals as soon as it reaches its target, so it can overshoot by at most the one blob
/// that crossed the line.
pub const MAX_BATCH_SIZE: usize = BATCH_TARGET + MAX_BLOB_SIZE;

/// Largest number of certificates in one consensus payload. Wire bound.
///
/// A decode limit, not a consensus rule: how many certificates a proposer may actually include is
/// decided by the application.
pub const PAYLOAD_MAX_CERTS: usize = 128;

/// Batch size a gateway aims for before sealing.
pub const BATCH_TARGET: usize = 8 * 1024 * 1024;

/// Batch size a gateway aims for in simulated tests.
pub const BATCH_TARGET_SIM: usize = 256 * 1024;

/// How long a gateway waits for more blobs before sealing an undersized batch.
pub const BATCH_TIMEOUT: Duration = Duration::from_millis(500);

/// Batch timer in simulated tests.
pub const BATCH_TIMEOUT_SIM: Duration = Duration::from_millis(100);

/// How long a gateway waits for a quorum of attestations before abandoning a batch.
///
/// Generous relative to the attestation path itself (a worst-case weaken plus check measured
/// under 14 ms): what this bounds is a slow or partitioned network, not local work.
pub const DISPERSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Dispersal timer in simulated tests.
pub const DISPERSE_TIMEOUT_SIM: Duration = Duration::from_millis(500);

/// How many dispersals a blob may take part in before a gateway gives up on it.
///
/// A batch that misses its quorum returns its blobs to the batcher, where they join a fresh
/// batch. Bounding the count is what stops a blob nobody will attest to from circulating forever;
/// past it the blob is reported failed and the client resubmits.
pub const MAX_DISPERSAL_ATTEMPTS: u8 = 3;

/// Largest strong shard accepted when decoding a dispersal request.
///
/// A strong shard of an 8 MiB batch at the four-validator deployment measured 4.10 MiB, so this
/// leaves roughly 2x headroom at the worst-case participant count.
pub const MAX_SHARD_SIZE: usize = 8 * 1024 * 1024;

/// Strong shard bound in simulated tests, where batches are small.
pub const MAX_SHARD_SIZE_SIM: usize = 1024 * 1024;

/// Largest p2p message a node accepts.
///
/// Must exceed [`MAX_SHARD_SIZE`] plus envelope, and must also cover a whole batch: retrieval
/// returns batch bytes in a single message rather than streaming them, which is a documented
/// shortcut of this example.
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// p2p message bound in simulated tests.
pub const MAX_MESSAGE_SIZE_SIM: usize = 2 * 1024 * 1024;

/// Largest number of blob statuses a gateway remembers at once.
///
/// The status board answers client polls, so it holds entries a client may still ask about rather
/// than everything ever submitted. Bounding it is what stops an unbounded stream of submissions
/// from growing the map without limit; the oldest terminal entry is evicted first, and a live
/// entry is only evicted when nothing terminal is left to drop.
pub const MAX_TRACKED_BLOBS: usize = 4096;

/// How long a terminal blob status stays on the status board.
///
/// A client that never polls should not pin an entry forever. Long enough that a client which
/// polls at any sensible interval still sees the outcome of its submission.
pub const STATUS_TTL: Duration = Duration::from_secs(300);

/// Maximum number of views a certificate may age between dispersal and inclusion.
///
/// A certificate with dispersal view `D` is rejected at inclusion view `H` when `D > H` or
/// `H - D > FRESHNESS`.
pub const FRESHNESS: ViewDelta = ViewDelta::new(32);

/// How long after inclusion a batch stays retrievable.
///
/// Custody keeps a shard until view `D + FRESHNESS + WINDOW`.
pub const WINDOW: ViewDelta = ViewDelta::new(64);

/// How far a dispersal view may sit either side of an attestor's watermark.
///
/// A gateway disperses at the view it believes is current, which may lead or lag the attestor's
/// last observed finalized view. Accepting a band rather than an exact match tolerates that skew;
/// keeping the band well inside [`FRESHNESS`] stops a gateway from post-dating a batch far enough
/// to escape the freshness rule applied when its certificate is included.
pub const ATTEST_SLACK: ViewDelta = ViewDelta::new(16);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob_tree::{BATCH_DEPTH, PAGE_DEPTH};

    #[test]
    fn p1_constants_bounds_match_tree_depths() {
        const {
            assert!(MAX_BLOBS_PER_BATCH == 1 << BATCH_DEPTH);
            assert!(MAX_BLOB_SIZE / BLOB_PAGE == 1 << PAGE_DEPTH);
            assert!(BATCH_TARGET_SIM < BATCH_TARGET);
            assert!(MAX_BATCH_SIZE > BATCH_TARGET);
            assert!(MAX_SHARD_SIZE_SIM < MAX_SHARD_SIZE);
            assert!(MAX_MESSAGE_SIZE > MAX_SHARD_SIZE);
            assert!(MAX_MESSAGE_SIZE_SIM > MAX_SHARD_SIZE_SIM);
            assert!(ATTEST_SLACK.get() < FRESHNESS.get());
            assert!(DISPERSE_TIMEOUT_SIM.as_nanos() < DISPERSE_TIMEOUT.as_nanos());
            assert!(BATCH_TIMEOUT_SIM.as_nanos() < DISPERSE_TIMEOUT_SIM.as_nanos());
            assert!(MAX_DISPERSAL_ATTEMPTS > 0);
            assert!(MAX_TRACKED_BLOBS > MAX_BLOBS_PER_BATCH);
        }
    }

    #[test]
    fn p1_constants_namespaces_are_distinct() {
        let attest = attest_namespace(NAMESPACE);
        let gateway = gateway_root_namespace(NAMESPACE);
        let coding = coding_namespace(NAMESPACE);
        assert_ne!(attest, gateway);
        assert_ne!(attest, coding);
        assert_ne!(gateway, coding);
        assert!(attest.starts_with(NAMESPACE));
        assert!(gateway.starts_with(NAMESPACE));
        assert!(coding.starts_with(NAMESPACE));
    }
}
