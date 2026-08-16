//! Post blobs to a ZODA-backed data-availability rail alongside a consensus chain.
//!
//! Blob bytes never enter a consensus block. A gateway batches blobs submitted by clients,
//! erasure-codes each batch with [ZODA](commonware_coding::Zoda), and disperses a single shard to
//! every validator. Each validator checks its own shard against the batch commitment, persists it,
//! and returns a signed attestation; once a quorum of attestations is collected they are aggregated
//! into a data-availability certificate. Only that certificate travels through consensus, so block
//! size stays constant regardless of blob volume while the data itself rides a separate rail that
//! any `f + 1` honest custodians can reconstruct on demand.
//!
//! # Two rails
//!
//! The data-availability rail and the consensus rail run at their own speeds and meet at exactly
//! one point: a leader draining its certificate pool into the block it proposes.
//!
//! ```text
//!  WRITE                                         READ
//!
//!  blob                                          blob, byte for byte
//!   |  submit                                     ^  located by its BlobId
//!   v                                             |
//!  gateway ....... batch, ZODA encode, n shards   batch bytes
//!   |                                             ^  decode
//!   |  shard i                                    |
//!   v                                             |  f + 1 checked shards
//!  validator i ... check shard i, custody, sign   custody of the certificate's signers
//!   |                                             ^
//!   |  attestation i                              |  one targeted request per signer
//!   v                                             |
//!  gateway ....... 2f + 1 attestations, DaCert    registry: commitment -> DaCert
//!   |                                             ^
//!   |  gossip                                     |  written when the block finalizes
//!   v                                             |
//!  certificate pool -> leader drains it -> Payload { parent, view, certs } at view H
//!                                              |                            |
//!                                              +-- simplex orders it -------+
//! ```
//!
//! The modules follow the diagram. [`gateway`] batches, encodes, disperses, and certifies;
//! [`attestor`] and [`custody`] are the validator side of dispersal; [`application`] and
//! [`payload`] are the consensus rail; [`registry`], [`retrieval`], and [`rpc`] are the read path,
//! and [`client`] is what a reader runs against them. [`node`] wires all of it together, once, for
//! both the tests and the binary; [`commands`] is the command line.
//!
//! # Trust model: three integrity tiers
//!
//! Every claim this example makes belongs to exactly one of three tiers, and comments throughout
//! name the tier they rely on.
//!
//! | Tier | The claim | What backs it | What a false one costs |
//! |---|---|---|---|
//! | **Attested availability** | the bytes behind commitment `S` can be retrieved | `2f + 1` signatures over a [`BatchHeader`](types::BatchHeader), each signer having checked its own shard and stored it | more than `f` faults, which is the security assumption itself |
//! | **Gateway-claimed structure** | the batch's blob-tree root is `R` | one gateway's ed25519 signature over `(S, R)`, outside the attested subject | provable misbehaviour by a named gateway; it never fakes availability |
//! | **Reader-derived truth** | these bytes are that batch, and this blob is in it | recomputation from the decoded bytes | nothing: nobody is trusted |
//!
//! The separation is forced rather than chosen. A validator holds one shard, and a hash tree is
//! not linear, so no validator can check a root from what it holds: signing one would be signing
//! hearsay. Attestors therefore sign only what a single shard settles, the gateway signs the root
//! as an attributable claim, and any reader who reconstructs the batch derives the truth for
//! itself. A submitter closes the claimed tier for its own blob with one retrieval ([`client`]).
//!
//! # Thresholds
//!
//! With `n = 3f + 1` validators, two thresholds do all the work, and they are deliberately
//! different:
//!
//! - **`2f + 1` attestations** certify a batch. This is the availability threshold.
//! - **`f + 1` shards** reconstruct it (`minimum_shards`, [`assignment::coding_config`]). This is
//!   the reconstruction threshold.
//!
//! `2f + 1` signers minus at most `f` faulty ones leaves `f + 1` honest custodians, which is
//! exactly what reconstruction needs. So a certificate is not a promise about the future: it is a
//! counting argument about the present, and it is why [`retrieval`] asks the certificate's signers
//! rather than the validator set at large.
//!
//! # Freshness and the retrievability window
//!
//! Two views describe a batch. `D` is the **dispersal view**, stamped into the signed header, and
//! `H` is the **inclusion view**, where the certificate rides into a finalized block. Both bounds
//! below are checked by every verifier, so they hold on the chain rather than by convention:
//!
//! - a certificate is admissible only while `D <= H` and `H - D` is at most
//!   [`FRESHNESS`](constants::FRESHNESS) views;
//! - custody keeps a shard, and the registry keeps a certificate, until the view
//!   [`FRESHNESS`](constants::FRESHNESS) plus [`WINDOW`](constants::WINDOW) beyond `D`.
//!
//! So a client that sees its blob included at `H` is promised retrievability for at least `WINDOW`
//! views past the last view its certificate could have been included at. Freshness is what makes
//! that promise bounded: without it, a certificate dispersed long ago could be included today and
//! oblige custodians who dropped its shards views before. Expiry is section-granular
//! ([`ITEMS_PER_SECTION`](constants::ITEMS_PER_SECTION)): a prunable archive drops whole sections,
//! so data lives a little past its floor rather than a little short of it, and custody and the
//! registry round identically so that "live" means the same thing to both.
//!
//! # Usage
//!
//! Four validators and one client on one machine, which is what `examples/blob/demo.sh` runs.
//! Every identity is derived from a seed, so a command line that lists seeds names the whole
//! deployment; see [`commands::identity`] for why that is a demo convenience and nothing more.
//!
//! ```sh
//! # Validator 0, which the others bootstrap from.
//! commonware-blob validator --me 0@3000 --participants 0,1,2,3 --clients 100 \
//!     --storage-dir /tmp/commonware-blob/0
//!
//! # Validators 1 to 3.
//! commonware-blob validator --me 1@3001 --participants 0,1,2,3 --clients 100 \
//!     --bootstrappers 0@127.0.0.1:3000 --storage-dir /tmp/commonware-blob/1
//!
//! # A client, submitting a file and reading it back from a validator that did not accept it.
//! commonware-blob client --me 100@4000 \
//!     --validators 0@127.0.0.1:3000,1@127.0.0.1:3001,2@127.0.0.1:3002,3@127.0.0.1:3003 \
//!     post --file ./input.bin --out ./output.bin --gateway 0 --from 2
//! ```
//!
//! # Persistence
//!
//! A validator's custody, payload store, and consensus journal all live under `--storage-dir` and
//! all replay what was durable when it reopens, so a validator that is killed and restarted
//! resumes rather than starts over.
//!
//! # Toward an execution layer
//!
//! Nothing below is implemented here. It is the design this rail was shaped for, recorded because
//! the shape only makes sense in light of it.
//!
//! ## The certificate registry
//!
//! When a payload finalizes, every certificate it carries is recorded under its commitment:
//!
//! ```text
//! registry[S] = { R, gw, D, H }
//! ```
//!
//! the blob-tree root, the gateway that claimed it, and the two views. In this example that map is
//! process-local ([`registry`]) and serves the read path. Enshrined in a state-transition
//! function, it is the analog of what makes EIP-4844 usable from a contract: versioned hashes are
//! valid *because the block is valid*, so `BLOBHASH` needs no proof. A `DACERT(S)` opcode would
//! return an entry no contract has to verify, because consensus already did.
//!
//! It is well defined only because inclusion is deduplicated by `S` across a fork's ancestry
//! ([`payload::PayloadStore::included`]): at most one certificate per commitment is ever finalized
//! on one chain, so there is never a question of which writer won.
//!
//! ## The verification ladder
//!
//! A contract asked to believe something about a blob climbs three rungs, cheapest first:
//!
//! 1. **`DACERT(S)`** -- a registry lookup. Availability, settled by consensus.
//! 2. **Poseidon2 membership** -- blob `b` is leaf `i` of `R`, and a 4 KiB page is at offset `o`
//!    of `b`. Both are fixed-depth paths over the trees in [`blob_tree`], verified in-circuit with
//!    the sponge in [`poseidon2`].
//! 3. **A content proof** -- an UltraHonk proof of whatever the application actually cares about,
//!    over the page opened in rung 2.
//!
//! Rung 2 is why a [`BlobId`](types::BlobId) is paged rather than a hash of the whole blob. Opening
//! a page costs about 78 permutations end to end (45 to absorb the page, 14 up the page tree, 2 for
//! the identity itself, 1 for the blob-tree leaf, 16 up the blob tree) and that cost does not move
//! with the size of the blob. It is the hash-native counterpart of 4844's point evaluation: a
//! constant-size opening of a small window of a large object, except that verifying it needs no
//! pairing, no trusted setup, and no barycentric bridge -- just permutations of the same hash the
//! rail already uses.
//!
//! ## Porting the hash
//!
//! A Noir port has one trap. The standard library no longer exposes `Poseidon2::hash`, so the
//! normative definition here is `Poseidon2Hasher::finish_ref` semantics -- capacity slot
//! `len << 64`, rate-3 absorb, a trailing permutation even when the tail is empty -- rebuilt on top
//! of the public `std::hash::poseidon2_permutation`. `conformance/noir/` does exactly that and
//! asserts the vectors this crate embeds, so the two implementations are checked against each other
//! rather than assumed to agree.
//!
//! ## Receipts are reconstructible
//!
//! The proof material for rung 2 is `(S, i, path)`, and none of it has to come from the gateway: a
//! reader that retrieves the batch derives all of it ([`blob_tree::BlobTree::build`]). A gateway
//! handing a submitter a receipt is therefore a convenience, not a trust component, and a gateway
//! that refuses to costs its client one retrieval.
//!
//! ## Closing the claimed tier
//!
//! The claimed tier is the only place a gateway's word counts for anything, and there are two ways
//! to end that. A **fraud window**: the claim is signed and attributable, `derive(decode(S)) != R`
//! is checkable by anyone who reconstructs, so a challenge period plus a slashable bond makes a
//! false root a losing move. Or **validity proofs**: a gateway proves `derive(decode(S)) == R` when
//! it claims it, and the claimed tier disappears into the attested one.
//!
//! A third route is research rather than engineering. If a coding scheme carried an auxiliary
//! commitment that each attestor could check from its own shard, structure would be attested
//! directly and no root would ever be claimed. ZODA's transcript commitment does not do this -- it
//! binds the encoding, not the contents' structure -- and making it do so is not a change that can
//! be made from outside the coding scheme.
//!
//! # Known limitations
//!
//! Every one of these is a deliberate boundary of an example, not an oversight:
//!
//! - **No payload backfill.** Bare simplex carries payload digests, and the gossip layer only
//!   caches what it has seen, so a node offline across a run of finalizations can never obtain
//!   those payloads. It stays a peer and keeps hearing the chain, but verification of anything
//!   built on what it missed remains pending forever. A node that is merely *late* recovers, since
//!   a finalized payload still in the gossip cache is stored when the finalization arrives.
//! - **No custody proofs.** A validator that attests and then silently deletes its shard is
//!   indistinguishable from an honest one until somebody tries to retrieve. Proofs of custody, or
//!   sampling, would close it; the attestation says only that the shard was checked and written.
//! - **No permanence across validator rotation.** Shard index `i` is bound to participant `i` of
//!   the current set. Nothing re-disperses a batch when the set changes, so a certificate can
//!   outlive the validators that custody it. Any real deployment needs a rotation story.
//! - **No inclusion guarantee and no fee market.** A gateway may drop a submission, a proposer may
//!   never carry a certificate, and nothing costs anything. Submissions are unpriced, so an open
//!   deployment would be a free denial-of-service target.
//! - **`commonware-coding` is ALPHA.** ZODA's wire formats may change without a migration path, and
//!   a shard or commitment written by one version is not promised to be readable by the next.
//! - **Retrieval returns a whole batch in one message.** No streaming and no range requests, which
//!   is what pins [`MAX_MESSAGE_SIZE`](constants::MAX_MESSAGE_SIZE) at 16 MiB. Blobs are capped at
//!   [`MAX_BLOB_SIZE`](constants::MAX_BLOB_SIZE) and are never split across batches.
//! - **Status is local to the accepting gateway.** [`gateway::StatusBoard`] is one node's
//!   bookkeeping about submissions it accepted, so a status poll must go back to the gateway that
//!   took the blob. Only the finalized certificate is chain state, and that is readable anywhere.
//! - **The client protocol has no correlation identifier.** A [`client::Client`] sends one request
//!   at a time and matches the reply by its shape, so a late reply can be consumed by the next
//!   poll. That costs a poll, never a wrong verdict, because every answer is verified against what
//!   was asked for -- but it is why nothing here is safe to pipeline.
//! - **The demo pins its ports and its directory.** `demo.sh` uses 3000-3003, 4000, and
//!   `/tmp/commonware-blob` with no collision detection, and will fight anything already there.
//! - **This crate is a binary with no library.** There is no public API to depend on, which is also
//!   why the stability sweep compiles it away rather than annotating it (see the `no_main` pair
//!   below).

// The workspace's stability sweep documents every crate under `commonware_stability_RESERVED`,
// which gates out every library item below that level. Nothing this example is built from survives
// it, and there is nothing here for the sweep to find: this is a `publish = false` binary with no
// public API to annotate. Compiling it away under that cfg is what lets the sweep document the
// rest of the workspace.
#![cfg_attr(commonware_stability_RESERVED, no_main)]
#![cfg(not(commonware_stability_RESERVED))]

mod application;
mod assignment;
mod attestor;
mod blob_tree;
mod client;
mod commands;
mod constants;
mod custody;
mod gateway;
#[cfg(test)]
mod measure;
mod node;
mod payload;
mod poseidon2;
mod registry;
mod retrieval;
mod rpc;
#[cfg(test)]
mod test_util;
mod types;
mod wire;

use std::process::ExitCode;

fn main() -> ExitCode {
    let matches = commands::cli().get_matches();
    let outcome = match matches.subcommand() {
        Some(("validator", matches)) => commands::validator::run(matches),
        Some(("client", matches)) => commands::client::run(matches),
        _ => unreachable!("the parser requires one of the two roles"),
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("commonware-blob: {err}");
            ExitCode::FAILURE
        }
    }
}
