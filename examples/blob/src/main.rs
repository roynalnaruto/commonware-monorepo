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

// The wire vocabulary is defined ahead of the actors that consume it, so most of it has no caller
// inside this binary yet.
#![allow(dead_code)]
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
