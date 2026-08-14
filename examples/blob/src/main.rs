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
//! # Status
//!
//! Under construction. The subcommands below parse and then exit non-zero; the validator and client
//! roles are built out in later stages.

// The wire vocabulary is defined ahead of the actors that consume it, so most of it has no caller
// inside this binary yet.
#![allow(dead_code)]

mod assignment;
mod attestor;
mod blob_tree;
mod constants;
mod custody;
#[cfg(test)]
mod measure;
mod poseidon2;
#[cfg(test)]
mod test_util;
mod types;
mod wire;

use clap::Command;
use std::process::ExitCode;

fn main() -> ExitCode {
    let matches = Command::new("commonware-blob")
        .about("post blobs to a data-availability rail alongside a consensus chain")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("validator")
                .about("run consensus while attesting to, custodying, and serving blob shards"),
        )
        .subcommand(
            Command::new("client")
                .about("submit blobs to the data-availability rail and retrieve them"),
        )
        .get_matches();

    let Some((role, _)) = matches.subcommand() else {
        eprintln!("commonware-blob: no subcommand provided");
        return ExitCode::FAILURE;
    };
    eprintln!("commonware-blob {role}: not yet implemented");
    ExitCode::FAILURE
}
