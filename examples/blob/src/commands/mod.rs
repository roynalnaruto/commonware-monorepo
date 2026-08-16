//! The two things this binary can be: a validator, or a client of one.
//!
//! [`validator`] runs the whole node: both rails, every actor, and the storage that survives a
//! restart. [`client`] runs nothing durable -- it dials validators as a secondary peer, submits,
//! polls, retrieves, and verifies everything it is told. [`identity`] is what both derive their
//! keys from, and is the one part of this command line that a real deployment would replace.
//!
//! Arguments are parsed into a struct before anything is started, so a misspelled flag fails
//! before a port is bound or a partition is opened.

pub mod client;
pub mod identity;
pub mod validator;

use clap::Command;

/// Why a command could not run.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An argument was not of the shape the command expects.
    #[error("--{argument}: {reason}")]
    Argument {
        /// The flag that carried it.
        argument: &'static str,
        /// What was wrong with it.
        reason: String,
    },
    /// A file could not be read or written.
    #[error("{path}: {source}")]
    File {
        /// The path that failed.
        path: String,
        /// What the filesystem said.
        #[source]
        source: std::io::Error,
    },
    /// A blob was outside the size a client may submit.
    ///
    /// Blobs are not chunked: a file too large for one blob is the caller's to split.
    #[error("file is {size} bytes; a blob must be between 1 and {limit} bytes")]
    BlobSize {
        /// Size of the file that was offered.
        size: usize,
        /// Largest blob the protocol accepts.
        limit: usize,
    },
    /// A participant could not prove possession of the key it publishes.
    #[error("participant {0} failed its proof of possession")]
    Possession(u64),
    /// The node could not be started.
    #[error("node: {0}")]
    Node(#[from] crate::node::Error),
    /// A request to a validator did not get an answer this client could use.
    #[error("{0}")]
    Client(#[from] crate::client::Error),
    /// The gateway gave up on a blob before it reached a block.
    #[error("the gateway abandoned the blob; resubmit it")]
    Abandoned,
    /// Every actor is meant to outlive the process, and one of them stopped.
    #[error("actor stopped: {0}")]
    Stopped(commonware_runtime::Error),
}

impl Error {
    /// Reports a malformed argument.
    pub fn argument(argument: &'static str, reason: impl Into<String>) -> Self {
        Self::Argument {
            argument,
            reason: reason.into(),
        }
    }
}

/// Builds the command tree.
///
/// Separate from `main` so the parser itself is testable: what a flag is named, which flags are
/// required, and which values are accepted are all decided here.
pub fn cli() -> Command {
    Command::new("commonware-blob")
        .about("post blobs to a data-availability rail alongside a consensus chain")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(validator::command())
        .subcommand(client::command())
}
