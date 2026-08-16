//! `validator` subcommand: run consensus while attesting to, custodying, and serving blob shards.
//!
//! # Two tiers of peer
//!
//! Validators are primary peers of one another: they dial each other, gossip addresses to each
//! other, and drive the chain. Clients are secondary -- tracked by identity so an authenticated
//! network will talk to them at all, but never dialed, because a client is the party that shows
//! up. That is why `--clients` is required rather than optional: there is no open ingress to a
//! validator, so a client nobody was told about cannot connect.

use super::{Error, identity};
use crate::{
    constants::{
        BATCH_TARGET, BATCH_TIMEOUT, CERT_GOSSIP_CHANNEL, CERTIFICATE_CHANNEL, CLIENT_RPC_CHANNEL,
        CLIENT_RPC_RATE, CODING_PARALLELISM, CONSENSUS_RATE, DISPERSE_REQ_CHANNEL,
        DISPERSE_REQ_RATE, DISPERSE_RES_CHANNEL, DISPERSE_RES_RATE, DISPERSE_TIMEOUT, GOSSIP_RATE,
        MAX_DISPERSAL_ATTEMPTS, MAX_MESSAGE_SIZE, MAX_SHARD_SIZE, NAMESPACE,
        PAYLOAD_GOSSIP_CHANNEL, RESOLVER_CHANNEL, RETRIEVAL_CHANNEL, RETRIEVAL_RATE, VOTE_CHANNEL,
    },
    node::{self, Channels, NodeConfig, Timing},
};
use clap::{Arg, ArgMatches, Command, value_parser};
use commonware_coding::CodecConfig;
use commonware_p2p::{
    Manager as _, TrackedPeers,
    authenticated::{discovery, peer_set_limit},
};
use commonware_runtime::{
    Runner as _, Strategizer as _, Supervisor as _,
    tokio::{self, telemetry::Logs},
};
use commonware_utils::{NZUsize, TryCollect as _, ordered::Set, union};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};
use tracing::{Level, info};

/// Mailbox capacity of every actor a validator runs.
const MAILBOX_SIZE: std::num::NonZeroUsize = NZUsize!(1024);

/// Peer-set index every node in this deployment tracks its peers at.
///
/// One fixed set: the demo does not rotate validators, and every node must track the same
/// composition at the same index or discovery bit vectors are read against the wrong peers.
const PEER_SET: u64 = 0;

/// Builds the `validator` subcommand.
pub fn command() -> Command {
    Command::new("validator")
        .about("run consensus while attesting to, custodying, and serving blob shards")
        .arg(
            Arg::new("me")
                .long("me")
                .required(true)
                .help("This validator, as <seed>@<port>"),
        )
        .arg(
            Arg::new("participants")
                .long("participants")
                .required(true)
                .value_delimiter(',')
                .value_parser(value_parser!(u64))
                .help("Seeds of every validator, including this one"),
        )
        .arg(
            Arg::new("clients")
                .long("clients")
                .required(true)
                .value_delimiter(',')
                .value_parser(value_parser!(u64))
                .help("Seeds of every client allowed to submit and retrieve"),
        )
        .arg(
            Arg::new("bootstrappers")
                .long("bootstrappers")
                .required(false)
                .value_delimiter(',')
                .help("Validators to dial on startup, as <seed>@<ip:port>"),
        )
        .arg(
            Arg::new("storage-dir")
                .long("storage-dir")
                .required(true)
                .value_parser(value_parser!(PathBuf))
                .help("Directory this validator's custody, payloads, and journal live in"),
        )
}

/// A validator's arguments, after everything about them has been checked.
#[derive(Debug, PartialEq, Eq)]
pub struct Args {
    /// Seed this validator's keys are derived from.
    pub seed: u64,
    /// Port it listens on.
    pub port: u16,
    /// Seeds of the whole participant set.
    pub participants: Vec<u64>,
    /// Seeds of the clients it accepts.
    pub clients: Vec<u64>,
    /// Validators dialed on startup.
    pub bootstrappers: Vec<(u64, SocketAddr)>,
    /// Where its storage lives.
    pub storage_dir: PathBuf,
}

impl Args {
    /// Reads the arguments, rejecting anything the node could not run with.
    ///
    /// Everything checkable is checked here rather than at startup, so a mistyped deployment
    /// fails before it has opened a socket or a storage partition.
    pub fn parse(matches: &ArgMatches) -> Result<Self, Error> {
        let me = matches
            .get_one::<String>("me")
            .expect("--me is required by the parser");
        let (seed, port) = identity::parse_local(me)
            .ok_or_else(|| Error::argument("me", format!("{me:?} is not <seed>@<port>")))?;

        let participants: Vec<u64> = matches
            .get_many::<u64>("participants")
            .expect("--participants is required by the parser")
            .copied()
            .collect();
        if identity::participants(&participants).is_none() {
            return Err(Error::argument(
                "participants",
                "seeds must be distinct and non-empty",
            ));
        }
        if !participants.contains(&seed) {
            return Err(Error::argument(
                "participants",
                format!("this validator's seed {seed} is not among them"),
            ));
        }

        let clients: Vec<u64> = matches
            .get_many::<u64>("clients")
            .expect("--clients is required by the parser")
            .copied()
            .collect();
        if let Some(both) = clients.iter().find(|client| participants.contains(client)) {
            return Err(Error::argument(
                "clients",
                format!("seed {both} is already a validator"),
            ));
        }

        let mut bootstrappers = Vec::new();
        for value in matches
            .get_many::<String>("bootstrappers")
            .into_iter()
            .flatten()
        {
            let peer = identity::parse_remote(value).ok_or_else(|| {
                Error::argument(
                    "bootstrappers",
                    format!("{value:?} is not <seed>@<ip:port>"),
                )
            })?;
            if !participants.contains(&peer.0) {
                return Err(Error::argument(
                    "bootstrappers",
                    format!("seed {} is not a validator", peer.0),
                ));
            }
            bootstrappers.push(peer);
        }

        Ok(Self {
            seed,
            port,
            participants,
            clients,
            bootstrappers,
            storage_dir: matches
                .get_one::<PathBuf>("storage-dir")
                .expect("--storage-dir is required by the parser")
                .clone(),
        })
    }
}

/// Runs a validator until one of its actors stops or the process is killed.
///
/// # Termination
///
/// There is no graceful-shutdown signal to wait on: the runtime exposes no handler for one, so a
/// validator runs until it is killed. Nothing is lost by that. Every store this node writes is
/// crash-durable and replays what was durable when it reopens, which is the same thing a restart
/// after a crash finds and is what `restart_rebuilds_dedup_and_custody` exercises. The one
/// thing that does end the process is an actor stopping, which is never expected: it is reported
/// rather than survived, because a node missing one of its actors is a node that answers some
/// questions and silently ignores others.
pub fn run(matches: &ArgMatches) -> Result<(), Error> {
    let args = Args::parse(matches)?;
    let me = identity::Identity::from_seed(args.seed);
    let participants =
        identity::participants(&args.participants).expect("argument parsing checked the seeds");

    // Every participant's proof of possession, before anything is signed under the assumption
    // that the set is what it says it is. See `identity::verify_possession` for why this is
    // vacuous with seed-derived keys and why it is here anyway.
    identity::verify_possession(&args.participants, NAMESPACE).map_err(Error::Possession)?;

    // Validators are primary and clients are secondary: the peers this node dials, and the peers
    // it merely answers.
    let validators: Set<_> = args
        .participants
        .iter()
        .map(|seed| identity::Identity::from_seed(*seed).key())
        .try_collect()
        .expect("argument parsing checked the seeds");
    let clients: Set<_> = args
        .clients
        .iter()
        .map(|seed| identity::Identity::from_seed(*seed).key())
        .try_collect()
        .map_err(|_| Error::argument("clients", "seeds must be distinct"))?;
    let tracked = TrackedPeers::new(validators, clients);
    let limit = peer_set_limit(tracked.clone().union().iter(), &me.key());

    let listen = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), args.port);
    let bootstrappers = args
        .bootstrappers
        .iter()
        .map(|(seed, address)| {
            (
                identity::Identity::from_seed(*seed).key(),
                (*address).into(),
            )
        })
        .collect();
    let p2p = discovery::Config::local(
        me.signer.clone(),
        &union(NAMESPACE, b"_P2P"),
        listen,
        listen,
        bootstrappers,
        limit,
        MAX_MESSAGE_SIZE as u32,
    );

    let runtime = tokio::Config::new().with_storage_directory(&args.storage_dir);
    tokio::Runner::new(runtime).start(|context| async move {
        tokio::telemetry::init(
            context.child("telemetry"),
            Logs {
                level: Level::INFO,
                json: false,
            },
            None,
            None,
        );
        info!(
            seed = args.seed,
            key = ?me.key(),
            %listen,
            validators = args.participants.len(),
            "starting validator"
        );

        let (mut network, mut oracle) = discovery::Network::new(context.child("network"), p2p);
        oracle.track(PEER_SET, tracked);

        // One channel per conversation the node has, each rate-limited for the size of message it
        // carries: consensus traffic is small and frequent, a dispersal is a multi-megabyte shard
        // and happens twice a second at most.
        let channels = Channels {
            votes: network.register(VOTE_CHANNEL, CONSENSUS_RATE),
            certificates: network.register(CERTIFICATE_CHANNEL, CONSENSUS_RATE),
            resolver: network.register(RESOLVER_CHANNEL, CONSENSUS_RATE),
            disperse_req: network.register(DISPERSE_REQ_CHANNEL, DISPERSE_REQ_RATE),
            disperse_res: network.register(DISPERSE_RES_CHANNEL, DISPERSE_RES_RATE),
            cert_gossip: network.register(CERT_GOSSIP_CHANNEL, GOSSIP_RATE),
            payload_gossip: network.register(PAYLOAD_GOSSIP_CHANNEL, GOSSIP_RATE),
            retrieval: network.register(RETRIEVAL_CHANNEL, RETRIEVAL_RATE),
            client_rpc: network.register(CLIENT_RPC_CHANNEL, CLIENT_RPC_RATE),
        };
        let network_handle = network.start();

        let mut node = node::start(
            context.child("node"),
            NodeConfig {
                signer: me.signer,
                bls: me.bls,
                participants,
                namespace: NAMESPACE.to_vec(),
                partition: format!("validator-{}", args.seed),
                blocker: oracle.clone(),
                peers: oracle,
                mailbox_size: MAILBOX_SIZE,
                batch_target: BATCH_TARGET,
                attempts: MAX_DISPERSAL_ATTEMPTS,
                shard: CodecConfig {
                    maximum_shard_size: MAX_SHARD_SIZE,
                },
                timing: Timing::production(BATCH_TIMEOUT, DISPERSE_TIMEOUT),
                strategy: context.strategy(CODING_PARALLELISM),
            },
            channels,
        )
        .await?;
        info!("validator started");

        // The network is one of the tasks the node is only alive with, so it joins the group the
        // node's own actors are supervised as.
        node.handles.push(network_handle);
        node.run().await.map_err(Error::Stopped)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::cli;

    /// Parses one validator command line.
    fn parse(args: &[&str]) -> Result<Args, Error> {
        let matches = cli()
            .try_get_matches_from(std::iter::once("commonware-blob").chain(args.iter().copied()))
            .expect("the parser accepts the arguments");
        let (role, matches) = matches.subcommand().expect("a subcommand was given");
        assert_eq!(role, "validator");
        Args::parse(matches)
    }

    /// A well-formed validator command line, as the demo script writes it.
    const VALID: &[&str] = &[
        "validator",
        "--me",
        "1@3001",
        "--participants",
        "0,1,2,3",
        "--clients",
        "100",
        "--bootstrappers",
        "0@127.0.0.1:3000",
        "--storage-dir",
        "/tmp/commonware-blob/1",
    ];

    #[test]
    fn parses_args() {
        assert_eq!(
            parse(VALID).expect("the arguments are well-formed"),
            Args {
                seed: 1,
                port: 3001,
                participants: vec![0, 1, 2, 3],
                clients: vec![100],
                bootstrappers: vec![(0, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3000))],
                storage_dir: PathBuf::from("/tmp/commonware-blob/1"),
            }
        );

        // Bootstrappers are how a node that is not first to start finds the others; the first one
        // has none.
        let bootstrapper = parse(&[
            "validator",
            "--me",
            "0@3000",
            "--participants",
            "0,1,2,3",
            "--clients",
            "100",
            "--storage-dir",
            "/tmp/commonware-blob/0",
        ])
        .expect("the arguments are well-formed");
        assert!(bootstrapper.bootstrappers.is_empty());
    }

    #[test]
    fn rejects_malformed_args() {
        /// Replaces the value of `flag` in an otherwise valid command line.
        fn with(flag: &str, value: &'static str) -> Vec<&'static str> {
            let mut args = VALID.to_vec();
            let position = args
                .iter()
                .position(|arg| *arg == flag)
                .expect("the flag is in the valid command line");
            args[position + 1] = value;
            args
        }

        // Identities that are not <seed>@<port>.
        for malformed in ["1", "1@", "@3001", "one@3001", "1@70000"] {
            assert!(
                matches!(
                    parse(&with("--me", malformed)),
                    Err(Error::Argument { argument: "me", .. })
                ),
                "accepted --me {malformed:?}"
            );
        }

        // A validator that is not in its own participant set has no shard and no vote.
        assert!(matches!(
            parse(&with("--participants", "0,2,3")),
            Err(Error::Argument {
                argument: "participants",
                ..
            })
        ));

        // A repeated participant would take two shards and two votes.
        assert!(matches!(
            parse(&with("--participants", "0,1,1")),
            Err(Error::Argument {
                argument: "participants",
                ..
            })
        ));

        // A client that is also a validator is a configuration mistake, not two tiers.
        assert!(matches!(
            parse(&with("--clients", "2")),
            Err(Error::Argument {
                argument: "clients",
                ..
            })
        ));

        // Bootstrappers name validators, at addresses that parse.
        for malformed in ["0@127.0.0.1", "0", "9@127.0.0.1:3009"] {
            assert!(
                matches!(
                    parse(&with("--bootstrappers", malformed)),
                    Err(Error::Argument {
                        argument: "bootstrappers",
                        ..
                    })
                ),
                "accepted --bootstrappers {malformed:?}"
            );
        }
    }

    #[test]
    fn requires_args() {
        // Every flag but `--bootstrappers` is required, and the parser is what enforces it.
        for missing in ["--me", "--participants", "--clients", "--storage-dir"] {
            let position = VALID
                .iter()
                .position(|arg| *arg == missing)
                .expect("the flag is in the valid command line");
            let mut args = VALID.to_vec();
            args.drain(position..position + 2);
            assert!(
                cli()
                    .try_get_matches_from(
                        std::iter::once("commonware-blob").chain(args.iter().copied())
                    )
                    .is_err(),
                "accepted a command line without {missing}"
            );
        }
    }
}
