//! `client` subcommand: submit blobs to the data-availability rail and retrieve them.
//!
//! # What a client is on this network
//!
//! A secondary peer with an identity of its own that is in nobody's participant set. It signs
//! nothing, votes on nothing, and custodies nothing; it dials the validators, which never dial it,
//! and the only channel it speaks on is the client one. It is configured with the participant set
//! because that is the one thing it takes on trust — every certificate it is shown is checked
//! against it, and everything else it re-derives for itself.
//!
//! # Four commands
//!
//! `submit` hands a file to a gateway and prints the identity it can poll with. `status` asks that
//! gateway where the blob has got to. `get` asks any validator for a batch and climbs the whole
//! verification ladder over the answer. `post` is the three of them in one, which is what the demo
//! runs.
//!
//! `status` targets the gateway rather than any validator on purpose: the status board is one
//! node's own bookkeeping about the blobs it accepted, so a validator the client never submitted
//! to knows nothing about the blob. `get`, by contrast, may target anyone, because nothing about
//! its answer is taken on trust.

use super::{Error, identity};
use crate::{
    client::{Client, Config, Fault},
    constants::{
        CERT_GOSSIP_CHANNEL, CERTIFICATE_CHANNEL, CLIENT_RPC_CHANNEL, CLIENT_RPC_RATE,
        CLIENT_TIMEOUT, CODING_PARALLELISM, CONSENSUS_RATE, DISPERSE_REQ_CHANNEL,
        DISPERSE_REQ_RATE, DISPERSE_RES_CHANNEL, DISPERSE_RES_RATE, GOSSIP_RATE, MAX_BLOB_SIZE,
        MAX_MESSAGE_SIZE, NAMESPACE, PAYLOAD_GOSSIP_CHANNEL, RESOLVER_CHANNEL, RETRIEVAL_CHANNEL,
        RETRIEVAL_RATE, VOTE_CHANNEL,
    },
    types::{Blob, BlobId},
    wire::BlobStatus,
};
use bytes::Bytes;
use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use commonware_codec::{DecodeExt as _, Encode as _, FixedSize as _};
use commonware_cryptography::transcript::Summary;
use commonware_formatting::{Hex, from_hex};
use commonware_p2p::{
    Manager as _,
    authenticated::{discovery, peer_set_limit},
};
use commonware_runtime::{
    Clock as _, Runner as _, Strategizer as _, Supervisor as _,
    tokio::{self, telemetry::Logs},
};
use commonware_utils::{TryCollect as _, ordered::Set, union};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};
use tracing::Level;

/// Peer-set index every node in this deployment tracks its peers at.
const PEER_SET: u64 = 0;

/// How long the client waits for its first answer from a validator.
///
/// Covers the dial, the handshake, and discovery: a client is the party that shows up, so nothing
/// happens until its connection is established.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// How often `--wait` asks the gateway again.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// How long `--wait` and `post` give a blob to reach a finalized block.
///
/// A batch seals on a timer, disperses, collects a quorum, is gossiped, and then waits for a
/// leader to propose it and for that block to finalize: several views rather than several
/// milliseconds.
const INCLUSION_TIMEOUT: Duration = Duration::from_secs(120);

/// Builds the `client` subcommand.
pub fn command() -> Command {
    Command::new("client")
        .about("submit blobs to the data-availability rail and retrieve them")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .arg(
            Arg::new("me")
                .long("me")
                .required(true)
                .help("This client, as <seed>@<port>"),
        )
        .arg(
            Arg::new("validators")
                .long("validators")
                .required(true)
                .value_delimiter(',')
                .help("Every validator, as <seed>@<ip:port>"),
        )
        .subcommand(
            Command::new("submit")
                .about("hand a file to a gateway")
                .arg(file())
                .arg(gateway()),
        )
        .subcommand(
            Command::new("status")
                .about("ask a gateway where a blob has got to")
                .arg(id())
                .arg(gateway())
                .arg(
                    Arg::new("wait")
                        .long("wait")
                        .action(ArgAction::SetTrue)
                        .help("Poll until the blob is included or abandoned"),
                ),
        )
        .subcommand(
            Command::new("get")
                .about("retrieve a blob and verify it against the chain")
                .arg(commitment())
                .arg(id())
                .arg(out())
                .arg(from()),
        )
        .subcommand(
            Command::new("post")
                .about("submit a file, wait for it to be included, and retrieve it")
                .arg(file())
                .arg(out())
                .arg(gateway())
                .arg(from()),
        )
}

/// The `--file` argument.
fn file() -> Arg {
    Arg::new("file")
        .long("file")
        .required(true)
        .value_parser(value_parser!(PathBuf))
        .help("File to submit, between 1 byte and 512 KiB")
}

/// The `--out` argument.
fn out() -> Arg {
    Arg::new("out")
        .long("out")
        .required(true)
        .value_parser(value_parser!(PathBuf))
        .help("Where to write the retrieved blob")
}

/// The `--gateway` argument.
fn gateway() -> Arg {
    Arg::new("gateway")
        .long("gateway")
        .value_parser(value_parser!(u64))
        .help("Seed of the validator to submit to and poll (default: the first validator)")
}

/// The `--from` argument.
fn from() -> Arg {
    Arg::new("from")
        .long("from")
        .value_parser(value_parser!(u64))
        .help("Seed of the validator to read from (default: one that is not the gateway)")
}

/// The `--id` argument.
fn id() -> Arg {
    Arg::new("id")
        .long("id")
        .required(true)
        .help("Blob identity, as printed by `submit`")
}

/// The `--commitment` argument.
fn commitment() -> Arg {
    Arg::new("commitment")
        .long("commitment")
        .required(true)
        .help("Commitment of the batch carrying the blob, as printed by `status`")
}

/// What the client was asked to do.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Hand a file to a gateway.
    Submit {
        /// File to submit.
        file: PathBuf,
    },
    /// Ask a gateway where a blob has got to.
    Status {
        /// The blob to ask about.
        id: BlobId,
        /// Whether to poll until it settles.
        wait: bool,
    },
    /// Retrieve a blob and verify it.
    Get {
        /// Commitment of the batch carrying it.
        commitment: Summary,
        /// The blob to extract from that batch.
        id: BlobId,
        /// Where to write it.
        out: PathBuf,
    },
    /// Submit, wait for inclusion, and retrieve, in one command.
    Post {
        /// File to submit.
        file: PathBuf,
        /// Where to write what comes back.
        out: PathBuf,
    },
}

/// A client's arguments, after everything about them has been checked.
#[derive(Debug, PartialEq, Eq)]
pub struct Args {
    /// Seed this client's identity is derived from.
    pub seed: u64,
    /// Port it listens on.
    pub port: u16,
    /// Every validator, and where to dial it.
    pub validators: Vec<(u64, SocketAddr)>,
    /// The validator submissions and status polls go to.
    pub gateway: u64,
    /// The validator batches are read from.
    pub from: u64,
    /// What to do.
    pub action: Action,
}

impl Args {
    /// Reads the arguments, rejecting anything the client could not act on.
    pub fn parse(matches: &ArgMatches) -> Result<Self, Error> {
        let me = matches
            .get_one::<String>("me")
            .expect("--me is required by the parser");
        let (seed, port) = identity::parse_local(me)
            .ok_or_else(|| Error::argument("me", format!("{me:?} is not <seed>@<port>")))?;

        let mut validators = Vec::new();
        for value in matches
            .get_many::<String>("validators")
            .expect("--validators is required by the parser")
        {
            validators.push(identity::parse_remote(value).ok_or_else(|| {
                Error::argument("validators", format!("{value:?} is not <seed>@<ip:port>"))
            })?);
        }
        let seeds: Vec<u64> = validators.iter().map(|(seed, _)| *seed).collect();
        if identity::participants(&seeds).is_none() {
            return Err(Error::argument(
                "validators",
                "seeds must be distinct and non-empty",
            ));
        }
        if seeds.contains(&seed) {
            return Err(Error::argument(
                "me",
                format!("seed {seed} is a validator; a client is not a participant"),
            ));
        }

        let (action, matches) = match matches.subcommand() {
            Some(("submit", matches)) => (
                Action::Submit {
                    file: path(matches, "file"),
                },
                matches,
            ),
            Some(("status", matches)) => (
                Action::Status {
                    id: blob_id(matches)?,
                    wait: matches.get_flag("wait"),
                },
                matches,
            ),
            Some(("get", matches)) => (
                Action::Get {
                    commitment: summary(matches)?,
                    id: blob_id(matches)?,
                    out: path(matches, "out"),
                },
                matches,
            ),
            Some(("post", matches)) => (
                Action::Post {
                    file: path(matches, "file"),
                    out: path(matches, "out"),
                },
                matches,
            ),
            _ => unreachable!("the parser requires one of the four commands"),
        };

        // The gateway defaults to the first validator listed, and the reader to one that is not
        // the gateway: a read from a validator that never held the blob is what proves the batch
        // was reconstructed from custodians rather than handed back by the node that built it.
        // Both targets are optional and neither is offered by every command, so each is read
        // where it exists and defaulted where it does not.
        let gateway = optional(matches, "gateway").unwrap_or(seeds[0]);
        if !seeds.contains(&gateway) {
            return Err(Error::argument(
                "gateway",
                format!("seed {gateway} is not among the validators"),
            ));
        }
        let default_reader = seeds
            .iter()
            .find(|seed| **seed != gateway)
            .copied()
            .unwrap_or(gateway);
        let from = optional(matches, "from").unwrap_or(default_reader);
        if !seeds.contains(&from) {
            return Err(Error::argument(
                "from",
                format!("seed {from} is not among the validators"),
            ));
        }

        Ok(Self {
            seed,
            port,
            validators,
            gateway,
            from,
            action,
        })
    }
}

/// Reads a seed-valued argument the command may not offer at all.
fn optional(matches: &ArgMatches, name: &str) -> Option<u64> {
    matches.try_get_one::<u64>(name).ok().flatten().copied()
}

/// Reads a required path argument.
fn path(matches: &ArgMatches, name: &'static str) -> PathBuf {
    matches
        .get_one::<PathBuf>(name)
        .expect("the parser requires the argument")
        .clone()
}

/// Parses `--id`, which is a blob identity in its wire form.
fn blob_id(matches: &ArgMatches) -> Result<BlobId, Error> {
    let value = matches
        .get_one::<String>("id")
        .expect("--id is required by the parser");
    from_hex(value)
        .and_then(|bytes| BlobId::decode(bytes.as_slice()).ok())
        .ok_or_else(|| {
            Error::argument(
                "id",
                format!("{value:?} is not a {}-byte blob identity", BlobId::SIZE),
            )
        })
}

/// Parses `--commitment`, which is a batch commitment.
fn summary(matches: &ArgMatches) -> Result<Summary, Error> {
    let value = matches
        .get_one::<String>("commitment")
        .expect("--commitment is required by the parser");
    from_hex(value)
        .and_then(|bytes| Summary::decode(bytes.as_slice()).ok())
        .ok_or_else(|| {
            Error::argument(
                "commitment",
                format!("{value:?} is not a 32-byte commitment"),
            )
        })
}

/// Renders a blob identity the way `--id` reads it back.
///
/// The wire form rather than the field element alone, so the version byte travels with it: an
/// identity printed by one release is refused rather than misread by the next.
pub fn print_id(id: &BlobId) -> String {
    format!("{}", Hex(id.encode()))
}

/// Reads the file a blob is made of, enforcing the size a blob may be.
///
/// Blobs are not chunked. A file larger than one blob is refused with its size rather than split,
/// because splitting it would hand back several identities where the caller asked for one, and
/// reassembly is the caller's protocol rather than this rail's.
fn read_blob(file: &Path) -> Result<Blob, Error> {
    let bytes = std::fs::read(file).map_err(|source| Error::File {
        path: file.display().to_string(),
        source,
    })?;
    Blob::new(Bytes::from(bytes.clone())).map_err(|_| Error::BlobSize {
        size: bytes.len(),
        limit: MAX_BLOB_SIZE,
    })
}

/// Writes retrieved bytes out.
fn write_blob(out: &Path, blob: &Blob) -> Result<(), Error> {
    std::fs::write(out, blob.as_ref()).map_err(|source| Error::File {
        path: out.display().to_string(),
        source,
    })
}

/// Prints one status line.
fn report(status: &BlobStatus) {
    match status {
        BlobStatus::Pending => println!("status     pending"),
        BlobStatus::Certified(commitment) => println!("status     certified in batch {commitment}"),
        BlobStatus::Included { commitment, view } => println!(
            "status     included in batch {commitment} at view {}",
            view.get()
        ),
        BlobStatus::Failed => println!("status     failed; the gateway gave up on the blob"),
    }
}

/// Prints the misbehaviour a retrieval witnessed, if any.
///
/// A fault is never a reason to distrust the bytes: the ladder has already settled those by the
/// time one can be recorded. It names a party, which is what a fraud process would act on.
fn report_faults(faults: &[Fault]) {
    if faults.is_empty() {
        println!("faults     none");
        return;
    }
    for fault in faults {
        match fault {
            Fault::Tampered { peer, commitment } => {
                println!("faults     {peer} served bytes that are not batch {commitment}");
            }
            Fault::FalseRoot {
                gateway,
                commitment,
                claimed,
                derived,
            } => println!(
                "faults     {gateway} claimed root {claimed:?} for batch {commitment}, which is really {derived:?}"
            ),
        }
    }
}

/// Runs one client command.
pub fn run(matches: &ArgMatches) -> Result<(), Error> {
    let args = Args::parse(matches)?;
    let me = identity::Identity::from_seed(args.seed);
    let seeds: Vec<u64> = args.validators.iter().map(|(seed, _)| *seed).collect();
    let participants = identity::participants(&seeds).expect("argument parsing checked the seeds");

    // Everything a client needs is read before the runtime starts, so a mistyped file or an
    // oversized one costs nothing.
    let payload = match &args.action {
        Action::Submit { file } | Action::Post { file, .. } => Some(read_blob(file)?),
        _ => None,
    };

    // The validators are this client's primary peers and its bootstrappers both: it is told where
    // they are because nobody will tell it, and it dials them because nobody will dial it.
    let validators: Set<_> = seeds
        .iter()
        .map(|seed| identity::Identity::from_seed(*seed).key())
        .try_collect()
        .expect("argument parsing checked the seeds");
    let limit = peer_set_limit(validators.iter(), &me.key());
    let bootstrappers = args
        .validators
        .iter()
        .map(|(seed, address)| {
            (
                identity::Identity::from_seed(*seed).key(),
                (*address).into(),
            )
        })
        .collect();
    let listen = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), args.port);
    let p2p = discovery::Config::local(
        me.signer,
        &union(NAMESPACE, b"_P2P"),
        listen,
        listen,
        bootstrappers,
        limit,
        MAX_MESSAGE_SIZE as u32,
    );

    let gateway = identity::Identity::from_seed(args.gateway).key();
    let reader = identity::Identity::from_seed(args.from).key();

    // A client keeps nothing across runs, so its runtime storage is a scratch directory named
    // after the identity that owns it.
    let scratch = std::env::temp_dir().join(format!("commonware-blob-client-{}", args.seed));
    let runtime = tokio::Config::new().with_storage_directory(scratch);
    tokio::Runner::new(runtime).start(|context| async move {
        tokio::telemetry::init(
            context.child("telemetry"),
            Logs {
                level: Level::WARN,
                json: false,
            },
            None,
            None,
        );

        let (mut network, mut oracle) = discovery::Network::new(context.child("network"), p2p);
        oracle.track(PEER_SET, validators);

        // Every channel, not just the one this client speaks on. Validators gossip votes,
        // certificates, and payloads to every peer they are connected to, and a message on a
        // channel this process never registered is a protocol error that drops the connection
        // (`p2p/src/authenticated/discovery/actors/peer/actor.rs`, "invalid channel"). Registering
        // them at the rates the validators use and then dropping the receiving halves is what
        // makes an observer able to sit on the network without listening to any of it: an
        // inbound message for a dropped half is discarded where it arrives, so nothing queues.
        for (channel, rate) in [
            (VOTE_CHANNEL, CONSENSUS_RATE),
            (CERTIFICATE_CHANNEL, CONSENSUS_RATE),
            (RESOLVER_CHANNEL, CONSENSUS_RATE),
            (DISPERSE_REQ_CHANNEL, DISPERSE_REQ_RATE),
            (DISPERSE_RES_CHANNEL, DISPERSE_RES_RATE),
            (CERT_GOSSIP_CHANNEL, GOSSIP_RATE),
            (PAYLOAD_GOSSIP_CHANNEL, GOSSIP_RATE),
            (RETRIEVAL_CHANNEL, RETRIEVAL_RATE),
        ] {
            drop(network.register(channel, rate));
        }
        let rpc = network.register(CLIENT_RPC_CHANNEL, CLIENT_RPC_RATE);
        network.start();

        let mut client = Client::new(
            context.child("client"),
            Config {
                participants,
                namespace: NAMESPACE.to_vec(),
                timeout: CLIENT_TIMEOUT,
                strategy: context.strategy(CODING_PARALLELISM),
            },
            rpc,
        );

        match args.action {
            Action::Submit { .. } => {
                let blob = payload.expect("a submission was read before the runtime started");
                println!("gateway    validator {}", args.gateway);
                client
                    .connect(&gateway, context.current() + CONNECT_TIMEOUT)
                    .await?;
                let id = client.submit(&gateway, blob.clone()).await?;
                println!("submitted  {} bytes", blob.len());
                println!("blob       {}", print_id(&id));
            }
            Action::Status { id, wait } => {
                println!("gateway    validator {}", args.gateway);
                client
                    .connect(&gateway, context.current() + CONNECT_TIMEOUT)
                    .await?;
                if wait {
                    client
                        .poll_status(
                            &gateway,
                            id,
                            context.current() + INCLUSION_TIMEOUT,
                            POLL_INTERVAL,
                            report,
                        )
                        .await?;
                } else {
                    match client.status(&gateway, id).await? {
                        Some(status) => report(&status),
                        None => println!("status     unknown to this gateway"),
                    }
                }
            }
            Action::Get {
                commitment,
                id,
                out,
            } => {
                println!("reader     validator {}", args.from);
                client
                    .connect(&reader, context.current() + CONNECT_TIMEOUT)
                    .await?;
                let blob = client.fetch_verified(&reader, commitment, id).await;
                report_faults(client.faults());
                let blob = blob?;
                println!(
                    "retrieved  {} bytes, verified against the certificate",
                    blob.len()
                );
                write_blob(&out, &blob)?;
                println!("wrote      {}", out.display());
            }
            Action::Post { out, .. } => {
                let blob = payload.expect("a submission was read before the runtime started");
                println!("gateway    validator {}", args.gateway);
                println!("reader     validator {}", args.from);
                client
                    .connect(&gateway, context.current() + CONNECT_TIMEOUT)
                    .await?;

                let id = client.submit(&gateway, blob.clone()).await?;
                println!("submitted  {} bytes", blob.len());
                println!("blob       {}", print_id(&id));

                let settled = client
                    .poll_status(
                        &gateway,
                        id,
                        context.current() + INCLUSION_TIMEOUT,
                        POLL_INTERVAL,
                        report,
                    )
                    .await?;
                let BlobStatus::Included { commitment, .. } = settled else {
                    return Err(Error::Abandoned);
                };

                // Read back from a validator that never saw the blob submitted, over a
                // certificate this client verifies itself.
                client
                    .connect(&reader, context.current() + CONNECT_TIMEOUT)
                    .await?;
                let retrieved = client.fetch_verified(&reader, commitment, id).await;
                report_faults(client.faults());
                let retrieved = retrieved?;
                println!(
                    "retrieved  {} bytes from validator {}, verified against the certificate",
                    retrieved.len(),
                    args.from
                );
                write_blob(&out, &retrieved)?;
                println!("wrote      {}", out.display());
            }
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::cli;

    /// Parses one client command line.
    fn parse(args: &[&str]) -> Result<Args, Error> {
        let matches = cli()
            .try_get_matches_from(std::iter::once("commonware-blob").chain(args.iter().copied()))
            .expect("the parser accepts the arguments");
        let (role, matches) = matches.subcommand().expect("a subcommand was given");
        assert_eq!(role, "client");
        Args::parse(matches)
    }

    /// The identity and validator list every command below shares.
    const PREFIX: &[&str] = &[
        "client",
        "--me",
        "100@4000",
        "--validators",
        "0@127.0.0.1:3000,1@127.0.0.1:3001,2@127.0.0.1:3002,3@127.0.0.1:3003",
    ];

    /// Builds a client command line out of [`PREFIX`] and `args`.
    fn line<'a>(args: &[&'a str]) -> Vec<&'a str> {
        let mut line = PREFIX.to_vec();
        line.extend_from_slice(args);
        line
    }

    /// Builds a client command line whose `flag` value has been replaced.
    fn replacing<'a>(flag: &str, value: &'a str, args: &[&'a str]) -> Vec<&'a str> {
        let mut line = line(args);
        let position = line
            .iter()
            .position(|arg| *arg == flag)
            .expect("the flag is in the shared prefix");
        line[position + 1] = value;
        line
    }

    /// A blob identity in the form `submit` prints and `--id` reads.
    fn sample_id() -> BlobId {
        Blob::new(Bytes::from_static(b"a blob to name"))
            .expect("the sample is within bounds")
            .id()
    }

    #[test]
    fn p7_cli_parses_client_args() {
        let submitted = parse(&line(&["submit", "--file", "/tmp/in.bin"]))
            .expect("the arguments are well-formed");
        assert_eq!(submitted.seed, 100);
        assert_eq!(submitted.port, 4000);
        assert_eq!(
            submitted.validators,
            (0..4)
                .map(|index| (
                    index,
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3000 + index as u16)
                ))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            submitted.action,
            Action::Submit {
                file: PathBuf::from("/tmp/in.bin")
            }
        );

        // The gateway defaults to the first validator, and the reader to one that is not it: a
        // read that came back from the node that built the batch would prove nothing about
        // reconstruction.
        assert_eq!(submitted.gateway, 0);
        assert_eq!(submitted.from, 1);
        let chosen = parse(&line(&[
            "post",
            "--file",
            "/tmp/in.bin",
            "--out",
            "/tmp/out.bin",
            "--gateway",
            "2",
            "--from",
            "3",
        ]))
        .expect("the arguments are well-formed");
        assert_eq!((chosen.gateway, chosen.from), (2, 3));
        assert_eq!(
            chosen.action,
            Action::Post {
                file: PathBuf::from("/tmp/in.bin"),
                out: PathBuf::from("/tmp/out.bin"),
            }
        );
        let defaulted = parse(&line(&[
            "post",
            "--file",
            "/tmp/in.bin",
            "--out",
            "/tmp/out.bin",
            "--gateway",
            "0",
        ]))
        .expect("the arguments are well-formed");
        assert_eq!(defaulted.from, 1);

        // `status` polls once unless it is told to wait.
        let id = sample_id();
        let printed = print_id(&id);
        let polled =
            parse(&line(&["status", "--id", &printed])).expect("the arguments are well-formed");
        assert_eq!(polled.action, Action::Status { id, wait: false });
        let waited = parse(&line(&["status", "--id", &printed, "--wait"]))
            .expect("the arguments are well-formed");
        assert_eq!(waited.action, Action::Status { id, wait: true });
    }

    #[test]
    fn p7_cli_round_trips_hex_arguments() {
        // What `submit` prints is what `--id` reads, and what `status` prints is what
        // `--commitment` reads: the demo pipes one command's output into the next.
        let id = sample_id();
        let commitment = Summary::decode([7u8; 32].as_slice()).expect("32 bytes are a commitment");
        let printed_id = print_id(&id);
        let printed_commitment = format!("{commitment}");
        let parsed = parse(&line(&[
            "get",
            "--commitment",
            &printed_commitment,
            "--id",
            &printed_id,
            "--out",
            "/tmp/out.bin",
        ]))
        .expect("the arguments are well-formed");
        assert_eq!(
            parsed.action,
            Action::Get {
                commitment,
                id,
                out: PathBuf::from("/tmp/out.bin"),
            }
        );
    }

    #[test]
    fn p7_cli_rejects_malformed_client_args() {
        let submit: &[&str] = &["submit", "--file", "/tmp/in.bin"];

        // Identities that are not <seed>@<port>, and validators that are not <seed>@<ip:port>.
        for malformed in ["100", "100@", "@4000", "x@4000"] {
            assert!(
                matches!(
                    parse(&replacing("--me", malformed, submit)),
                    Err(Error::Argument { argument: "me", .. })
                ),
                "accepted --me {malformed:?}"
            );
        }
        for malformed in ["0@127.0.0.1", "0,1", "0@127.0.0.1:3000,0@127.0.0.1:3001"] {
            assert!(
                matches!(
                    parse(&replacing("--validators", malformed, submit)),
                    Err(Error::Argument {
                        argument: "validators",
                        ..
                    })
                ),
                "accepted --validators {malformed:?}"
            );
        }

        // A client that is one of the validators is not a client.
        assert!(matches!(
            parse(&replacing("--me", "2@4000", submit)),
            Err(Error::Argument { argument: "me", .. })
        ));

        // Peers that are not in the deployment cannot be targeted.
        assert!(matches!(
            parse(&line(&[
                "submit",
                "--file",
                "/tmp/in.bin",
                "--gateway",
                "9"
            ])),
            Err(Error::Argument {
                argument: "gateway",
                ..
            })
        ));
        assert!(matches!(
            parse(&line(&[
                "post",
                "--file",
                "/tmp/in.bin",
                "--out",
                "/tmp/out.bin",
                "--from",
                "9"
            ])),
            Err(Error::Argument {
                argument: "from",
                ..
            })
        ));

        // Identities and commitments that are not what they claim to be: the wrong length, the
        // wrong version byte, and not hexadecimal at all.
        let mut wrong_version = sample_id().encode().to_vec();
        wrong_version[0] = 0x02;
        let wrong_version = format!("{}", Hex(&wrong_version));
        for malformed in ["", "0x00", "zz", "01", wrong_version.as_str()] {
            assert!(
                matches!(
                    parse(&line(&["status", "--id", malformed])),
                    Err(Error::Argument { argument: "id", .. })
                ),
                "accepted --id {malformed:?}"
            );
        }
        let printed = print_id(&sample_id());
        for malformed in ["", "abcd", "00"] {
            assert!(
                matches!(
                    parse(&line(&[
                        "get",
                        "--commitment",
                        malformed,
                        "--id",
                        &printed,
                        "--out",
                        "/tmp/out.bin"
                    ])),
                    Err(Error::Argument {
                        argument: "commitment",
                        ..
                    })
                ),
                "accepted --commitment {malformed:?}"
            );
        }
    }

    #[test]
    fn p7_cli_enforces_blob_size() {
        let dir = std::env::temp_dir().join("commonware-blob-p7-size");
        std::fs::create_dir_all(&dir).expect("the scratch directory is writable");

        // Blobs are not chunked, so both ends of the range are refused rather than worked around.
        let empty = dir.join("empty.bin");
        std::fs::write(&empty, []).expect("the scratch directory is writable");
        assert!(matches!(
            read_blob(&empty),
            Err(Error::BlobSize { size: 0, .. })
        ));

        let oversize = dir.join("oversize.bin");
        std::fs::write(&oversize, vec![0u8; MAX_BLOB_SIZE + 1])
            .expect("the scratch directory is writable");
        assert!(matches!(
            read_blob(&oversize),
            Err(Error::BlobSize { size, .. }) if size == MAX_BLOB_SIZE + 1
        ));

        let largest = dir.join("largest.bin");
        std::fs::write(&largest, vec![0u8; MAX_BLOB_SIZE])
            .expect("the scratch directory is writable");
        assert_eq!(
            read_blob(&largest)
                .expect("the largest blob is accepted")
                .len(),
            MAX_BLOB_SIZE
        );

        assert!(matches!(
            read_blob(&dir.join("absent.bin")),
            Err(Error::File { .. })
        ));
    }
}
