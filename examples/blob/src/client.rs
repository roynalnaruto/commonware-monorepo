//! The client side of the rail, which trusts no validator with anything.
//!
//! A client talks to validators over one channel and believes none of them. Everything it acts on
//! it re-derives: the identity of a blob it submitted, the commitment of a batch it was handed,
//! the blob tree the gateway claimed, and the bytes of its own blob. The only thing it takes on
//! faith is the participant set, which it is configured with, and that is what a certificate is
//! checked against.
//!
//! # The ladder
//!
//! [`Client::fetch_verified`] climbs the three integrity tiers in order, and the order is the
//! point:
//!
//! 1. **Attested.** A quorum of the participant set signed the batch header. This is the only
//!    availability statement anywhere in the protocol, and without it the rest is arithmetic over
//!    bytes a stranger chose.
//! 2. **Derived, availability half.** Re-encoding the bytes reproduces the commitment. ZODA's
//!    commitment binds the encoding, so bytes that reproduce it *are* the batch the quorum
//!    attested to — no matter who sent them.
//! 3. **Claimed vs derived, structure half.** The blob tree rebuilt from those bytes either
//!    matches the root the gateway signed or it does not. A mismatch is provable misbehaviour by a
//!    named gateway, and it is recorded as such — but it does not withhold the blob, because
//!    steps 1 and 2 have already settled that these are the right bytes. A gateway can misdescribe
//!    structure; it cannot fake availability.
//! 4. **Located.** The blob whose identity matches is returned, byte for byte.
//!
//! # Correlation
//!
//! One request at a time, matched by the shape of the reply. See [`crate::rpc`] for why, and treat
//! a [`Client`] as a single-threaded conversation with one validator at a time.

use crate::{
    blob_tree::BlobTree,
    constants::coding_namespace,
    poseidon2::Fr,
    types::{self, Blob, BlobId, Scheme},
    wire::{BatchResult, BlobStatus, ClientRequest, ClientResponse, Coder},
};
use commonware_codec::{Encode as _, Error as CodecError};
use commonware_coding::PhasedScheme;
use commonware_cryptography::{
    bls12381::primitives::variant::{MinSig, Variant},
    certificate::Verifier as _,
    ed25519, sha256,
    transcript::Summary,
};
use commonware_macros::select;
use commonware_p2p::{
    Receiver, Recipients, Sender,
    utils::codec::{WrappedReceiver, WrappedSender},
};
use commonware_parallel::Strategy;
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner};
use commonware_utils::ordered::BiMap;
use rand_core::CryptoRng;
use std::time::Duration;
use tracing::warn;

/// Why a client could not get what it asked for.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The request could not be put on the wire.
    #[error("validator is unreachable")]
    Unreachable,
    /// No usable answer arrived in time.
    #[error("validator did not answer in time")]
    Timeout,
    /// The answer did not decode.
    #[error("undecodable response: {0}")]
    Decode(#[from] CodecError),
    /// No certificate over this commitment has been finalized, as far as the validator asked.
    #[error("no finalized certificate over this commitment")]
    Unknown,
    /// The batch is past its retrievability window.
    #[error("batch is past its retrievability window")]
    Expired,
    /// The validator holds a live certificate but could not gather the batch.
    #[error("batch could not be gathered")]
    Unavailable,
    /// The certificate returned is not over the batch that was asked for.
    #[error("response is about another batch")]
    WrongBatch,
    /// The certificate does not carry a quorum of the configured participant set.
    #[error("certificate does not verify")]
    Certificate,
    /// Re-encoding the bytes did not reproduce the attested commitment.
    #[error("bytes are not the attested batch")]
    Commitment,
    /// The bytes could not be re-encoded or rehashed at all.
    #[error("batch could not be re-derived: {0}")]
    Derivation(String),
    /// The batch is genuine, and does not contain the blob that was asked for.
    #[error("batch does not carry this blob")]
    Missing,
}

/// Provable misbehaviour a client has witnessed.
///
/// Kept rather than thrown, because each one names a party: this is the evidence a fraud process
/// would act on, and in this example it is what the tests assert against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fault {
    /// A validator served bytes that are not the batch it claimed.
    ///
    /// Attributable to the serving peer alone: the certificate it sent verifies, and the bytes it
    /// sent do not re-encode to the commitment inside it.
    Tampered {
        /// The validator that served them.
        peer: ed25519::PublicKey,
        /// Commitment the bytes were supposed to reproduce.
        commitment: Summary,
    },
    /// A gateway signed a blob-tree root the batch does not have.
    ///
    /// Attributable to the gateway alone, and provable to anyone who can read the batch: the
    /// signature is the gateway's, and the root is recomputable from the bytes a quorum attested
    /// to. It says nothing about availability.
    FalseRoot {
        /// The gateway that signed the claim.
        gateway: ed25519::PublicKey,
        /// Commitment of the batch it described.
        commitment: Summary,
        /// The root it claimed.
        claimed: Fr,
        /// The root the batch actually has.
        derived: Fr,
    },
}

/// Which reply a request is waiting for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tag {
    Ack,
    Status,
    Batch,
}

/// Returns the shape of a response.
const fn tag(response: &ClientResponse) -> Tag {
    match response {
        ClientResponse::Ack { .. } => Tag::Ack,
        ClientResponse::Status { .. } => Tag::Status,
        ClientResponse::Batch { .. } => Tag::Batch,
    }
}

/// Configuration for a [`Client`].
pub struct Config<T: Strategy> {
    /// The participant set, ordered by ed25519 identity.
    ///
    /// The one thing a client takes on trust, and the thing every certificate is checked against.
    pub participants: BiMap<ed25519::PublicKey, <MinSig as Variant>::Public>,
    /// Base namespace of the deployment.
    pub namespace: Vec<u8>,
    /// How long one request waits for its reply.
    pub timeout: Duration,
    /// Parallelism for re-encoding and signature verification.
    pub strategy: T,
}

/// A non-validator participant in the rail.
pub struct Client<E, S, R, T>
where
    E: BufferPooler + Clock + CryptoRng + Metrics + Spawner,
    S: Sender<PublicKey = ed25519::PublicKey>,
    R: Receiver<PublicKey = ed25519::PublicKey>,
    T: Strategy,
{
    context: E,
    verifier: Scheme,
    namespace: Vec<u8>,
    coding: Vec<u8>,
    timeout: Duration,
    strategy: T,
    sender: WrappedSender<S, ClientRequest>,
    receiver: WrappedReceiver<R, ClientResponse>,
    faults: Vec<Fault>,
}

impl<E, S, R, T> Client<E, S, R, T>
where
    E: BufferPooler + Clock + CryptoRng + Metrics + Spawner,
    S: Sender<PublicKey = ed25519::PublicKey>,
    R: Receiver<PublicKey = ed25519::PublicKey>,
    T: Strategy,
{
    /// Builds a client speaking over `rpc`.
    pub fn new(context: E, config: Config<T>, rpc: (S, R)) -> Self {
        let participants = config.participants.keys().len();
        let sender = WrappedSender::new(context.network_buffer_pool().clone(), rpc.0);
        let receiver = WrappedReceiver::new(participants, rpc.1);
        Self {
            verifier: Scheme::verifier(&config.namespace, config.participants),
            coding: coding_namespace(&config.namespace),
            namespace: config.namespace,
            timeout: config.timeout,
            strategy: config.strategy,
            context,
            sender,
            receiver,
            faults: Vec::new(),
        }
    }

    /// Returns the misbehaviour this client has witnessed, oldest first.
    pub fn faults(&self) -> &[Fault] {
        &self.faults
    }

    /// Hands `blob` to `gateway`, returning the identity to poll with.
    ///
    /// The identity is checked against the client's own bytes before it is returned: a gateway
    /// that acknowledges something else is answering about a blob nobody submitted.
    pub async fn submit(
        &mut self,
        gateway: &ed25519::PublicKey,
        blob: Blob,
    ) -> Result<BlobId, Error> {
        let expected = self.identify(blob.clone()).await?;
        let response = self
            .exchange(gateway, ClientRequest::Submit(blob), Tag::Ack)
            .await?;
        let ClientResponse::Ack { id } = response else {
            return Err(Error::WrongBatch);
        };
        if id != expected {
            warn!(?gateway, "gateway acknowledged another blob");
            return Err(Error::WrongBatch);
        }
        Ok(id)
    }

    /// Asks `gateway` where a blob has got to.
    ///
    /// A hint, never a proof: a status says what one validator's bookkeeping believes, and its
    /// only use is deciding when it is worth asking for something checkable. `None` means that
    /// validator has no record, which is also what a client gets from a validator it never
    /// submitted to.
    pub async fn status(
        &mut self,
        gateway: &ed25519::PublicKey,
        id: BlobId,
    ) -> Result<Option<BlobStatus>, Error> {
        let response = self
            .exchange(gateway, ClientRequest::Status(id), Tag::Status)
            .await?;
        let ClientResponse::Status { status } = response else {
            return Err(Error::WrongBatch);
        };
        Ok(status)
    }

    /// Retrieves the blob `id` from the batch `commitment`, verifying every step itself.
    ///
    /// See the module documentation for the ladder and why step 3 does not withhold the blob.
    pub async fn fetch_verified(
        &mut self,
        peer: &ed25519::PublicKey,
        commitment: Summary,
        id: BlobId,
    ) -> Result<Blob, Error> {
        let response = self
            .exchange(peer, ClientRequest::GetBatch(commitment), Tag::Batch)
            .await?;
        let ClientResponse::Batch { result } = response else {
            return Err(Error::WrongBatch);
        };
        let (batch, cert) = match result {
            BatchResult::Found { batch, cert } => (batch, *cert),
            BatchResult::Unknown => return Err(Error::Unknown),
            BatchResult::Expired => return Err(Error::Expired),
            BatchResult::Unavailable => return Err(Error::Unavailable),
        };

        // A response about another batch is not evidence of anything: the certificate inside it
        // may be perfectly good, just not an answer to the question.
        if cert.header.commitment != commitment {
            return Err(Error::WrongBatch);
        }

        // 1. Attested tier. Both signatures on the certificate: the quorum over the header, and
        //    the gateway over its claim. Neither says the bytes below are right; what the first
        //    says is that these bytes exist somewhere, and what the second says is who to blame
        //    if the structure is misdescribed.
        if !self.verifier.verify_certificate::<_, sha256::Digest>(
            &mut self.context,
            &cert.header,
            &cert.certificate,
            &self.strategy,
        ) {
            return Err(Error::Certificate);
        }
        if !cert.claimed_root.verify(&self.namespace, &commitment) {
            return Err(Error::Certificate);
        }

        // 2. Derived tier, availability half. The commitment binds the encoding, so bytes that
        //    re-encode to it are the attested batch and bytes that do not are the serving peer's
        //    invention.
        let derived = self.recommit(&batch, cert.header.config).await?;
        if derived != commitment {
            warn!(
                ?peer,
                ?commitment,
                "served bytes are not the attested batch"
            );
            self.faults.push(Fault::Tampered {
                peer: peer.clone(),
                commitment,
            });
            return Err(Error::Commitment);
        }

        // 3. Claimed against derived. From here the bytes are known good, so a disagreement is
        //    the gateway's alone, and it costs the client nothing.
        let (ids, root) = self.rederive(batch.clone()).await?;
        if root != cert.claimed_root.root {
            warn!(
                ?commitment,
                gateway = ?cert.claimed_root.gateway,
                "gateway claimed a root the batch does not have"
            );
            self.faults.push(Fault::FalseRoot {
                gateway: cert.claimed_root.gateway.clone(),
                commitment,
                claimed: cert.claimed_root.root,
                derived: root,
            });
        }

        // 4. The blob itself, located by an identity the client recomputed from the batch.
        let position = ids.iter().position(|held| *held == id);
        position
            .and_then(|position| batch.blobs().get(position).cloned())
            .ok_or(Error::Missing)
    }

    /// Computes a blob's identity off the caller's task.
    async fn identify(&self, blob: Blob) -> Result<BlobId, Error> {
        self.context
            .child("blob_id")
            .shared(true)
            .spawn(move |_| async move { blob.id() })
            .await
            .map_err(|err| Error::Derivation(err.to_string()))
    }

    /// Re-encodes a batch and returns the commitment it produces.
    async fn recommit(
        &self,
        batch: &types::Batch,
        config: commonware_coding::Config,
    ) -> Result<Summary, Error> {
        let bytes = batch.encode();
        let namespace = self.coding.clone();
        let strategy = self.strategy.clone();
        // The expensive half of verification, and the reason a client is not a thin wrapper over
        // a socket: it repeats the gateway's encode rather than believing its result.
        let encoded = self
            .context
            .child("encode")
            .shared(true)
            .spawn(move |_| async move {
                <Coder as PhasedScheme>::encode(&namespace, &config, bytes, &strategy)
                    .map(|(commitment, _)| commitment)
                    .map_err(|err| format!("{err:?}"))
            })
            .await
            .map_err(|err| Error::Derivation(err.to_string()))?;
        encoded.map_err(Error::Derivation)
    }

    /// Rebuilds every blob identity and the blob-tree root over them.
    async fn rederive(&self, batch: types::Batch) -> Result<(Vec<BlobId>, Fr), Error> {
        self.context
            .child("blob_tree")
            .shared(true)
            .spawn(move |_| async move {
                let ids = batch.ids();
                BlobTree::build(&ids)
                    .map(|tree| (ids, tree.root()))
                    .map_err(|err| format!("{err}"))
            })
            .await
            .map_err(|err| Error::Derivation(err.to_string()))?
            .map_err(Error::Derivation)
    }

    /// Sends one request and waits for the reply that answers it.
    ///
    /// Replies of another shape are discarded: they belong to a request that has already timed
    /// out, and holding on to them would answer the wrong question.
    async fn exchange(
        &mut self,
        peer: &ed25519::PublicKey,
        request: ClientRequest,
        want: Tag,
    ) -> Result<ClientResponse, Error> {
        if self
            .sender
            .send(Recipients::One(peer.clone()), request, false)
            .is_empty()
        {
            return Err(Error::Unreachable);
        }
        let deadline = self.context.current() + self.timeout;
        loop {
            let received = select! {
                _ = self.context.sleep_until(deadline) => return Err(Error::Timeout),
                message = self.receiver.recv() => message,
            };
            let Ok((from, decoded)) = received else {
                return Err(Error::Unreachable);
            };
            if &from != peer {
                continue;
            }
            match decoded {
                Ok(response) if tag(&response) == want => return Ok(response),
                Ok(_) => continue,
                Err(err) => return Err(Error::Decode(err)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        constants::{
            BATCH_TARGET_SIM, BATCH_TIMEOUT_SIM, CERT_GOSSIP_CHANNEL, CERTIFICATE_CHANNEL,
            CLIENT_RPC_CHANNEL, CLIENT_TIMEOUT_SIM, DISPERSE_REQ_CHANNEL, DISPERSE_RES_CHANNEL,
            DISPERSE_TIMEOUT_SIM, MAX_DISPERSAL_ATTEMPTS, NAMESPACE, PAYLOAD_GOSSIP_CHANNEL,
            RESOLVER_CHANNEL, RETRIEVAL_CHANNEL, VOTE_CHANNEL,
        },
        node::{self, Channels, Node, NodeConfig, Timing},
        test_util::{self, Keys},
        types::{Batch, BatchHeader, DaCert},
        wire::ClientResponse,
    };
    use bytes::Bytes;
    use commonware_consensus::types::View;
    use commonware_cryptography::{Signer as _, transcript::Summary};
    use commonware_p2p::simulated::{
        Oracle, Receiver as SimulatedReceiver, Sender as SimulatedSender,
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner, Supervisor as _, deterministic};
    use commonware_utils::NZUsize;
    use std::time::Duration;

    /// Validators in the full-pipeline tests.
    ///
    /// Ten, which is the data-availability deployment of the plan: `f = 3`, quorum 7, and four
    /// shards reconstruct.
    const VALIDATORS: usize = 10;

    /// The validator a client submits to.
    const GATEWAY: usize = 0;

    /// The validator it later reads from, which is deliberately not the one it submitted to.
    const READER: usize = 4;

    /// Views a submitted blob is given to reach a finalized block.
    const INCLUSION_BUDGET: Duration = Duration::from_secs(60);

    fn runner() -> deterministic::Runner {
        deterministic::Runner::timed(Duration::from_secs(900))
    }

    /// The channel halves a peer speaks to clients over.
    type Rpc = (
        SimulatedSender<ed25519::PublicKey, deterministic::Context>,
        SimulatedReceiver<ed25519::PublicKey>,
    );

    /// A client over a simulated network.
    type TestClient = Client<
        deterministic::Context,
        SimulatedSender<ed25519::PublicKey, deterministic::Context>,
        SimulatedReceiver<ed25519::PublicKey>,
        Sequential,
    >;

    /// Builds a client with the deployment's participant set.
    fn client(context: &deterministic::Context, keys: &Keys, rpc: Rpc) -> TestClient {
        Client::new(
            context.child("client"),
            Config {
                participants: keys.participants.clone(),
                namespace: NAMESPACE.to_vec(),
                timeout: CLIENT_TIMEOUT_SIM,
                strategy: Sequential,
            },
            rpc,
        )
    }

    /// Answers every request on `rpc` with the same canned response.
    ///
    /// Stands in for a validator whose bookkeeping is beside the point: what is under test is
    /// what a client does with an answer, not how the answer was reached.
    fn stub(context: &deterministic::Context, rpc: Rpc, response: ClientResponse) {
        let mut sender =
            WrappedSender::<_, ClientResponse>::new(context.network_buffer_pool().clone(), rpc.0);
        let mut receiver = rpc.1;
        context.child("stub").spawn(move |_| async move {
            while let Ok((peer, _)) = receiver.recv().await {
                let _ = sender.send(Recipients::One(peer), response.clone(), false);
            }
        });
    }

    /// A batch, its header, and a certificate a quorum really attested to.
    ///
    /// `root` is what the gateway claims, which a caller can make disagree with the batch.
    fn certified(keys: &Keys, root: Fr) -> (Batch, BatchHeader, DaCert) {
        let (header, _) = test_util::dispersal(1, 0x77);
        let cert = test_util::genuine_cert(
            &test_util::attesting(keys),
            &header,
            &keys.privates[GATEWAY],
            root,
            test_util::QUORUM,
        );
        (test_util::sample_batch(0x77), header, cert)
    }

    /// Starts a network of a stub validator and a client, and returns the client.
    async fn against(
        context: &deterministic::Context,
        keys: &Keys,
        response: ClientResponse,
    ) -> (TestClient, ed25519::PublicKey) {
        let validator = keys.privates[GATEWAY].public_key();
        let caller = ed25519::PrivateKey::from_seed(VALIDATORS as u64).public_key();
        let oracle = test_util::network(context, &[validator.clone(), caller.clone()]).await;
        stub(
            context,
            test_util::register(&oracle, &validator, CLIENT_RPC_CHANNEL).await,
            response,
        );
        let rpc = test_util::register(&oracle, &caller, CLIENT_RPC_CHANNEL).await;
        (client(context, keys, rpc), validator)
    }

    #[test]
    fn p5_client_detects_tampered_batch() {
        runner().start(|context| async move {
            let keys = test_util::keys(VALIDATORS);
            let (batch, header, cert) = certified(&keys, Fr::from(1u64));

            // The certificate is genuine and the bytes are not: one blob has had a byte flipped,
            // which no signature covers and every reader can catch.
            let mut blobs = batch.blobs().to_vec();
            let mut bytes = blobs[0].as_ref().to_vec();
            bytes[0] ^= 1;
            blobs[0] = Blob::new(Bytes::from(bytes)).expect("blob is within bounds");
            let tampered = Batch::new(blobs).expect("batch is within bounds");
            let wanted = batch.ids()[0];

            let (mut client, validator) = against(
                &context,
                &keys,
                ClientResponse::Batch {
                    result: BatchResult::Found {
                        batch: tampered,
                        cert: Box::new(cert),
                    },
                },
            )
            .await;

            let outcome = client
                .fetch_verified(&validator, header.commitment, wanted)
                .await;
            assert!(
                matches!(outcome, Err(Error::Commitment)),
                "tampered bytes were accepted: {outcome:?}"
            );
            assert_eq!(
                client.faults(),
                [Fault::Tampered {
                    peer: validator,
                    commitment: header.commitment,
                }],
                "the server that tampered was not named"
            );
        });
    }

    #[test]
    fn p5_client_detects_false_claimed_root() {
        runner().start(|context| async move {
            let keys = test_util::keys(VALIDATORS);

            // The gateway signs a root the batch does not have. The signature verifies, which is
            // the point: this is a claim, and a false one is evidence rather than noise.
            let lie = Fr::from(4242u64);
            let (batch, header, cert) = certified(&keys, lie);
            let truth = batch.root().expect("root is computable");
            assert_ne!(truth, lie);
            let wanted = batch.ids()[1];
            let expected = batch.blobs()[1].clone();

            let (mut client, validator) = against(
                &context,
                &keys,
                ClientResponse::Batch {
                    result: BatchResult::Found {
                        batch,
                        cert: Box::new(cert.clone()),
                    },
                },
            )
            .await;

            // Tier separation: structure is misdescribed, availability is not, and the blob is
            // exactly the blob.
            let blob = client
                .fetch_verified(&validator, header.commitment, wanted)
                .await
                .expect("the blob is still extractable");
            assert_eq!(blob, expected);
            assert_eq!(
                client.faults(),
                [Fault::FalseRoot {
                    gateway: cert.claimed_root.gateway.clone(),
                    commitment: header.commitment,
                    claimed: lie,
                    derived: truth,
                }],
                "the gateway that lied was not named"
            );
        });
    }

    #[test]
    fn p5_client_rejects_unattested_batch() {
        runner().start(|context| async move {
            let keys = test_util::keys(VALIDATORS);
            let (batch, header, cert) = certified(&keys, Fr::from(1u64));
            let wanted = batch.ids()[0];

            // The quorum signed a header naming one dispersal view, and this certificate is
            // offered against another. The commitment is untouched, so nothing but checking the
            // signatures catches it.
            let mut unattested = cert.clone();
            unattested.header.dispersal_view = View::new(header.dispersal_view.get() + 1);
            assert_eq!(unattested.header.commitment, header.commitment);

            let (mut client, validator) = against(
                &context,
                &keys,
                ClientResponse::Batch {
                    result: BatchResult::Found {
                        batch: batch.clone(),
                        cert: Box::new(unattested),
                    },
                },
            )
            .await;
            let outcome = client
                .fetch_verified(&validator, header.commitment, wanted)
                .await;
            assert!(
                matches!(outcome, Err(Error::Certificate)),
                "an unattested batch was accepted: {outcome:?}"
            );

            // Nothing is climbed at all when the answer is about another batch, however good the
            // certificate inside it is.
            let (mut client, validator) = against(
                &context,
                &keys,
                ClientResponse::Batch {
                    result: BatchResult::Found {
                        batch,
                        cert: Box::new(cert),
                    },
                },
            )
            .await;
            let outcome = client
                .fetch_verified(&validator, test_util::summary(0x9c), wanted)
                .await;
            assert!(
                matches!(outcome, Err(Error::WrongBatch)),
                "an answer about another batch was accepted: {outcome:?}"
            );
            assert!(client.faults().is_empty());
        });
    }

    /// Registers every channel one validator speaks on.
    async fn channels(
        oracle: &Oracle<ed25519::PublicKey, deterministic::Context>,
        peer: &ed25519::PublicKey,
    ) -> Channels<
        SimulatedSender<ed25519::PublicKey, deterministic::Context>,
        SimulatedReceiver<ed25519::PublicKey>,
    > {
        Channels {
            votes: test_util::register(oracle, peer, VOTE_CHANNEL).await,
            certificates: test_util::register(oracle, peer, CERTIFICATE_CHANNEL).await,
            resolver: test_util::register(oracle, peer, RESOLVER_CHANNEL).await,
            disperse_req: test_util::register(oracle, peer, DISPERSE_REQ_CHANNEL).await,
            disperse_res: test_util::register(oracle, peer, DISPERSE_RES_CHANNEL).await,
            cert_gossip: test_util::register(oracle, peer, CERT_GOSSIP_CHANNEL).await,
            payload_gossip: test_util::register(oracle, peer, PAYLOAD_GOSSIP_CHANNEL).await,
            retrieval: test_util::register(oracle, peer, RETRIEVAL_CHANNEL).await,
            client_rpc: test_util::register(oracle, peer, CLIENT_RPC_CHANNEL).await,
        }
    }

    /// Starts `VALIDATORS` full nodes and one client beside them.
    ///
    /// The client is a real peer with an identity of its own that is in nobody's participant set:
    /// it signs nothing, votes on nothing, and custodies nothing, and the only channel it speaks
    /// on is the client one.
    async fn deploy(
        context: &deterministic::Context,
        prefix: &str,
    ) -> (Vec<Node<deterministic::Context>>, Keys, TestClient) {
        let keys = test_util::keys(VALIDATORS);
        let validators: Vec<ed25519::PublicKey> = keys
            .privates
            .iter()
            .map(|private| private.public_key())
            .collect();
        let caller = ed25519::PrivateKey::from_seed(VALIDATORS as u64).public_key();
        let mut peers = validators.clone();
        peers.push(caller.clone());
        let oracle = test_util::network(context, &peers).await;

        let mut nodes = Vec::new();
        for (index, peer) in validators.iter().enumerate() {
            let node = context.child("validator").with_attribute("index", index);
            let channels = channels(&oracle, peer).await;
            nodes.push(
                node::start(
                    node,
                    NodeConfig {
                        signer: keys.privates[index].clone(),
                        bls: keys.bls[index].clone(),
                        participants: keys.participants.clone(),
                        namespace: NAMESPACE.to_vec(),
                        partition: format!("{prefix}-{index}"),
                        blocker: oracle.control(peer.clone()),
                        peers: oracle.manager(),
                        mailbox_size: NZUsize!(256),
                        batch_target: BATCH_TARGET_SIM,
                        attempts: MAX_DISPERSAL_ATTEMPTS,
                        shard: test_util::shard_cfg(),
                        timing: Timing::simulated(BATCH_TIMEOUT_SIM, DISPERSE_TIMEOUT_SIM),
                        strategy: Sequential,
                    },
                    channels,
                )
                .await
                .expect("node starts"),
            );
        }
        let rpc = test_util::register(&oracle, &caller, CLIENT_RPC_CHANNEL).await;
        let caller = client(context, &keys, rpc);
        (nodes, keys, caller)
    }

    /// Polls `gateway` until `id` is included.
    ///
    /// Returns the commitment, the view it was included at, and every distinct status observed
    /// on the way, so a caller that started polling early can assert the whole lifecycle.
    async fn until_included(
        context: &deterministic::Context,
        client: &mut TestClient,
        gateway: &ed25519::PublicKey,
        id: BlobId,
    ) -> (Summary, View, Vec<Option<BlobStatus>>) {
        let deadline = context.current() + INCLUSION_BUDGET;
        let mut seen = Vec::new();
        loop {
            let status = client
                .status(gateway, id)
                .await
                .expect("gateway answers a status poll");
            if seen.last() != Some(&status) {
                seen.push(status.clone());
            }
            match status {
                Some(BlobStatus::Included { commitment, view }) => {
                    return (commitment, view, seen);
                }
                Some(BlobStatus::Failed) => panic!("the gateway gave up on the blob"),
                _ => {}
            }
            assert!(
                context.current() < deadline,
                "blob was not included in time: {seen:?}"
            );
            context.sleep(Duration::from_millis(20)).await;
        }
    }

    #[test]
    fn p5_client_status_lifecycle() {
        runner().start(|context| async move {
            let (nodes, keys, mut client) = deploy(&context, "p5-status").await;
            let gateway = keys.privates[GATEWAY].public_key();

            // Nothing is known about a blob nobody submitted.
            let stranger = test_util::blobs(1, 512, 0x01).remove(0);
            assert_eq!(
                client
                    .status(&gateway, stranger.id())
                    .await
                    .expect("gateway answers"),
                None
            );

            let blob = test_util::blobs(1, 4096, 0x02).remove(0);
            let id = client
                .submit(&gateway, blob.clone())
                .await
                .expect("gateway accepts the blob");
            assert_eq!(id, blob.id(), "the gateway acknowledged another blob");

            let (commitment, view, seen) =
                until_included(&context, &mut client, &gateway, id).await;

            // The status a client acts on is only ever a hint, but the hint walked the whole
            // lifecycle: accepted by a gateway, certified by a quorum, then finalized.
            assert_eq!(
                seen.first(),
                Some(&Some(BlobStatus::Pending)),
                "the blob was never pending: {seen:?}"
            );
            assert!(
                seen.iter().any(|status| matches!(
                    status,
                    Some(BlobStatus::Certified(certified)) if *certified == commitment
                )),
                "the blob went from pending to included without certifying: {seen:?}"
            );

            // Included means finalized, so every node's registry holds the certificate, and the
            // read path is open on all of them rather than only on the gateway.
            for (index, node) in nodes.iter().enumerate() {
                let (cert, included) = node
                    .registry
                    .get(&commitment)
                    .unwrap_or_else(|| panic!("validator {index} did not register the batch"));
                assert_eq!(cert.header.commitment, commitment);
                assert_eq!(included, view);
            }

            // A validator the client never submitted to knows nothing about the blob itself,
            // which is what makes a status a gateway's bookkeeping rather than chain state.
            assert_eq!(
                client
                    .status(&keys.privates[READER].public_key(), id)
                    .await
                    .expect("validator answers"),
                None
            );
        });
    }

    #[test]
    fn p5_e2e_full_loop() {
        runner().start(|context| async move {
            let (nodes, keys, mut client) = deploy(&context, "p5-e2e").await;
            let gateway = keys.privates[GATEWAY].public_key();
            let reader = keys.privates[READER].public_key();

            // Three blobs of different sizes, submitted to one gateway.
            let sample = test_util::blobs(3, 6 * 1024, 0x5e);
            let mut ids = Vec::new();
            for blob in &sample {
                ids.push(
                    client
                        .submit(&gateway, blob.clone())
                        .await
                        .expect("gateway accepts the blob"),
                );
            }

            // All the way through: batched, dispersed, attested by a quorum, certified,
            // gossiped, proposed, and finalized. Nothing was injected anywhere.
            let mut located = Vec::new();
            for id in &ids {
                let (commitment, view, _) =
                    until_included(&context, &mut client, &gateway, *id).await;
                located.push((commitment, view));
            }
            for (index, node) in nodes.iter().enumerate() {
                for (commitment, view) in &located {
                    let (cert, included) = node
                        .registry
                        .get(commitment)
                        .unwrap_or_else(|| panic!("validator {index} did not register the batch"));
                    assert_eq!(included, *view);

                    // The certificate is one this deployment's validators really signed, over a
                    // batch that was really encoded.
                    assert!(cert.certificate.signers.count() >= test_util::QUORUM);
                    assert!(cert.claimed_root.verify(NAMESPACE, commitment));
                }
            }

            // The read, from a validator that is not the gateway. Every step of the ladder runs
            // against bytes gathered from custodians the client never spoke to.
            for (blob, (id, (commitment, _))) in sample.iter().zip(ids.iter().zip(located.iter())) {
                let retrieved = client
                    .fetch_verified(&reader, *commitment, *id)
                    .await
                    .expect("blob is retrieved and verified");
                assert_eq!(
                    &retrieved, blob,
                    "retrieved bytes differ from what was sent"
                );
            }

            // Nobody misbehaved, and the client would have said so if they had.
            assert!(client.faults().is_empty(), "{:?}", client.faults());

            // A batch this chain never finalized is refused rather than guessed at.
            assert!(matches!(
                client
                    .fetch_verified(&reader, test_util::summary(0xfe), ids[0])
                    .await,
                Err(Error::Unknown)
            ));
        });
    }
}
