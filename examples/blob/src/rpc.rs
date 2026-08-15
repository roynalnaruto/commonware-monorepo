//! What a validator offers clients: submit a blob, poll its status, take a batch back.
//!
//! Three requests, and none of them asks the client to trust the answer. A submission is
//! acknowledged with an identity the client can recompute from its own bytes; a status is a
//! gateway's local bookkeeping and is only ever a hint about when to ask for something checkable;
//! a batch comes with the certificate over it, and the client re-derives the commitment from the
//! bytes rather than believing the sender. That is why any validator can answer a batch query,
//! not just the gateway that built the batch: there is nothing to trust it about.
//!
//! # Shape
//!
//! One actor per validator on a single channel, with requests decoded on the way in and responses
//! encoded on the way out. Two of the three requests wait on something — intake hashes a blob,
//! a batch query waits on a whole gather — so each request is answered on its own task and the
//! loop never blocks behind one client.
//!
//! Requests and responses are not correlated by an identifier: a client sends one request at a
//! time and matches the reply by its shape. That is a documented shortcut of this example, and it
//! is why nothing here is safe to pipeline.

use crate::{
    gateway::{StatusBoard, batcher},
    registry::{Lookup, Registry},
    retrieval,
    wire::{BatchResult, ClientRequest, ClientResponse},
};
use commonware_cryptography::ed25519;
use commonware_macros::select_loop;
use commonware_p2p::{
    Receiver, Recipients, Sender,
    utils::codec::{WrappedReceiver, WrappedSender},
};
use commonware_runtime::{BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell};
use tracing::debug;

/// Configuration for a [`Server`].
pub struct Config<E: Clock + Metrics + Spawner> {
    /// Intake for blobs this node gateways.
    pub batcher: batcher::Mailbox<E>,
    /// Where every blob this node accepted has got to.
    pub board: StatusBoard<E>,
    /// Certificates this node has seen finalized.
    pub registry: Registry,
    /// The retrieval coordinator, which gathers a batch from its custodians.
    pub retrieval: retrieval::Mailbox,
}

/// The client-facing actor.
pub struct Server<E: BufferPooler + Clock + Metrics + Spawner> {
    context: ContextCell<E>,
    batcher: batcher::Mailbox<E>,
    board: StatusBoard<E>,
    registry: Registry,
    retrieval: retrieval::Mailbox,
}

impl<E: BufferPooler + Clock + Metrics + Spawner> Server<E> {
    /// Builds the server.
    pub fn new(context: E, config: Config<E>) -> Self {
        Self {
            context: ContextCell::new(context),
            batcher: config.batcher,
            board: config.board,
            registry: config.registry,
            retrieval: config.retrieval,
        }
    }

    /// Starts the actor over the client channel.
    pub fn start(
        mut self,
        rpc: (
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl Receiver<PublicKey = ed25519::PublicKey>,
        ),
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(rpc))
    }

    async fn run(
        mut self,
        rpc: (
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl Receiver<PublicKey = ed25519::PublicKey>,
        ),
    ) {
        // One channel carries both directions, so the two halves are wrapped in the types they
        // actually see rather than in one shared type.
        let sender = WrappedSender::<_, ClientResponse>::new(
            self.context.network_buffer_pool().clone(),
            rpc.0,
        );
        let mut inbound = WrappedReceiver::<_, ClientRequest>::new((), rpc.1);
        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping client server");
            },
            Ok((peer, decoded)) = inbound.recv() else break => {
                match decoded {
                    Ok(request) => self.serve(peer, request, sender.clone()),
                    Err(err) => debug!(?peer, ?err, "undecodable client request"),
                }
            },
        }
    }

    /// Answers one request on its own task.
    fn serve<S: Sender<PublicKey = ed25519::PublicKey>>(
        &mut self,
        peer: ed25519::PublicKey,
        request: ClientRequest,
        mut sender: WrappedSender<S, ClientResponse>,
    ) {
        let mut batcher = self.batcher.clone();
        let board = self.board.clone();
        let registry = self.registry.clone();
        let retrieval = self.retrieval.clone();
        self.context.child("request").spawn(move |_| async move {
            let response = match request {
                ClientRequest::Submit(blob) => {
                    // Intake hashes the blob on a shared executor, so this waits on work rather
                    // than on the batcher's loop.
                    let Some(id) = batcher.submit(blob).await else {
                        debug!(?peer, "batcher is stopped; submission unanswered");
                        return;
                    };
                    ClientResponse::Ack { id }
                }
                ClientRequest::Status(id) => ClientResponse::Status {
                    status: board.get(&id).map(|entry| entry.status),
                },
                ClientRequest::GetBatch(commitment) => {
                    // The registry settles the two answers that need no work at all. Anything
                    // else is a live certificate, which means the shards are supposed to be out
                    // there and it is worth gathering them.
                    let result = match registry.lookup(&commitment) {
                        Lookup::Unknown => BatchResult::Unknown,
                        Lookup::Expired => BatchResult::Expired,
                        Lookup::Live { .. } => match retrieval.fetch(commitment).await {
                            Ok(Ok((batch, cert))) => BatchResult::Found {
                                batch,
                                cert: Box::new(cert),
                            },
                            Ok(Err(retrieval::Error::Unknown)) => BatchResult::Unknown,
                            Ok(Err(retrieval::Error::Expired)) => BatchResult::Expired,
                            Ok(Err(err)) => {
                                debug!(?peer, ?commitment, ?err, "retrieval failed");
                                BatchResult::Unavailable
                            }
                            Err(_) => {
                                debug!(?peer, ?commitment, "retrieval coordinator is stopped");
                                BatchResult::Unavailable
                            }
                        },
                    };
                    ClientResponse::Batch { result }
                }
            };
            if sender
                .send(Recipients::One(peer.clone()), response, false)
                .is_empty()
            {
                debug!(?peer, "client is unreachable");
            }
        });
    }
}
