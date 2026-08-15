//! The handle consensus and the gateway hold, and the traits it satisfies.
//!
//! Everything here is an enqueue. The decisions all belong to the actor, which owns the payload
//! store and the certificate pool; a mailbox that decided anything would be deciding it on
//! whichever task happened to call it.

use super::{Context, actor::Snapshot};
use crate::{types::DaCert, wire::Payload};
use commonware_actor::{
    Feedback,
    mailbox::{Policy, Sender},
};
use commonware_broadcast::Broadcaster;
use commonware_consensus::{
    Automaton, CertifiableAutomaton, Relay,
    simplex::Plan,
    types::{Round, View},
};
use commonware_cryptography::{ed25519, sha256};
use commonware_p2p::Recipients;
use commonware_utils::channel::oneshot;
use std::{collections::VecDeque, sync::Arc};

/// Work handed to the application.
pub(super) enum Message {
    /// Consensus wants a payload for a position on the chain.
    Propose {
        context: Context,
        response: oneshot::Sender<sha256::Digest>,
    },
    /// Consensus wants somebody else's payload checked at a position on the chain.
    Verify {
        context: Context,
        payload: sha256::Digest,
        response: oneshot::Sender<bool>,
    },
    /// A payload arrived from the gossip layer, answering an outstanding [`Message::Verify`].
    Fetched {
        context: Context,
        payload: Arc<Payload>,
        response: oneshot::Sender<bool>,
    },
    /// Consensus asks whether a notarized payload is safe to commit to.
    Certify {
        round: Round,
        payload: sha256::Digest,
        response: oneshot::Sender<bool>,
    },
    /// Consensus asks for a proposal to be disseminated.
    Relay {
        payload: sha256::Digest,
        recipients: Recipients<ed25519::PublicKey>,
    },
    /// A certificate to pool, and whether peers should hear about it from this node.
    ///
    /// Boxed because a certificate is an order of magnitude larger than anything else here, and
    /// every queued message would otherwise be sized by it.
    Certificate { cert: Box<DaCert>, forward: bool },
    /// A block finalized.
    Finalized { view: View, payload: sha256::Digest },
    /// Diagnostic: the payload behind a digest, if this node holds it.
    Held {
        digest: sha256::Digest,
        response: oneshot::Sender<Option<Arc<Payload>>>,
    },
    /// Diagnostic: what this node believes about the finalized chain and its pool.
    Inspect { response: oneshot::Sender<Snapshot> },
}

impl Policy for Message {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut VecDeque<Self>, message: Self) {
        // Consensus requests are single-shot and a certificate is not offered twice, so nothing
        // here can be recovered by dropping it and waiting for a repeat.
        overflow.push_back(message);
    }
}

/// Handle to an [`Application`](super::Application).
#[derive(Clone)]
pub struct Mailbox {
    sender: Sender<Message>,
}

impl Mailbox {
    /// Creates a handle onto `sender`.
    pub(super) const fn new(sender: Sender<Message>) -> Self {
        Self { sender }
    }

    /// Offers a certificate to this node's pool without gossiping it.
    ///
    /// The path a certificate takes when it is already known to be local: a gateway's own
    /// assembly reaches the pool through [`Broadcaster::broadcast`], which also puts it on the
    /// wire, while this is for a certificate that is already where it needs to be.
    ///
    /// Returns whether the offer was accepted for processing, not whether it was pooled: the
    /// certificate is checked on the actor's task.
    pub fn certificate(&self, cert: DaCert) -> bool {
        self.sender
            .enqueue(Message::Certificate {
                cert: Box::new(cert),
                forward: false,
            })
            .accepted()
    }

    /// Returns the payload behind `digest`, if this node holds it.
    pub async fn held(&self, digest: sha256::Digest) -> Option<Arc<Payload>> {
        let (response, receiver) = oneshot::channel();
        if !self
            .sender
            .enqueue(Message::Held { digest, response })
            .accepted()
        {
            return None;
        }
        receiver.await.ok().flatten()
    }

    /// Returns what this node believes about the finalized chain and its certificate pool.
    ///
    /// Diagnostic rather than protocol: nothing in the rail depends on it.
    pub async fn inspect(&self) -> Option<Snapshot> {
        let (response, receiver) = oneshot::channel();
        if !self
            .sender
            .enqueue(Message::Inspect { response })
            .accepted()
        {
            return None;
        }
        receiver.await.ok()
    }
}

impl Automaton for Mailbox {
    type Digest = sha256::Digest;
    type Context = Context;

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        let (response, receiver) = oneshot::channel();
        if !self
            .sender
            .enqueue(Message::Propose { context, response })
            .accepted()
        {
            // Dropping the responder withdraws the proposal, which consensus reads as this node
            // having nothing to offer for the view.
            tracing::debug!("application is stopped; proposal withdrawn");
        }
        receiver
    }

    async fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let (response, receiver) = oneshot::channel();
        if !self
            .sender
            .enqueue(Message::Verify {
                context,
                payload,
                response,
            })
            .accepted()
        {
            tracing::debug!("application is stopped; verification abandoned");
        }
        receiver
    }
}

impl CertifiableAutomaton for Mailbox {
    async fn certify(&mut self, round: Round, payload: Self::Digest) -> oneshot::Receiver<bool> {
        let (response, receiver) = oneshot::channel();
        if !self
            .sender
            .enqueue(Message::Certify {
                round,
                payload,
                response,
            })
            .accepted()
        {
            tracing::debug!("application is stopped; certification abandoned");
        }
        receiver
    }
}

impl Relay for Mailbox {
    type Digest = sha256::Digest;
    type PublicKey = ed25519::PublicKey;
    type Plan = Plan<ed25519::PublicKey>;

    fn broadcast(&mut self, payload: Self::Digest, plan: Self::Plan) -> Feedback {
        // Bare simplex carries digests, so this is what actually puts a proposal where its
        // verifiers can find it.
        let recipients = match plan {
            Plan::Propose { .. } => Recipients::All,
            Plan::Forward { recipients, .. } => recipients,
        };
        self.sender.enqueue(Message::Relay {
            payload,
            recipients,
        })
    }
}

impl Broadcaster for Mailbox {
    type Recipients = Recipients<ed25519::PublicKey>;
    type Message = DaCert;

    /// Pools a certificate and puts it on the wire.
    ///
    /// This is the gateway's gossip handle. Recipients are decided here rather than by the
    /// caller: a certificate is worth the same to every validator, and the pool it has to reach
    /// first is this node's own.
    fn broadcast(&self, _: Self::Recipients, cert: Self::Message) -> Feedback {
        self.sender.enqueue(Message::Certificate {
            cert: Box::new(cert),
            forward: true,
        })
    }
}
