//! What the rest of the node learns from consensus.
//!
//! One event matters here: a block finalized. That single fact moves every floor the node keeps --
//! the attestor's watermark, custody expiry, payload retention, the certificate pool, and the
//! status a client polls -- so it is reported once, to one place, and fanned out on the actor's
//! task where those handles live.
//!
//! Notarizations and votes are deliberately ignored. A notarized block may still be replaced, and
//! advancing a floor on one would let a fork prune data the surviving fork still owes.

use super::{Activity, ingress::Message};
use commonware_actor::{Feedback, mailbox::Sender};
use commonware_consensus::Viewable as _;

/// Consensus observer for the application.
#[derive(Clone)]
pub struct Reporter {
    sender: Sender<Message>,
}

impl Reporter {
    /// Creates a reporter that hands finalizations to `sender`.
    pub(super) const fn new(sender: Sender<Message>) -> Self {
        Self { sender }
    }
}

impl commonware_consensus::Reporter for Reporter {
    type Activity = Activity;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let view = activity.view();
        match activity {
            Activity::Finalization(finalization) => self.sender.enqueue(Message::Finalized {
                view,
                payload: finalization.proposal.payload,
            }),
            _ => Feedback::Ok,
        }
    }
}
