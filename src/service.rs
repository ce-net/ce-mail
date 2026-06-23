//! The mailbox service — turns inbound [`MailRequest`]s into [`MailboxStore`] operations.
//!
//! A node running a mailbox feeds each inbound app request through [`MailService::handle`], which
//! applies the capability gate and returns a [`MailReply`]. This is pure (no I/O), so the whole
//! delivery/drain/ack state machine is unit-testable; the binary wires it to the live
//! `request`/`reply` loop.

use crate::envelope::parse_node_id;
use crate::mailbox::{Accepted, MailboxStore};
use crate::proto::{MailReply, MailRequest};
use ce_identity::NodeId;

/// A mailbox service over a [`MailboxStore`], gated by capabilities.
pub struct MailService {
    store: MailboxStore,
}

impl MailService {
    /// Wrap a store in a service.
    pub fn new(store: MailboxStore) -> Self {
        MailService { store }
    }

    /// The underlying store (e.g. to persist it).
    pub fn store(&self) -> &MailboxStore {
        &self.store
    }

    /// Mutable access to the underlying store.
    pub fn store_mut(&mut self) -> &mut MailboxStore {
        &mut self.store
    }

    /// Handle a request from `requester` (the authenticated sender NodeId from app-messaging) at
    /// unix time `now`, consulting `is_revoked` for on-chain revocations. Never panics: every
    /// failure becomes a [`MailReply::Error`].
    pub fn handle(
        &mut self,
        requester: &NodeId,
        request: MailRequest,
        now: u64,
        is_revoked: &dyn Fn(&NodeId, u64) -> bool,
    ) -> MailReply {
        match request {
            MailRequest::Deliver { envelope, grant } => {
                // The envelope must be addressed to someone. Parse the recipient.
                let recipient = match parse_node_id(&envelope.body.to) {
                    Ok(r) => r,
                    Err(e) => return MailReply::Error { message: format!("bad recipient: {e}") },
                };
                // Authorization: either the recipient is draining their *own* mail at us (we hold a
                // grant), or this is a third party delivering. We require a valid accept-grant from
                // the recipient to this mailbox unless the recipient is delivering to themselves and
                // we are their node. Here we always require the grant (open-relay protection): a
                // mailbox stores mail only for recipients that delegated to it.
                if let Err(e) =
                    self.store.check_accept_grant(&recipient, &grant, now, is_revoked)
                {
                    return MailReply::Error { message: e.to_string() };
                }
                match self.store.accept(envelope, now) {
                    Ok(Accepted::Stored) => MailReply::Delivered { duplicate: false },
                    Ok(Accepted::Duplicate) => MailReply::Delivered { duplicate: true },
                    Err(e) => MailReply::Error { message: e.to_string() },
                }
            }
            MailRequest::Drain { recipient, since, grant } => {
                let recip = match parse_node_id(&recipient) {
                    Ok(r) => r,
                    Err(e) => return MailReply::Error { message: format!("bad recipient: {e}") },
                };
                // Only the recipient (or a delegate it authorized) may drain its inbox. The
                // requester must equal the recipient, OR present a grant rooted at the recipient
                // naming the requester. We reuse the accept-grant: a node that may accept mail for R
                // is R's delegate and may drain. Simplest correct rule: requester == recipient, or a
                // valid accept-grant whose leaf audience is the requester.
                if requester != &recip
                    && let Err(e) = self.gate_delegate(&recip, requester, &grant, now, is_revoked)
                {
                    return MailReply::Error { message: e };
                }
                let (stored, cursor) = self.store.read_from(&recipient, since);
                let envelopes = stored.into_iter().map(|s| s.envelope).collect();
                MailReply::Drained { envelopes, cursor }
            }
            MailRequest::Ack { recipient, cursor, grant } => {
                let recip = match parse_node_id(&recipient) {
                    Ok(r) => r,
                    Err(e) => return MailReply::Error { message: format!("bad recipient: {e}") },
                };
                if requester != &recip
                    && let Err(e) = self.gate_delegate(&recip, requester, &grant, now, is_revoked)
                {
                    return MailReply::Error { message: e };
                }
                let removed = self.store.ack(&recipient, cursor);
                MailReply::Acked { removed }
            }
        }
    }

    /// Authorize a delegate `requester` to act for `recipient`: a chain rooted at `recipient`
    /// granting [`crate::mailbox::ABILITY_ACCEPT`] on `Resource::Node(recipient)` whose leaf audience
    /// is `requester`. (The mailbox holding such a grant for itself is the common case; a recipient
    /// draining its own mail hits the `requester == recipient` fast path above.)
    fn gate_delegate(
        &self,
        recipient: &NodeId,
        requester: &NodeId,
        grant: &[ce_cap::SignedCapability],
        now: u64,
        is_revoked: &dyn Fn(&NodeId, u64) -> bool,
    ) -> Result<(), String> {
        ce_cap::authorize(
            recipient,
            &[*recipient],
            &[],
            now,
            requester,
            crate::mailbox::ABILITY_ACCEPT,
            grant,
            is_revoked,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{Envelope, EnvelopeBody};
    use ce_cap::{Caveats, Resource, SignedCapability};
    use ce_identity::Identity;

    fn id(tag: &str) -> Identity {
        let dir = std::env::temp_dir().join(format!("ce-mail-svc-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Identity::load_or_generate(&dir).unwrap()
    }

    fn never_revoked(_: &NodeId, _: u64) -> bool {
        false
    }

    fn accept_grant(recipient: &Identity, mailbox: &Identity) -> Vec<SignedCapability> {
        vec![SignedCapability::issue(
            recipient,
            mailbox.node_id(),
            vec![crate::mailbox::ABILITY_ACCEPT.to_string()],
            Resource::Node(recipient.node_id()),
            Caveats::default(),
            1,
            None,
        )]
    }

    fn envelope(sender: &Identity, to_hex: &str, subject: &str) -> Envelope {
        Envelope::seal(
            sender,
            EnvelopeBody {
                from: String::new(),
                to: to_hex.to_string(),
                subject: subject.into(),
                body_cid: "ab".repeat(32),
                attachment_cids: vec![],
                in_reply_to: String::new(),
                sent_at: 1,
                postage_receipt: String::new(),
            },
        )
    }

    #[test]
    fn deliver_with_valid_grant_stores() {
        let mailbox = id("svc-mb1");
        let recipient = id("svc-rc1");
        let sender = id("svc-sn1");
        let mut svc = MailService::new(MailboxStore::new(mailbox.node_id(), 100));
        let env = envelope(&sender, &recipient.node_id_hex(), "hi");
        let grant = accept_grant(&recipient, &mailbox);
        let reply = svc.handle(
            &sender.node_id(),
            MailRequest::Deliver { envelope: env, grant },
            1000,
            &never_revoked,
        );
        assert!(matches!(reply, MailReply::Delivered { duplicate: false }));
        assert_eq!(svc.store().pending_count(&recipient.node_id_hex()), 1);
    }

    #[test]
    fn deliver_without_grant_is_refused() {
        let mailbox = id("svc-mb2");
        let recipient = id("svc-rc2");
        let sender = id("svc-sn2");
        let mut svc = MailService::new(MailboxStore::new(mailbox.node_id(), 100));
        let env = envelope(&sender, &recipient.node_id_hex(), "hi");
        let reply = svc.handle(
            &sender.node_id(),
            MailRequest::Deliver { envelope: env, grant: vec![] },
            1000,
            &never_revoked,
        );
        assert!(matches!(reply, MailReply::Error { .. }));
        assert_eq!(svc.store().pending_count(&recipient.node_id_hex()), 0);
    }

    #[test]
    fn recipient_drains_own_inbox() {
        let mailbox = id("svc-mb3");
        let recipient = id("svc-rc3");
        let sender = id("svc-sn3");
        let mut svc = MailService::new(MailboxStore::new(mailbox.node_id(), 100));
        let grant = accept_grant(&recipient, &mailbox);
        svc.handle(
            &sender.node_id(),
            MailRequest::Deliver { envelope: envelope(&sender, &recipient.node_id_hex(), "m"), grant },
            1,
            &never_revoked,
        );
        // The recipient drains (requester == recipient fast path).
        let reply = svc.handle(
            &recipient.node_id(),
            MailRequest::Drain { recipient: recipient.node_id_hex(), since: 0, grant: vec![] },
            2,
            &never_revoked,
        );
        match reply {
            MailReply::Drained { envelopes, cursor } => {
                assert_eq!(envelopes.len(), 1);
                assert_eq!(cursor, 1);
            }
            _ => panic!("expected Drained"),
        }
    }

    #[test]
    fn stranger_cannot_drain_inbox() {
        let mailbox = id("svc-mb4");
        let recipient = id("svc-rc4");
        let stranger = id("svc-x4");
        let mut svc = MailService::new(MailboxStore::new(mailbox.node_id(), 100));
        let reply = svc.handle(
            &stranger.node_id(),
            MailRequest::Drain { recipient: recipient.node_id_hex(), since: 0, grant: vec![] },
            1,
            &never_revoked,
        );
        assert!(matches!(reply, MailReply::Error { .. }));
    }

    #[test]
    fn ack_frees_storage_for_recipient() {
        let mailbox = id("svc-mb5");
        let recipient = id("svc-rc5");
        let sender = id("svc-sn5");
        let mut svc = MailService::new(MailboxStore::new(mailbox.node_id(), 100));
        let grant = accept_grant(&recipient, &mailbox);
        svc.handle(
            &sender.node_id(),
            MailRequest::Deliver { envelope: envelope(&sender, &recipient.node_id_hex(), "m"), grant },
            1,
            &never_revoked,
        );
        let reply = svc.handle(
            &recipient.node_id(),
            MailRequest::Ack { recipient: recipient.node_id_hex(), cursor: 1, grant: vec![] },
            2,
            &never_revoked,
        );
        assert!(matches!(reply, MailReply::Acked { removed: 1 }));
        assert_eq!(svc.store().pending_count(&recipient.node_id_hex()), 0);
    }

    #[test]
    fn bad_recipient_hex_yields_error_not_panic() {
        let mailbox = id("svc-mb6");
        let sender = id("svc-sn6");
        let mut svc = MailService::new(MailboxStore::new(mailbox.node_id(), 100));
        // A Deliver with a malformed `to` field.
        let mut env = envelope(&sender, &"ab".repeat(32), "m");
        env.body.to = "not-hex".into();
        // re-sign so signature is valid but recipient is unparseable
        let env = Envelope::seal(&sender, env.body);
        let reply = svc.handle(
            &sender.node_id(),
            MailRequest::Deliver { envelope: env, grant: vec![] },
            1,
            &never_revoked,
        );
        assert!(matches!(reply, MailReply::Error { .. }));
    }
}
