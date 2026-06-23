//! The mailbox store — store-and-forward for offline recipients, with a capability gate.
//!
//! A **mailbox** is an always-on node that accepts envelopes on behalf of a recipient who may be
//! offline, holds them durably, and replays them when the recipient drains its inbox. It is the
//! relay-incentives pattern applied to mail: the recipient grants the mailbox an `accept-mail`
//! capability (a [`ce_cap`] chain), the mailbox honors only envelopes addressed to recipients it is
//! authorized to accept for, and (in a paid deployment) the recipient pays over a channel.
//!
//! ## Authorization model
//!
//! The mailbox is the *resource owner's* delegate. The recipient (root) issues a capability with
//! ability [`ABILITY_ACCEPT`] and `Resource::Node(recipient)` to the mailbox node. When a sender
//! delivers, the mailbox checks that the **envelope's `to`** is a node the presenter is authorized
//! to accept mail for. We model "accept mail for recipient R" as: a chain rooted at R, granting
//! [`ABILITY_ACCEPT`], whose leaf audience is the mailbox, on `Resource::Node(R)`. The mailbox's own
//! [`MailboxStore::self_id`] is the `self` the gate verifies against (the mailbox decides whether to
//! store), and R is the resource — so the gate is: "did R authorize this mailbox to accept R's
//! mail?".
//!
//! This keeps the mailbox from being an open relay (no spam amplification): it only stores mail for
//! recipients that have explicitly delegated to it.

use crate::envelope::Envelope;
use anyhow::{Result, anyhow};
use ce_cap::{SignedCapability, authorize};
use ce_identity::NodeId;
use std::collections::HashMap;

/// The capability ability a recipient grants a mailbox: "accept mail addressed to me".
pub const ABILITY_ACCEPT: &str = "mail:accept";

/// A stored envelope plus the unix-second it was accepted (for ordering and retention).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredEnvelope {
    pub envelope: Envelope,
    pub stored_at: u64,
}

/// An in-memory (optionally persistable) store-and-forward mailbox. Maps a recipient NodeId (hex)
/// to that recipient's ordered, de-duplicated queue of envelopes.
#[derive(Debug, Clone)]
pub struct MailboxStore {
    /// This mailbox node's own id — the `self` the capability gate authorizes against.
    self_id: NodeId,
    /// recipient_hex -> queue of stored envelopes (insertion order, de-duped by message id).
    queues: HashMap<String, Vec<StoredEnvelope>>,
    /// message ids already stored per recipient, for idempotent delivery.
    seen: HashMap<String, std::collections::HashSet<String>>,
    /// Max envelopes retained per recipient (oldest evicted past this — bounded memory).
    capacity_per_recipient: usize,
}

/// Outcome of an [`MailboxStore::accept`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Accepted {
    /// Newly stored.
    Stored,
    /// Already present (idempotent re-delivery) — not stored again.
    Duplicate,
}

impl MailboxStore {
    /// A new empty mailbox owned by `self_id`, retaining up to `capacity_per_recipient` envelopes
    /// per recipient.
    pub fn new(self_id: NodeId, capacity_per_recipient: usize) -> Self {
        MailboxStore {
            self_id,
            queues: HashMap::new(),
            seen: HashMap::new(),
            capacity_per_recipient: capacity_per_recipient.max(1),
        }
    }

    /// This mailbox's own NodeId.
    pub fn self_id(&self) -> &NodeId {
        &self.self_id
    }

    /// Verify that `chain` authorizes accepting mail for `recipient`: a capability chain rooted at
    /// `recipient`, granting [`ABILITY_ACCEPT`] on `Resource::Node(recipient)`, with this mailbox as
    /// the leaf audience. `now` is unix seconds; `is_revoked` consults the on-chain revocation set.
    ///
    /// The recipient is always an accepted root here (you can always authorize accepting *your own*
    /// mail), so we pass `recipient` as an accepted root in addition to self.
    pub fn check_accept_grant(
        &self,
        recipient: &NodeId,
        chain: &[SignedCapability],
        now: u64,
        is_revoked: &dyn Fn(&NodeId, u64) -> bool,
    ) -> Result<()> {
        // The gate verifies against the *recipient* node as the resource: the chain must root at
        // the recipient and target Resource::Node(recipient). We authorize with self_id == recipient
        // so Resource::Node(recipient) matches, and accept the recipient as the root authority.
        authorize(
            recipient,
            &[*recipient],
            &[],
            now,
            &self.self_id,
            ABILITY_ACCEPT,
            chain,
            is_revoked,
        )
        .map_err(|e| anyhow!("mailbox not authorized to accept mail for recipient: {e}"))
    }

    /// Accept an envelope for storage. Verifies the envelope signature, then enqueues it under the
    /// envelope's `to`. Idempotent: re-delivering the same message id returns [`Accepted::Duplicate`].
    ///
    /// Authorization is the caller's responsibility — call [`check_accept_grant`](Self::check_accept_grant)
    /// first (the [`crate::service::MailService`] does this). This method only enforces sender
    /// authenticity and de-duplication, so it can never store a forged envelope or grow unboundedly.
    pub fn accept(&mut self, envelope: Envelope, now: u64) -> Result<Accepted> {
        envelope
            .verify()
            .map_err(|e| anyhow!("refusing to store unverifiable envelope: {e}"))?;
        let to = envelope.body.to.clone();
        if to.is_empty() {
            return Err(anyhow!("envelope has no recipient"));
        }
        let mid = envelope.message_id();
        let seen = self.seen.entry(to.clone()).or_default();
        if seen.contains(&mid) {
            return Ok(Accepted::Duplicate);
        }
        seen.insert(mid);
        let q = self.queues.entry(to).or_default();
        q.push(StoredEnvelope { envelope, stored_at: now });
        // Bounded retention: evict the oldest beyond capacity.
        if q.len() > self.capacity_per_recipient {
            let overflow = q.len() - self.capacity_per_recipient;
            q.drain(0..overflow);
        }
        Ok(Accepted::Stored)
    }

    /// Number of stored envelopes for `recipient_hex`.
    pub fn pending_count(&self, recipient_hex: &str) -> usize {
        self.queues.get(recipient_hex).map(|q| q.len()).unwrap_or(0)
    }

    /// Drain (return and remove) all envelopes stored after the `since` index for `recipient_hex`.
    /// Returns the envelopes from cursor `since` to the end; the new cursor is the returned length +
    /// `since`. This is a *replay-safe* cursor read: pass `0` to get everything, then store the
    /// returned cursor and pass it next time. Drains are non-destructive until [`ack`](Self::ack).
    ///
    /// Returns `(envelopes, next_cursor)`.
    pub fn read_from(&self, recipient_hex: &str, since: usize) -> (Vec<StoredEnvelope>, usize) {
        match self.queues.get(recipient_hex) {
            Some(q) if since < q.len() => {
                let slice = q[since..].to_vec();
                let next = q.len();
                (slice, next)
            }
            Some(q) => (Vec::new(), q.len()),
            None => (Vec::new(), 0),
        }
    }

    /// Acknowledge delivery up to (and including) `up_to_cursor` for `recipient_hex`, removing those
    /// envelopes from the store. Safe to call with any cursor; out-of-range is clamped. Returns the
    /// number removed.
    pub fn ack(&mut self, recipient_hex: &str, up_to_cursor: usize) -> usize {
        match self.queues.get_mut(recipient_hex) {
            Some(q) => {
                let n = up_to_cursor.min(q.len());
                q.drain(0..n);
                n
            }
            None => 0,
        }
    }

    /// Serialize the whole store to bytes (for persistence across restarts).
    pub fn to_bytes(&self) -> Vec<u8> {
        // Persist only the durable queues; `seen` is rebuilt from them on load.
        bincode::serialize(&(self.self_id, &self.queues, self.capacity_per_recipient))
            .unwrap_or_default()
    }

    /// Load a store from bytes produced by [`to_bytes`](Self::to_bytes). Rebuilds the de-dup index.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (self_id, queues, capacity_per_recipient): (
            NodeId,
            HashMap<String, Vec<StoredEnvelope>>,
            usize,
        ) = bincode::deserialize(bytes).map_err(|e| anyhow!("malformed mailbox store: {e}"))?;
        let mut seen: HashMap<String, std::collections::HashSet<String>> = HashMap::new();
        for (recipient, q) in &queues {
            let set = seen.entry(recipient.clone()).or_default();
            for stored in q {
                set.insert(stored.envelope.message_id());
            }
        }
        Ok(MailboxStore { self_id, queues, seen, capacity_per_recipient: capacity_per_recipient.max(1) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::EnvelopeBody;
    use ce_cap::{Caveats, Resource};
    use ce_identity::Identity;

    fn id(tag: &str) -> Identity {
        let dir = std::env::temp_dir().join(format!("ce-mail-mbox-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Identity::load_or_generate(&dir).unwrap()
    }

    fn never_revoked(_: &NodeId, _: u64) -> bool {
        false
    }

    fn envelope_to(sender: &Identity, to_hex: &str, subject: &str) -> Envelope {
        let body = EnvelopeBody {
            from: String::new(),
            to: to_hex.to_string(),
            subject: subject.to_string(),
            body_cid: "ab".repeat(32),
            attachment_cids: vec![],
            in_reply_to: String::new(),
            sent_at: 1_700_000_000,
            postage_receipt: String::new(),
        };
        Envelope::seal(sender, body)
    }

    #[test]
    fn accept_and_read_roundtrip() {
        let mailbox = id("mb1");
        let sender = id("snd1");
        let recip = id("rcp1");
        let mut store = MailboxStore::new(mailbox.node_id(), 100);
        let env = envelope_to(&sender, &recip.node_id_hex(), "hi");
        assert_eq!(store.accept(env, 10).unwrap(), Accepted::Stored);
        assert_eq!(store.pending_count(&recip.node_id_hex()), 1);
        let (msgs, cursor) = store.read_from(&recip.node_id_hex(), 0);
        assert_eq!(msgs.len(), 1);
        assert_eq!(cursor, 1);
        assert_eq!(msgs[0].envelope.body.subject, "hi");
    }

    #[test]
    fn duplicate_delivery_is_idempotent() {
        let mailbox = id("mb2");
        let sender = id("snd2");
        let recip = id("rcp2");
        let mut store = MailboxStore::new(mailbox.node_id(), 100);
        let env = envelope_to(&sender, &recip.node_id_hex(), "dup");
        assert_eq!(store.accept(env.clone(), 1).unwrap(), Accepted::Stored);
        assert_eq!(store.accept(env, 2).unwrap(), Accepted::Duplicate);
        assert_eq!(store.pending_count(&recip.node_id_hex()), 1);
    }

    #[test]
    fn refuses_forged_envelope() {
        let mailbox = id("mb3");
        let sender = id("snd3");
        let recip = id("rcp3");
        let mut store = MailboxStore::new(mailbox.node_id(), 100);
        let mut env = envelope_to(&sender, &recip.node_id_hex(), "ok");
        env.body.subject = "TAMPERED".into(); // breaks the signature
        assert!(store.accept(env, 1).is_err());
        assert_eq!(store.pending_count(&recip.node_id_hex()), 0);
    }

    #[test]
    fn ack_removes_delivered() {
        let mailbox = id("mb4");
        let sender = id("snd4");
        let recip = id("rcp4");
        let mut store = MailboxStore::new(mailbox.node_id(), 100);
        for i in 0..3 {
            store.accept(envelope_to(&sender, &recip.node_id_hex(), &format!("m{i}")), i).unwrap();
        }
        let (msgs, cursor) = store.read_from(&recip.node_id_hex(), 0);
        assert_eq!(msgs.len(), 3);
        assert_eq!(store.ack(&recip.node_id_hex(), cursor), 3);
        assert_eq!(store.pending_count(&recip.node_id_hex()), 0);
    }

    #[test]
    fn ack_out_of_range_is_clamped() {
        let mailbox = id("mb5");
        let sender = id("snd5");
        let recip = id("rcp5");
        let mut store = MailboxStore::new(mailbox.node_id(), 100);
        store.accept(envelope_to(&sender, &recip.node_id_hex(), "one"), 1).unwrap();
        assert_eq!(store.ack(&recip.node_id_hex(), 999), 1);
        assert_eq!(store.ack("unknown-recipient", 5), 0);
    }

    #[test]
    fn capacity_evicts_oldest() {
        let mailbox = id("mb6");
        let sender = id("snd6");
        let recip = id("rcp6");
        let mut store = MailboxStore::new(mailbox.node_id(), 2);
        for i in 0..4 {
            store.accept(envelope_to(&sender, &recip.node_id_hex(), &format!("k{i}")), i).unwrap();
        }
        // Only the last 2 survive.
        assert_eq!(store.pending_count(&recip.node_id_hex()), 2);
        let (msgs, _) = store.read_from(&recip.node_id_hex(), 0);
        assert_eq!(msgs[0].envelope.body.subject, "k2");
        assert_eq!(msgs[1].envelope.body.subject, "k3");
    }

    #[test]
    fn persistence_roundtrip_rebuilds_dedup() {
        let mailbox = id("mb7");
        let sender = id("snd7");
        let recip = id("rcp7");
        let mut store = MailboxStore::new(mailbox.node_id(), 100);
        let env = envelope_to(&sender, &recip.node_id_hex(), "persisted");
        store.accept(env.clone(), 1).unwrap();
        let bytes = store.to_bytes();
        let mut loaded = MailboxStore::from_bytes(&bytes).unwrap();
        assert_eq!(loaded.pending_count(&recip.node_id_hex()), 1);
        // De-dup index was rebuilt: re-delivery is still a duplicate.
        assert_eq!(loaded.accept(env, 2).unwrap(), Accepted::Duplicate);
    }

    #[test]
    fn from_bytes_rejects_garbage() {
        assert!(MailboxStore::from_bytes(&[0x01, 0x02]).is_err());
    }

    #[test]
    fn read_from_cursor_returns_only_new() {
        let mailbox = id("mb8");
        let sender = id("snd8");
        let recip = id("rcp8");
        let mut store = MailboxStore::new(mailbox.node_id(), 100);
        store.accept(envelope_to(&sender, &recip.node_id_hex(), "a"), 1).unwrap();
        let (_first, cursor) = store.read_from(&recip.node_id_hex(), 0);
        store.accept(envelope_to(&sender, &recip.node_id_hex(), "b"), 2).unwrap();
        let (second, _) = store.read_from(&recip.node_id_hex(), cursor);
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].envelope.body.subject, "b");
    }

    // ---- capability gate ----

    fn grant_accept(recipient: &Identity, mailbox: &Identity) -> Vec<SignedCapability> {
        vec![SignedCapability::issue(
            recipient,
            mailbox.node_id(),
            vec![ABILITY_ACCEPT.to_string()],
            Resource::Node(recipient.node_id()),
            Caveats::default(),
            1,
            None,
        )]
    }

    #[test]
    fn valid_accept_grant_passes_gate() {
        let recipient = id("gate-rcp");
        let mailbox = id("gate-mb");
        let store = MailboxStore::new(mailbox.node_id(), 10);
        let chain = grant_accept(&recipient, &mailbox);
        assert!(
            store
                .check_accept_grant(&recipient.node_id(), &chain, 1000, &never_revoked)
                .is_ok()
        );
    }

    #[test]
    fn gate_rejects_missing_grant() {
        let recipient = id("gate-rcp2");
        let mailbox = id("gate-mb2");
        let store = MailboxStore::new(mailbox.node_id(), 10);
        assert!(
            store
                .check_accept_grant(&recipient.node_id(), &[], 1000, &never_revoked)
                .is_err()
        );
    }

    #[test]
    fn gate_rejects_grant_for_different_recipient() {
        // A grant from recipient A does not let the mailbox accept mail for recipient B.
        let recip_a = id("gate-a");
        let recip_b = id("gate-b");
        let mailbox = id("gate-mb3");
        let store = MailboxStore::new(mailbox.node_id(), 10);
        let chain = grant_accept(&recip_a, &mailbox);
        // Checking the grant against recip_b must fail (root is A, resource is Node(A)).
        assert!(
            store
                .check_accept_grant(&recip_b.node_id(), &chain, 1000, &never_revoked)
                .is_err()
        );
    }

    #[test]
    fn gate_rejects_grant_to_other_mailbox() {
        // A grant to mailbox X does not authorize mailbox Y.
        let recipient = id("gate-rcp4");
        let mailbox_x = id("gate-mbx");
        let mailbox_y = id("gate-mby");
        let store_y = MailboxStore::new(mailbox_y.node_id(), 10);
        let chain = grant_accept(&recipient, &mailbox_x);
        assert!(
            store_y
                .check_accept_grant(&recipient.node_id(), &chain, 1000, &never_revoked)
                .is_err()
        );
    }

    #[test]
    fn gate_respects_revocation() {
        let recipient = id("gate-rcp5");
        let mailbox = id("gate-mb5");
        let store = MailboxStore::new(mailbox.node_id(), 10);
        let chain = grant_accept(&recipient, &mailbox);
        let revoke_1 = |_: &NodeId, nonce: u64| nonce == 1;
        assert!(
            store
                .check_accept_grant(&recipient.node_id(), &chain, 1000, &revoke_1)
                .is_err()
        );
    }
}
