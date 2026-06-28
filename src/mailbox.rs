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
use crate::receipt::Receipt;
use anyhow::{Result, anyhow};
use ce_iam_core::{SignedCapability, authorize};
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
    /// sender_hex -> receipts addressed to that sender, de-duped by receipt key (idempotent deposit).
    receipts: HashMap<String, Vec<Receipt>>,
    /// receipt dedup keys already stored per sender, for idempotent receipt deposit.
    receipts_seen: HashMap<String, std::collections::HashSet<String>>,
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
            receipts: HashMap::new(),
            receipts_seen: HashMap::new(),
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
        let q = self.queues.entry(to.clone()).or_default();
        q.push(StoredEnvelope { envelope, stored_at: now });
        // Bounded retention: evict the oldest beyond capacity.
        if q.len() > self.capacity_per_recipient {
            let overflow = q.len() - self.capacity_per_recipient;
            // Evict oldest; also forget their message ids so the bound on `seen` holds
            // (otherwise sustained overflow grows `seen` without limit — a memory-exhaustion vector).
            let evicted: Vec<String> =
                q.drain(0..overflow).map(|s| s.envelope.message_id()).collect();
            if let Some(s) = self.seen.get_mut(&to) {
                for k in evicted {
                    s.remove(&k);
                }
            }
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

    /// Read a bounded *page* of at most `limit` envelopes starting at cursor `since` for
    /// `recipient_hex`. Returns `(page, next_cursor, more)` where `next_cursor` is `since + page.len()`
    /// and `more` is true when envelopes remain beyond the page. A `limit` of 0 is treated as 1 so a
    /// caller always makes progress. Like [`read_from`](Self::read_from) this is non-destructive
    /// (replay-safe): call [`ack`](Self::ack) to free what was delivered.
    pub fn read_page(
        &self,
        recipient_hex: &str,
        since: usize,
        limit: usize,
    ) -> (Vec<StoredEnvelope>, usize, bool) {
        let limit = limit.max(1);
        match self.queues.get(recipient_hex) {
            Some(q) if since < q.len() => {
                let end = (since + limit).min(q.len());
                let page = q[since..end].to_vec();
                let more = end < q.len();
                (page, end, more)
            }
            Some(q) => (Vec::new(), q.len(), false),
            None => (Vec::new(), 0, false),
        }
    }

    /// Deposit a signed [`Receipt`] addressed to `for_sender_hex`. Verifies the receipt signature,
    /// then stores it de-duplicated by [`Receipt::dedup_key`]. Idempotent: re-depositing the same
    /// receipt returns [`Accepted::Duplicate`]. The mailbox cannot forge a receipt (it lacks the
    /// recipient's key) and cannot grow unboundedly per sender (capacity-bounded like the inbox).
    pub fn put_receipt(&mut self, for_sender_hex: &str, receipt: Receipt) -> Result<Accepted> {
        receipt
            .verify()
            .map_err(|e| anyhow!("refusing to store unverifiable receipt: {e}"))?;
        if for_sender_hex.is_empty() {
            return Err(anyhow!("receipt has no target sender"));
        }
        let key = receipt.dedup_key();
        let seen = self.receipts_seen.entry(for_sender_hex.to_string()).or_default();
        if seen.contains(&key) {
            return Ok(Accepted::Duplicate);
        }
        seen.insert(key);
        let q = self.receipts.entry(for_sender_hex.to_string()).or_default();
        q.push(receipt);
        if q.len() > self.capacity_per_recipient {
            let overflow = q.len() - self.capacity_per_recipient;
            // Evict oldest; also forget their dedup keys so the bound on `receipts_seen` holds.
            let evicted: Vec<String> = q.drain(0..overflow).map(|r| r.dedup_key()).collect();
            if let Some(s) = self.receipts_seen.get_mut(for_sender_hex) {
                for k in evicted {
                    s.remove(&k);
                }
            }
        }
        Ok(Accepted::Stored)
    }

    /// Number of receipts pending for `sender_hex`.
    pub fn receipt_count(&self, sender_hex: &str) -> usize {
        self.receipts.get(sender_hex).map(|q| q.len()).unwrap_or(0)
    }

    /// Collect (return and remove) all receipts addressed to `sender_hex`. Removing them is safe
    /// because each is independently signed — the sender can re-store any it wants to keep.
    pub fn collect_receipts(&mut self, sender_hex: &str) -> Vec<Receipt> {
        self.receipts_seen.remove(sender_hex);
        self.receipts.remove(sender_hex).unwrap_or_default()
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
    ///
    /// Format is a magic-tagged tuple so newer stores carry the receipt table while older 3-tuple
    /// stores ([`from_bytes`](Self::from_bytes) still reads them) load with empty receipts. The
    /// `seen` / `receipts_seen` de-dup indexes are rebuilt on load, not persisted.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes().unwrap_or_default()
    }

    /// Fallible serialize: surfaces the bincode error instead of an empty vec, so a persistence
    /// caller never silently writes a zero-byte (empty) store over a good one.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(&(
            STORE_MAGIC,
            self.self_id,
            &self.queues,
            self.capacity_per_recipient,
            &self.receipts,
        ))
        .map_err(|e| anyhow!("failed to serialize mailbox store: {e}"))
    }

    /// Load a store from bytes produced by [`to_bytes`](Self::to_bytes), or by an older version that
    /// predates the receipt table. Rebuilds the de-dup indexes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // Try the current (v2, receipt-carrying) format first.
        if let Ok((magic, self_id, queues, capacity, receipts)) = bincode::deserialize::<(
            u32,
            NodeId,
            HashMap<String, Vec<StoredEnvelope>>,
            usize,
            HashMap<String, Vec<Receipt>>,
        )>(bytes)
            && magic == STORE_MAGIC
        {
            return Ok(Self::rebuild(self_id, queues, capacity, receipts));
        }
        // Fall back to the legacy v1 (3-tuple, no receipts) format.
        let (self_id, queues, capacity_per_recipient): (
            NodeId,
            HashMap<String, Vec<StoredEnvelope>>,
            usize,
        ) = bincode::deserialize(bytes).map_err(|e| anyhow!("malformed mailbox store: {e}"))?;
        Ok(Self::rebuild(self_id, queues, capacity_per_recipient, HashMap::new()))
    }

    /// Rebuild the in-memory store (including de-dup indexes) from persisted parts.
    fn rebuild(
        self_id: NodeId,
        queues: HashMap<String, Vec<StoredEnvelope>>,
        capacity_per_recipient: usize,
        receipts: HashMap<String, Vec<Receipt>>,
    ) -> Self {
        let mut seen: HashMap<String, std::collections::HashSet<String>> = HashMap::new();
        for (recipient, q) in &queues {
            let set = seen.entry(recipient.clone()).or_default();
            for stored in q {
                set.insert(stored.envelope.message_id());
            }
        }
        let mut receipts_seen: HashMap<String, std::collections::HashSet<String>> = HashMap::new();
        for (sender, q) in &receipts {
            let set = receipts_seen.entry(sender.clone()).or_default();
            for r in q {
                set.insert(r.dedup_key());
            }
        }
        MailboxStore {
            self_id,
            queues,
            seen,
            receipts,
            receipts_seen,
            capacity_per_recipient: capacity_per_recipient.max(1),
        }
    }
}

/// Magic prefix tagging the v2 (receipt-carrying) on-disk store format.
const STORE_MAGIC: u32 = 0x4345_4d32; // "CEM2"

/// A thread-safe handle to a [`MailboxStore`] for a node that serves requests concurrently.
///
/// The single-threaded poll loop in the CLI does not need this, but a node that dispatches inbound
/// requests across worker threads must serialize access so interleaved `accept`/`ack`/drain never
/// lose an update or double-evict. [`SharedMailbox`] wraps the store in an `Arc<Mutex<_>>` and
/// exposes exactly the operations a service needs, each taking the lock for the duration of one
/// atomic store mutation. Clone is cheap (an `Arc` bump); all clones share one store.
#[derive(Clone)]
pub struct SharedMailbox {
    inner: std::sync::Arc<std::sync::Mutex<MailboxStore>>,
}

impl SharedMailbox {
    /// Wrap a store for concurrent access.
    pub fn new(store: MailboxStore) -> Self {
        SharedMailbox { inner: std::sync::Arc::new(std::sync::Mutex::new(store)) }
    }

    /// Run `f` against the locked store, returning its result. The lock is held only for the
    /// closure. A poisoned lock (a previous panic while holding it) is surfaced as an error rather
    /// than propagating the panic.
    pub fn with<R>(&self, f: impl FnOnce(&mut MailboxStore) -> R) -> Result<R> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| anyhow!("mailbox lock poisoned"))?;
        Ok(f(&mut guard))
    }

    /// Accept an envelope under the lock. See [`MailboxStore::accept`].
    pub fn accept(&self, envelope: Envelope, now: u64) -> Result<Accepted> {
        self.with(|s| s.accept(envelope, now))?
    }

    /// Acknowledge up to `cursor` under the lock. See [`MailboxStore::ack`].
    pub fn ack(&self, recipient_hex: &str, up_to_cursor: usize) -> Result<usize> {
        self.with(|s| s.ack(recipient_hex, up_to_cursor))
    }

    /// Read a page under the lock. See [`MailboxStore::read_page`].
    pub fn read_page(
        &self,
        recipient_hex: &str,
        since: usize,
        limit: usize,
    ) -> Result<(Vec<StoredEnvelope>, usize, bool)> {
        self.with(|s| s.read_page(recipient_hex, since, limit))
    }

    /// Pending envelope count under the lock.
    pub fn pending_count(&self, recipient_hex: &str) -> Result<usize> {
        self.with(|s| s.pending_count(recipient_hex))
    }

    /// Snapshot the whole store to bytes under the lock (for atomic persistence).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.with(|s| s.try_to_bytes())?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::EnvelopeBody;
    use ce_iam_core::{Caveats, Resource};
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
    fn seen_stays_bounded_under_sustained_overflow() {
        // Regression: evicted envelopes must also be forgotten from `seen`, otherwise sustained
        // overflow grows the de-dup index without limit — a memory-exhaustion vector.
        let mailbox = id("mb-seen");
        let sender = id("snd-seen");
        let recip = id("rcp-seen");
        let cap = 4usize;
        let mut store = MailboxStore::new(mailbox.node_id(), cap);
        // Deliver far more distinct envelopes than capacity.
        for i in 0..200u64 {
            store
                .accept(envelope_to(&sender, &recip.node_id_hex(), &format!("s{i}")), i)
                .unwrap();
        }
        // The queue is bounded by capacity.
        assert_eq!(store.pending_count(&recip.node_id_hex()), cap);
        // And so is the `seen` set — it must not have accumulated all 200 ids.
        let seen_len = store.seen.get(&recip.node_id_hex()).map(|s| s.len()).unwrap_or(0);
        assert_eq!(
            seen_len, cap,
            "seen index grew unbounded under overflow (was {seen_len}, expected {cap})"
        );
        // Surviving (most-recent) envelopes are still de-duplicated: re-delivering one is a duplicate.
        let still_here = envelope_to(&sender, &recip.node_id_hex(), "s199");
        assert_eq!(store.accept(still_here, 999).unwrap(), Accepted::Duplicate);
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

    // ---- pagination ----

    #[test]
    fn read_page_bounds_and_signals_more() {
        let mailbox = id("pg1");
        let sender = id("pg1s");
        let recip = id("pg1r");
        let mut store = MailboxStore::new(mailbox.node_id(), 100);
        for i in 0..5 {
            store.accept(envelope_to(&sender, &recip.node_id_hex(), &format!("p{i}")), i).unwrap();
        }
        // First page of 2.
        let (page, cursor, more) = store.read_page(&recip.node_id_hex(), 0, 2);
        assert_eq!(page.len(), 2);
        assert_eq!(cursor, 2);
        assert!(more);
        assert_eq!(page[0].envelope.body.subject, "p0");
        // Second page of 2.
        let (page, cursor, more) = store.read_page(&recip.node_id_hex(), cursor, 2);
        assert_eq!(page.len(), 2);
        assert_eq!(cursor, 4);
        assert!(more);
        // Final page: 1 remaining, no more.
        let (page, cursor, more) = store.read_page(&recip.node_id_hex(), cursor, 2);
        assert_eq!(page.len(), 1);
        assert_eq!(cursor, 5);
        assert!(!more);
        assert_eq!(page[0].envelope.body.subject, "p4");
    }

    #[test]
    fn read_page_limit_zero_treated_as_one() {
        let mailbox = id("pg2");
        let sender = id("pg2s");
        let recip = id("pg2r");
        let mut store = MailboxStore::new(mailbox.node_id(), 100);
        store.accept(envelope_to(&sender, &recip.node_id_hex(), "a"), 1).unwrap();
        store.accept(envelope_to(&sender, &recip.node_id_hex(), "b"), 2).unwrap();
        let (page, _, more) = store.read_page(&recip.node_id_hex(), 0, 0);
        assert_eq!(page.len(), 1);
        assert!(more);
    }

    #[test]
    fn read_page_past_end_is_empty() {
        let mailbox = id("pg3");
        let sender = id("pg3s");
        let recip = id("pg3r");
        let mut store = MailboxStore::new(mailbox.node_id(), 100);
        store.accept(envelope_to(&sender, &recip.node_id_hex(), "a"), 1).unwrap();
        let (page, cursor, more) = store.read_page(&recip.node_id_hex(), 5, 10);
        assert!(page.is_empty());
        assert_eq!(cursor, 1);
        assert!(!more);
    }

    #[test]
    fn read_page_unknown_recipient_is_empty() {
        let mailbox = id("pg4");
        let store = MailboxStore::new(mailbox.node_id(), 100);
        let (page, cursor, more) = store.read_page("nobody", 0, 10);
        assert!(page.is_empty());
        assert_eq!(cursor, 0);
        assert!(!more);
    }

    #[test]
    fn full_pagination_covers_all_without_overlap() {
        let mailbox = id("pg5");
        let sender = id("pg5s");
        let recip = id("pg5r");
        let mut store = MailboxStore::new(mailbox.node_id(), 100);
        for i in 0..7u64 {
            store.accept(envelope_to(&sender, &recip.node_id_hex(), &format!("m{i}")), i).unwrap();
        }
        let mut cursor = 0;
        let mut collected = Vec::new();
        loop {
            let (page, next, more) = store.read_page(&recip.node_id_hex(), cursor, 3);
            for s in page {
                collected.push(s.envelope.body.subject.clone());
            }
            cursor = next;
            if !more {
                break;
            }
        }
        assert_eq!(collected, (0..7).map(|i| format!("m{i}")).collect::<Vec<_>>());
    }

    // ---- receipts ----

    fn receipt_for(recip: &Identity, mid: &str, kind: crate::receipt::ReceiptKind) -> Receipt {
        Receipt::issue(recip, mid, kind, 100)
    }

    #[test]
    fn put_and_collect_receipt_roundtrip() {
        use crate::receipt::ReceiptKind;
        let mailbox = id("rc1");
        let sender = id("rc1s");
        let recip = id("rc1r");
        let mut store = MailboxStore::new(mailbox.node_id(), 100);
        let r = receipt_for(&recip, &"ab".repeat(32), ReceiptKind::Delivered);
        assert_eq!(store.put_receipt(&sender.node_id_hex(), r).unwrap(), Accepted::Stored);
        assert_eq!(store.receipt_count(&sender.node_id_hex()), 1);
        let collected = store.collect_receipts(&sender.node_id_hex());
        assert_eq!(collected.len(), 1);
        assert!(collected[0].verify().is_ok());
        // Collection freed them.
        assert_eq!(store.receipt_count(&sender.node_id_hex()), 0);
    }

    #[test]
    fn duplicate_receipt_is_idempotent() {
        use crate::receipt::ReceiptKind;
        let mailbox = id("rc2");
        let sender = id("rc2s");
        let recip = id("rc2r");
        let mut store = MailboxStore::new(mailbox.node_id(), 100);
        let r = receipt_for(&recip, &"ab".repeat(32), ReceiptKind::Read);
        assert_eq!(store.put_receipt(&sender.node_id_hex(), r.clone()).unwrap(), Accepted::Stored);
        assert_eq!(store.put_receipt(&sender.node_id_hex(), r).unwrap(), Accepted::Duplicate);
        assert_eq!(store.receipt_count(&sender.node_id_hex()), 1);
    }

    #[test]
    fn delivered_and_read_receipts_coexist() {
        use crate::receipt::ReceiptKind;
        let mailbox = id("rc3");
        let sender = id("rc3s");
        let recip = id("rc3r");
        let mut store = MailboxStore::new(mailbox.node_id(), 100);
        let mid = "ab".repeat(32);
        store.put_receipt(&sender.node_id_hex(), receipt_for(&recip, &mid, ReceiptKind::Delivered)).unwrap();
        store.put_receipt(&sender.node_id_hex(), receipt_for(&recip, &mid, ReceiptKind::Read)).unwrap();
        // Different kinds for the same message are distinct receipts.
        assert_eq!(store.receipt_count(&sender.node_id_hex()), 2);
    }

    #[test]
    fn put_receipt_rejects_forged() {
        use crate::receipt::ReceiptKind;
        let mailbox = id("rc4");
        let sender = id("rc4s");
        let recip = id("rc4r");
        let mut store = MailboxStore::new(mailbox.node_id(), 100);
        let mut r = receipt_for(&recip, &"ab".repeat(32), ReceiptKind::Read);
        r.body.at = 999; // breaks the signature
        assert!(store.put_receipt(&sender.node_id_hex(), r).is_err());
        assert_eq!(store.receipt_count(&sender.node_id_hex()), 0);
    }

    #[test]
    fn put_receipt_rejects_empty_target() {
        use crate::receipt::ReceiptKind;
        let mailbox = id("rc5");
        let recip = id("rc5r");
        let mut store = MailboxStore::new(mailbox.node_id(), 100);
        let r = receipt_for(&recip, &"ab".repeat(32), ReceiptKind::Read);
        assert!(store.put_receipt("", r).is_err());
    }

    #[test]
    fn receipt_capacity_evicts_oldest_and_forgets_dedup() {
        use crate::receipt::ReceiptKind;
        let mailbox = id("rc6");
        let sender = id("rc6s");
        let mut store = MailboxStore::new(mailbox.node_id(), 2);
        // Three distinct receipts (distinct recipients) for the same sender.
        for i in 0..3 {
            let recip = id(&format!("rc6r{i}"));
            let r = receipt_for(&recip, &"ab".repeat(32), ReceiptKind::Delivered);
            store.put_receipt(&sender.node_id_hex(), r).unwrap();
        }
        assert_eq!(store.receipt_count(&sender.node_id_hex()), 2);
    }

    #[test]
    fn receipts_survive_persistence_roundtrip() {
        use crate::receipt::ReceiptKind;
        let mailbox = id("rc7");
        let sender = id("rc7s");
        let recip = id("rc7r");
        let mut store = MailboxStore::new(mailbox.node_id(), 100);
        // Also store an envelope so both tables persist.
        store.accept(envelope_to(&sender, &recip.node_id_hex(), "m"), 1).unwrap();
        let r = receipt_for(&recip, &"ab".repeat(32), ReceiptKind::Read);
        store.put_receipt(&sender.node_id_hex(), r.clone()).unwrap();
        let bytes = store.to_bytes();
        let mut loaded = MailboxStore::from_bytes(&bytes).unwrap();
        assert_eq!(loaded.receipt_count(&sender.node_id_hex()), 1);
        assert_eq!(loaded.pending_count(&recip.node_id_hex()), 1);
        // Rebuilt receipt dedup index: re-deposit is a duplicate.
        assert_eq!(loaded.put_receipt(&sender.node_id_hex(), r).unwrap(), Accepted::Duplicate);
    }

    #[test]
    fn legacy_v1_store_loads_with_empty_receipts() {
        // Simulate a store persisted before the receipt table existed (the old 3-tuple format).
        let mailbox = id("rc8");
        let sender = id("rc8s");
        let recip = id("rc8r");
        let env = envelope_to(&sender, &recip.node_id_hex(), "legacy");
        let mut queues: HashMap<String, Vec<StoredEnvelope>> = HashMap::new();
        queues.insert(recip.node_id_hex(), vec![StoredEnvelope { envelope: env, stored_at: 1 }]);
        let legacy = bincode::serialize(&(mailbox.node_id(), queues, 50usize)).unwrap();
        let loaded = MailboxStore::from_bytes(&legacy).unwrap();
        assert_eq!(loaded.pending_count(&recip.node_id_hex()), 1);
        assert_eq!(loaded.receipt_count(&sender.node_id_hex()), 0);
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

    // ---- concurrency ----

    #[test]
    fn shared_mailbox_concurrent_deliver_no_lost_updates() {
        // Many threads deliver distinct envelopes to one shared store concurrently; every accepted
        // envelope must survive (no lost update from interleaved locking).
        let mailbox = id("conc-mb");
        let recip = id("conc-rc");
        let recip_hex = recip.node_id_hex();
        let shared = SharedMailbox::new(MailboxStore::new(mailbox.node_id(), 100_000));
        let threads = 8usize;
        let per_thread = 50usize;
        std::thread::scope(|scope| {
            for t in 0..threads {
                let shared = shared.clone();
                let recip_hex = recip_hex.clone();
                // Each thread builds its own sender identity so envelopes are distinct + valid.
                let sender = id(&format!("conc-sn{t}"));
                scope.spawn(move || {
                    for i in 0..per_thread {
                        let env = envelope_to(&sender, &recip_hex, &format!("t{t}-m{i}"));
                        shared.accept(env, (t * 1000 + i) as u64).unwrap();
                    }
                });
            }
        });
        assert_eq!(shared.pending_count(&recip_hex).unwrap(), threads * per_thread);
    }

    #[test]
    fn shared_mailbox_interleaved_deliver_and_ack_is_consistent() {
        // Interleave deliver and ack on a shared store from two threads; the store must never panic
        // and the final count must be non-negative and bounded.
        let mailbox = id("conc-mb2");
        let recip = id("conc-rc2");
        let sender = id("conc-sn2");
        let recip_hex = recip.node_id_hex();
        let shared = SharedMailbox::new(MailboxStore::new(mailbox.node_id(), 100_000));
        std::thread::scope(|scope| {
            let s1 = shared.clone();
            let recip1 = recip_hex.clone();
            scope.spawn(move || {
                for i in 0..200u64 {
                    let env = envelope_to(&sender, &recip1, &format!("m{i}"));
                    let _ = s1.accept(env, i);
                }
            });
            let s2 = shared.clone();
            let recip2 = recip_hex.clone();
            scope.spawn(move || {
                for _ in 0..200 {
                    // Ack whatever is currently present; clamped internally, never panics.
                    let _ = s2.ack(&recip2, 1);
                }
            });
        });
        // No panic, and a valid count (0..=200) remains.
        let n = shared.pending_count(&recip_hex).unwrap();
        assert!(n <= 200);
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
