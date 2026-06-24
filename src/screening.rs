//! Recipient-side screening — allowlists, contacts, and refundable-postage anti-spam.
//!
//! Sender *authenticity* is solved cryptographically (an envelope's `from` is its signing key), but
//! authenticity does not stop **unsolicited bulk mail from real or freshly-minted identities**. This
//! module is the recipient's policy for deciding whether an authenticated message reaches the inbox,
//! lands in spam, or is rejected outright. It is deliberately **app/recipient-side** (not enforced by
//! the node or the mailbox): CE provides the mechanism (signed envelopes, payment-channel receipts,
//! `GET /history/:node_id`), and each recipient composes its own policy here.
//!
//! ## The layered rule (matching the threat model)
//!
//! 1. **Contacts are free.** A sender on the allowlist (an address book, or anyone the recipient has
//!    previously corresponded with) is always delivered to the inbox — no postage required.
//! 2. **Strangers pay refundable postage.** An unknown sender must attach a non-empty
//!    `postage_receipt` (a payment-channel receipt). With it, the message reaches the inbox marked
//!    "postage held"; the recipient releases it back if the mail is legitimate and simply does not
//!    refund spam. Without it, the message is filed as [`Verdict::Spam`] (surfaced, but quarantined)
//!    or [`Verdict::Rejected`] when the policy is strict.
//! 3. **Reputation gradient.** A [`SenderStanding`] derived from `GET /history/:node_id` lets a
//!    policy waive postage for proven senders and treat newcomers more cautiously. This is the same
//!    trust gradient CE uses for compute.
//!
//! The postage *value* is checked against [`ScreeningPolicy::min_postage`] via a verifier the caller
//! supplies (it must confirm the receipt is a real channel receipt to this recipient for at least the
//! minimum). That keeps this module free of any node/SDK dependency while still enforcing real money.

use crate::envelope::Envelope;
use ce_rs::Amount;
use std::collections::HashSet;

/// What the policy decided to do with a screened message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Deliver to the inbox. `postage_held` is true when the inbox copy carries postage the
    /// recipient may refund (a stranger who paid) and false for free contact mail.
    Inbox { postage_held: bool },
    /// Quarantine: surfaced in a spam folder, not the inbox. A stranger with no (or insufficient)
    /// postage under a lenient policy.
    Spam,
    /// Refuse to surface at all. A stranger with no postage under a strict policy, or a message that
    /// fails a hard precondition (e.g. addressed to someone else).
    Rejected,
}

impl Verdict {
    /// Whether this verdict puts the message in the inbox.
    pub fn is_inbox(self) -> bool {
        matches!(self, Verdict::Inbox { .. })
    }
}

/// A coarse standing for a sender, derived from on-chain interaction history. Apps map a
/// `ce_rs::NodeHistory` into this (or supply their own); the policy only needs the gradient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SenderStanding {
    /// No recorded history — a stranger at the bottom of the trust gradient.
    Newcomer,
    /// Some proven, settled work/spend on record — a known participant.
    Established,
}

/// A recipient's screening policy. Construct, then classify each inbound (already signature-verified)
/// envelope with [`ScreeningPolicy::screen`].
///
/// ```
/// use ce_mail::{ScreeningPolicy, Verdict};
/// let me = "ab".repeat(32);
/// let friend = "cd".repeat(32);
/// let policy = ScreeningPolicy::new(me).allow(&friend);
/// assert!(policy.is_contact(&friend));
/// ```
#[derive(Debug, Clone)]
pub struct ScreeningPolicy {
    /// The recipient's own NodeId hex — a message not addressed here is always rejected.
    me: String,
    /// Senders that bypass postage entirely (contacts / address book / prior correspondents).
    allowlist: HashSet<String>,
    /// Senders that are always rejected regardless of postage (block / mute list).
    blocklist: HashSet<String>,
    /// Minimum postage a stranger must prove to reach the inbox. Zero disables the money check
    /// (a non-empty receipt string then suffices — useful in tests / un-monetized deployments).
    min_postage: Amount,
    /// When true, a stranger with no/insufficient postage is [`Verdict::Rejected`]; when false they
    /// are filed as [`Verdict::Spam`] (the gentler default — quarantine, do not bounce).
    strict: bool,
    /// When true, an `Established` sender (proven history) is treated like a contact and waived
    /// postage even if not explicitly on the allowlist.
    waive_postage_for_established: bool,
}

impl ScreeningPolicy {
    /// A new policy for recipient `me_hex`, with sane defaults: empty lists, no money minimum (a
    /// non-empty postage receipt suffices), lenient (strangers without postage are quarantined as
    /// spam, not bounced), and proven senders waived.
    pub fn new(me_hex: impl Into<String>) -> Self {
        ScreeningPolicy {
            me: me_hex.into(),
            allowlist: HashSet::new(),
            blocklist: HashSet::new(),
            min_postage: Amount::ZERO,
            strict: false,
            waive_postage_for_established: true,
        }
    }

    /// Add a contact (waived from postage). Returns `self` for chaining.
    pub fn allow(mut self, node_hex: impl Into<String>) -> Self {
        self.allowlist.insert(node_hex.into());
        self
    }

    /// Add many contacts at once.
    pub fn allow_all<I: IntoIterator<Item = String>>(mut self, nodes: I) -> Self {
        self.allowlist.extend(nodes);
        self
    }

    /// Block a sender entirely (always rejected). Returns `self` for chaining.
    pub fn block(mut self, node_hex: impl Into<String>) -> Self {
        self.blocklist.insert(node_hex.into());
        self
    }

    /// Require at least `amount` of proven postage from strangers.
    pub fn require_postage(mut self, amount: Amount) -> Self {
        self.min_postage = amount;
        self
    }

    /// Make the policy strict: strangers without sufficient postage are rejected, not quarantined.
    pub fn strict(mut self) -> Self {
        self.strict = true;
        self
    }

    /// Do not waive postage for established senders (require it from everyone not explicitly allowed).
    pub fn no_reputation_waiver(mut self) -> Self {
        self.waive_postage_for_established = false;
        self
    }

    /// Whether `node_hex` is a known contact.
    pub fn is_contact(&self, node_hex: &str) -> bool {
        self.allowlist.contains(node_hex)
    }

    /// Whether `node_hex` is blocked.
    pub fn is_blocked(&self, node_hex: &str) -> bool {
        self.blocklist.contains(node_hex)
    }

    /// The configured minimum postage.
    pub fn min_postage(&self) -> Amount {
        self.min_postage
    }

    /// Classify an inbound envelope. `standing` is the sender's reputation standing (from history),
    /// and `verify_postage` confirms the envelope's `postage_receipt` is a real channel receipt to
    /// this recipient worth at least [`min_postage`](Self::min_postage); it returns the verified
    /// amount (or `None`/`Err` if the receipt is absent or invalid).
    ///
    /// The caller is responsible for having already verified the envelope signature (a forged
    /// envelope never reaches screening). Screening is pure over the policy + the supplied closures.
    pub fn screen(
        &self,
        env: &Envelope,
        standing: SenderStanding,
        verify_postage: impl Fn(&str) -> Option<Amount>,
    ) -> Verdict {
        // Hard preconditions first.
        if env.body.to != self.me {
            return Verdict::Rejected;
        }
        let from = &env.body.from;
        if self.is_blocked(from) {
            return Verdict::Rejected;
        }
        // A message from yourself (e.g. a self-note / draft sync) is always inbox.
        if from == &self.me || self.is_contact(from) {
            return Verdict::Inbox { postage_held: false };
        }
        if self.waive_postage_for_established && standing == SenderStanding::Established {
            return Verdict::Inbox { postage_held: false };
        }

        // Stranger path: postage required.
        if env.body.postage_receipt.is_empty() {
            return self.deny();
        }
        match verify_postage(&env.body.postage_receipt) {
            Some(amount) if amount.base() >= self.min_postage.base() => {
                Verdict::Inbox { postage_held: true }
            }
            // Present but invalid / underpaid.
            _ => self.deny(),
        }
    }

    /// The denial verdict for a stranger without acceptable postage, per the strict flag.
    fn deny(&self) -> Verdict {
        if self.strict { Verdict::Rejected } else { Verdict::Spam }
    }
}

/// Map a `ce_rs::NodeHistory` into a coarse [`SenderStanding`] using the SDK's own newcomer rule.
pub fn standing_from_history(h: &ce_rs::NodeHistory) -> SenderStanding {
    if h.is_newcomer() {
        SenderStanding::Newcomer
    } else {
        SenderStanding::Established
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::EnvelopeBody;
    use ce_identity::Identity;

    fn id(tag: &str) -> Identity {
        let dir = std::env::temp_dir().join(format!("ce-mail-scr-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Identity::load_or_generate(&dir).unwrap()
    }

    fn env(sender: &Identity, to: &str, postage: &str) -> Envelope {
        Envelope::seal(
            sender,
            EnvelopeBody {
                from: String::new(),
                to: to.to_string(),
                subject: "s".into(),
                body_cid: String::new(),
                attachment_cids: vec![],
                in_reply_to: String::new(),
                sent_at: 1,
                postage_receipt: postage.to_string(),
            },
        )
    }

    fn no_postage(_: &str) -> Option<Amount> {
        None
    }

    #[test]
    fn contact_is_always_inbox_without_postage() {
        let me = id("scr-me1");
        let friend = id("scr-fr1");
        let policy = ScreeningPolicy::new(me.node_id_hex()).allow(friend.node_id_hex());
        let e = env(&friend, &me.node_id_hex(), "");
        assert_eq!(
            policy.screen(&e, SenderStanding::Newcomer, no_postage),
            Verdict::Inbox { postage_held: false }
        );
    }

    #[test]
    fn stranger_without_postage_is_spam_when_lenient() {
        let me = id("scr-me2");
        let stranger = id("scr-st2");
        let policy = ScreeningPolicy::new(me.node_id_hex());
        let e = env(&stranger, &me.node_id_hex(), "");
        assert_eq!(policy.screen(&e, SenderStanding::Newcomer, no_postage), Verdict::Spam);
    }

    #[test]
    fn stranger_without_postage_is_rejected_when_strict() {
        let me = id("scr-me3");
        let stranger = id("scr-st3");
        let policy = ScreeningPolicy::new(me.node_id_hex()).strict();
        let e = env(&stranger, &me.node_id_hex(), "");
        assert_eq!(policy.screen(&e, SenderStanding::Newcomer, no_postage), Verdict::Rejected);
    }

    #[test]
    fn stranger_with_sufficient_postage_reaches_inbox_held() {
        let me = id("scr-me4");
        let stranger = id("scr-st4");
        let policy =
            ScreeningPolicy::new(me.node_id_hex()).require_postage(Amount::from_credits(1));
        let e = env(&stranger, &me.node_id_hex(), "receipt-xyz");
        let verify = |_: &str| Some(Amount::from_credits(2));
        assert_eq!(
            policy.screen(&e, SenderStanding::Newcomer, verify),
            Verdict::Inbox { postage_held: true }
        );
    }

    #[test]
    fn stranger_with_underpaid_postage_is_denied() {
        let me = id("scr-me5");
        let stranger = id("scr-st5");
        let policy = ScreeningPolicy::new(me.node_id_hex())
            .require_postage(Amount::from_credits(5))
            .strict();
        let e = env(&stranger, &me.node_id_hex(), "receipt-too-small");
        let verify = |_: &str| Some(Amount::from_credits(1));
        assert_eq!(policy.screen(&e, SenderStanding::Newcomer, verify), Verdict::Rejected);
    }

    #[test]
    fn established_sender_is_waived_by_default() {
        let me = id("scr-me6");
        let proven = id("scr-pr6");
        let policy =
            ScreeningPolicy::new(me.node_id_hex()).require_postage(Amount::from_credits(10));
        let e = env(&proven, &me.node_id_hex(), "");
        assert_eq!(
            policy.screen(&e, SenderStanding::Established, no_postage),
            Verdict::Inbox { postage_held: false }
        );
    }

    #[test]
    fn established_sender_not_waived_when_disabled() {
        let me = id("scr-me7");
        let proven = id("scr-pr7");
        let policy = ScreeningPolicy::new(me.node_id_hex())
            .require_postage(Amount::from_credits(10))
            .no_reputation_waiver();
        let e = env(&proven, &me.node_id_hex(), "");
        assert_eq!(policy.screen(&e, SenderStanding::Established, no_postage), Verdict::Spam);
    }

    #[test]
    fn blocked_sender_always_rejected_even_with_postage() {
        let me = id("scr-me8");
        let troll = id("scr-tr8");
        let policy = ScreeningPolicy::new(me.node_id_hex())
            .allow(troll.node_id_hex()) // even if also "allowed"
            .block(troll.node_id_hex());
        let e = env(&troll, &me.node_id_hex(), "receipt");
        let verify = |_: &str| Some(Amount::from_credits(100));
        assert_eq!(policy.screen(&e, SenderStanding::Established, verify), Verdict::Rejected);
    }

    #[test]
    fn message_addressed_elsewhere_is_rejected() {
        let me = id("scr-me9");
        let other = id("scr-ot9");
        let sender = id("scr-sn9");
        let policy = ScreeningPolicy::new(me.node_id_hex()).allow(sender.node_id_hex());
        // Addressed to `other`, not us.
        let e = env(&sender, &other.node_id_hex(), "");
        assert_eq!(policy.screen(&e, SenderStanding::Established, no_postage), Verdict::Rejected);
    }

    #[test]
    fn self_mail_is_inbox() {
        let me = id("scr-me10");
        let e = env(&me, &me.node_id_hex(), "");
        let policy = ScreeningPolicy::new(me.node_id_hex());
        assert_eq!(
            policy.screen(&e, SenderStanding::Newcomer, no_postage),
            Verdict::Inbox { postage_held: false }
        );
    }

    #[test]
    fn zero_min_postage_accepts_any_nonempty_receipt() {
        let me = id("scr-me11");
        let stranger = id("scr-st11");
        let policy = ScreeningPolicy::new(me.node_id_hex()); // min_postage = 0
        let e = env(&stranger, &me.node_id_hex(), "any-token");
        // verify returns the amount the (un-monetized) deployment treats as present.
        let verify = |_: &str| Some(Amount::ZERO);
        assert_eq!(
            policy.screen(&e, SenderStanding::Newcomer, verify),
            Verdict::Inbox { postage_held: true }
        );
    }
}
