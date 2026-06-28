//! The ce-mail mesh request/reply protocol.
//!
//! ce-mail rides CE's app-messaging primitive (`AppRequest`/reply over `/ce/rpc/1`). Both direct
//! delivery (recipient online) and mailbox delivery (recipient offline) use the same small request
//! enum, carried as the opaque payload of [`ce_rs::CeClient::request`] / answered with
//! [`ce_rs::CeClient::reply`]. The topic is [`MAIL_TOPIC`].
//!
//! Keeping the protocol in one serde enum makes the wire format testable in isolation (round-trip +
//! malformed-input tests) without any network.

use crate::envelope::Envelope;
use crate::receipt::Receipt;
use anyhow::{Result, anyhow};
use ce_iam_core::SignedCapability;
use serde::{Deserialize, Serialize};

/// The app-messaging topic ce-mail uses for all requests.
pub const MAIL_TOPIC: &str = "ce-mail/v1";

/// A request sent to a recipient node (direct) or a mailbox node (store-and-forward).
///
/// `Deliver` is intentionally the largest variant (it carries a full envelope) — these values are
/// short-lived, serialized immediately, and never stored in bulk, so the size asymmetry is fine.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MailRequest {
    /// Deliver an envelope. To a recipient directly, or to a mailbox storing for that recipient.
    /// `grant` is the [`crate::mailbox::ABILITY_ACCEPT`] capability chain proving the mailbox may
    /// accept mail for the envelope's `to` (empty for direct delivery to the recipient itself).
    Deliver {
        envelope: Envelope,
        #[serde(default)]
        grant: Vec<SignedCapability>,
    },
    /// Drain a recipient's inbox at a mailbox, from cursor `since`. The mailbox returns envelopes
    /// and the new cursor. `grant` proves the requester is the recipient (or its delegate).
    Drain {
        recipient: String,
        since: usize,
        #[serde(default)]
        grant: Vec<SignedCapability>,
    },
    /// Acknowledge delivery up to `cursor`, letting the mailbox free the storage.
    Ack {
        recipient: String,
        cursor: usize,
        #[serde(default)]
        grant: Vec<SignedCapability>,
    },
    /// Drain a bounded *page* of a recipient's inbox: at most `limit` envelopes from cursor `since`.
    /// Lets a client page through a large inbox instead of pulling everything at once. The mailbox
    /// returns the page, the cursor advanced past it, and whether more remain.
    DrainPage {
        recipient: String,
        since: usize,
        limit: usize,
        #[serde(default)]
        grant: Vec<SignedCapability>,
    },
    /// Deposit a signed [`Receipt`] (delivery/read acknowledgement) at the mailbox, addressed to the
    /// original sender, for the sender to collect later. Idempotent: re-depositing the same receipt
    /// is a no-op. `for_sender` is the original sender's NodeId (hex) — whose receipt mailbox this
    /// goes to. `grant` proves the mailbox may accept on the sender's behalf (same ABILITY_ACCEPT).
    PutReceipt {
        for_sender: String,
        receipt: Receipt,
        #[serde(default)]
        grant: Vec<SignedCapability>,
    },
    /// Collect receipts addressed to `sender` (the requester). Returns all signed receipts and frees
    /// them. `grant` is empty when the requester *is* the sender (fast path).
    CollectReceipts {
        sender: String,
        #[serde(default)]
        grant: Vec<SignedCapability>,
    },
}

/// A reply from a recipient or mailbox node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MailReply {
    /// Delivery accepted (stored or already present).
    Delivered { duplicate: bool },
    /// Drain result: the envelopes from the requested cursor onward and the new cursor.
    Drained { envelopes: Vec<Envelope>, cursor: usize },
    /// Paginated drain result: a bounded page, the advanced cursor, and whether more remain.
    Page { envelopes: Vec<Envelope>, cursor: usize, more: bool },
    /// Ack result: how many envelopes were freed.
    Acked { removed: usize },
    /// A receipt was accepted (stored or already present).
    ReceiptAccepted { duplicate: bool },
    /// Collected receipts addressed to the requester.
    Receipts { receipts: Vec<Receipt> },
    /// The request was rejected (unauthorized, malformed, etc.).
    Error { message: String },
}

impl MailRequest {
    /// Encode to wire bytes. Infallible in practice (see [`MailRequest::try_encode`]).
    pub fn encode(&self) -> Vec<u8> {
        self.try_encode().unwrap_or_default()
    }
    /// Fallible encode: surfaces the bincode error instead of an empty vec.
    pub fn try_encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow!("failed to encode mail request: {e}"))
    }
    /// Decode from wire bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow!("malformed mail request: {e}"))
    }
}

impl MailReply {
    /// Encode to wire bytes. Infallible in practice (see [`MailReply::try_encode`]).
    pub fn encode(&self) -> Vec<u8> {
        self.try_encode().unwrap_or_default()
    }
    /// Fallible encode: surfaces the bincode error instead of an empty vec.
    pub fn try_encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow!("failed to encode mail reply: {e}"))
    }
    /// Decode from wire bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow!("malformed mail reply: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::EnvelopeBody;
    use ce_identity::Identity;

    fn id(tag: &str) -> Identity {
        let dir = std::env::temp_dir().join(format!("ce-mail-proto-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Identity::load_or_generate(&dir).unwrap()
    }

    fn env(sender: &Identity, to: &str) -> Envelope {
        Envelope::seal(
            sender,
            EnvelopeBody {
                from: String::new(),
                to: to.to_string(),
                subject: "s".into(),
                body_cid: "ab".repeat(32),
                attachment_cids: vec![],
                in_reply_to: String::new(),
                sent_at: 1,
                postage_receipt: String::new(),
            },
        )
    }

    #[test]
    fn deliver_request_roundtrip() {
        let s = id("p1");
        let r = id("p1r");
        let req = MailRequest::Deliver { envelope: env(&s, &r.node_id_hex()), grant: vec![] };
        let back = MailRequest::decode(&req.encode()).unwrap();
        match back {
            MailRequest::Deliver { envelope, grant } => {
                assert!(envelope.verify().is_ok());
                assert!(grant.is_empty());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn drain_request_roundtrip() {
        let req = MailRequest::Drain { recipient: "ab".repeat(32), since: 7, grant: vec![] };
        let back = MailRequest::decode(&req.encode()).unwrap();
        match back {
            MailRequest::Drain { recipient, since, .. } => {
                assert_eq!(recipient, "ab".repeat(32));
                assert_eq!(since, 7);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn ack_request_roundtrip() {
        let req = MailRequest::Ack { recipient: "cd".repeat(32), cursor: 3, grant: vec![] };
        let back = MailRequest::decode(&req.encode()).unwrap();
        matches!(back, MailRequest::Ack { cursor: 3, .. });
    }

    #[test]
    fn reply_variants_roundtrip() {
        for r in [
            MailReply::Delivered { duplicate: false },
            MailReply::Delivered { duplicate: true },
            MailReply::Drained { envelopes: vec![], cursor: 5 },
            MailReply::Page { envelopes: vec![], cursor: 3, more: true },
            MailReply::Acked { removed: 2 },
            MailReply::ReceiptAccepted { duplicate: false },
            MailReply::Receipts { receipts: vec![] },
            MailReply::Error { message: "nope".into() },
        ] {
            let back = MailReply::decode(&r.encode()).unwrap();
            assert_eq!(format!("{back:?}"), format!("{r:?}"));
        }
    }

    #[test]
    fn drain_page_request_roundtrip() {
        let req =
            MailRequest::DrainPage { recipient: "ab".repeat(32), since: 2, limit: 10, grant: vec![] };
        let back = MailRequest::decode(&req.encode()).unwrap();
        match back {
            MailRequest::DrainPage { recipient, since, limit, .. } => {
                assert_eq!(recipient, "ab".repeat(32));
                assert_eq!(since, 2);
                assert_eq!(limit, 10);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn put_receipt_request_roundtrip() {
        use crate::receipt::{Receipt, ReceiptKind};
        let recip = id("p-rcpt");
        let receipt = Receipt::issue(&recip, &"ab".repeat(32), ReceiptKind::Read, 9);
        let req = MailRequest::PutReceipt {
            for_sender: "cd".repeat(32),
            receipt: receipt.clone(),
            grant: vec![],
        };
        let back = MailRequest::decode(&req.encode()).unwrap();
        match back {
            MailRequest::PutReceipt { for_sender, receipt: r, .. } => {
                assert_eq!(for_sender, "cd".repeat(32));
                assert_eq!(r, receipt);
                assert!(r.verify().is_ok());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn collect_receipts_request_roundtrip() {
        let req = MailRequest::CollectReceipts { sender: "ef".repeat(32), grant: vec![] };
        let back = MailRequest::decode(&req.encode()).unwrap();
        matches!(back, MailRequest::CollectReceipts { .. });
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(MailRequest::decode(&[0xff, 0xff, 0xff, 0xff]).is_err());
        assert!(MailReply::decode(&[0xff, 0xff, 0xff, 0xff]).is_err());
    }
}
