//! Delivery / read receipts for ce-mail.
//!
//! A receipt is a tiny **signed** acknowledgement that a recipient produces for a message they have
//! received (delivered) or opened (read). Because it is Ed25519-signed by the recipient over the
//! message id, the original sender can verify — unforgeably — that *that specific recipient*
//! acknowledged *that specific message*. This is the messaging analogue of a read receipt, but
//! cryptographically attributable rather than trust-me metadata.
//!
//! Receipts ride the same mesh request/reply protocol ([`crate::proto`]) and can be relayed through a
//! mailbox just like envelopes: the recipient hands the mailbox a signed receipt, the sender later
//! collects it. The mailbox cannot forge one (it lacks the recipient's key) and re-submitting the
//! same receipt is idempotent (content-addressed by `(message_id, kind, recipient)`).

use crate::envelope::{MessageId, parse_node_id};
use anyhow::{Result, anyhow};
use ce_identity::{Identity, NodeId, verify};
use serde::{Deserialize, Serialize};

/// Domain tag so a receipt signature can never be confused with an envelope signature.
const RECEIPT_DOMAIN: &[u8] = b"ce-mail-receipt-v1";

/// What a receipt attests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReceiptKind {
    /// The recipient received (the message reached their inbox / was drained).
    Delivered,
    /// The recipient opened/read the message (decrypted the body).
    Read,
}

impl ReceiptKind {
    fn tag(self) -> u8 {
        match self {
            ReceiptKind::Delivered => 1,
            ReceiptKind::Read => 2,
        }
    }
}

/// The unsigned receipt contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptBody {
    /// The message id being acknowledged.
    pub message_id: MessageId,
    /// The acknowledging recipient's NodeId (hex). The signer.
    pub by: String,
    /// What is being attested.
    pub kind: ReceiptKind,
    /// Unix seconds the recipient stamped the receipt.
    pub at: u64,
}

/// Canonical signing bytes for a receipt. Domain-separated and deterministic.
fn receipt_signing_bytes(b: &ReceiptBody) -> Vec<u8> {
    bincode::serialize(&(RECEIPT_DOMAIN, &b.message_id, &b.by, b.kind.tag(), b.at))
        .unwrap_or_default()
}

mod sig_serde {
    use serde::{Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(sig: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(sig)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(d)?;
        bytes.try_into().map_err(|_| D::Error::custom("expected 64 bytes for signature"))
    }
}

/// A signed receipt: the body plus the recipient's Ed25519 signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Receipt {
    pub body: ReceiptBody,
    #[serde(with = "sig_serde")]
    pub sig: [u8; 64],
}

impl Receipt {
    /// Issue a signed receipt from `recipient` for `message_id`. Overwrites `by` with the signer's
    /// NodeId so a signed receipt always self-attests who acknowledged.
    pub fn issue(recipient: &Identity, message_id: &str, kind: ReceiptKind, at: u64) -> Self {
        let body = ReceiptBody {
            message_id: message_id.to_string(),
            by: recipient.node_id_hex(),
            kind,
            at,
        };
        let sig = recipient.sign(&receipt_signing_bytes(&body));
        Receipt { body, sig }
    }

    /// Verify the recipient's signature. Errors if `by` is not a key or the signature does not match
    /// (forged or tampered).
    pub fn verify(&self) -> Result<()> {
        let by = parse_node_id(&self.body.by)?;
        verify(&by, &receipt_signing_bytes(&self.body), &self.sig)
            .map_err(|_| anyhow!("receipt signature does not verify (forged or tampered)"))
    }

    /// A stable de-dup key: `(message_id, kind, by)`. Two receipts with the same key are the same
    /// acknowledgement (idempotent collection).
    pub fn dedup_key(&self) -> String {
        format!("{}:{}:{}", self.body.message_id, self.body.kind.tag(), self.body.by)
    }

    /// The acknowledging recipient as a NodeId.
    pub fn by_node(&self) -> Result<NodeId> {
        parse_node_id(&self.body.by)
    }

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }
    /// Decode from wire bytes. Does **not** verify — call [`Receipt::verify`].
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow!("malformed receipt: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(tag: &str) -> Identity {
        let dir = std::env::temp_dir().join(format!("ce-mail-rcpt-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Identity::load_or_generate(&dir).unwrap()
    }

    #[test]
    fn issue_sets_by_and_verifies() {
        let recip = id("r1");
        let r = Receipt::issue(&recip, &"ab".repeat(32), ReceiptKind::Delivered, 100);
        assert_eq!(r.body.by, recip.node_id_hex());
        assert!(r.verify().is_ok());
    }

    #[test]
    fn read_receipt_verifies() {
        let recip = id("r2");
        let r = Receipt::issue(&recip, &"cd".repeat(32), ReceiptKind::Read, 200);
        assert_eq!(r.body.kind, ReceiptKind::Read);
        assert!(r.verify().is_ok());
    }

    #[test]
    fn encode_decode_roundtrip() {
        let recip = id("r3");
        let r = Receipt::issue(&recip, &"ab".repeat(32), ReceiptKind::Read, 5);
        let back = Receipt::decode(&r.encode()).unwrap();
        assert_eq!(r, back);
        assert!(back.verify().is_ok());
    }

    #[test]
    fn tampered_message_id_fails_verification() {
        let recip = id("r4");
        let mut r = Receipt::issue(&recip, &"ab".repeat(32), ReceiptKind::Delivered, 1);
        r.body.message_id = "ff".repeat(32);
        assert!(r.verify().is_err());
    }

    #[test]
    fn tampered_kind_fails_verification() {
        let recip = id("r5");
        let mut r = Receipt::issue(&recip, &"ab".repeat(32), ReceiptKind::Delivered, 1);
        r.body.kind = ReceiptKind::Read;
        assert!(r.verify().is_err());
    }

    #[test]
    fn forged_by_fails_verification() {
        let recip = id("r6");
        let victim = id("r6-victim");
        let mut r = Receipt::issue(&recip, &"ab".repeat(32), ReceiptKind::Read, 1);
        r.body.by = victim.node_id_hex();
        assert!(r.verify().is_err());
    }

    #[test]
    fn dedup_key_is_stable_and_distinguishes_kind() {
        let recip = id("r7");
        let d = Receipt::issue(&recip, &"ab".repeat(32), ReceiptKind::Delivered, 1);
        let r = Receipt::issue(&recip, &"ab".repeat(32), ReceiptKind::Read, 9);
        // Same message + recipient, different kind -> different keys; at does not affect the key.
        assert_ne!(d.dedup_key(), r.dedup_key());
        let d2 = Receipt::issue(&recip, &"ab".repeat(32), ReceiptKind::Delivered, 999);
        assert_eq!(d.dedup_key(), d2.dedup_key());
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(Receipt::decode(&[0x00, 0x01]).is_err());
    }

    #[test]
    fn verify_rejects_bad_by_hex() {
        let recip = id("r8");
        let mut r = Receipt::issue(&recip, &"ab".repeat(32), ReceiptKind::Read, 1);
        r.body.by = "not-hex".into();
        assert!(r.verify().is_err());
    }
}
