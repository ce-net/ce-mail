//! The ce-mail envelope — the signed metadata that travels over the mesh.
//!
//! A message is split into two parts, mirroring real email's headers/body split but content-
//! addressed and E2E-encrypted:
//!
//! * **Body + attachments** are [`crate::crypto::SealedBody`] blobs stored in the CE blob store and
//!   referenced by **CID** (sha256). They are fetched *lazily* — a 40 MB attachment is never
//!   downloaded until the recipient opens it.
//! * **The envelope** is small signed metadata (`from`, `to`, `subject`, `body_cid`, thread id,
//!   timestamp, optional postage). It is what travels over `AppRequest`/pubsub and what a mailbox
//!   stores for an offline recipient. Every envelope is Ed25519-signed by `from`, so the sender is
//!   cryptographically unforgeable — no SPF/DKIM needed.
//!
//! The envelope deliberately does **not** carry the body: keeping it tiny makes store-and-forward
//! cheap and lets the recipient decide whether to pull the (possibly large) body at all.

use anyhow::{Result, anyhow};
use ce_identity::{Identity, NodeId, verify};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain tag so an envelope signature can never be confused with another CE signature.
const ENVELOPE_DOMAIN: &[u8] = b"ce-mail-envelope-v1";

/// A message id: `sha256(envelope_signing_bytes)`, hex. Stable, content-addressed, and used to
/// thread replies (`in_reply_to`) and de-duplicate at the mailbox.
pub type MessageId = String;

/// The unsigned envelope contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeBody {
    /// Sender NodeId (hex, 64 chars). The signer.
    pub from: String,
    /// Recipient NodeId (hex, 64 chars).
    pub to: String,
    /// Cleartext subject line (metadata; not encrypted, like an email subject).
    pub subject: String,
    /// CID (sha256 hex) of the sealed body blob in the CE blob store. Empty for a bodiless ping.
    pub body_cid: String,
    /// CIDs of sealed attachment blobs, fetched lazily on open.
    #[serde(default)]
    pub attachment_cids: Vec<String>,
    /// The [`MessageId`] this message replies to, threading the conversation. Empty if a new thread.
    #[serde(default)]
    pub in_reply_to: String,
    /// Unix seconds the sender stamped the message.
    pub sent_at: u64,
    /// Optional postage receipt id (a payment-channel receipt) proving the sender paid postage.
    /// Recipients may require this from strangers as anti-spam; contacts are waived. Empty = none.
    #[serde(default)]
    pub postage_receipt: String,
}

/// Canonical signing bytes for an envelope. Domain-separated and deterministic (bincode).
pub fn envelope_signing_bytes(e: &EnvelopeBody) -> Vec<u8> {
    bincode::serialize(&(
        ENVELOPE_DOMAIN,
        &e.from,
        &e.to,
        &e.subject,
        &e.body_cid,
        &e.attachment_cids,
        &e.in_reply_to,
        e.sent_at,
        &e.postage_receipt,
    ))
    .unwrap_or_default()
}

/// The content-addressed message id for an envelope: `sha256(signing_bytes)`, hex.
pub fn message_id(e: &EnvelopeBody) -> MessageId {
    let mut h = Sha256::new();
    h.update(envelope_signing_bytes(e));
    hex::encode(h.finalize())
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

/// A signed envelope: the body plus the sender's Ed25519 signature over [`envelope_signing_bytes`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub body: EnvelopeBody,
    #[serde(with = "sig_serde")]
    pub sig: [u8; 64],
}

impl Envelope {
    /// Sign an envelope body with the sender's identity. Sets/overwrites `body.from` to the
    /// signer's NodeId so a signed envelope always self-attests its sender.
    pub fn seal(sender: &Identity, mut body: EnvelopeBody) -> Self {
        body.from = sender.node_id_hex();
        let sig = sender.sign(&envelope_signing_bytes(&body));
        Envelope { body, sig }
    }

    /// Verify the sender's signature. Returns an error if `from` is not valid hex / not a key, or
    /// the signature does not match the contents (tampered or forged).
    pub fn verify(&self) -> Result<()> {
        let from = parse_node_id(&self.body.from)?;
        verify(&from, &envelope_signing_bytes(&self.body), &self.sig)
            .map_err(|_| anyhow!("envelope signature does not verify (forged or tampered)"))
    }

    /// This envelope's content-addressed message id.
    pub fn message_id(&self) -> MessageId {
        message_id(&self.body)
    }

    /// The number of attachments this envelope references (without fetching any blob).
    pub fn attachment_count(&self) -> usize {
        self.body.attachment_cids.len()
    }

    /// Encode to deterministic wire bytes (carried over AppRequest / stored at a mailbox).
    ///
    /// Serialization of a well-formed envelope cannot fail (all fields are owned, sized types), so
    /// this is infallible in practice; [`Envelope::try_encode`] surfaces the bincode error for
    /// callers that prefer to propagate it rather than rely on the invariant.
    pub fn encode(&self) -> Vec<u8> {
        self.try_encode().unwrap_or_default()
    }

    /// Fallible encode: returns the bincode error instead of an empty vec on the (practically
    /// impossible) serialization failure. Prefer this on paths where a silent empty encode would
    /// corrupt a stored message.
    pub fn try_encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow!("failed to encode envelope: {e}"))
    }

    /// The exact serialized byte length of this envelope, for the total-size limit check. Computed
    /// without allocating the full buffer.
    pub fn encoded_len(&self) -> usize {
        bincode::serialized_size(self).map(|n| n as usize).unwrap_or(usize::MAX)
    }

    /// Decode from wire bytes. Does **not** verify the signature — call [`Envelope::verify`].
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow!("malformed envelope: {e}"))
    }
}

/// Parse a 64-hex NodeId.
pub fn parse_node_id(hex_str: &str) -> Result<NodeId> {
    let bytes = hex::decode(hex_str.trim()).map_err(|_| anyhow!("node id is not valid hex"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("node id must be 32 bytes (64 hex chars)"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ce_identity::Identity;

    fn id(tag: &str) -> Identity {
        let dir = std::env::temp_dir().join(format!("ce-mail-env-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Identity::load_or_generate(&dir).unwrap()
    }

    fn sample_body(to: &str) -> EnvelopeBody {
        EnvelopeBody {
            from: String::new(),
            to: to.to_string(),
            subject: "hello".into(),
            body_cid: "ab".repeat(32),
            attachment_cids: vec!["cd".repeat(32)],
            in_reply_to: String::new(),
            sent_at: 1_700_000_000,
            postage_receipt: String::new(),
        }
    }

    #[test]
    fn seal_sets_from_and_verifies() {
        let sender = id("s1");
        let recip = id("r1");
        let env = Envelope::seal(&sender, sample_body(&recip.node_id_hex()));
        assert_eq!(env.body.from, sender.node_id_hex());
        assert!(env.verify().is_ok());
    }

    #[test]
    fn encode_decode_roundtrip() {
        let sender = id("s2");
        let recip = id("r2");
        let env = Envelope::seal(&sender, sample_body(&recip.node_id_hex()));
        let bytes = env.encode();
        let back = Envelope::decode(&bytes).unwrap();
        assert_eq!(env.body, back.body);
        assert_eq!(env.sig, back.sig);
        assert!(back.verify().is_ok());
    }

    #[test]
    fn message_id_is_stable_and_hex() {
        let sender = id("s3");
        let recip = id("r3");
        let env = Envelope::seal(&sender, sample_body(&recip.node_id_hex()));
        let mid = env.message_id();
        assert_eq!(mid.len(), 64);
        assert!(mid.chars().all(|c| c.is_ascii_hexdigit()));
        // Recomputed id is identical.
        assert_eq!(mid, env.message_id());
    }

    #[test]
    fn tampered_subject_fails_verification() {
        let sender = id("s4");
        let recip = id("r4");
        let mut env = Envelope::seal(&sender, sample_body(&recip.node_id_hex()));
        env.body.subject = "MALICIOUS".into();
        assert!(env.verify().is_err());
    }

    #[test]
    fn forged_from_fails_verification() {
        // Attacker takes a valid envelope and swaps `from` to impersonate someone else.
        let sender = id("s5");
        let victim = id("victim");
        let recip = id("r5");
        let mut env = Envelope::seal(&sender, sample_body(&recip.node_id_hex()));
        env.body.from = victim.node_id_hex();
        assert!(env.verify().is_err());
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(Envelope::decode(&[0x00, 0x01, 0x02]).is_err());
    }

    #[test]
    fn verify_rejects_bad_from_hex() {
        let sender = id("s6");
        let recip = id("r6");
        let mut env = Envelope::seal(&sender, sample_body(&recip.node_id_hex()));
        env.body.from = "not-hex".into();
        assert!(env.verify().is_err());
    }

    #[test]
    fn parse_node_id_validates_length() {
        assert!(parse_node_id(&"ab".repeat(32)).is_ok());
        assert!(parse_node_id("abcd").is_err());
        assert!(parse_node_id("zz").is_err());
    }

    #[test]
    fn distinct_content_yields_distinct_ids() {
        let sender = id("s7");
        let recip = id("r7");
        let a = Envelope::seal(&sender, sample_body(&recip.node_id_hex()));
        let mut b2 = sample_body(&recip.node_id_hex());
        b2.subject = "different".into();
        let b = Envelope::seal(&sender, b2);
        assert_ne!(a.message_id(), b.message_id());
    }
}
