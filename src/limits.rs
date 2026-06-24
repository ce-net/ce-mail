//! Resource bounds for ce-mail — the single source of truth for every size/count limit that
//! protects a mailbox (and a client) from memory-amplification and denial-of-service.
//!
//! Email is an *adversarial* medium: a malicious or buggy peer can hand a mailbox an arbitrarily
//! large subject, an envelope referencing thousands of attachment CIDs, or a `DrainPage` asking for
//! a billion messages in one round-trip. None of those are bounded by the per-recipient message
//! *count* (`capacity_per_recipient`), so they are enforced here, at the point an external input
//! crosses the trust boundary ([`Limits::check_envelope`] before storing, [`Limits::clamp_page`]
//! before reading).
//!
//! All limits are generous for honest use and tight enough that a single request cannot exhaust a
//! 4 GB mailbox node. They are configurable per [`crate::service::MailService`] so a private mailbox
//! can loosen them and a public one can tighten them.

/// Hard caps on the sizes ce-mail accepts from the network. Cheap to clone; carried by the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Max bytes in a cleartext subject (it is signed but unbounded otherwise — a DoS vector).
    pub max_subject_bytes: usize,
    /// Max bytes in a CID string (`body_cid`, each `attachment_cid`, `in_reply_to`). A sha256 hex
    /// CID is 64 bytes; we allow a little slack for future multi-hash prefixes but reject essays.
    pub max_cid_bytes: usize,
    /// Max number of attachment CIDs an envelope may reference.
    pub max_attachments: usize,
    /// Max bytes in the opaque `postage_receipt` string.
    pub max_postage_bytes: usize,
    /// Max total serialized size of an inbound envelope (a backstop over the field-level limits).
    pub max_envelope_bytes: usize,
    /// Server-side ceiling on a single `DrainPage` limit, so one request can never ask for an
    /// unbounded page.
    pub max_page: usize,
    /// Max plaintext bytes a single attachment may carry (sealed before storage). Mirrors the
    /// classic email attachment ceiling; the sealed blob is fetched lazily, never with the envelope.
    pub max_attachment_bytes: usize,
    /// Max plaintext bytes a single message body may carry.
    pub max_body_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_subject_bytes: 4 * 1024,        // 4 KiB — far beyond any real subject.
            max_cid_bytes: 256,                 // a sha256 hex CID is 64 bytes.
            max_attachments: 64,                // generous; Gmail caps at ~50.
            max_postage_bytes: 1024,            // a channel receipt id / token.
            max_envelope_bytes: 256 * 1024,     // 256 KiB metadata backstop.
            max_page: 500,                      // mirrors the chain-sync batch ceiling.
            max_attachment_bytes: 40 * 1024 * 1024, // 40 MiB — the documented per-attachment cap.
            max_body_bytes: 25 * 1024 * 1024,   // 25 MiB body.
        }
    }
}

impl Limits {
    /// Validate an inbound [`crate::envelope::Envelope`] against the field-level and total-size
    /// bounds. Returns a human-readable error naming the first limit exceeded. Pure; no I/O.
    pub fn check_envelope(&self, env: &crate::envelope::Envelope) -> anyhow::Result<()> {
        use anyhow::ensure;
        let b = &env.body;
        ensure!(
            b.subject.len() <= self.max_subject_bytes,
            "subject too large: {} > {} bytes",
            b.subject.len(),
            self.max_subject_bytes
        );
        ensure!(
            b.body_cid.len() <= self.max_cid_bytes,
            "body_cid too large: {} > {} bytes",
            b.body_cid.len(),
            self.max_cid_bytes
        );
        ensure!(
            b.in_reply_to.len() <= self.max_cid_bytes,
            "in_reply_to too large: {} > {} bytes",
            b.in_reply_to.len(),
            self.max_cid_bytes
        );
        ensure!(
            b.postage_receipt.len() <= self.max_postage_bytes,
            "postage_receipt too large: {} > {} bytes",
            b.postage_receipt.len(),
            self.max_postage_bytes
        );
        ensure!(
            b.attachment_cids.len() <= self.max_attachments,
            "too many attachments: {} > {}",
            b.attachment_cids.len(),
            self.max_attachments
        );
        for (i, cid) in b.attachment_cids.iter().enumerate() {
            ensure!(
                cid.len() <= self.max_cid_bytes,
                "attachment_cid[{i}] too large: {} > {} bytes",
                cid.len(),
                self.max_cid_bytes
            );
        }
        // Total-size backstop: catches a pathological combination the field checks individually
        // pass (e.g. the maximum number of maximum-length CIDs).
        let total = env.encoded_len();
        ensure!(
            total <= self.max_envelope_bytes,
            "envelope too large: {total} > {} bytes",
            self.max_envelope_bytes
        );
        Ok(())
    }

    /// Clamp a requested page `limit` to the server-side ceiling, treating `0` as `1` so a caller
    /// always makes progress. A malicious `usize::MAX` becomes [`Limits::max_page`].
    pub fn clamp_page(&self, limit: usize) -> usize {
        limit.clamp(1, self.max_page)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{Envelope, EnvelopeBody};
    use ce_identity::Identity;

    fn id(tag: &str) -> Identity {
        let dir = std::env::temp_dir().join(format!("ce-mail-lim-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Identity::load_or_generate(&dir).unwrap()
    }

    fn body(to: &str) -> EnvelopeBody {
        EnvelopeBody {
            from: String::new(),
            to: to.to_string(),
            subject: "ok".into(),
            body_cid: "ab".repeat(32),
            attachment_cids: vec![],
            in_reply_to: String::new(),
            sent_at: 1,
            postage_receipt: String::new(),
        }
    }

    #[test]
    fn default_envelope_passes() {
        let s = id("ok-s");
        let r = id("ok-r");
        let env = Envelope::seal(&s, body(&r.node_id_hex()));
        assert!(Limits::default().check_envelope(&env).is_ok());
    }

    #[test]
    fn oversized_subject_rejected() {
        let s = id("subj-s");
        let r = id("subj-r");
        let mut b = body(&r.node_id_hex());
        b.subject = "x".repeat(5000);
        let env = Envelope::seal(&s, b);
        assert!(Limits::default().check_envelope(&env).is_err());
    }

    #[test]
    fn too_many_attachments_rejected() {
        let s = id("att-s");
        let r = id("att-r");
        let mut b = body(&r.node_id_hex());
        b.attachment_cids = (0..1000).map(|_| "cd".repeat(32)).collect();
        let env = Envelope::seal(&s, b);
        assert!(Limits::default().check_envelope(&env).is_err());
    }

    #[test]
    fn oversized_cid_rejected() {
        let s = id("cid-s");
        let r = id("cid-r");
        let mut b = body(&r.node_id_hex());
        b.body_cid = "a".repeat(1000);
        let env = Envelope::seal(&s, b);
        assert!(Limits::default().check_envelope(&env).is_err());
    }

    #[test]
    fn oversized_postage_rejected() {
        let s = id("post-s");
        let r = id("post-r");
        let mut b = body(&r.node_id_hex());
        b.postage_receipt = "z".repeat(2048);
        let env = Envelope::seal(&s, b);
        assert!(Limits::default().check_envelope(&env).is_err());
    }

    #[test]
    fn clamp_page_bounds_both_ends() {
        let l = Limits::default();
        assert_eq!(l.clamp_page(0), 1);
        assert_eq!(l.clamp_page(10), 10);
        assert_eq!(l.clamp_page(usize::MAX), l.max_page);
    }
}
