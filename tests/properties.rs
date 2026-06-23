//! Property tests for ce-mail's serialization and crypto invariants. We assert that:
//! * sealed bodies survive seal→encode→decode→open for arbitrary plaintext;
//! * envelopes survive sign→encode→decode and keep verifying for arbitrary metadata;
//! * malformed bytes never panic any decoder (graceful errors only);
//! * the message id is a deterministic function of envelope content.

use ce_identity::Identity;
use ce_mail::crypto::{self, SealedBody};
use ce_mail::envelope::{Envelope, EnvelopeBody, message_id};
use ce_mail::proto::{MailReply, MailRequest};
use proptest::prelude::*;

fn recipient() -> Identity {
    let dir = std::env::temp_dir().join(format!("ce-mail-prop-recip-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    Identity::load_or_generate(&dir).unwrap()
}

fn sender() -> Identity {
    let dir = std::env::temp_dir().join(format!("ce-mail-prop-sender-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    Identity::load_or_generate(&dir).unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Seal then open recovers any plaintext.
    #[test]
    fn seal_open_recovers_plaintext(body in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let recip = recipient();
        let sealed = crypto::seal(&recip.node_id(), &body).unwrap();
        let encoded = crypto::encode_sealed(&sealed);
        let decoded = crypto::decode_sealed(&encoded).unwrap();
        let opened = crypto::open(&recip.secret_bytes(), &decoded).unwrap();
        prop_assert_eq!(opened, body);
    }

    /// Envelope sign→encode→decode keeps verifying, for arbitrary metadata.
    #[test]
    fn envelope_roundtrip_verifies(
        subject in ".{0,200}",
        body_cid in "[0-9a-f]{0,64}",
        in_reply_to in "[0-9a-f]{0,64}",
        sent_at in any::<u64>(),
    ) {
        let snd = sender();
        let recip = recipient();
        let env = Envelope::seal(&snd, EnvelopeBody {
            from: String::new(),
            to: recip.node_id_hex(),
            subject,
            body_cid,
            attachment_cids: vec![],
            in_reply_to,
            sent_at,
            postage_receipt: String::new(),
        });
        let back = Envelope::decode(&env.encode()).unwrap();
        prop_assert!(back.verify().is_ok());
        prop_assert_eq!(env.message_id(), back.message_id());
    }

    /// The message id depends only on content: equal bodies → equal ids.
    #[test]
    fn message_id_is_deterministic(subject in ".{0,64}", sent_at in any::<u64>()) {
        let recip = recipient();
        let body = EnvelopeBody {
            from: "ab".repeat(32),
            to: recip.node_id_hex(),
            subject,
            body_cid: String::new(),
            attachment_cids: vec![],
            in_reply_to: String::new(),
            sent_at,
            postage_receipt: String::new(),
        };
        prop_assert_eq!(message_id(&body), message_id(&body.clone()));
    }

    /// Arbitrary bytes never panic the sealed-body decoder.
    #[test]
    fn decode_sealed_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        let _: Result<SealedBody, _> = crypto::decode_sealed(&bytes);
    }

    /// Arbitrary bytes never panic the envelope decoder.
    #[test]
    fn decode_envelope_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        let _ = Envelope::decode(&bytes);
    }

    /// Arbitrary bytes never panic the protocol decoders.
    #[test]
    fn decode_proto_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        let _ = MailRequest::decode(&bytes);
        let _ = MailReply::decode(&bytes);
    }

    /// Flipping any single ciphertext byte must make open() fail (AEAD integrity), never panic.
    #[test]
    fn tampering_ciphertext_fails(
        body in proptest::collection::vec(any::<u8>(), 1..256),
        idx in any::<usize>(),
    ) {
        let recip = recipient();
        let mut sealed = crypto::seal(&recip.node_id(), &body).unwrap();
        let i = idx % sealed.ciphertext.len();
        sealed.ciphertext[i] ^= 0xff;
        prop_assert!(crypto::open(&recip.secret_bytes(), &sealed).is_err());
    }
}
