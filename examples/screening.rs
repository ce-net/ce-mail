//! Self-contained example (no node required): show how a recipient's [`ScreeningPolicy`] classifies
//! inbound mail into inbox / spam / rejected using contacts, refundable postage, and a reputation
//! gradient — the anti-spam story without filters or guesswork.
//!
//! Run: `cargo run --example screening`

use ce_identity::Identity;
use ce_mail::envelope::{Envelope, EnvelopeBody};
use ce_mail::screening::SenderStanding;
use ce_mail::{ScreeningPolicy, Verdict};
use ce_rs::Amount;

fn note(sender: &Identity, to: &str, subject: &str, postage: &str) -> Envelope {
    Envelope::seal(
        sender,
        EnvelopeBody {
            from: String::new(),
            to: to.to_string(),
            subject: subject.into(),
            body_cid: String::new(),
            attachment_cids: vec![],
            in_reply_to: String::new(),
            sent_at: 0,
            postage_receipt: postage.to_string(),
        },
    )
}

fn main() -> anyhow::Result<()> {
    let me = Identity::load_or_generate(&std::env::temp_dir().join("ce-mail-ex-me"))?;
    let friend = Identity::load_or_generate(&std::env::temp_dir().join("ce-mail-ex-friend"))?;
    let stranger = Identity::load_or_generate(&std::env::temp_dir().join("ce-mail-ex-stranger"))?;
    let proven = Identity::load_or_generate(&std::env::temp_dir().join("ce-mail-ex-proven"))?;

    // Require 1 credit of postage from strangers; contacts and proven senders are waived.
    let policy = ScreeningPolicy::new(me.node_id_hex())
        .allow(friend.node_id_hex())
        .require_postage(Amount::from_credits(1));

    // A verifier that confirms a (toy) postage receipt is worth 2 credits.
    let verify = |receipt: &str| {
        if receipt == "paid-2-credits" { Some(Amount::from_credits(2)) } else { None }
    };

    let cases = [
        ("contact, no postage", &friend, "", SenderStanding::Newcomer),
        ("stranger, no postage", &stranger, "", SenderStanding::Newcomer),
        ("stranger, valid postage", &stranger, "paid-2-credits", SenderStanding::Newcomer),
        ("proven sender, no postage", &proven, "", SenderStanding::Established),
    ];

    for (label, sender, postage, standing) in cases {
        let env = note(sender, &me.node_id_hex(), "hi", postage);
        let verdict = policy.screen(&env, standing, verify);
        let bucket = match verdict {
            Verdict::Inbox { postage_held: true } => "INBOX (postage held, refundable)",
            Verdict::Inbox { postage_held: false } => "INBOX",
            Verdict::Spam => "SPAM (quarantined)",
            Verdict::Rejected => "REJECTED",
        };
        println!("{label:28} -> {bucket}");
    }
    Ok(())
}
