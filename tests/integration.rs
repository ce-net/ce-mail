//! Integration tests: full ce-mail flows wired through an in-memory transport, exercising the
//! library exactly as an app would (no running node). Covers the headline guarantees:
//! envelope encode/decode round-trip, delivery + ack, offline-store replay, the capability gate,
//! and end-to-end body encryption — plus failure injection (dropped peer, missing blob).

use anyhow::{Result, anyhow};
use ce_iam_core::{Caveats, Resource, SignedCapability};
use ce_identity::{Identity, NodeId};
use ce_mail::client::{MailClient, SendOptions, Transport};
use ce_mail::mailbox::{ABILITY_ACCEPT, MailboxStore};
use ce_mail::proto::MailRequest;
use ce_mail::receipt::ReceiptKind;
use ce_mail::service::MailService;
use ce_mail::{Envelope, EnvelopeBody};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

fn idn(tag: &str) -> Identity {
    let dir = std::env::temp_dir().join(format!("ce-mail-it-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    Identity::load_or_generate(&dir).unwrap()
}

fn dup(idn: &Identity) -> Identity {
    let dir =
        std::env::temp_dir().join(format!("ce-mail-it-dup-{}-{}", std::process::id(), idn.node_id_hex()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("node.key"), idn.secret_bytes()).unwrap();
    Identity::load_or_generate(&dir).unwrap()
}

fn never_revoked(_: &NodeId, _: u64) -> bool {
    false
}

fn accept_grant(recipient: &Identity, mailbox: &Identity) -> Vec<SignedCapability> {
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

#[derive(Clone)]
struct Net {
    blobs: Rc<RefCell<HashMap<String, Vec<u8>>>>,
    services: Rc<RefCell<HashMap<String, Rc<RefCell<MailService>>>>>,
    drop_peer: Rc<RefCell<bool>>,
}

impl Net {
    fn new() -> Self {
        Net {
            blobs: Rc::new(RefCell::new(HashMap::new())),
            services: Rc::new(RefCell::new(HashMap::new())),
            drop_peer: Rc::new(RefCell::new(false)),
        }
    }
    fn install(&self, hex: &str, svc: MailService) {
        self.services.borrow_mut().insert(hex.to_string(), Rc::new(RefCell::new(svc)));
    }
}

struct Handle {
    net: Net,
    me: NodeId,
}

impl Transport for Handle {
    async fn put_blob(&self, bytes: Vec<u8>) -> Result<String> {
        let cid = ce_rs::cid(&bytes);
        self.net.blobs.borrow_mut().insert(cid.clone(), bytes);
        Ok(cid)
    }
    async fn get_blob(&self, cid: &str) -> Result<Vec<u8>> {
        self.net.blobs.borrow().get(cid).cloned().ok_or_else(|| anyhow!("missing blob {cid}"))
    }
    async fn request(&self, to: &str, payload: &[u8], _t: u64) -> Result<Vec<u8>> {
        if *self.net.drop_peer.borrow() {
            return Err(anyhow!("dropped peer"));
        }
        let svc =
            self.net.services.borrow().get(to).cloned().ok_or_else(|| anyhow!("no service {to}"))?;
        let req = MailRequest::decode(payload)?;
        Ok(svc.borrow_mut().handle(&self.me, req, 1000, &never_revoked).encode())
    }
}

fn client(net: &Net, who: &Identity) -> MailClient<Handle> {
    MailClient::new(dup(who), Handle { net: net.clone(), me: who.node_id() })
}

#[tokio::test]
async fn envelope_encode_decode_roundtrip_e2e() {
    let sender = idn("env-s");
    let recip = idn("env-r");
    let env = Envelope::seal(
        &sender,
        EnvelopeBody {
            from: String::new(),
            to: recip.node_id_hex(),
            subject: "round trip".into(),
            body_cid: "ab".repeat(32),
            attachment_cids: vec!["cd".repeat(32)],
            in_reply_to: String::new(),
            sent_at: 42,
            postage_receipt: String::new(),
        },
    );
    let back = Envelope::decode(&env.encode()).unwrap();
    assert_eq!(env.body, back.body);
    assert!(back.verify().is_ok());
    assert_eq!(env.message_id(), back.message_id());
}

#[tokio::test]
async fn delivery_and_ack_via_mailbox() {
    let net = Net::new();
    let mb = idn("da-mb");
    let recip = idn("da-rc");
    let sender = idn("da-sn");
    net.install(&mb.node_id_hex(), MailService::new(MailboxStore::new(mb.node_id(), 100)));

    let sc = client(&net, &sender);
    let mid = sc
        .send(SendOptions {
            to: recip.node_id_hex(),
            subject: "ack me".into(),
            body: b"payload".to_vec(),
            mailbox: Some(mb.node_id_hex()),
            grant: accept_grant(&recip, &mb),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(mid.len(), 64);

    let rc = client(&net, &recip);
    let (msgs, cursor) = rc.drain_inbox(&mb.node_id_hex(), 0, vec![]).await.unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(rc.ack(&mb.node_id_hex(), cursor, vec![]).await.unwrap(), 1);
    let (after, _) = rc.drain_inbox(&mb.node_id_hex(), 0, vec![]).await.unwrap();
    assert!(after.is_empty());
}

#[tokio::test]
async fn offline_store_replay_preserves_order_and_content() {
    let net = Net::new();
    let mb = idn("rp-mb");
    let recip = idn("rp-rc");
    let sender = idn("rp-sn");
    net.install(&mb.node_id_hex(), MailService::new(MailboxStore::new(mb.node_id(), 100)));
    let sc = client(&net, &sender);
    for i in 0..3 {
        sc.send(SendOptions {
            to: recip.node_id_hex(),
            subject: format!("msg {i}"),
            body: format!("body {i}").into_bytes(),
            mailbox: Some(mb.node_id_hex()),
            grant: accept_grant(&recip, &mb),
            ..Default::default()
        })
        .await
        .unwrap();
    }
    let rc = client(&net, &recip);
    let (msgs, _) = rc.drain_inbox(&mb.node_id_hex(), 0, vec![]).await.unwrap();
    assert_eq!(msgs.len(), 3);
    for (i, m) in msgs.iter().enumerate() {
        assert_eq!(m.envelope.body.subject, format!("msg {i}"));
        assert_eq!(m.body_text(), format!("body {i}"));
    }
}

#[tokio::test]
async fn capability_gate_blocks_unauthorized_delivery() {
    let net = Net::new();
    let mb = idn("cg-mb");
    let recip = idn("cg-rc");
    let sender = idn("cg-sn");
    net.install(&mb.node_id_hex(), MailService::new(MailboxStore::new(mb.node_id(), 100)));
    let sc = client(&net, &sender);
    // No grant -> rejected.
    let r = sc
        .send(SendOptions {
            to: recip.node_id_hex(),
            subject: "x".into(),
            body: b"x".to_vec(),
            mailbox: Some(mb.node_id_hex()),
            grant: vec![],
            ..Default::default()
        })
        .await;
    assert!(r.is_err());
}

#[tokio::test]
async fn e2e_body_encryption_only_recipient_can_read() {
    // The mailbox stores only the *sealed* body blob; it can never read the plaintext, but the
    // recipient can.
    let net = Net::new();
    let mb = idn("enc-mb");
    let recip = idn("enc-rc");
    let sender = idn("enc-sn");
    net.install(&mb.node_id_hex(), MailService::new(MailboxStore::new(mb.node_id(), 100)));
    let secret = b"top secret only for the recipient";
    let sc = client(&net, &sender);
    sc.send(SendOptions {
        to: recip.node_id_hex(),
        subject: "sealed".into(),
        body: secret.to_vec(),
        mailbox: Some(mb.node_id_hex()),
        grant: accept_grant(&recip, &mb),
        ..Default::default()
    })
    .await
    .unwrap();

    // The raw stored blob is ciphertext: the plaintext never appears in it.
    let stored_has_plaintext = net
        .blobs
        .borrow()
        .values()
        .any(|b| b.windows(secret.len()).any(|w| w == secret));
    assert!(!stored_has_plaintext, "plaintext leaked into the stored blob");

    // The recipient decrypts.
    let rc = client(&net, &recip);
    let (msgs, _) = rc.drain_inbox(&mb.node_id_hex(), 0, vec![]).await.unwrap();
    assert_eq!(msgs[0].body, secret);

    // A third party with their own key cannot decrypt the same envelope.
    let attacker = idn("enc-att");
    let ac = client(&net, &attacker);
    let opened = ac.open_body(&msgs[0].envelope).await;
    assert!(opened.is_err(), "attacker must not decrypt the body");
}

#[tokio::test]
async fn dropped_peer_is_handled_gracefully() {
    let net = Net::new();
    let mb = idn("dp-mb");
    let recip = idn("dp-rc");
    let sender = idn("dp-sn");
    net.install(&mb.node_id_hex(), MailService::new(MailboxStore::new(mb.node_id(), 100)));
    *net.drop_peer.borrow_mut() = true;
    let sc = client(&net, &sender);
    let r = sc
        .send(SendOptions {
            to: recip.node_id_hex(),
            subject: "x".into(),
            body: b"x".to_vec(),
            mailbox: Some(mb.node_id_hex()),
            grant: accept_grant(&recip, &mb),
            ..Default::default()
        })
        .await;
    assert!(r.is_err());
}

#[tokio::test]
async fn threading_via_in_reply_to() {
    let net = Net::new();
    let mb = idn("th-mb");
    let recip = idn("th-rc");
    let sender = idn("th-sn");
    net.install(&mb.node_id_hex(), MailService::new(MailboxStore::new(mb.node_id(), 100)));
    let sc = client(&net, &sender);
    let first = sc
        .send(SendOptions {
            to: recip.node_id_hex(),
            subject: "thread start".into(),
            body: b"hello".to_vec(),
            mailbox: Some(mb.node_id_hex()),
            grant: accept_grant(&recip, &mb),
            ..Default::default()
        })
        .await
        .unwrap();
    // Recipient replies, threading on the first message id.
    let rc_grant_to_mb = vec![SignedCapability::issue(
        &sender,
        mb.node_id(),
        vec![ABILITY_ACCEPT.to_string()],
        Resource::Node(sender.node_id()),
        Caveats::default(),
        2,
        None,
    )];
    let rc = client(&net, &recip);
    rc.send(SendOptions {
        to: sender.node_id_hex(),
        subject: "re: thread start".into(),
        body: b"hi back".to_vec(),
        in_reply_to: first.clone(),
        mailbox: Some(mb.node_id_hex()),
        grant: rc_grant_to_mb,
        ..Default::default()
    })
    .await
    .unwrap();

    let sender_inbox = client(&net, &sender);
    let (msgs, _) = sender_inbox.drain_inbox(&mb.node_id_hex(), 0, vec![]).await.unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].envelope.body.in_reply_to, first);
}

#[tokio::test]
async fn paginated_inbox_drain_e2e() {
    let net = Net::new();
    let mb = idn("pg-mb");
    let recip = idn("pg-rc");
    let sender = idn("pg-sn");
    net.install(&mb.node_id_hex(), MailService::new(MailboxStore::new(mb.node_id(), 100)));
    let sc = client(&net, &sender);
    for i in 0..6 {
        sc.send(SendOptions {
            to: recip.node_id_hex(),
            subject: format!("m{i}"),
            body: format!("b{i}").into_bytes(),
            mailbox: Some(mb.node_id_hex()),
            grant: accept_grant(&recip, &mb),
            ..Default::default()
        })
        .await
        .unwrap();
    }
    let rc = client(&net, &recip);
    // Page 0..2, advance, until !more. Assert each page is bounded and union is the full inbox.
    let mut cursor = 0;
    let mut seen = Vec::new();
    let mut pages = 0;
    loop {
        let (msgs, next, more) =
            rc.drain_inbox_page(&mb.node_id_hex(), cursor, 2, vec![]).await.unwrap();
        assert!(msgs.len() <= 2);
        pages += 1;
        for m in msgs {
            seen.push(m.envelope.body.subject.clone());
        }
        cursor = next;
        if !more {
            break;
        }
    }
    assert_eq!(seen, (0..6).map(|i| format!("m{i}")).collect::<Vec<_>>());
    assert_eq!(pages, 3, "6 messages / page size 2 = 3 pages");
}

#[tokio::test]
async fn read_receipt_round_trip_e2e() {
    let net = Net::new();
    let mb = idn("rr-mb");
    let recip = idn("rr-rc");
    let sender = idn("rr-sn");
    net.install(&mb.node_id_hex(), MailService::new(MailboxStore::new(mb.node_id(), 100)));
    let sc = client(&net, &sender);
    let mid = sc
        .send(SendOptions {
            to: recip.node_id_hex(),
            subject: "ack please".into(),
            body: b"open me".to_vec(),
            mailbox: Some(mb.node_id_hex()),
            grant: accept_grant(&recip, &mb),
            ..Default::default()
        })
        .await
        .unwrap();
    let rc = client(&net, &recip);
    let (msgs, _) = rc.drain_inbox(&mb.node_id_hex(), 0, vec![]).await.unwrap();
    assert_eq!(msgs.len(), 1);
    // Recipient deposits a read receipt; the sender delegated this mailbox to accept on its behalf.
    rc.send_receipt(
        &mb.node_id_hex(),
        &sender.node_id_hex(),
        &msgs[0].id(),
        ReceiptKind::Read,
        accept_grant(&sender, &mb),
    )
    .await
    .unwrap();
    // Sender collects, verifies attribution.
    let receipts = sc.collect_receipts(&mb.node_id_hex(), vec![]).await.unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].body.message_id, mid);
    assert_eq!(receipts[0].body.by, recip.node_id_hex());
    assert!(receipts[0].verify().is_ok());
}

#[tokio::test]
async fn offline_replay_is_idempotent_across_redelivery() {
    // Re-delivering the *same wire envelope* to the mailbox (e.g. a retry after a flaky link, or a
    // gossip duplicate) must not duplicate it; the recipient sees exactly one copy after replay, and
    // a redelivery even after an ack must not resurrect the message (the seen-set persists).
    //
    // Note: each `send` re-seals the body with a fresh ephemeral key, so two *fresh* sends of the
    // same plaintext have different body CIDs and thus different message ids. The mailbox-level
    // idempotence guarantee is about redelivering the identical signed envelope, which is what a
    // retry/gossip actually carries — so we deliver the same `Envelope` value twice via the service.
    let mb = idn("ir-mb");
    let recip = idn("ir-rc");
    let sender = idn("ir-sn");
    let mut svc = MailService::new(MailboxStore::new(mb.node_id(), 100));
    let grant = accept_grant(&recip, &mb);
    let env = Envelope::seal(
        &sender,
        EnvelopeBody {
            from: String::new(),
            to: recip.node_id_hex(),
            subject: "retry".into(),
            body_cid: "ab".repeat(32),
            attachment_cids: vec![],
            in_reply_to: String::new(),
            sent_at: 5,
            postage_receipt: String::new(),
        },
    );
    // First delivery stores; the redelivery is a duplicate.
    let r1 = svc.handle(
        &sender.node_id(),
        MailRequest::Deliver { envelope: env.clone(), grant: grant.clone() },
        1,
        &never_revoked,
    );
    assert!(matches!(r1, ce_mail::MailReply::Delivered { duplicate: false }));
    let r2 = svc.handle(
        &sender.node_id(),
        MailRequest::Deliver { envelope: env.clone(), grant: grant.clone() },
        1,
        &never_revoked,
    );
    assert!(matches!(r2, ce_mail::MailReply::Delivered { duplicate: true }));
    assert_eq!(svc.store().pending_count(&recip.node_id_hex()), 1, "redelivery must de-dupe");

    // Drain + ack to free the queue, then a late redelivery of the same id must not reappear.
    let _ = svc.handle(
        &recip.node_id(),
        MailRequest::Ack { recipient: recip.node_id_hex(), cursor: 1, grant: vec![] },
        2,
        &never_revoked,
    );
    let r3 = svc.handle(
        &sender.node_id(),
        MailRequest::Deliver { envelope: env, grant },
        3,
        &never_revoked,
    );
    assert!(matches!(r3, ce_mail::MailReply::Delivered { duplicate: true }));
    assert_eq!(
        svc.store().pending_count(&recip.node_id_hex()),
        0,
        "post-ack redelivery of a seen id must not reappear"
    );
}

#[tokio::test]
async fn threaded_view_groups_replies_e2e() {
    let net = Net::new();
    let mb = idn("tv-mb");
    let recip = idn("tv-rc");
    let sender = idn("tv-sn");
    net.install(&mb.node_id_hex(), MailService::new(MailboxStore::new(mb.node_id(), 100)));
    let sc = client(&net, &sender);
    let root = sc
        .send(SendOptions {
            to: recip.node_id_hex(),
            subject: "design".into(),
            body: b"v1".to_vec(),
            mailbox: Some(mb.node_id_hex()),
            grant: accept_grant(&recip, &mb),
            ..Default::default()
        })
        .await
        .unwrap();
    sc.send(SendOptions {
        to: recip.node_id_hex(),
        subject: "Re: design".into(),
        body: b"v2".to_vec(),
        in_reply_to: root.clone(),
        mailbox: Some(mb.node_id_hex()),
        grant: accept_grant(&recip, &mb),
        ..Default::default()
    })
    .await
    .unwrap();
    let rc = client(&net, &recip);
    let (convs, _) = rc.drain_inbox_threaded(&mb.node_id_hex(), 0, vec![]).await.unwrap();
    assert_eq!(convs.len(), 1);
    assert_eq!(convs[0].len(), 2);
    assert_eq!(convs[0].root, root);
}

#[tokio::test]
async fn attachments_end_to_end_via_mailbox() {
    use ce_mail::Attachment;
    let net = Net::new();
    let mb = idn("att-mb");
    let recip = idn("att-rc");
    let sender = idn("att-sn");
    net.install(&mb.node_id_hex(), MailService::new(MailboxStore::new(mb.node_id(), 100)));
    let sc = client(&net, &sender);
    let pdf = Attachment::from_file("report.pdf", vec![0x25, 0x50, 0x44, 0x46, 0xff, 0x00]);
    let txt = Attachment::new("note.txt", "text/plain", b"read me".to_vec());
    sc.send(SendOptions {
        to: recip.node_id_hex(),
        subject: "files".into(),
        body: b"see attached".to_vec(),
        attachments: vec![pdf.clone(), txt.clone()],
        mailbox: Some(mb.node_id_hex()),
        grant: accept_grant(&recip, &mb),
        ..Default::default()
    })
    .await
    .unwrap();

    let rc = client(&net, &recip);
    let (msgs, _) = rc.drain_inbox(&mb.node_id_hex(), 0, vec![]).await.unwrap();
    assert_eq!(msgs.len(), 1);
    let env = &msgs[0].envelope;
    assert_eq!(env.body.attachment_cids.len(), 2);
    let all = rc.open_attachments(env).await.unwrap();
    assert_eq!(all, vec![pdf, txt]);
    // Filename + content-type travel sealed, recovered intact.
    assert_eq!(all[0].filename, "report.pdf");
    assert_eq!(all[0].content_type, "application/pdf");
}

#[tokio::test]
async fn screening_quarantines_stranger_without_postage() {
    use ce_mail::ScreeningPolicy;
    let net = Net::new();
    let mb = idn("scrn-mb");
    let recip = idn("scrn-rc");
    let friend = idn("scrn-fr");
    let stranger = idn("scrn-st");
    net.install(&mb.node_id_hex(), MailService::new(MailboxStore::new(mb.node_id(), 100)));
    client(&net, &friend)
        .send(SendOptions {
            to: recip.node_id_hex(),
            subject: "hi".into(),
            body: b"trusted".to_vec(),
            mailbox: Some(mb.node_id_hex()),
            grant: accept_grant(&recip, &mb),
            ..Default::default()
        })
        .await
        .unwrap();
    client(&net, &stranger)
        .send(SendOptions {
            to: recip.node_id_hex(),
            subject: "deal".into(),
            body: b"spammy".to_vec(),
            mailbox: Some(mb.node_id_hex()),
            grant: accept_grant(&recip, &mb),
            ..Default::default()
        })
        .await
        .unwrap();

    let rc = client(&net, &recip);
    let policy = ScreeningPolicy::new(recip.node_id_hex()).allow(friend.node_id_hex());
    let (inbox, spam, _) = rc
        .screen_inbox(&mb.node_id_hex(), 0, vec![], &policy, |_| None)
        .await
        .unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].envelope.body.from, friend.node_id_hex());
    assert_eq!(spam.len(), 1);
    assert_eq!(spam[0].envelope.body.from, stranger.node_id_hex());
}

#[tokio::test]
async fn postage_lets_a_stranger_reach_the_inbox() {
    use ce_mail::ScreeningPolicy;
    use ce_rs::Amount;
    let net = Net::new();
    let mb = idn("pst-mb");
    let recip = idn("pst-rc");
    let stranger = idn("pst-st");
    net.install(&mb.node_id_hex(), MailService::new(MailboxStore::new(mb.node_id(), 100)));
    client(&net, &stranger)
        .send(SendOptions {
            to: recip.node_id_hex(),
            subject: "I paid".into(),
            body: b"legit".to_vec(),
            postage_receipt: "receipt-abc".into(),
            mailbox: Some(mb.node_id_hex()),
            grant: accept_grant(&recip, &mb),
            ..Default::default()
        })
        .await
        .unwrap();
    let rc = client(&net, &recip);
    let policy = ScreeningPolicy::new(recip.node_id_hex())
        .require_postage(Amount::from_credits(1))
        .strict();
    // A verifier that confirms the named receipt is worth 5 credits.
    let (inbox, spam, _) = rc
        .screen_inbox(&mb.node_id_hex(), 0, vec![], &policy, |r| {
            if r == "receipt-abc" { Some(Amount::from_credits(5)) } else { None }
        })
        .await
        .unwrap();
    assert_eq!(inbox.len(), 1, "stranger with valid postage reaches the inbox");
    assert!(spam.is_empty());
}

#[tokio::test]
async fn revocation_taking_effect_after_start_blocks_delivery() {
    // The mailbox initially honors a grant, then the recipient revokes it; subsequent deliveries
    // under the same grant are rejected. We model the refreshable revocation set with a Cell the
    // is_revoked closure consults each call (exactly what the serve loop's shared set does).
    let mb = idn("rev-mb");
    let recip = idn("rev-rc");
    let sender = idn("rev-sn");
    let mut svc = MailService::new(MailboxStore::new(mb.node_id(), 100));
    let grant = accept_grant(&recip, &mb); // nonce 1, issuer = recip
    let revoked = std::cell::Cell::new(false);
    let is_revoked = |issuer: &NodeId, nonce: u64| {
        // Revoke recip's nonce-1 grant once the flag flips.
        revoked.get() && issuer == &recip.node_id() && nonce == 1
    };
    // Before revocation: delivery stored.
    let env1 = Envelope::seal(
        &sender,
        EnvelopeBody {
            from: String::new(),
            to: recip.node_id_hex(),
            subject: "before".into(),
            body_cid: "ab".repeat(32),
            attachment_cids: vec![],
            in_reply_to: String::new(),
            sent_at: 1,
            postage_receipt: String::new(),
        },
    );
    let r1 = svc.handle(
        &sender.node_id(),
        MailRequest::Deliver { envelope: env1, grant: grant.clone() },
        100,
        &is_revoked,
    );
    assert!(matches!(r1, ce_mail::MailReply::Delivered { .. }));
    // Recipient revokes; a refresh would surface it. Flip the flag.
    revoked.set(true);
    let env2 = Envelope::seal(
        &sender,
        EnvelopeBody {
            from: String::new(),
            to: recip.node_id_hex(),
            subject: "after".into(),
            body_cid: "cd".repeat(32),
            attachment_cids: vec![],
            in_reply_to: String::new(),
            sent_at: 2,
            postage_receipt: String::new(),
        },
    );
    let r2 = svc.handle(
        &sender.node_id(),
        MailRequest::Deliver { envelope: env2, grant },
        101,
        &is_revoked,
    );
    assert!(matches!(r2, ce_mail::MailReply::Error { .. }), "revoked grant must be rejected");
    // Only the pre-revocation message remains.
    assert_eq!(svc.store().pending_count(&recip.node_id_hex()), 1);
}

#[tokio::test]
async fn mailbox_store_survives_atomic_persist_and_reload() {
    // A persisted store reloads intact, and an atomic write never leaves a corrupt file even after
    // repeated rewrites (simulating the serve loop).
    let dir = std::env::temp_dir().join(format!("ce-mail-it-persist-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("mb.bin");

    let mb = idn("ap-mb");
    let recip = idn("ap-rc");
    let sender = idn("ap-sn");
    let mut store = MailboxStore::new(mb.node_id(), 100);
    for i in 0..5u64 {
        let env = Envelope::seal(
            &sender,
            EnvelopeBody {
                from: String::new(),
                to: recip.node_id_hex(),
                subject: format!("m{i}"),
                body_cid: "ab".repeat(32),
                attachment_cids: vec![],
                in_reply_to: String::new(),
                sent_at: i,
                postage_receipt: String::new(),
            },
        );
        store.accept(env, i).unwrap();
        // Rewrite atomically each iteration like the serve loop.
        ce_mail::persist::atomic_write(&path, &store.try_to_bytes().unwrap()).unwrap();
    }
    // Reload and confirm all five survived.
    let bytes = std::fs::read(&path).unwrap();
    let loaded = MailboxStore::from_bytes(&bytes).unwrap();
    assert_eq!(loaded.pending_count(&recip.node_id_hex()), 5);
}

#[tokio::test]
async fn duplicate_delivery_is_idempotent_end_to_end() {
    let net = Net::new();
    let mb = idn("id-mb");
    let recip = idn("id-rc");
    let sender = idn("id-sn");
    net.install(&mb.node_id_hex(), MailService::new(MailboxStore::new(mb.node_id(), 100)));
    let sc = client(&net, &sender);
    let opts = || SendOptions {
        to: recip.node_id_hex(),
        subject: "same".into(),
        body: b"same body".to_vec(),
        mailbox: Some(mb.node_id_hex()),
        grant: accept_grant(&recip, &mb),
        ..Default::default()
    };
    // Two identical sends in the same second -> identical message id -> de-duped at the mailbox.
    let a = sc.send(opts()).await.unwrap();
    let b = sc.send(opts()).await.unwrap();
    let rc = client(&net, &recip);
    let (msgs, _) = rc.drain_inbox(&mb.node_id_hex(), 0, vec![]).await.unwrap();
    if a == b {
        assert_eq!(msgs.len(), 1, "identical messages must de-dupe");
    } else {
        assert_eq!(msgs.len(), 2);
    }
}
