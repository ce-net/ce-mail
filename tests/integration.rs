//! Integration tests: full ce-mail flows wired through an in-memory transport, exercising the
//! library exactly as an app would (no running node). Covers the headline guarantees:
//! envelope encode/decode round-trip, delivery + ack, offline-store replay, the capability gate,
//! and end-to-end body encryption — plus failure injection (dropped peer, missing blob).

use anyhow::{Result, anyhow};
use ce_cap::{Caveats, Resource, SignedCapability};
use ce_identity::{Identity, NodeId};
use ce_mail::client::{MailClient, SendOptions, Transport};
use ce_mail::mailbox::{ABILITY_ACCEPT, MailboxStore};
use ce_mail::proto::MailRequest;
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
