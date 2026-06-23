//! The high-level mail client — compose [`ce_rs`] blobs + app-messaging into send/inbox/read.
//!
//! [`MailClient`] is what an app or the CLI uses. It seals the body, stores it as a blob (CID), and
//! delivers a tiny signed envelope over the mesh — directly to the recipient if online, or to a
//! mailbox node for store-and-forward if offline. Draining the inbox pulls envelopes back, fetches
//! the (lazy) bodies, and decrypts them locally.
//!
//! Network access goes through the [`Transport`] trait so the orchestration logic is unit-testable
//! against an in-memory fake (see tests) with no running node. [`CeTransport`] is the real impl over
//! [`ce_rs::CeClient`].

use crate::crypto::{self, SealedBody};
use crate::envelope::{Envelope, EnvelopeBody, parse_node_id};
use crate::proto::{MAIL_TOPIC, MailReply, MailRequest};
use anyhow::{Result, anyhow};
use ce_cap::SignedCapability;
use ce_identity::Identity;
use std::time::{SystemTime, UNIX_EPOCH};

/// Default request timeout for a mesh round-trip (ms).
pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;

/// The network operations ce-mail needs. Implemented by [`CeTransport`] over a real node; mocked in
/// tests. All methods are async and return `anyhow::Result`.
#[allow(async_fn_in_trait)]
pub trait Transport {
    /// Store bytes in the content-addressed blob store; return the CID (sha256 hex).
    async fn put_blob(&self, bytes: Vec<u8>) -> Result<String>;
    /// Fetch a blob by CID.
    async fn get_blob(&self, cid: &str) -> Result<Vec<u8>>;
    /// Send a request to `to` on [`MAIL_TOPIC`], returning the reply bytes.
    async fn request(&self, to: &str, payload: &[u8], timeout_ms: u64) -> Result<Vec<u8>>;
}

/// The real transport over a CE node's HTTP API.
pub struct CeTransport {
    ce: ce_rs::CeClient,
}

impl CeTransport {
    /// Wrap a [`ce_rs::CeClient`].
    pub fn new(ce: ce_rs::CeClient) -> Self {
        CeTransport { ce }
    }
    /// A transport for the local node on the default port.
    pub fn local() -> Self {
        CeTransport { ce: ce_rs::CeClient::local() }
    }
}

impl Transport for CeTransport {
    async fn put_blob(&self, bytes: Vec<u8>) -> Result<String> {
        self.ce.put_blob(bytes).await
    }
    async fn get_blob(&self, cid: &str) -> Result<Vec<u8>> {
        self.ce.get_blob(cid).await
    }
    async fn request(&self, to: &str, payload: &[u8], timeout_ms: u64) -> Result<Vec<u8>> {
        self.ce.request(to, MAIL_TOPIC, payload, timeout_ms).await
    }
}

/// A composed, decrypted message as the inbox returns it.
#[derive(Debug, Clone)]
pub struct Message {
    /// The verified envelope (sender is cryptographically authenticated).
    pub envelope: Envelope,
    /// Decrypted body bytes (empty if the message had no body).
    pub body: Vec<u8>,
}

impl Message {
    /// The message id (content-addressed).
    pub fn id(&self) -> String {
        self.envelope.message_id()
    }
    /// The body as a UTF-8 string (lossy), convenient for text mail.
    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// Parameters for composing and sending a message.
#[derive(Debug, Clone, Default)]
pub struct SendOptions {
    /// Recipient NodeId hex.
    pub to: String,
    /// Cleartext subject.
    pub subject: String,
    /// Plaintext body (sealed E2E to the recipient before storage).
    pub body: Vec<u8>,
    /// The message id this replies to (threading). Empty = new thread.
    pub in_reply_to: String,
    /// Optional postage receipt id.
    pub postage_receipt: String,
    /// If set, deliver to this mailbox node (hex) for store-and-forward, presenting `grant`.
    /// If `None`, deliver directly to the recipient.
    pub mailbox: Option<String>,
    /// Accept-grant chain to present to the mailbox (empty for direct delivery).
    pub grant: Vec<SignedCapability>,
}

/// The high-level mail client, bound to one identity.
pub struct MailClient<T: Transport> {
    identity: Identity,
    transport: T,
    timeout_ms: u64,
}

impl<T: Transport> MailClient<T> {
    /// Build a client from an identity and transport.
    pub fn new(identity: Identity, transport: T) -> Self {
        MailClient { identity, transport, timeout_ms: DEFAULT_TIMEOUT_MS }
    }

    /// Override the per-request timeout (ms).
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// This client's own NodeId hex.
    pub fn node_id_hex(&self) -> String {
        self.identity.node_id_hex()
    }

    /// Seal `body` to `recipient`, store it as a blob, and return the CID. Empty bodies return an
    /// empty CID (no blob stored) so a bodiless ping costs nothing.
    async fn seal_and_store(&self, recipient: &[u8; 32], body: &[u8]) -> Result<String> {
        if body.is_empty() {
            return Ok(String::new());
        }
        let sealed = crypto::seal(recipient, body)?;
        let bytes = crypto::encode_sealed(&sealed);
        self.transport.put_blob(bytes).await
    }

    /// Compose, seal, sign, and deliver a message. Returns the message id on acceptance.
    pub async fn send(&self, opts: SendOptions) -> Result<String> {
        let recipient = parse_node_id(&opts.to)?;
        let body_cid = self.seal_and_store(&recipient, &opts.body).await?;

        let env_body = EnvelopeBody {
            from: String::new(),
            to: opts.to.clone(),
            subject: opts.subject,
            body_cid,
            attachment_cids: vec![],
            in_reply_to: opts.in_reply_to,
            sent_at: now_secs(),
            postage_receipt: opts.postage_receipt,
        };
        let envelope = Envelope::seal(&self.identity, env_body);
        let mid = envelope.message_id();

        // Direct delivery targets the recipient; store-and-forward targets the mailbox.
        let (target, grant) = match &opts.mailbox {
            Some(mb) => (mb.clone(), opts.grant.clone()),
            None => (opts.to.clone(), vec![]),
        };
        let req = MailRequest::Deliver { envelope, grant };
        let reply = self.round_trip(&target, req).await?;
        match reply {
            MailReply::Delivered { .. } => Ok(mid),
            MailReply::Error { message } => Err(anyhow!("delivery rejected: {message}")),
            other => Err(anyhow!("unexpected reply to Deliver: {other:?}")),
        }
    }

    /// Drain the inbox from a mailbox node, returning decrypted messages and the new cursor. Pass
    /// the prior cursor (`0` the first time). `grant` is empty when *you* are the recipient (the
    /// mailbox recognizes the requester == recipient fast path).
    pub async fn drain_inbox(
        &self,
        mailbox: &str,
        since: usize,
        grant: Vec<SignedCapability>,
    ) -> Result<(Vec<Message>, usize)> {
        let req = MailRequest::Drain { recipient: self.node_id_hex(), since, grant };
        let reply = self.round_trip(mailbox, req).await?;
        let (envelopes, cursor) = match reply {
            MailReply::Drained { envelopes, cursor } => (envelopes, cursor),
            MailReply::Error { message } => return Err(anyhow!("drain rejected: {message}")),
            other => return Err(anyhow!("unexpected reply to Drain: {other:?}")),
        };
        let mut out = Vec::with_capacity(envelopes.len());
        for env in envelopes {
            // Skip (don't fail the whole drain on) any single bad envelope: failure isolation.
            if env.verify().is_err() {
                continue;
            }
            let body = self.open_body(&env).await.unwrap_or_default();
            out.push(Message { envelope: env, body });
        }
        Ok((out, cursor))
    }

    /// Acknowledge delivery up to `cursor` at the mailbox, freeing storage.
    pub async fn ack(&self, mailbox: &str, cursor: usize, grant: Vec<SignedCapability>) -> Result<usize> {
        let req = MailRequest::Ack { recipient: self.node_id_hex(), cursor, grant };
        match self.round_trip(mailbox, req).await? {
            MailReply::Acked { removed } => Ok(removed),
            MailReply::Error { message } => Err(anyhow!("ack rejected: {message}")),
            other => Err(anyhow!("unexpected reply to Ack: {other:?}")),
        }
    }

    /// Fetch and decrypt the body of an envelope. Returns empty for a bodiless envelope. Errors if
    /// the blob is missing or decryption fails (wrong recipient / tampered).
    pub async fn open_body(&self, envelope: &Envelope) -> Result<Vec<u8>> {
        if envelope.body.body_cid.is_empty() {
            return Ok(Vec::new());
        }
        let bytes = self.transport.get_blob(&envelope.body.body_cid).await?;
        let sealed: SealedBody = crypto::decode_sealed(&bytes)?;
        crypto::open(&self.identity.secret_bytes(), &sealed)
    }

    /// Send a request and decode the reply.
    async fn round_trip(&self, to: &str, req: MailRequest) -> Result<MailReply> {
        let reply_bytes = self.transport.request(to, &req.encode(), self.timeout_ms).await?;
        MailReply::decode(&reply_bytes)
    }
}

/// Unix seconds now (saturating to 0 before the epoch).
fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mailbox::{ABILITY_ACCEPT, MailboxStore};
    use crate::service::MailService;
    use ce_cap::{Caveats, Resource};
    use ce_identity::{Identity, NodeId};
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    fn id(tag: &str) -> Identity {
        let dir = std::env::temp_dir().join(format!("ce-mail-client-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Identity::load_or_generate(&dir).unwrap()
    }

    fn never_revoked(_: &NodeId, _: u64) -> bool {
        false
    }

    /// An in-memory transport backed by a shared blob store and a routing table of mailbox/recipient
    /// services. Lets us drive the full send→store→drain→decrypt flow with no node.
    #[derive(Clone)]
    struct FakeNet {
        blobs: Rc<RefCell<HashMap<String, Vec<u8>>>>,
        services: Rc<RefCell<HashMap<String, Rc<RefCell<MailService>>>>>,
        /// When set, request() fails (dropped-peer / 5xx injection).
        fail_request: Rc<RefCell<bool>>,
        /// When set, get_blob() fails (missing-blob injection).
        fail_blob: Rc<RefCell<bool>>,
    }

    impl FakeNet {
        fn new() -> Self {
            FakeNet {
                blobs: Rc::new(RefCell::new(HashMap::new())),
                services: Rc::new(RefCell::new(HashMap::new())),
                fail_request: Rc::new(RefCell::new(false)),
                fail_blob: Rc::new(RefCell::new(false)),
            }
        }
        fn install_service(&self, node_hex: &str, svc: MailService) {
            self.services.borrow_mut().insert(node_hex.to_string(), Rc::new(RefCell::new(svc)));
        }
    }

    /// Each MailClient gets a handle that remembers *its own* identity, so request() can pass the
    /// authenticated requester to the service (the node would do this over Noise).
    struct FakeHandle {
        net: FakeNet,
        me: NodeId,
    }

    impl Transport for FakeHandle {
        async fn put_blob(&self, bytes: Vec<u8>) -> Result<String> {
            let cid = ce_rs::cid(&bytes);
            self.net.blobs.borrow_mut().insert(cid.clone(), bytes);
            Ok(cid)
        }
        async fn get_blob(&self, cid: &str) -> Result<Vec<u8>> {
            if *self.net.fail_blob.borrow() {
                return Err(anyhow!("injected blob fetch failure"));
            }
            self.net
                .blobs
                .borrow()
                .get(cid)
                .cloned()
                .ok_or_else(|| anyhow!("blob {cid} not found"))
        }
        async fn request(&self, to: &str, payload: &[u8], _timeout_ms: u64) -> Result<Vec<u8>> {
            if *self.net.fail_request.borrow() {
                return Err(anyhow!("injected request failure (dropped peer)"));
            }
            let svc = self
                .net
                .services
                .borrow()
                .get(to)
                .cloned()
                .ok_or_else(|| anyhow!("no service for {to}"))?;
            let req = MailRequest::decode(payload)?;
            let reply = svc.borrow_mut().handle(&self.me, req, 1000, &never_revoked);
            Ok(reply.encode())
        }
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

    #[tokio::test]
    async fn offline_store_and_forward_replay() {
        // sender -> mailbox (store) ; recipient later drains and decrypts.
        let net = FakeNet::new();
        let mailbox = id("e2e-mb");
        let recipient = id("e2e-rc");
        let sender = id("e2e-sn");

        // Mailbox node runs a service.
        net.install_service(
            &mailbox.node_id_hex(),
            MailService::new(MailboxStore::new(mailbox.node_id(), 100)),
        );

        let sender_client =
            MailClient::new(sender_dup(&sender), FakeHandle { net: net.clone(), me: sender.node_id() });

        let grant = accept_grant(&recipient, &mailbox);
        let mid = sender_client
            .send(SendOptions {
                to: recipient.node_id_hex(),
                subject: "offline hello".into(),
                body: b"see you when you're back online".to_vec(),
                mailbox: Some(mailbox.node_id_hex()),
                grant,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(mid.len(), 64);

        // Recipient comes online and drains.
        let recip_client =
            MailClient::new(sender_dup(&recipient), FakeHandle { net: net.clone(), me: recipient.node_id() });
        let (msgs, cursor) = recip_client.drain_inbox(&mailbox.node_id_hex(), 0, vec![]).await.unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].body_text(), "see you when you're back online");
        assert_eq!(msgs[0].envelope.body.from, sender.node_id_hex());

        // Ack frees the mailbox.
        let removed = recip_client.ack(&mailbox.node_id_hex(), cursor, vec![]).await.unwrap();
        assert_eq!(removed, 1);
        let (after, _) = recip_client.drain_inbox(&mailbox.node_id_hex(), 0, vec![]).await.unwrap();
        assert!(after.is_empty());
    }

    /// Load the same identity bytes into a new Identity instance (tests build several clients on the
    /// same key without sharing ownership).
    fn sender_dup(idn: &Identity) -> Identity {
        let dir = std::env::temp_dir()
            .join(format!("ce-mail-dup-{}-{}", std::process::id(), idn.node_id_hex()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("node.key");
        std::fs::write(&key, idn.secret_bytes()).unwrap();
        Identity::load_or_generate(&dir).unwrap()
    }

    #[tokio::test]
    async fn send_to_unauthorized_mailbox_is_rejected() {
        let net = FakeNet::new();
        let mailbox = id("u-mb");
        let recipient = id("u-rc");
        let sender = id("u-sn");
        net.install_service(
            &mailbox.node_id_hex(),
            MailService::new(MailboxStore::new(mailbox.node_id(), 100)),
        );
        let client =
            MailClient::new(sender_dup(&sender), FakeHandle { net: net.clone(), me: sender.node_id() });
        // No grant presented -> mailbox refuses.
        let r = client
            .send(SendOptions {
                to: recipient.node_id_hex(),
                subject: "spam?".into(),
                body: b"x".to_vec(),
                mailbox: Some(mailbox.node_id_hex()),
                grant: vec![],
                ..Default::default()
            })
            .await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn dropped_peer_send_errors_gracefully() {
        let net = FakeNet::new();
        let mailbox = id("d-mb");
        let recipient = id("d-rc");
        let sender = id("d-sn");
        net.install_service(
            &mailbox.node_id_hex(),
            MailService::new(MailboxStore::new(mailbox.node_id(), 100)),
        );
        *net.fail_request.borrow_mut() = true;
        let client =
            MailClient::new(sender_dup(&sender), FakeHandle { net: net.clone(), me: sender.node_id() });
        let r = client
            .send(SendOptions {
                to: recipient.node_id_hex(),
                subject: "x".into(),
                body: b"x".to_vec(),
                mailbox: Some(mailbox.node_id_hex()),
                grant: accept_grant(&recipient, &mailbox),
                ..Default::default()
            })
            .await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn missing_blob_on_drain_yields_empty_body_not_panic() {
        let net = FakeNet::new();
        let mailbox = id("mb-blob");
        let recipient = id("rc-blob");
        let sender = id("sn-blob");
        net.install_service(
            &mailbox.node_id_hex(),
            MailService::new(MailboxStore::new(mailbox.node_id(), 100)),
        );
        let sclient =
            MailClient::new(sender_dup(&sender), FakeHandle { net: net.clone(), me: sender.node_id() });
        sclient
            .send(SendOptions {
                to: recipient.node_id_hex(),
                subject: "body lost".into(),
                body: b"this body will vanish".to_vec(),
                mailbox: Some(mailbox.node_id_hex()),
                grant: accept_grant(&recipient, &mailbox),
                ..Default::default()
            })
            .await
            .unwrap();
        // Inject blob loss before the recipient fetches.
        *net.fail_blob.borrow_mut() = true;
        let rclient =
            MailClient::new(sender_dup(&recipient), FakeHandle { net: net.clone(), me: recipient.node_id() });
        let (msgs, _) = rclient.drain_inbox(&mailbox.node_id_hex(), 0, vec![]).await.unwrap();
        // Envelope still delivered; body is empty because the blob was unreachable (graceful).
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].body.is_empty());
    }

    #[tokio::test]
    async fn bodiless_ping_stores_no_blob() {
        let net = FakeNet::new();
        let mailbox = id("p-mb");
        let recipient = id("p-rc");
        let sender = id("p-sn");
        net.install_service(
            &mailbox.node_id_hex(),
            MailService::new(MailboxStore::new(mailbox.node_id(), 100)),
        );
        let sclient =
            MailClient::new(sender_dup(&sender), FakeHandle { net: net.clone(), me: sender.node_id() });
        sclient
            .send(SendOptions {
                to: recipient.node_id_hex(),
                subject: "ping".into(),
                body: vec![],
                mailbox: Some(mailbox.node_id_hex()),
                grant: accept_grant(&recipient, &mailbox),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(net.blobs.borrow().is_empty());
        let rclient =
            MailClient::new(sender_dup(&recipient), FakeHandle { net: net.clone(), me: recipient.node_id() });
        let (msgs, _) = rclient.drain_inbox(&mailbox.node_id_hex(), 0, vec![]).await.unwrap();
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].body.is_empty());
    }
}
