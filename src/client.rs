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

use crate::attachment::Attachment;
use crate::crypto::{self, SealedBody};
use crate::envelope::{Envelope, EnvelopeBody, parse_node_id};
use crate::limits::Limits;
use crate::proto::{MAIL_TOPIC, MailReply, MailRequest};
use crate::receipt::{Receipt, ReceiptKind};
use crate::thread::{Conversation, group_threads};
use anyhow::{Result, anyhow};
use ce_iam_core::SignedCapability;
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
    /// The reputation standing of `node_hex` from on-chain history, for screening. The default
    /// treats everyone as a newcomer (no history backend); [`CeTransport`] consults
    /// `GET /history/:node_id`.
    async fn sender_standing(&self, _node_hex: &str) -> Result<crate::screening::SenderStanding> {
        Ok(crate::screening::SenderStanding::Newcomer)
    }
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
    async fn sender_standing(&self, node_hex: &str) -> Result<crate::screening::SenderStanding> {
        // A node with no recorded history (or a lookup failure) is treated as a newcomer — the
        // cautious default, never an over-trust.
        match self.ce.history(node_hex).await {
            Ok(h) => Ok(crate::screening::standing_from_history(&h)),
            Err(_) => Ok(crate::screening::SenderStanding::Newcomer),
        }
    }
}

/// Marks a sealed body blob whose plaintext is a structured [`BodyContent`] (sealed subject) rather
/// than a raw body. The first plaintext byte after decryption selects the format; any other value is
/// a legacy raw body. `0xC5` ("CE") was chosen to be an unlikely first byte of UTF-8 text.
const BODY_CONTENT_MAGIC: u8 = 0xC5;

/// The structured plaintext sealed into a body blob when subject confidentiality is requested. The
/// envelope's cleartext `subject` then carries only a redaction placeholder; the real subject lives
/// here, sealed E2E like the body. Recovered by [`MailClient::open_message`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct BodyContent {
    /// The confidential subject (empty if none was sealed).
    subject: String,
    /// The message body bytes.
    body: Vec<u8>,
}

impl BodyContent {
    /// Encode to the sealed-blob plaintext: a magic byte then bincode. Infallible in practice.
    fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.body.len() + self.subject.len() + 16);
        out.push(BODY_CONTENT_MAGIC);
        out.extend_from_slice(
            &bincode::serialize(self).map_err(|e| anyhow!("encode body content: {e}"))?,
        );
        Ok(out)
    }

    /// Try to decode structured content from decrypted body bytes. Returns `None` for a legacy raw
    /// body (no magic), so callers can fall back to treating the bytes as the body verbatim.
    fn try_decode(plaintext: &[u8]) -> Option<BodyContent> {
        match plaintext.split_first() {
            Some((&BODY_CONTENT_MAGIC, rest)) => bincode::deserialize(rest).ok(),
            _ => None,
        }
    }
}

/// The placeholder a sealed-subject envelope shows in its cleartext `subject` field. A mailbox /
/// observer sees only this, never the real subject.
pub const REDACTED_SUBJECT: &str = "(encrypted subject)";

/// A composed, decrypted message as the inbox returns it.
#[derive(Debug, Clone)]
pub struct Message {
    /// The verified envelope (sender is cryptographically authenticated).
    pub envelope: Envelope,
    /// Decrypted body bytes (empty if the message had no body).
    pub body: Vec<u8>,
    /// The recovered confidential subject, if the sender sealed one (else `None`; the cleartext
    /// `envelope.body.subject` is then the real subject).
    pub sealed_subject: Option<String>,
}

impl Message {
    /// The best-known subject: the sealed subject if present, else the cleartext envelope subject.
    pub fn subject(&self) -> String {
        self.sealed_subject
            .clone()
            .unwrap_or_else(|| self.envelope.body.subject.clone())
    }

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
    /// Attachments, each sealed E2E to the recipient and stored as a lazily-fetched blob. The
    /// envelope carries only their CIDs; the recipient recovers them with
    /// [`MailClient::open_attachment`] / [`MailClient::open_attachments`].
    pub attachments: Vec<Attachment>,
    /// The message id this replies to (threading). Empty = new thread.
    pub in_reply_to: String,
    /// When true, the subject is sealed E2E (into the body blob) and the envelope's cleartext
    /// `subject` carries only [`REDACTED_SUBJECT`]; a mailbox/observer never learns it. The recipient
    /// recovers it via [`Message::subject`]. Requires a recipient who can decrypt — use only for
    /// CE-native mail, not for the (cleartext) SMTP bridge.
    pub seal_subject: bool,
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
    limits: Limits,
}

impl<T: Transport> MailClient<T> {
    /// Build a client from an identity and transport.
    pub fn new(identity: Identity, transport: T) -> Self {
        MailClient {
            identity,
            transport,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            limits: Limits::default(),
        }
    }

    /// Override the per-request timeout (ms).
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Override the client-side resource [`Limits`] (body/attachment size caps enforced on send).
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
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
        let bytes = crypto::try_encode_sealed(&sealed)?;
        self.transport.put_blob(bytes).await
    }

    /// Compose, seal, sign, and deliver a message. Returns the message id on acceptance.
    ///
    /// The body and each attachment are sealed E2E to the recipient and stored as content-addressed
    /// blobs; the signed envelope carries only their CIDs. Body and attachment sizes are bounded by
    /// the client [`Limits`] so a caller cannot accidentally try to ship a 2 GB payload.
    pub async fn send(&self, opts: SendOptions) -> Result<String> {
        let recipient = parse_node_id(&opts.to)?;

        // Enforce client-side payload bounds before doing any (potentially large) work.
        if opts.body.len() > self.limits.max_body_bytes {
            return Err(anyhow!(
                "body too large: {} > {} bytes",
                opts.body.len(),
                self.limits.max_body_bytes
            ));
        }
        if opts.attachments.len() > self.limits.max_attachments {
            return Err(anyhow!(
                "too many attachments: {} > {}",
                opts.attachments.len(),
                self.limits.max_attachments
            ));
        }
        for a in &opts.attachments {
            if a.bytes.len() > self.limits.max_attachment_bytes {
                return Err(anyhow!(
                    "attachment {:?} too large: {} > {} bytes",
                    a.filename,
                    a.bytes.len(),
                    self.limits.max_attachment_bytes
                ));
            }
        }

        // Body: a sealed structured BodyContent when the subject is to be sealed too, otherwise the
        // raw sealed body (or no blob for a bodiless ping).
        let (body_cid, cleartext_subject) = if opts.seal_subject {
            let content = BodyContent { subject: opts.subject.clone(), body: opts.body.clone() };
            let plaintext = content.encode()?;
            let sealed = crypto::seal(&recipient, &plaintext)?;
            let bytes = crypto::try_encode_sealed(&sealed)?;
            let cid = self.transport.put_blob(bytes).await?;
            (cid, REDACTED_SUBJECT.to_string())
        } else {
            (self.seal_and_store(&recipient, &opts.body).await?, opts.subject.clone())
        };

        // Seal + store each attachment, collecting CIDs in order.
        let mut attachment_cids = Vec::with_capacity(opts.attachments.len());
        for a in &opts.attachments {
            let plaintext = a.encode()?;
            let sealed = crypto::seal(&recipient, &plaintext)?;
            let bytes = crypto::try_encode_sealed(&sealed)?;
            let cid = self.transport.put_blob(bytes).await?;
            attachment_cids.push(cid);
        }

        let env_body = EnvelopeBody {
            from: String::new(),
            to: opts.to.clone(),
            subject: cleartext_subject,
            body_cid,
            attachment_cids,
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
        let out = self.compose_messages(envelopes).await;
        Ok((out, cursor))
    }

    /// Drain a bounded *page* of the inbox: at most `limit` decrypted messages from cursor `since`.
    /// Returns `(messages, next_cursor, more)`. Use this to page through a large inbox instead of
    /// pulling everything in one round-trip.
    pub async fn drain_inbox_page(
        &self,
        mailbox: &str,
        since: usize,
        limit: usize,
        grant: Vec<SignedCapability>,
    ) -> Result<(Vec<Message>, usize, bool)> {
        let req =
            MailRequest::DrainPage { recipient: self.node_id_hex(), since, limit, grant };
        let reply = self.round_trip(mailbox, req).await?;
        let (envelopes, cursor, more) = match reply {
            MailReply::Page { envelopes, cursor, more } => (envelopes, cursor, more),
            MailReply::Error { message } => return Err(anyhow!("drain page rejected: {message}")),
            other => return Err(anyhow!("unexpected reply to DrainPage: {other:?}")),
        };
        let messages = self.compose_messages(envelopes).await;
        Ok((messages, cursor, more))
    }

    /// Drain the whole inbox and group it into [`Conversation`]s (threaded view). A convenience over
    /// [`drain_inbox`](Self::drain_inbox) + [`group_threads`].
    pub async fn drain_inbox_threaded(
        &self,
        mailbox: &str,
        since: usize,
        grant: Vec<SignedCapability>,
    ) -> Result<(Vec<Conversation>, usize)> {
        let (msgs, cursor) = self.drain_inbox(mailbox, since, grant).await?;
        let envelopes: Vec<Envelope> = msgs.into_iter().map(|m| m.envelope).collect();
        Ok((group_threads(&envelopes), cursor))
    }

    /// Drain the inbox, then split it into delivered (inbox) and quarantined (spam) messages using a
    /// recipient [`crate::screening::ScreeningPolicy`]. Rejected messages are dropped. `verify_postage`
    /// confirms a stranger's postage receipt (return `None` to treat all postage as absent, e.g. when
    /// channel verification is not wired). Sender standing is fetched from on-chain history via the
    /// transport. Returns `(inbox, spam, cursor)`.
    pub async fn screen_inbox(
        &self,
        mailbox: &str,
        since: usize,
        grant: Vec<SignedCapability>,
        policy: &crate::screening::ScreeningPolicy,
        verify_postage: impl Fn(&str) -> Option<ce_rs::Amount>,
    ) -> Result<(Vec<Message>, Vec<Message>, usize)> {
        use crate::screening::Verdict;
        let (msgs, cursor) = self.drain_inbox(mailbox, since, grant).await?;
        let mut inbox = Vec::new();
        let mut spam = Vec::new();
        for m in msgs {
            // Standing lookup failures degrade to "newcomer" (the cautious default).
            let standing = self
                .transport
                .sender_standing(&m.envelope.body.from)
                .await
                .unwrap_or(crate::screening::SenderStanding::Newcomer);
            match policy.screen(&m.envelope, standing, &verify_postage) {
                Verdict::Inbox { .. } => inbox.push(m),
                Verdict::Spam => spam.push(m),
                Verdict::Rejected => {}
            }
        }
        Ok((inbox, spam, cursor))
    }

    /// Verify, fetch, and decrypt a batch of envelopes into [`Message`]s, skipping any single bad
    /// envelope (failure isolation) and tolerating missing bodies.
    async fn compose_messages(&self, envelopes: Vec<Envelope>) -> Vec<Message> {
        let mut out = Vec::with_capacity(envelopes.len());
        for env in envelopes {
            if env.verify().is_err() {
                continue;
            }
            let (body, sealed_subject) = self.open_content(&env).await.unwrap_or_default();
            out.push(Message { envelope: env, body, sealed_subject });
        }
        out
    }

    /// Fetch + decrypt the body blob, splitting it into `(body, sealed_subject)`. A structured
    /// (sealed-subject) blob yields the recovered subject; a raw body yields `None`. A bodiless or
    /// unreachable blob yields empty body and `None`.
    async fn open_content(&self, env: &Envelope) -> Result<(Vec<u8>, Option<String>)> {
        if env.body.body_cid.is_empty() {
            return Ok((Vec::new(), None));
        }
        let bytes = self.transport.get_blob(&env.body.body_cid).await?;
        let sealed: SealedBody = crypto::decode_sealed(&bytes)?;
        let plaintext = crypto::open(&self.identity.secret_bytes(), &sealed)?;
        match BodyContent::try_decode(&plaintext) {
            Some(content) => Ok((content.body, Some(content.subject))),
            None => Ok((plaintext, None)),
        }
    }

    /// Issue a signed [`Receipt`] for `message_id` and deposit it at `mailbox` for `for_sender` to
    /// collect. `kind` distinguishes a delivery acknowledgement from a read acknowledgement. The
    /// receipt is signed by *this* client, so the sender can verify who acknowledged.
    pub async fn send_receipt(
        &self,
        mailbox: &str,
        for_sender: &str,
        message_id: &str,
        kind: ReceiptKind,
        grant: Vec<SignedCapability>,
    ) -> Result<bool> {
        let receipt = Receipt::issue(&self.identity, message_id, kind, now_secs());
        let req = MailRequest::PutReceipt { for_sender: for_sender.to_string(), receipt, grant };
        match self.round_trip(mailbox, req).await? {
            MailReply::ReceiptAccepted { duplicate } => Ok(duplicate),
            MailReply::Error { message } => Err(anyhow!("receipt rejected: {message}")),
            other => Err(anyhow!("unexpected reply to PutReceipt: {other:?}")),
        }
    }

    /// Collect receipts addressed to *this* client from `mailbox`. Returns only receipts whose
    /// signature verifies (a malicious mailbox cannot inject forged acknowledgements). `grant` is
    /// empty when you are the sender (fast path).
    pub async fn collect_receipts(
        &self,
        mailbox: &str,
        grant: Vec<SignedCapability>,
    ) -> Result<Vec<Receipt>> {
        let req = MailRequest::CollectReceipts { sender: self.node_id_hex(), grant };
        match self.round_trip(mailbox, req).await? {
            MailReply::Receipts { receipts } => {
                Ok(receipts.into_iter().filter(|r| r.verify().is_ok()).collect())
            }
            MailReply::Error { message } => Err(anyhow!("collect rejected: {message}")),
            other => Err(anyhow!("unexpected reply to CollectReceipts: {other:?}")),
        }
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
    /// the blob is missing or decryption fails (wrong recipient / tampered). If the sender sealed the
    /// subject too, this returns just the body bytes (the subject is recovered via
    /// [`open_message`](Self::open_message) / [`Message::subject`]).
    pub async fn open_body(&self, envelope: &Envelope) -> Result<Vec<u8>> {
        Ok(self.open_content(envelope).await?.0)
    }

    /// Fetch + decrypt an envelope into a full [`Message`] (body + recovered sealed subject). The
    /// envelope is assumed already signature-verified by the caller.
    pub async fn open_message(&self, envelope: &Envelope) -> Result<Message> {
        let (body, sealed_subject) = self.open_content(envelope).await?;
        Ok(Message { envelope: envelope.clone(), body, sealed_subject })
    }

    /// Lazily fetch and decrypt one attachment by index. The blob is downloaded only here — the
    /// envelope alone never carries attachment bytes — so a 40 MB file costs nothing until opened.
    /// Errors if the index is out of range, the blob is missing, or decryption fails.
    pub async fn open_attachment(&self, envelope: &Envelope, index: usize) -> Result<Attachment> {
        let cid = envelope
            .body
            .attachment_cids
            .get(index)
            .ok_or_else(|| anyhow!("attachment index {index} out of range"))?;
        if cid.is_empty() {
            return Err(anyhow!("attachment {index} has no CID"));
        }
        let bytes = self.transport.get_blob(cid).await?;
        let sealed: SealedBody = crypto::decode_sealed(&bytes)?;
        let plaintext = crypto::open(&self.identity.secret_bytes(), &sealed)?;
        Attachment::decode(&plaintext)
    }

    /// Fetch and decrypt every attachment in order. Returns an error if *any* attachment fails to
    /// open (use [`open_attachment`](Self::open_attachment) per-index for partial tolerance).
    pub async fn open_attachments(&self, envelope: &Envelope) -> Result<Vec<Attachment>> {
        let mut out = Vec::with_capacity(envelope.body.attachment_cids.len());
        for i in 0..envelope.body.attachment_cids.len() {
            out.push(self.open_attachment(envelope, i).await?);
        }
        Ok(out)
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
    use ce_iam_core::{Caveats, Resource};
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
    async fn paginated_drain_covers_all_messages() {
        let net = FakeNet::new();
        let mailbox = id("pg-mb");
        let recipient = id("pg-rc");
        let sender = id("pg-sn");
        net.install_service(
            &mailbox.node_id_hex(),
            MailService::new(MailboxStore::new(mailbox.node_id(), 100)),
        );
        let sclient =
            MailClient::new(sender_dup(&sender), FakeHandle { net: net.clone(), me: sender.node_id() });
        for i in 0..5 {
            sclient
                .send(SendOptions {
                    to: recipient.node_id_hex(),
                    subject: format!("p{i}"),
                    body: format!("b{i}").into_bytes(),
                    mailbox: Some(mailbox.node_id_hex()),
                    grant: accept_grant(&recipient, &mailbox),
                    ..Default::default()
                })
                .await
                .unwrap();
        }
        let rclient = MailClient::new(
            sender_dup(&recipient),
            FakeHandle { net: net.clone(), me: recipient.node_id() },
        );
        let mut cursor = 0;
        let mut bodies = Vec::new();
        loop {
            let (msgs, next, more) =
                rclient.drain_inbox_page(&mailbox.node_id_hex(), cursor, 2, vec![]).await.unwrap();
            assert!(msgs.len() <= 2);
            for m in msgs {
                bodies.push(m.body_text());
            }
            cursor = next;
            if !more {
                break;
            }
        }
        assert_eq!(bodies, (0..5).map(|i| format!("b{i}")).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn read_receipt_round_trip() {
        // Recipient drains, sends a read receipt; the sender collects and verifies it.
        let net = FakeNet::new();
        let mailbox = id("rcpt-mb");
        let recipient = id("rcpt-rc");
        let sender = id("rcpt-sn");
        net.install_service(
            &mailbox.node_id_hex(),
            MailService::new(MailboxStore::new(mailbox.node_id(), 100)),
        );
        let sclient =
            MailClient::new(sender_dup(&sender), FakeHandle { net: net.clone(), me: sender.node_id() });
        let mid = sclient
            .send(SendOptions {
                to: recipient.node_id_hex(),
                subject: "please ack".into(),
                body: b"read me".to_vec(),
                mailbox: Some(mailbox.node_id_hex()),
                grant: accept_grant(&recipient, &mailbox),
                ..Default::default()
            })
            .await
            .unwrap();

        let rclient = MailClient::new(
            sender_dup(&recipient),
            FakeHandle { net: net.clone(), me: recipient.node_id() },
        );
        let (msgs, _) = rclient.drain_inbox(&mailbox.node_id_hex(), 0, vec![]).await.unwrap();
        assert_eq!(msgs.len(), 1);
        // The recipient deposits a read receipt for the sender (sender delegated this mailbox).
        let dup = rclient
            .send_receipt(
                &mailbox.node_id_hex(),
                &sender.node_id_hex(),
                &msgs[0].id(),
                ReceiptKind::Read,
                accept_grant(&sender, &mailbox),
            )
            .await
            .unwrap();
        assert!(!dup);

        // The sender collects the receipt.
        let receipts = sclient.collect_receipts(&mailbox.node_id_hex(), vec![]).await.unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].body.message_id, mid);
        assert_eq!(receipts[0].body.by, recipient.node_id_hex());
        assert_eq!(receipts[0].body.kind, ReceiptKind::Read);
        assert!(receipts[0].verify().is_ok());
    }

    #[tokio::test]
    async fn duplicate_receipt_deposit_reports_duplicate() {
        let net = FakeNet::new();
        let mailbox = id("dr-mb");
        let recipient = id("dr-rc");
        let sender = id("dr-sn");
        net.install_service(
            &mailbox.node_id_hex(),
            MailService::new(MailboxStore::new(mailbox.node_id(), 100)),
        );
        let rclient = MailClient::new(
            sender_dup(&recipient),
            FakeHandle { net: net.clone(), me: recipient.node_id() },
        );
        let mid = "ab".repeat(32);
        let first = rclient
            .send_receipt(
                &mailbox.node_id_hex(),
                &sender.node_id_hex(),
                &mid,
                ReceiptKind::Delivered,
                accept_grant(&sender, &mailbox),
            )
            .await
            .unwrap();
        assert!(!first);
        let second = rclient
            .send_receipt(
                &mailbox.node_id_hex(),
                &sender.node_id_hex(),
                &mid,
                ReceiptKind::Delivered,
                accept_grant(&sender, &mailbox),
            )
            .await
            .unwrap();
        assert!(second, "second identical receipt deposit must be a duplicate");
    }

    #[tokio::test]
    async fn threaded_drain_groups_conversation() {
        let net = FakeNet::new();
        let mailbox = id("td-mb");
        let recipient = id("td-rc");
        let sender = id("td-sn");
        net.install_service(
            &mailbox.node_id_hex(),
            MailService::new(MailboxStore::new(mailbox.node_id(), 100)),
        );
        let sclient =
            MailClient::new(sender_dup(&sender), FakeHandle { net: net.clone(), me: sender.node_id() });
        // Root message.
        let root = sclient
            .send(SendOptions {
                to: recipient.node_id_hex(),
                subject: "topic".into(),
                body: b"start".to_vec(),
                mailbox: Some(mailbox.node_id_hex()),
                grant: accept_grant(&recipient, &mailbox),
                ..Default::default()
            })
            .await
            .unwrap();
        // A reply on the same thread, plus an unrelated message.
        sclient
            .send(SendOptions {
                to: recipient.node_id_hex(),
                subject: "Re: topic".into(),
                body: b"continued".to_vec(),
                in_reply_to: root.clone(),
                mailbox: Some(mailbox.node_id_hex()),
                grant: accept_grant(&recipient, &mailbox),
                ..Default::default()
            })
            .await
            .unwrap();
        sclient
            .send(SendOptions {
                to: recipient.node_id_hex(),
                subject: "unrelated".into(),
                body: b"other".to_vec(),
                mailbox: Some(mailbox.node_id_hex()),
                grant: accept_grant(&recipient, &mailbox),
                ..Default::default()
            })
            .await
            .unwrap();

        let rclient = MailClient::new(
            sender_dup(&recipient),
            FakeHandle { net: net.clone(), me: recipient.node_id() },
        );
        let (convs, _) = rclient.drain_inbox_threaded(&mailbox.node_id_hex(), 0, vec![]).await.unwrap();
        assert_eq!(convs.len(), 2);
        let topic = convs.iter().find(|c| c.root == root).unwrap();
        assert_eq!(topic.len(), 2);
    }

    #[tokio::test]
    async fn attachments_round_trip_e2e() {
        use crate::attachment::Attachment;
        let net = FakeNet::new();
        let mailbox = id("att-mb");
        let recipient = id("att-rc");
        let sender = id("att-sn");
        net.install_service(
            &mailbox.node_id_hex(),
            MailService::new(MailboxStore::new(mailbox.node_id(), 100)),
        );
        let sclient =
            MailClient::new(sender_dup(&sender), FakeHandle { net: net.clone(), me: sender.node_id() });
        let a1 = Attachment::new("notes.txt", "text/plain", b"hello attachment".to_vec());
        let a2 = Attachment::from_file("data.bin", vec![0u8, 1, 2, 3, 255]);
        sclient
            .send(SendOptions {
                to: recipient.node_id_hex(),
                subject: "with files".into(),
                body: b"see attached".to_vec(),
                attachments: vec![a1.clone(), a2.clone()],
                mailbox: Some(mailbox.node_id_hex()),
                grant: accept_grant(&recipient, &mailbox),
                ..Default::default()
            })
            .await
            .unwrap();

        let rclient = MailClient::new(
            sender_dup(&recipient),
            FakeHandle { net: net.clone(), me: recipient.node_id() },
        );
        let (msgs, _) = rclient.drain_inbox(&mailbox.node_id_hex(), 0, vec![]).await.unwrap();
        assert_eq!(msgs.len(), 1);
        let env = &msgs[0].envelope;
        assert_eq!(env.attachment_count(), 2);
        // Body separate from attachments.
        assert_eq!(msgs[0].body_text(), "see attached");
        // Lazily open each attachment.
        let got1 = rclient.open_attachment(env, 0).await.unwrap();
        let got2 = rclient.open_attachment(env, 1).await.unwrap();
        assert_eq!(got1, a1);
        assert_eq!(got2, a2);
        // open_attachments fetches all.
        let all = rclient.open_attachments(env).await.unwrap();
        assert_eq!(all, vec![a1, a2]);
        // Out-of-range index errors gracefully.
        assert!(rclient.open_attachment(env, 9).await.is_err());
    }

    #[tokio::test]
    async fn attachment_plaintext_never_in_stored_blob() {
        use crate::attachment::Attachment;
        let net = FakeNet::new();
        let mailbox = id("att-sec-mb");
        let recipient = id("att-sec-rc");
        let sender = id("att-sec-sn");
        net.install_service(
            &mailbox.node_id_hex(),
            MailService::new(MailboxStore::new(mailbox.node_id(), 100)),
        );
        let sclient =
            MailClient::new(sender_dup(&sender), FakeHandle { net: net.clone(), me: sender.node_id() });
        let secret = b"confidential-attachment-marker-9f3a";
        sclient
            .send(SendOptions {
                to: recipient.node_id_hex(),
                subject: "sealed file".into(),
                attachments: vec![Attachment::new("s.bin", "application/octet-stream", secret.to_vec())],
                mailbox: Some(mailbox.node_id_hex()),
                grant: accept_grant(&recipient, &mailbox),
                ..Default::default()
            })
            .await
            .unwrap();
        let leaked = net
            .blobs
            .borrow()
            .values()
            .any(|b| b.windows(secret.len()).any(|w| w == secret));
        assert!(!leaked, "attachment plaintext leaked into a stored blob");
        // An attacker cannot open it.
        let attacker = id("att-sec-x");
        let aclient =
            MailClient::new(sender_dup(&attacker), FakeHandle { net: net.clone(), me: attacker.node_id() });
        let rclient = MailClient::new(
            sender_dup(&recipient),
            FakeHandle { net: net.clone(), me: recipient.node_id() },
        );
        let (msgs, _) = rclient.drain_inbox(&mailbox.node_id_hex(), 0, vec![]).await.unwrap();
        assert!(aclient.open_attachment(&msgs[0].envelope, 0).await.is_err());
    }

    #[tokio::test]
    async fn oversized_body_send_is_rejected() {
        let net = FakeNet::new();
        let recipient = id("ob-rc");
        let sender = id("ob-sn");
        let client = MailClient::new(
            sender_dup(&sender),
            FakeHandle { net: net.clone(), me: sender.node_id() },
        )
        .with_limits(crate::limits::Limits { max_body_bytes: 8, ..Default::default() });
        let r = client
            .send(SendOptions {
                to: recipient.node_id_hex(),
                subject: "big".into(),
                body: vec![0u8; 100],
                ..Default::default()
            })
            .await;
        assert!(r.is_err());
        // Nothing was stored because the size check ran before any blob put.
        assert!(net.blobs.borrow().is_empty());
    }

    #[tokio::test]
    async fn sealed_subject_is_confidential_and_recovered() {
        let net = FakeNet::new();
        let mailbox = id("ss-mb");
        let recipient = id("ss-rc");
        let sender = id("ss-sn");
        net.install_service(
            &mailbox.node_id_hex(),
            MailService::new(MailboxStore::new(mailbox.node_id(), 100)),
        );
        let sclient =
            MailClient::new(sender_dup(&sender), FakeHandle { net: net.clone(), me: sender.node_id() });
        let real_subject = "Acquisition terms — confidential";
        sclient
            .send(SendOptions {
                to: recipient.node_id_hex(),
                subject: real_subject.into(),
                body: b"the body".to_vec(),
                seal_subject: true,
                mailbox: Some(mailbox.node_id_hex()),
                grant: accept_grant(&recipient, &mailbox),
                ..Default::default()
            })
            .await
            .unwrap();

        // The envelope's cleartext subject is redacted — a mailbox/observer never sees the real one.
        let rclient = MailClient::new(
            sender_dup(&recipient),
            FakeHandle { net: net.clone(), me: recipient.node_id() },
        );
        let (msgs, _) = rclient.drain_inbox(&mailbox.node_id_hex(), 0, vec![]).await.unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].envelope.body.subject, REDACTED_SUBJECT);
        // The recipient recovers the real subject and the body.
        assert_eq!(msgs[0].subject(), real_subject);
        assert_eq!(msgs[0].body_text(), "the body");
        // The real subject never appears in any stored blob in cleartext.
        let leaked = net
            .blobs
            .borrow()
            .values()
            .any(|b| b.windows(real_subject.len()).any(|w| w == real_subject.as_bytes()));
        assert!(!leaked, "sealed subject leaked into a stored blob");
    }

    #[tokio::test]
    async fn unsealed_subject_is_plain_and_default_path_unchanged() {
        // Regression: when seal_subject is false (the default), Message::subject == cleartext subject
        // and sealed_subject is None.
        let net = FakeNet::new();
        let mailbox = id("us-mb");
        let recipient = id("us-rc");
        let sender = id("us-sn");
        net.install_service(
            &mailbox.node_id_hex(),
            MailService::new(MailboxStore::new(mailbox.node_id(), 100)),
        );
        let sclient =
            MailClient::new(sender_dup(&sender), FakeHandle { net: net.clone(), me: sender.node_id() });
        sclient
            .send(SendOptions {
                to: recipient.node_id_hex(),
                subject: "plain subject".into(),
                body: b"hi".to_vec(),
                mailbox: Some(mailbox.node_id_hex()),
                grant: accept_grant(&recipient, &mailbox),
                ..Default::default()
            })
            .await
            .unwrap();
        let rclient = MailClient::new(
            sender_dup(&recipient),
            FakeHandle { net: net.clone(), me: recipient.node_id() },
        );
        let (msgs, _) = rclient.drain_inbox(&mailbox.node_id_hex(), 0, vec![]).await.unwrap();
        assert_eq!(msgs[0].envelope.body.subject, "plain subject");
        assert_eq!(msgs[0].subject(), "plain subject");
        assert!(msgs[0].sealed_subject.is_none());
    }

    #[tokio::test]
    async fn screen_inbox_separates_contact_from_stranger() {
        use crate::screening::ScreeningPolicy;
        let net = FakeNet::new();
        let mailbox = id("sc-mb");
        let recipient = id("sc-rc");
        let friend = id("sc-fr");
        let stranger = id("sc-st");
        net.install_service(
            &mailbox.node_id_hex(),
            MailService::new(MailboxStore::new(mailbox.node_id(), 100)),
        );
        // Friend sends.
        let fclient =
            MailClient::new(sender_dup(&friend), FakeHandle { net: net.clone(), me: friend.node_id() });
        fclient
            .send(SendOptions {
                to: recipient.node_id_hex(),
                subject: "hi from friend".into(),
                body: b"trusted".to_vec(),
                mailbox: Some(mailbox.node_id_hex()),
                grant: accept_grant(&recipient, &mailbox),
                ..Default::default()
            })
            .await
            .unwrap();
        // Stranger sends with no postage.
        let stclient = MailClient::new(
            sender_dup(&stranger),
            FakeHandle { net: net.clone(), me: stranger.node_id() },
        );
        stclient
            .send(SendOptions {
                to: recipient.node_id_hex(),
                subject: "buy now".into(),
                body: b"spam".to_vec(),
                mailbox: Some(mailbox.node_id_hex()),
                grant: accept_grant(&recipient, &mailbox),
                ..Default::default()
            })
            .await
            .unwrap();

        let rclient = MailClient::new(
            sender_dup(&recipient),
            FakeHandle { net: net.clone(), me: recipient.node_id() },
        );
        let policy = ScreeningPolicy::new(recipient.node_id_hex()).allow(friend.node_id_hex());
        let (inbox, spam, _) = rclient
            .screen_inbox(&mailbox.node_id_hex(), 0, vec![], &policy, |_| None)
            .await
            .unwrap();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].envelope.body.from, friend.node_id_hex());
        assert_eq!(spam.len(), 1);
        assert_eq!(spam[0].envelope.body.from, stranger.node_id_hex());
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
