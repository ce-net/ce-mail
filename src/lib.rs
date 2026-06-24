//! # ce-mail — decentralized, identity-native email/messaging over the CE mesh
//!
//! ce-mail is store-and-forward messaging between CE identities. An address **is** a `NodeId`
//! (Ed25519 public key) — so every message is cryptographically signed by its sender (no spoofing,
//! no SPF/DKIM) and every body is end-to-end encrypted to the recipient (the host that stores or
//! relays it never sees plaintext). It is an *app* over the CE SDK, composing existing primitives —
//! it adds **no node endpoints**:
//!
//! | ce-mail need | CE primitive |
//! |---|---|
//! | address + free auth | [`ce_identity`] NodeId + Ed25519 signatures |
//! | message body / attachments | [`ce_rs`] content-addressed blobs (sealed, fetched lazily by CID) |
//! | delivery envelope on the wire | [`ce_rs`] app-messaging (`request`/`reply` over `/ce/rpc/1`) |
//! | store-and-forward for offline recipients | a mailbox node ([`mailbox`]) holding signed envelopes |
//! | who may accept/drain mail | [`ce_cap`] capability chains ([`mailbox::ABILITY_ACCEPT`]) |
//! | postage / spam economics | payment-channel receipts verified by recipient [`screening`] policy |
//!
//! ## Pieces
//!
//! * [`crypto`] — Ed25519→X25519 sealed-box E2E body encryption.
//! * [`envelope`] — the small signed envelope (metadata + body CID); encode/verify.
//! * [`attachment`] — sealed, content-addressed file payloads ([`Attachment`]) fetched lazily by CID.
//! * [`thread`] — conversation modeling: `in_reply_to` chain resolution, subject normalization,
//!   grouping a flat inbox into ordered [`thread::Conversation`]s.
//! * [`receipt`] — signed delivery/read receipts the sender can verify and collect.
//! * [`screening`] — recipient-side anti-spam: allowlists/contacts + refundable-postage +
//!   reputation gradient, classifying inbound mail into inbox/spam/rejected ([`ScreeningPolicy`]).
//! * [`limits`] — the resource bounds ([`Limits`]) every mailbox enforces (DoS / amplification guard).
//! * [`proto`] — the mesh request/reply protocol (`Deliver`/`Drain`/`DrainPage`/`Ack`/receipts).
//! * [`mailbox`] — the store-and-forward store (paginated, bounded) + a receipt mailbox + the
//!   capability gate; [`SharedMailbox`] adds concurrency-safe access.
//! * [`persist`] — crash-safe atomic persistence (temp-file + fsync + rename).
//! * [`service`] — turns inbound requests into store operations (mailbox-node side); enforces limits.
//! * [`client`] — the high-level [`client::MailClient`]: `send` (body + attachments + sealed
//!   subject), `drain_inbox`, pagination, threading, receipts, and `screen_inbox`.
//!
//! ## Minimal flow
//!
//! ```no_run
//! use ce_mail::client::{CeTransport, MailClient, SendOptions};
//! use ce_identity::Identity;
//! # async fn demo() -> anyhow::Result<()> {
//! let me = Identity::load_or_generate(std::path::Path::new("/tmp/ce-mail-demo"))?;
//! let client = MailClient::new(me, CeTransport::local());
//! // Direct delivery (recipient online): no mailbox, no grant.
//! let mid = client.send(SendOptions {
//!     to: "<recipient-node-id-hex>".into(),
//!     subject: "hello".into(),
//!     body: b"first decentralized mail".to_vec(),
//!     ..Default::default()
//! }).await?;
//! println!("sent {mid}");
//! # Ok(()) }
//! ```
//!
//! See `docs/smtp-gateway.md` and `docs/threat-model.md` for the (documented, not implemented) SMTP
//! interop bridge and the spam/threat model.

pub mod attachment;
pub mod client;
pub mod crypto;
pub mod envelope;
pub mod limits;
pub mod mailbox;
pub mod persist;
pub mod proto;
pub mod receipt;
pub mod screening;
pub mod service;
pub mod thread;

pub use attachment::Attachment;
pub use client::{CeTransport, MailClient, Message, REDACTED_SUBJECT, SendOptions, Transport};
pub use crypto::SealedBody;
pub use envelope::{Envelope, EnvelopeBody, MessageId, message_id};
pub use limits::Limits;
pub use mailbox::{ABILITY_ACCEPT, Accepted, MailboxStore, SharedMailbox, StoredEnvelope};
pub use proto::{MAIL_TOPIC, MailReply, MailRequest};
pub use receipt::{Receipt, ReceiptBody, ReceiptKind};
pub use screening::{ScreeningPolicy, Verdict};
pub use service::MailService;
pub use thread::{Conversation, group_threads, normalize_subject, thread_root};
