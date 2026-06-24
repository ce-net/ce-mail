# ce-mail

**Decentralized, identity-native email/messaging between CE identities, over the mesh.**

Your address *is* your CE `NodeId` (an Ed25519 public key). Every message is signed by its sender
(so there is no spoofing and no SPF/DKIM/DMARC machinery to run), every body is end-to-end encrypted
to the recipient (the host that stores or relays it never sees plaintext), and offline recipients are
served by a **mailbox** — an always-on store-and-forward node that the recipient authorizes with a CE
capability. ce-mail is an *app over the CE SDK*: it adds **no node endpoints**, composing primitives
that already exist.

```
sender ──seal body──▶ blob store (CID)         recipient (offline)
   │                                                  ▲
   └──signed envelope (AppRequest)──▶ mailbox ──drain─┘  (capability-gated)
                                      store-and-forward
```

## What it composes (CE-vs-app boundary honored)

| ce-mail need | CE primitive used |
|---|---|
| address + free authentication | `ce-identity` NodeId + Ed25519 signatures |
| message body / attachments | `ce-rs` content-addressed **blobs** (sealed, fetched lazily by CID) |
| on-the-wire delivery | `ce-rs` **app-messaging** (`request`/`reply` over `/ce/rpc/1`) |
| store-and-forward for offline recipients | a **mailbox** node holding signed envelopes |
| who may accept / drain mail | `ce-cap` **capability chains** (`mail:accept`) |
| postage / spam economics | payment-channel receipt in the envelope, verified by recipient `screening` policy |
| reputation gradient | `GET /history/:node_id` → `is_newcomer()` for sender standing |

No new RPCs, no allowlists, no stored `ip:port` — every device-to-device hop is an authenticated
mesh request authorized by a signed, attenuating capability chain.

## Architecture

Eleven small, independently testable modules:

| Module | Responsibility |
|---|---|
| `crypto`   | Ed25519→X25519 **sealed-box** E2E body encryption (anonymous-sender, AEAD-authenticated). |
| `envelope` | The small **signed envelope** (from/to/subject/body-CID/attachment-CIDs/thread/postage); encode + verify + size-bounded. |
| `attachment` | **Sealed attachments** — `(filename, content-type, bytes)` sealed E2E and stored as a lazily-fetched blob; filename + type are confidential too. |
| `thread`   | **Conversation modeling**: `in_reply_to` chain resolution (cycle-safe), `Re:`/`Fwd:` subject normalization, grouping a flat inbox into ordered, deduplicated `Conversation`s. |
| `receipt`  | **Signed delivery/read receipts** — Ed25519-attributable acknowledgements the original sender can verify and collect. |
| `screening`| **Recipient-side anti-spam**: allowlists/contacts, blocklist, **refundable postage** (verified channel receipt) from strangers, and a **reputation gradient** (`is_newcomer()`), classifying mail into inbox / spam / rejected. |
| `limits`   | The **resource bounds** every mailbox enforces (max subject/CID/attachment-count/page/body sizes) — the DoS / memory-amplification guard. |
| `proto`    | The mesh request/reply protocol: `Deliver` / `Drain` / `DrainPage` / `Ack` / `PutReceipt` / `CollectReceipts`. |
| `mailbox`  | The **store-and-forward store** (bounded, de-duplicated, paginated, persistable) + a receipt mailbox + the capability gate. `SharedMailbox` adds concurrency-safe access. |
| `persist`  | **Crash-safe atomic persistence** (temp-file + `fsync` + `rename` + dir `fsync`). |
| `service`  | Turns inbound requests into store operations (the mailbox-node side); pure, no I/O; enforces `limits`. |
| `client`   | The high-level `MailClient`: `send` (body + **attachments** + **sealed subject**), `drain_inbox`, `drain_inbox_page`, `drain_inbox_threaded`, **`screen_inbox`**, `ack`, `send_receipt`, `collect_receipts`, `open_body`, `open_attachment`, behind a `Transport`. |

### Why split body from envelope?

The **body and attachments** are sealed blobs referenced by **CID** and fetched *lazily* — a 40 MB
attachment is never downloaded until the recipient opens it. The **envelope** is tiny signed metadata.
This keeps store-and-forward cheap (mailboxes hold envelopes, not payloads) and gives the recipient
the choice of whether to pull a large body at all.

### Attachments & subject confidentiality

`SendOptions::attachments` carries any number of `Attachment`s; each is sealed E2E to the recipient
(filename and content type included) and stored as its own blob, referenced by CID in the envelope.
The recipient pulls them lazily with `open_attachment(envelope, i)`. Set `SendOptions::seal_subject`
to seal the subject too: the cleartext envelope then shows only `(encrypted subject)` to a mailbox or
observer, and the recipient recovers the real subject via `Message::subject()`.

### Anti-spam: postage + screening (implemented)

A recipient builds a `ScreeningPolicy` and calls `client.screen_inbox(...)`, which drains the inbox
and splits it into **inbox** and **spam** (rejecting blocked/mis-addressed mail):

- **Contacts are free** — anyone on the allowlist (or a proven, `Established` sender) skips postage.
- **Strangers pay refundable postage** — the envelope's `postage_receipt` is checked by a caller-
  supplied verifier (a real payment-channel receipt worth at least `require_postage(...)`); without
  acceptable postage a stranger is quarantined as spam (lenient) or rejected (`strict()`).
- **Reputation gradient** — sender standing comes from `GET /history/:node_id` (`is_newcomer()`),
  the same trust gradient CE uses for compute. This is **recipient/app policy**, never node-enforced.

### Durability & resource bounds

Mailbox persistence is **atomic** (`persist::atomic_write`: temp-file + `fsync` + `rename`), so a
crash or full disk mid-write never corrupts the store; the serve loop batches writes (a dirty flag,
once per drain) instead of rewriting on every message. Every inbound envelope is checked against
`Limits` (subject ≤ 4 KiB, ≤ 64 attachments, page ≤ 500, …) before storage, and a `DrainPage` limit
is clamped server-side — closing the memory-amplification / DoS holes. Revocation is **refreshed on
an interval** in `serve-mailbox`, so a grant revoked after start takes effect without a restart.

### Encryption

CE identities are Ed25519. For asymmetric encryption we derive a deterministic **X25519** keypair from
the same key, so a sender who knows only a recipient's `NodeId` can encrypt to them with no key
exchange: the recipient's X25519 public key is the Montgomery form of their Ed25519 public key. We then
do an ephemeral-static ECDH, derive a key with SHA-256 (domain-separated), and seal with
ChaCha20-Poly1305 — the NaCl "sealed box" construction, built on the same dalek primitives
`ce-identity` already uses. A unit test asserts the sender's derived public key equals the recipient's,
so the two sides provably agree on the shared secret.

## CLI

```
ce-mail id                                   # print your NodeId — your mail address
ce-mail send <to-hex> --subject "hi" --body "first decentralized mail"
ce-mail send <to-hex> --body "stored for you" --mailbox <mb-hex> --grant <token>
ce-mail send <to-hex> --subject "secret" --seal-subject --attach ./report.pdf --attach ./photo.png
ce-mail grant-mailbox <mailbox-hex> --expires-days 90   # authorize a mailbox to hold your mail
ce-mail inbox <mailbox-hex> --ack            # drain + decrypt + free at the mailbox
ce-mail read <message-id>                    # print one message from the last inbox snapshot
ce-mail serve-mailbox --store ~/.ce-mail/mb.bin --revocation-refresh-secs 60   # run a mailbox
```

`--attach` is repeatable (each file is sealed E2E and stored lazily); `--seal-subject` hides the
subject from the mailbox. `serve-mailbox` persists atomically, refreshes on-chain revocation on an
interval, and enforces resource limits on every inbound envelope.

Direct delivery (recipient online) needs no mailbox and no grant. Store-and-forward needs a `mailbox`
node and the recipient's `mail:accept` grant (issued with `grant-mailbox`). The CLI talks to a local
CE node at `--node` (default `http://127.0.0.1:8844`) and keeps its identity + inbox cursor in
`--data-dir` (default platform data dir).

## Library

```rust
use ce_mail::{MailClient, SendOptions};
use ce_mail::client::CeTransport;
use ce_identity::Identity;

# async fn demo() -> anyhow::Result<()> {
let me = Identity::load_or_generate(std::path::Path::new("/tmp/ce-mail"))?;
let client = MailClient::new(me, CeTransport::local());

// Direct delivery to an online recipient.
let mid = client.send(SendOptions {
    to: "<recipient-node-id-hex>".into(),
    subject: "hello".into(),
    body: b"first decentralized mail".to_vec(),
    ..Default::default()
}).await?;

// Later: drain your mailbox (offline path) and read decrypted messages.
let (messages, cursor) = client.drain_inbox("<mailbox-hex>", 0, vec![]).await?;
for m in &messages {
    println!("{} from {}: {}", m.envelope.body.subject, m.envelope.body.from, m.body_text());
}
client.ack("<mailbox-hex>", cursor, vec![]).await?;
# Ok(()) }
```

Network access is behind the `Transport` trait, so the whole orchestration is unit-testable against an
in-memory fake (the test suite drives full send→store→drain→decrypt with no running node).

## Mailbox authorization (open-relay protection)

A mailbox is **not** an open relay. It stores mail for a recipient `R` only if `R` issued it a
capability chain:

```
root = R  ──grants──▶  mailbox     ability: "mail:accept"     resource: Node(R)
```

On `Deliver`, the mailbox runs `ce_cap::authorize` with `R` as both the resource node and the accepted
root: *"did R authorize this mailbox to accept R's mail?"*. A grant for recipient A cannot be used to
accept mail for B, a grant to mailbox X cannot authorize mailbox Y, and revocation (on-chain
`RevokeCapability` + expiry) kills it. Draining/acking an inbox requires `requester == recipient` or a
valid delegate grant. This makes spam **non-amplifiable** at the storage layer.

## Tests

```
cargo test
```

- **Unit** (139) — every public fn, happy + error paths, in each module: subject normalization and
  `in_reply_to` thread-root resolution (incl. cycle-safety and orphan replies), conversation grouping
  and ordering, inbox pagination bounds/`more` signaling, signed-receipt issue/verify/dedup, the
  receipt mailbox (idempotent deposit, capacity eviction, persistence), the capability gate, the
  **resource-limit checks**, **screening verdicts** (contact/stranger/postage/blocked/established),
  **atomic-write** durability, and **concurrent `SharedMailbox`** deliver/ack with no lost updates.
- **Integration** (17, in-memory transport) — envelope round-trip, delivery+ack, offline-store replay
  (order + content, **idempotent across redelivery and post-ack**), paginated drain, threaded view,
  signed **read-receipt round-trip**, the capability gate, E2E body encryption (stored blob never
  contains plaintext; attacker can't decrypt), **attachments end-to-end**, **screening** splitting
  contact-vs-stranger, **postage** letting a stranger through, **revocation taking effect after start**,
  **atomic persist + reload**, threading, idempotent delivery, and dropped-peer handling.
- **Property** (16, `proptest`) — seal/open recovers arbitrary plaintext; envelope/attachment/receipt
  round-trips keep verifying; message ids are deterministic; subject normalization is idempotent and
  collapses any stack of reply/forward prefixes; **no decoder panics** on arbitrary bytes; ciphertext
  tampering always fails AEAD; **resource limits** reject any oversized subject / over-count attachments
  and `clamp_page` is always bounded.
- **Doctests** (4) — runnable examples on `Attachment`, `ScreeningPolicy`, and `normalize_subject`.

Failure injection (dropped peer, missing blob, malformed input, forged/tampered envelope, wrong
recipient, oversized payload, revoked grant) is covered across unit, integration, and property suites
— every path degrades gracefully and **never panics**.

## Implemented in this milestone

- **Attachments** end-to-end (sealed name + type + bytes, lazy fetch by CID).
- **Subject confidentiality** (`--seal-subject`): the subject is sealed E2E; mailbox sees a placeholder.
- **Anti-spam screening**: allowlists/contacts, blocklist, **refundable postage** verification, and a
  history-based reputation gradient, classifying inbound mail into inbox/spam/rejected.
- **Resource bounds** on every inbound envelope + server-clamped `DrainPage` (DoS / amplification guard).
- **Crash-safe atomic persistence** + batched, dirty-flagged writes in `serve-mailbox`.
- **Periodic revocation refresh** so on-chain revocation takes effect on a long-running mailbox.
- **Concurrency-safe** `SharedMailbox`, `tracing` logging, and `try_*` encoders that surface errors.

## Documented, not yet implemented (honestly deferred)

- [`docs/smtp-gateway.md`](docs/smtp-gateway.md) — an SMTP gateway cell for interop with legacy email
  (RFC 5322 ↔ CE envelope, MX/SPF/DKIM/DMARC at the bridge). This is a large, non-E2E interop surface
  intentionally left for a follow-up; CE-to-CE mail needs none of it. The threat model spells out what
  it inherits from legacy email.
- **On-chain postage *locking/refund settlement*** — `screening` verifies a postage receipt and the
  policy decides delivery, but the credit-locking and the read-then-release-vs-keep settlement over a
  payment channel is the recipient-app/channel wiring beyond this crate's verification slice.

## Status

CE-to-CE mail works end-to-end in tests: send (body + attachments + sealed subject), seal,
store-and-forward, drain, decrypt, thread, capability-gate, screen for spam, persist crash-safely.
The SMTP bridge and the channel-settlement half of postage are designed here and deferred; the honest
hard parts (metadata at the mailbox, key-loss recovery, the bridge's legacy inheritance) are called
out in the threat model.

## License

MIT. Author: Leif Rydenfalk &lt;ledamecrydenfalk@gmail.com&gt;.
