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
| postage / spam economics | payment-channel receipt referenced in the envelope (designed; see threat model) |

No new RPCs, no allowlists, no stored `ip:port` — every device-to-device hop is an authenticated
mesh request authorized by a signed, attenuating capability chain.

## Architecture

Six small, independently testable modules:

| Module | Responsibility |
|---|---|
| `crypto`   | Ed25519→X25519 **sealed-box** E2E body encryption (anonymous-sender, AEAD-authenticated). |
| `envelope` | The small **signed envelope** (from/to/subject/body-CID/thread/postage); encode + verify. |
| `proto`    | The mesh request/reply protocol: `Deliver` / `Drain` / `Ack`. |
| `mailbox`  | The **store-and-forward store** (bounded, de-duplicated, persistable) + the capability gate. |
| `service`  | Turns inbound requests into store operations (the mailbox-node side); pure, no I/O. |
| `client`   | The high-level `MailClient`: `send`, `drain_inbox`, `ack`, `open_body`, behind a `Transport`. |

### Why split body from envelope?

The **body and attachments** are sealed blobs referenced by **CID** and fetched *lazily* — a 40 MB
attachment is never downloaded until the recipient opens it. The **envelope** is tiny signed metadata.
This keeps store-and-forward cheap (mailboxes hold envelopes, not payloads) and gives the recipient
the choice of whether to pull a large body at all.

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
ce-mail send <to-hex> --mailbox <mb-hex> --grant <token> --body "stored for you"
ce-mail grant-mailbox <mailbox-hex> --expires-days 90   # authorize a mailbox to hold your mail
ce-mail inbox <mailbox-hex> --ack            # drain + decrypt + free at the mailbox
ce-mail read <message-id>                    # print one message from the last inbox snapshot
ce-mail serve-mailbox --store ~/.ce-mail/mb.bin   # run a store-and-forward mailbox
```

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

- **Unit** (51) — every public fn, happy + error paths, in each module.
- **Integration** (8) — full flows over an in-memory transport: envelope round-trip, delivery+ack,
  offline-store replay (order + content), the capability gate, E2E body encryption (incl. that the
  stored blob never contains plaintext and an attacker can't decrypt), threading, idempotent delivery,
  and dropped-peer handling.
- **Property** (7, `proptest`) — seal/open recovers arbitrary plaintext; envelope sign→encode→decode
  keeps verifying; message ids are deterministic; **no decoder panics** on arbitrary bytes;
  ciphertext tampering always fails AEAD.

Failure injection (dropped peer, missing blob, malformed input, forged/tampered envelope, wrong
recipient) is covered across unit, integration, and property suites — every path degrades gracefully
and **never panics**.

## Documented, not implemented

- [`docs/smtp-gateway.md`](docs/smtp-gateway.md) — an SMTP gateway cell for interop with legacy email
  (RFC 5322 ↔ CE envelope, MX/SPF/DKIM/DMARC at the bridge).
- [`docs/threat-model.md`](docs/threat-model.md) — the spam/threat model: postage economics, metadata
  exposure at the mailbox, key-loss = identity-loss, and what the bridge inherits from legacy email.

## Status

Foundation, validated from the start. CE-to-CE mail (send, seal, store-and-forward, drain, decrypt,
thread, capability-gate, persist) works end-to-end in tests. The SMTP bridge and on-chain postage
enforcement are designed here and left for a follow-up; the honest hard parts are called out in the
threat model.

## License

MIT. Author: Leif Rydenfalk &lt;ledamecrydenfalk@gmail.com&gt;.
