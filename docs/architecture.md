# ce-mail architecture

This document covers the runtime model that the per-module rustdoc does not: the mailbox request
loop, the persistence model and its durability guarantees, the authorization derivation, and the
operational limits. It complements `README.md` (feature overview) and `threat-model.md` (security).

## The two roles

ce-mail has exactly two runtime roles, both built on the same `proto` request/reply enum:

- **Client** (`MailClient`) — what a person/app runs. It seals bodies + attachments, signs a tiny
  envelope, delivers it (direct to an online recipient, or to a mailbox for an offline one), and
  later drains/decrypts/screens its own inbox. Stateless beyond a saved inbox cursor.
- **Mailbox** (`MailService` over a `MailboxStore`) — an always-on node that stores signed envelopes
  for recipients that granted it `mail:accept`, and replays them on drain. The `serve-mailbox` CLI
  subcommand runs it.

CE itself is untouched: every hop is a `ce-rs` app-message (`request`/`reply` over `/ce/rpc/1`) plus a
`ce-rs` blob `put`/`get`. No node endpoints are added.

## Send path (client)

```
send(opts)
  ├─ enforce client Limits (body / attachment-count / attachment-size)
  ├─ seal body  → blob put → body_cid           (or seal {subject,body} when seal_subject)
  ├─ for each attachment: seal(Attachment) → blob put → attachment_cid
  ├─ build EnvelopeBody{from,to,subject|REDACTED,body_cid,attachment_cids,in_reply_to,sent_at,postage}
  ├─ Envelope::seal(identity, body)             (Ed25519 sign over domain-separated bytes)
  └─ Deliver{envelope, grant} → request(target) → expect Delivered
```

The body and each attachment are **separate sealed blobs**, so a recipient pulls a 40 MB attachment
only when it calls `open_attachment` — never with the envelope.

## Mailbox request loop (`serve-mailbox`)

```
subscribe(MAIL_TOPIC)
load store (atomic file) or new
spawn revocation-refresher (re-fetch ce.revoked() every N s into a shared, mutex-guarded set)
loop:
  messages = ce.messages()                       (poll; failure → exponential backoff, capped)
  dirty = false
  for each msg on MAIL_TOPIC with a reply_token:
    requester = authenticated msg.from           (CE authenticates the sender)
    req = decode(payload)                         (malformed → ignore)
    reply = service.handle(requester, req, now, is_revoked)
    dirty |= (req mutates store && reply != Error)
    ce.reply(token, reply)
  if dirty && store_path: atomic_write(path, store.try_to_bytes())   (once per batch)
  sleep(poll_ms)
```

Key properties:

- **One persist per drain batch**, gated by a dirty flag — not one full-store rewrite per message
  (the previous O(n)-per-message cost and corruption window).
- **Atomic, durable writes** — see below.
- **Live revocation** — the `is_revoked` closure reads a shared set refreshed on an interval, so a
  grant revoked after the mailbox started is honored within the refresh window (a poisoned lock fails
  *closed*: treated as revoked).

## Authorization derivation (the capability gate)

A mailbox is not an open relay. `MailboxStore::check_accept_grant(recipient, chain, now, is_revoked)`
calls `ce_cap::authorize` with:

- **root authority** = the recipient `R` (you may always authorize accepting *your own* mail),
- **resource** = `Resource::Node(R)`,
- **ability** = `mail:accept`,
- **self / leaf audience** = this mailbox node.

So the gate answers exactly *"did R sign a chain authorizing this mailbox to accept R's mail?"*. A
grant for A can't accept for B; a grant to mailbox X can't authorize Y; expiry / on-chain revocation
kills it. Draining/acking requires `requester == recipient` or an equivalent delegate grant.

## Persistence & durability

`persist::atomic_write(path, bytes)`:

1. write to `dir/.<name>.tmp.<pid>`,
2. `flush` + `fsync` the temp file (contents durable),
3. `rename` temp → target (atomic within a directory on POSIX),
4. best-effort `fsync` the directory (the rename itself durable).

A reader or a restart therefore always observes either the complete old file or the complete new file
— never a truncated one. The store serializes with a magic-tagged format (`try_to_bytes`); loading
falls back to the legacy 3-tuple format and rebuilds the de-dup indexes. Inbox snapshot + cursor are
written the same way, snapshot **before** cursor, so a crash never advances the cursor past mail the
local `read` can still show.

## Operational limits (defaults; see `limits::Limits`)

| Limit | Default | Why |
|---|---|---|
| subject | 4 KiB | cleartext + signed but otherwise unbounded |
| CID string | 256 B | a sha256 hex CID is 64 B |
| attachments per message | 64 | generous; Gmail caps ~50 |
| postage receipt | 1 KiB | a channel receipt id/token |
| envelope total | 256 KiB | backstop over field checks |
| `DrainPage` limit | 500 | clamped server-side; one request can't ask for unbounded mail |
| attachment payload | 40 MiB | documented per-attachment ceiling |
| body payload | 25 MiB | message body |

Limits are per-`MailService` (`with_limits`) — a private mailbox can loosen, a public one tighten.
Capacity (`capacity_per_recipient`) bounds message **count**; limits bound **bytes** — both are needed.

## What is intentionally not here

- **SMTP gateway** (legacy interop) — `docs/smtp-gateway.md`, non-E2E, deferred.
- **Channel settlement for postage** — `screening` verifies a receipt and decides delivery; locking
  credits and the read-then-refund settlement is recipient-app/channel wiring beyond this crate.
- **Onion routing / metadata privacy** — a mailbox necessarily learns who-has-mail-for-whom; see the
  threat model for mitigations (run your own mailbox, seal subjects, pad/batch drains).
