# ce-mail threat model (spam, abuse, privacy)

This document states what ce-mail defends against, what it does **not**, and the economic and
capability mechanisms that make CE-native mail strictly better than legacy email on the parts that
matter — while honestly naming the hard parts (metadata, key loss, the SMTP bridge).

## Assets

- **Message confidentiality** — the body/attachments of a message.
- **Sender authenticity** — who actually sent a message.
- **Mailbox availability** — a recipient's ability to receive while offline.
- **Recipient attention** — protection from unsolicited bulk mail (spam).
- **Metadata** — who mails whom, when, and how much.

## Adversaries

1. **Forger** — wants to send mail that appears to come from someone else.
2. **Eavesdropper** — a relay/mailbox/network observer reading message contents.
3. **Spammer** — wants to flood inboxes cheaply, possibly from many fresh identities (Sybil).
4. **Open-relay abuser** — wants to use someone's mailbox to amplify or launder mail.
5. **Metadata harvester** — a mailbox or network observer mapping social graphs.
6. **Thief** — steals a key to impersonate or read mail.

## Defenses (what CE-native mail gets for free)

### Sender authenticity — solved cryptographically

Every envelope is Ed25519-signed over domain-separated canonical bytes (`ce-mail-envelope-v1`). The
`from` field *is* the signing key; `Envelope::verify()` recomputes and checks the signature. Changing
`from`, `subject`, `body_cid`, or any field invalidates it. There is **no spoofing** and no SPF/DKIM to
configure — the property tests assert tampered and forged envelopes always fail verification. A mailbox
refuses to store an envelope that does not verify (`MailboxStore::accept`).

### Confidentiality — E2E by construction

Bodies are sealed to the recipient's X25519 key (derived from their NodeId) with ChaCha20-Poly1305
before they ever leave the sender (`crypto::seal`). The mailbox stores **only ciphertext**; a relay,
mailbox operator, or network observer learns nothing about the body. An integration test asserts the
stored blob never contains the plaintext and that a third party cannot decrypt it. Subject lines are
metadata (cleartext, like legacy email) — see metadata below.

### Open-relay abuse — capability-gated storage

A mailbox stores mail for recipient `R` **only** if `R` issued it a `mail:accept` capability scoped to
`Resource::Node(R)` (verified by `ce_cap::authorize` rooted at `R`). Consequences, all tested:

- a grant for recipient A cannot accept mail for B;
- a grant to mailbox X cannot authorize mailbox Y;
- revocation (on-chain `RevokeCapability`) or expiry kills the grant;
- draining/acking an inbox requires `requester == recipient` or an explicit delegate grant.

So a mailbox is never an open relay and cannot be used as a spam amplifier.

### Integrity / replay — content addressing + idempotence

The message id is `sha256` of the signed envelope; the mailbox de-duplicates by id, so re-delivering
the same message stores it once (`Accepted::Duplicate`). Bounded per-recipient retention prevents a
single recipient's queue from exhausting mailbox memory. Bodies are content-addressed and verified
against their CID on fetch (the `ce-rs` blob layer), so a tampered body fails to reassemble.

## Spam economics (the hard part, addressed not eliminated)

Authenticity stops *spoofing* but not *unsolicited bulk mail from real (or freshly minted) identities*.
ce-mail's answer is **postage**, layered:

1. **Contacts are free.** A recipient's screening policy waives postage for senders it already trusts
   (an allow-cap, or any sender in its address book / prior-thread set). Most legitimate mail is free.

2. **Strangers pay refundable postage.** The envelope carries a `postage_receipt` — a payment-channel
   receipt to the recipient (or its mailbox). A recipient's policy can require a non-empty postage
   receipt from unknown senders before the message is surfaced. Postage is *refundable*: a recipient
   that reads and does not mark spam can release it back; spam is simply not refunded. This makes a
   10,000-message blast from fresh identities **economically infeasible** — each stranger-message locks
   real credits, and Sybil identities don't help because cost is per-message, not per-identity.

3. **Reputation gradient.** `GET /history/:node_id` gives immutable interaction facts; a recipient can
   prioritize senders with delivered-work/spend history and deprioritize newcomers (`is_newcomer()`),
   exactly the trust gradient CE uses for compute. This is policy in the *app/recipient*, not the node.

> Status: the envelope field and the verification hooks exist; *enforcing* a minimum postage and the
> refund flow is recipient-side policy and is the next implementation milestone. The threat model
> commits to the mechanism; the wiring to channels is documented, not yet shipped.

## What ce-mail does NOT defend against (honest limits)

- **Metadata.** A mailbox necessarily learns *who has mail waiting for whom* and *when it is drained* —
  a who-mails-whom point. Subject lines are cleartext. Mitigations (not yet built): run your own
  mailbox (no third-party metadata), encrypt subjects for known contacts, pad/batch drains, and use
  multiple mailboxes. This is strictly better than legacy email (where the provider sees full content
  and graph) but it is not metadata-private.

- **Key loss = identity loss.** Your NodeId is your address and your decryption key. Lose the key and
  you lose your mail identity and any sealed mail you have not opened. ce-mail does not solve recovery;
  it defers to the CE frontier's social/hardware key-recovery work. Operationally: back up
  `identity/node.key`.

- **Traffic analysis.** An observer of the mesh can see envelope-sized requests flowing to a mailbox
  even though contents are sealed. Onion-style routing is out of scope.

- **The SMTP bridge inherits legacy spam and metadata.** Anything crossing the SMTP gateway is only as
  trustworthy as SPF/DKIM/DMARC allow, and outbound-to-legacy is not E2E (the destination can't decrypt
  CE sealed boxes). The gateway is exactly as hard as running email is today — see
  [`smtp-gateway.md`](smtp-gateway.md). CE-to-CE mail avoids all of this; only interop pays the tax.

## Summary

ce-mail makes **spoofing impossible** and **confidentiality default** with no PKI to run, turns the
mailbox into a **capability-gated, non-amplifiable** relay, and makes **bulk spam uneconomical** via
refundable postage + a reputation gradient instead of guesswork filters. The residual risks —
mailbox metadata, key-loss recovery, and the SMTP bridge's legacy inheritance — are named explicitly
rather than papered over, each with a stated mitigation or a pointer to the frontier work that
addresses it.
