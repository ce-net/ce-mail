# ce-mail SMTP gateway (design — not implemented)

This document specifies an **SMTP gateway** that bridges ce-mail (CE-native, identity-addressed) and
the legacy email world (RFC 5321/5322 over SMTP, addressed by `user@domain`). It is a *design stub*:
ce-mail ships CE-to-CE mail today; the gateway is the interop layer for talking to the rest of the
internet. It is deliberately separate because the bridge inherits the hard, unfixable parts of legacy
email (spam, metadata trust, DNS/TLS PKI) that CE-native mail avoids.

## Goal

Let a CE identity send to and receive from `alice@example.com`, and let `alice@example.com` reach a CE
identity, without either side knowing the other is on a different system.

## Shape

The gateway is a **cell** (a long-running CE job) run by an operator who controls a DNS domain (say
`gw.example`). It has two halves:

```
 legacy world                         CE mesh
 ────────────                         ───────
 sender MTA ──SMTP──▶ [ gateway cell ] ──ce-mail Deliver──▶ recipient / mailbox
 recipient MTA ◀──SMTP── [ gateway cell ] ◀──ce-mail Drain── sender
                         holds: MX record, SPF/DKIM/DMARC keys,
                                a CE identity, a name→NodeId map
```

### Inbound (legacy → CE)

1. The operator publishes an `MX` record for `gw.example` pointing at the gateway cell's ingress
   (reached via CE `tunnel`, exposing port 25 to the internet).
2. A legacy MTA connects over SMTP and delivers a message for `<local-part>@gw.example`.
3. The gateway authenticates the *sending domain* the legacy way — **SPF** (envelope-from IP),
   **DKIM** (signature over headers/body), **DMARC** (alignment policy). This is the trust ceiling of
   legacy email and the gateway cannot do better than the sender's domain allows.
4. The gateway resolves `<local-part>` to a CE `NodeId` via a **name map** it maintains
   (`local-part → NodeId`, e.g. backed by `ce-coord` or on-chain `NameClaim`).
5. It wraps the RFC 5322 message into a ce-mail `EnvelopeBody`:
   - `from` = the gateway's own `NodeId` (the gateway vouches it relayed it; the original
     `From:`/DKIM result travels in a structured header blob, see below),
   - `to` = the resolved recipient `NodeId`,
   - `subject` = the `Subject:` header,
   - `body_cid` = a sealed blob containing the full original MIME message (so nothing is lost) plus a
     small JSON sidecar `{ smtp_from, dkim_pass, spf_pass, dmarc_pass, received_chain }`,
   - `attachment_cids` = sealed blobs for each MIME part over a size threshold.
6. The gateway signs the envelope and `Deliver`s it to the recipient (or its mailbox, presenting the
   gateway's `mail:accept` grant). Because the body is sealed **to the recipient**, the gateway *can*
   read inbound legacy mail (it received it in cleartext over SMTP) but stores only ciphertext on the
   mesh.

### Outbound (CE → legacy)

1. A CE client sends a ce-mail message addressed to a *legacy* recipient. Two addressing options:
   - a reserved syntax in `to` metadata, e.g. an envelope field `smtp_to: alice@example.com` with
     `to` = the gateway's `NodeId`; or
   - a `NameClaim`/`ce-coord` alias that resolves `alice.example.com` to the gateway `NodeId`.
2. The client `Deliver`s the envelope to the gateway (it must hold a `mail:relay-out` capability the
   gateway issues to senders it serves — this is where outbound postage/abuse policy lives).
3. The gateway opens the sealed body **only if the sender chose to share it with the gateway**
   (outbound to legacy is inherently not E2E — the destination can't decrypt CE sealed boxes, so the
   sender accepts that the gateway and the legacy path see plaintext; the client must warn about this).
4. The gateway re-materializes an RFC 5322 message, signs it with **its** DKIM key for `gw.example`,
   sets `From: <local-part>@gw.example` (a stable per-CE-identity alias), and relays it over SMTP to
   the destination MX.
5. Replies come back inbound through the same MX and the name map.

## Header/identity mapping

| RFC 5322 | ce-mail |
|---|---|
| `From:` | sealed sidecar `smtp_from`; envelope `from` is the gateway's NodeId (relay attestation) |
| `To:` | resolved to `NodeId` (inbound) / `smtp_to` sidecar (outbound) |
| `Subject:` | `EnvelopeBody.subject` |
| `Message-ID:` | mapped to/from the content-addressed ce-mail `MessageId` |
| `In-Reply-To:`/`References:` | `EnvelopeBody.in_reply_to` |
| `DKIM-Signature` / SPF / DMARC results | sealed sidecar booleans (inbound provenance) |
| body + MIME parts | sealed `body_cid` + `attachment_cids` |

## Trust and naming

- **Inbound provenance is only as good as the sender's domain.** The gateway forwards SPF/DKIM/DMARC
  results as data; recipients (or their clients) decide how much to trust mail relayed by this gateway.
  A recipient may require that legacy mail arrive only via gateways it has whitelisted (a `mail:accept`
  grant scoped to gateway NodeIds).
- **The gateway is a named, accountable relay**, not a global root. Multiple competing gateways can
  exist; a recipient picks which to trust, exactly like choosing an email provider — except switching
  is a capability re-grant, not a data migration.
- **Name map** (`local-part ↔ NodeId`) is the gateway's responsibility. On-chain `NameClaim` gives a
  censorship-resistant global option; a `ce-coord` collection gives a per-gateway private option.

## Why it is intentionally not implemented yet

The bridge buys interop at the cost of importing legacy email's three unsolved problems: spam
(addressed below in the threat model, but never *solved* at an open SMTP edge), metadata exposure (the
gateway sees who-mails-whom across the boundary, and outbound-to-legacy is not E2E), and the
DNS/TLS/DKIM PKI (the gateway must run an MTA, hold private keys, and stay off blocklists). CE-to-CE
mail is strictly better than legacy email on all three; the gateway is *exactly as hard as running
email is today*, so it is scoped as a separate operator-run cell rather than core ce-mail.

## Minimal milestones (if/when built)

1. Inbound-only relay: MX + SPF/DKIM verification + wrap + `Deliver` to a single mapped NodeId.
2. Name map over `ce-coord`; multi-recipient.
3. Outbound relay with per-sender `mail:relay-out` capability + DKIM signing + abuse rate-limits.
4. Postage interop: require a CE postage receipt for outbound; for inbound, surface a "no postage
   (legacy)" flag the recipient's screening policy can weigh.
