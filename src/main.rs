//! `ce-mail` — CLI for decentralized, identity-native mail over the CE mesh.
//!
//! Subcommands:
//! * `send`          — compose, seal, and deliver a message (direct or via a mailbox).
//! * `inbox`         — drain your mailbox, listing decrypted messages (saves a cursor).
//! * `read`          — print one message body by id from the last `inbox` snapshot.
//! * `grant-mailbox` — issue an accept-mail capability to a mailbox you trust to hold your mail.
//! * `serve-mailbox` — run a store-and-forward mailbox for recipients that granted you.
//! * `id`            — print this identity's NodeId (your mail address).
//!
//! Money is never a float; postage is a payment-channel receipt id (opaque string) per CE rules.

use anyhow::{Context, Result, anyhow};
use ce_cap::{Caveats, Resource, SignedCapability, decode_chain, encode_chain};
use ce_identity::Identity;
use ce_mail::client::{CeTransport, MailClient, Message, SendOptions};
use ce_mail::mailbox::{ABILITY_ACCEPT, MailboxStore};
use ce_mail::proto::{MAIL_TOPIC, MailRequest};
use ce_mail::service::MailService;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(
    name = "ce-mail",
    about = "Decentralized, identity-native email over the CE mesh",
    version
)]
struct Cli {
    /// CE node HTTP API base URL.
    #[arg(long, default_value = "http://127.0.0.1:8844", global = true)]
    node: String,
    /// Data directory holding this identity's key (and the inbox cursor).
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print your NodeId — your mail address.
    Id,
    /// Send a message. Direct delivery by default; use --mailbox for offline store-and-forward.
    Send {
        /// Recipient NodeId hex.
        to: String,
        /// Subject line.
        #[arg(long, default_value = "")]
        subject: String,
        /// Body text. If omitted, read the body from stdin.
        #[arg(long)]
        body: Option<String>,
        /// Message id this replies to (threading).
        #[arg(long, default_value = "")]
        in_reply_to: String,
        /// Deliver to this mailbox node (hex) for store-and-forward.
        #[arg(long)]
        mailbox: Option<String>,
        /// Accept-grant token (hex) to present to the mailbox.
        #[arg(long)]
        grant: Option<String>,
        /// Postage receipt id (payment-channel receipt) to attach.
        #[arg(long, default_value = "")]
        postage: String,
    },
    /// Drain your mailbox and list messages (saves them locally for `read`).
    Inbox {
        /// Mailbox node hex to drain from.
        mailbox: String,
        /// Start cursor (default: resume from the saved cursor).
        #[arg(long)]
        since: Option<usize>,
        /// Accept-grant token (hex) if draining as a delegate (omit when you are the recipient).
        #[arg(long)]
        grant: Option<String>,
        /// Acknowledge (free) drained messages at the mailbox after listing.
        #[arg(long)]
        ack: bool,
    },
    /// Print a message body by id from the last inbox snapshot.
    Read {
        /// Message id (from `inbox`).
        id: String,
    },
    /// Issue an accept-mail capability to a mailbox node you trust to hold your mail.
    GrantMailbox {
        /// Mailbox NodeId hex (the audience).
        mailbox: String,
        /// Days until the grant expires (0 = never).
        #[arg(long, default_value_t = 90)]
        expires_days: u64,
        /// Issuer nonce (unique per issuer; names the grant for revocation).
        #[arg(long, default_value_t = 1)]
        nonce: u64,
    },
    /// Run a store-and-forward mailbox for recipients that granted you accept-mail.
    ServeMailbox {
        /// Max envelopes retained per recipient.
        #[arg(long, default_value_t = 10_000)]
        capacity: usize,
        /// Path to persist the mailbox store (loaded on start, saved on each change).
        #[arg(long)]
        store: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let data_dir = cli.data_dir.clone().unwrap_or_else(default_data_dir);
    std::fs::create_dir_all(&data_dir).with_context(|| format!("create {}", data_dir.display()))?;
    let identity = Identity::load_or_generate(&data_dir)
        .with_context(|| format!("load identity from {}", data_dir.display()))?;

    match cli.cmd {
        Command::Id => {
            println!("{}", identity.node_id_hex());
            Ok(())
        }
        Command::Send { to, subject, body, in_reply_to, mailbox, grant, postage } => {
            let body = match body {
                Some(b) => b.into_bytes(),
                None => read_stdin()?,
            };
            let grant_chain = match grant {
                Some(g) => decode_chain(&g).context("decode --grant")?,
                None => vec![],
            };
            let client = MailClient::new(identity, CeTransport::new(ce_rs::CeClient::new(cli.node)));
            let mid = client
                .send(SendOptions {
                    to,
                    subject,
                    body,
                    in_reply_to,
                    postage_receipt: postage,
                    mailbox,
                    grant: grant_chain,
                })
                .await
                .context("send")?;
            println!("sent {mid}");
            Ok(())
        }
        Command::Inbox { mailbox, since, grant, ack } => {
            let cursor_path = data_dir.join("inbox.cursor");
            let snapshot_path = data_dir.join("inbox.json");
            let start = since.unwrap_or_else(|| read_cursor(&cursor_path));
            let grant_chain = match grant {
                Some(g) => decode_chain(&g).context("decode --grant")?,
                None => vec![],
            };
            let client = MailClient::new(identity, CeTransport::new(ce_rs::CeClient::new(cli.node)));
            let (msgs, cursor) = client
                .drain_inbox(&mailbox, start, grant_chain.clone())
                .await
                .context("drain inbox")?;
            print_inbox(&msgs);
            save_snapshot(&snapshot_path, &msgs)?;
            write_cursor(&cursor_path, cursor)?;
            if ack && cursor > start {
                let removed = client.ack(&mailbox, cursor, grant_chain).await.context("ack")?;
                eprintln!("acked {removed} message(s)");
            }
            Ok(())
        }
        Command::Read { id } => {
            let snapshot_path = data_dir.join("inbox.json");
            let msgs = load_snapshot(&snapshot_path)?;
            match msgs.iter().find(|m| m.id == id || m.id.starts_with(&id)) {
                Some(m) => {
                    println!("From:    {}", m.from);
                    println!("Subject: {}", m.subject);
                    if !m.in_reply_to.is_empty() {
                        println!("In-Reply-To: {}", m.in_reply_to);
                    }
                    println!();
                    println!("{}", m.body);
                    Ok(())
                }
                None => Err(anyhow!("no message with id starting {id} in the last inbox snapshot")),
            }
        }
        Command::GrantMailbox { mailbox, expires_days, nonce } => {
            let audience = ce_mail::envelope::parse_node_id(&mailbox).context("parse mailbox id")?;
            let not_after = if expires_days == 0 {
                0
            } else {
                now_secs() + expires_days * 86_400
            };
            let cap = SignedCapability::issue(
                &identity,
                audience,
                vec![ABILITY_ACCEPT.to_string()],
                Resource::Node(identity.node_id()),
                Caveats { not_after, ..Default::default() },
                nonce,
                None,
            );
            let token = encode_chain(&[cap]);
            eprintln!(
                "Accept-mail grant for mailbox {mailbox} (expires_days={expires_days}). Token:"
            );
            println!("{token}");
            Ok(())
        }
        Command::ServeMailbox { capacity, store } => {
            serve_mailbox(identity, cli.node, capacity, store).await
        }
    }
}

/// Run the mailbox request loop: poll inbound app messages on [`MAIL_TOPIC`], handle each, reply.
async fn serve_mailbox(
    identity: Identity,
    node: String,
    capacity: usize,
    store_path: Option<PathBuf>,
) -> Result<()> {
    let ce = ce_rs::CeClient::new(node);
    ce.subscribe(MAIL_TOPIC).await.context("subscribe to mail topic")?;

    let store = match &store_path {
        Some(p) if p.exists() => {
            let bytes = std::fs::read(p).with_context(|| format!("read {}", p.display()))?;
            MailboxStore::from_bytes(&bytes).context("load mailbox store")?
        }
        _ => MailboxStore::new(identity.node_id(), capacity),
    };
    let mut svc = MailService::new(store);
    // Revocation is consulted from the node's on-chain set.
    let revoked = ce.revoked().await.unwrap_or_default();
    let is_revoked = move |issuer: &ce_identity::NodeId, nonce: u64| {
        let issuer_hex = hex::encode(issuer);
        revoked.iter().any(|(i, n)| i == &issuer_hex && *n == nonce)
    };

    eprintln!("ce-mail mailbox serving as {} (topic {MAIL_TOPIC})", identity.node_id_hex());
    eprintln!("Recipients must grant you '{ABILITY_ACCEPT}' (see: ce-mail grant-mailbox).");

    loop {
        let messages = match ce.messages().await {
            Ok(m) => m,
            Err(e) => {
                eprintln!("warn: poll failed: {e}");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                continue;
            }
        };
        for msg in messages {
            if msg.topic != MAIL_TOPIC {
                continue;
            }
            let Some(token) = msg.reply_token else { continue };
            let requester = match ce_mail::envelope::parse_node_id(&msg.from) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let payload = match msg.payload() {
                Ok(p) => p,
                Err(_) => continue,
            };
            let req = match MailRequest::decode(&payload) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let reply = svc.handle(&requester, req, now_secs(), &is_revoked);
            if let Err(e) = ce.reply(token, &ce_mail::proto::MailReply::encode(&reply)).await {
                eprintln!("warn: reply failed: {e}");
            }
            if let Some(p) = &store_path
                && let Err(e) = std::fs::write(p, svc.store().to_bytes())
            {
                eprintln!("warn: persist failed: {e}");
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

// ----- local snapshot persistence for `read` -----

#[derive(serde::Serialize, serde::Deserialize)]
struct SnapMsg {
    id: String,
    from: String,
    subject: String,
    in_reply_to: String,
    body: String,
}

fn print_inbox(msgs: &[Message]) {
    if msgs.is_empty() {
        println!("(no new messages)");
        return;
    }
    for m in msgs {
        println!(
            "{}  {}  {}",
            &m.id()[..16.min(m.id().len())],
            truncate(&m.envelope.body.from, 12),
            m.envelope.body.subject
        );
    }
}

fn save_snapshot(path: &std::path::Path, msgs: &[Message]) -> Result<()> {
    let snap: Vec<SnapMsg> = msgs
        .iter()
        .map(|m| SnapMsg {
            id: m.id(),
            from: m.envelope.body.from.clone(),
            subject: m.envelope.body.subject.clone(),
            in_reply_to: m.envelope.body.in_reply_to.clone(),
            body: m.body_text(),
        })
        .collect();
    std::fs::write(path, serde_json::to_vec_pretty(&snap)?)?;
    Ok(())
}

fn load_snapshot(path: &std::path::Path) -> Result<Vec<SnapMsg>> {
    let bytes = std::fs::read(path).context("no inbox snapshot — run `ce-mail inbox` first")?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn read_cursor(path: &std::path::Path) -> usize {
    std::fs::read_to_string(path).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0)
}

fn write_cursor(path: &std::path::Path, cursor: usize) -> Result<()> {
    std::fs::write(path, cursor.to_string())?;
    Ok(())
}

fn read_stdin() -> Result<Vec<u8>> {
    use std::io::Read;
    let mut buf = Vec::new();
    std::io::stdin().read_to_end(&mut buf)?;
    Ok(buf)
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n { s.to_string() } else { format!("{}…", &s[..n]) }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn default_data_dir() -> PathBuf {
    directories::ProjectDirs::from("", "", "ce-mail")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".ce-mail"))
}
