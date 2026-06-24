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
        /// Attach a file (repeatable). Each file is sealed E2E and stored as a lazy blob.
        #[arg(long = "attach", value_name = "PATH")]
        attach: Vec<PathBuf>,
        /// Seal the subject E2E too (the envelope shows only a redaction placeholder to a mailbox).
        #[arg(long)]
        seal_subject: bool,
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
        /// Path to persist the mailbox store (loaded on start, saved atomically as it changes).
        #[arg(long)]
        store: Option<PathBuf>,
        /// Seconds between on-chain revocation-set refreshes (a revoked grant takes effect within
        /// this window on a long-running mailbox).
        #[arg(long, default_value_t = 60)]
        revocation_refresh_secs: u64,
        /// Poll interval (ms) for inbound mail when no streaming subscription is available.
        #[arg(long, default_value_t = 500)]
        poll_ms: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
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
        Command::Send {
            to,
            subject,
            body,
            in_reply_to,
            mailbox,
            grant,
            postage,
            attach,
            seal_subject,
        } => {
            let body = match body {
                Some(b) => b.into_bytes(),
                None => read_stdin()?,
            };
            let grant_chain = match grant {
                Some(g) => decode_chain(&g).context("decode --grant")?,
                None => vec![],
            };
            let mut attachments = Vec::with_capacity(attach.len());
            for path in &attach {
                let bytes =
                    std::fs::read(path).with_context(|| format!("read attachment {}", path.display()))?;
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "attachment".to_string());
                attachments.push(ce_mail::Attachment::from_file(name, bytes));
            }
            let client = MailClient::new(identity, CeTransport::new(ce_rs::CeClient::new(cli.node)));
            let mid = client
                .send(SendOptions {
                    to,
                    subject,
                    body,
                    attachments,
                    in_reply_to,
                    seal_subject,
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
            // Persist the snapshot BEFORE advancing the cursor, so a crash never leaves a cursor
            // pointing past mail that `read` can no longer see.
            save_snapshot(&snapshot_path, &msgs)?;
            write_cursor(&cursor_path, cursor)?;
            if ack && cursor > start {
                let removed = client.ack(&mailbox, cursor, grant_chain).await.context("ack")?;
                tracing::info!(removed, "acked message(s)");
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
        Command::ServeMailbox { capacity, store, revocation_refresh_secs, poll_ms } => {
            serve_mailbox(
                identity,
                cli.node,
                capacity,
                store,
                revocation_refresh_secs,
                poll_ms.max(50),
            )
            .await
        }
    }
}

/// Run the mailbox request loop: poll inbound app messages on [`MAIL_TOPIC`], handle each, reply.
///
/// Hardening over the naive loop: persistence is **atomic** (temp-file + fsync + rename, never a
/// truncating in-place write) and is flushed at most once per drain batch only when the store
/// actually changed (a dirty flag) rather than after every message; the on-chain revocation set is
/// **refreshed** on an interval in a background task so a grant revoked after start takes effect;
/// poll failures back off with a cap; and all logging uses `tracing`.
async fn serve_mailbox(
    identity: Identity,
    node: String,
    capacity: usize,
    store_path: Option<PathBuf>,
    revocation_refresh_secs: u64,
    poll_ms: u64,
) -> Result<()> {
    use std::sync::Arc;
    use std::sync::Mutex;

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

    // Shared, periodically-refreshed revocation set so on-chain revocation takes effect on a
    // long-running mailbox (was previously captured once at startup and never updated).
    let revoked: Arc<Mutex<Vec<(String, u64)>>> =
        Arc::new(Mutex::new(ce.revoked().await.unwrap_or_default()));
    spawn_revocation_refresher(ce.clone(), revoked.clone(), revocation_refresh_secs.max(5));

    let is_revoked = {
        let revoked = revoked.clone();
        move |issuer: &ce_identity::NodeId, nonce: u64| {
            let issuer_hex = hex::encode(issuer);
            match revoked.lock() {
                Ok(set) => set.iter().any(|(i, n)| i == &issuer_hex && *n == nonce),
                // A poisoned lock should fail closed (treat as revoked) rather than honor a grant.
                Err(_) => true,
            }
        }
    };

    tracing::info!(
        node = %identity.node_id_hex(),
        topic = MAIL_TOPIC,
        "ce-mail mailbox serving"
    );
    tracing::info!("recipients must grant '{ABILITY_ACCEPT}' (see: ce-mail grant-mailbox)");

    let mut backoff_ms = poll_ms;
    let max_backoff_ms = 30_000u64;
    loop {
        let messages = match ce.messages().await {
            Ok(m) => {
                backoff_ms = poll_ms; // healthy poll resets the backoff.
                m
            }
            Err(e) => {
                tracing::warn!(error = %e, backoff_ms, "mailbox poll failed; backing off");
                tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(max_backoff_ms);
                continue;
            }
        };

        let mut dirty = false;
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
                Err(e) => {
                    tracing::debug!(error = %e, from = %msg.from, "ignoring malformed request");
                    continue;
                }
            };
            let mutates = request_mutates(&req);
            let reply = svc.handle(&requester, req, now_secs(), &is_revoked);
            // Only mark dirty when the request could have changed the store AND was not an error.
            if mutates && !matches!(reply, ce_mail::proto::MailReply::Error { .. }) {
                dirty = true;
            }
            if let Err(e) = ce.reply(token, &ce_mail::proto::MailReply::encode(&reply)).await {
                tracing::warn!(error = %e, "mailbox reply failed");
            }
        }

        // Persist once per batch, atomically, only when something changed.
        if dirty && let Some(p) = &store_path {
            match svc.store().try_to_bytes() {
                Ok(bytes) => {
                    if let Err(e) = ce_mail::persist::atomic_write(p, &bytes) {
                        tracing::error!(error = %e, path = %p.display(), "mailbox persist failed");
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "mailbox serialize failed; skipping persist");
                }
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(poll_ms)).await;
    }
}

/// Whether a request can mutate the store (so we only re-persist when it might have changed).
fn request_mutates(req: &MailRequest) -> bool {
    matches!(
        req,
        MailRequest::Deliver { .. }
            | MailRequest::Ack { .. }
            | MailRequest::PutReceipt { .. }
            | MailRequest::CollectReceipts { .. }
    )
}

/// Spawn a background task that refreshes the shared revocation set on an interval.
fn spawn_revocation_refresher(
    ce: ce_rs::CeClient,
    revoked: std::sync::Arc<std::sync::Mutex<Vec<(String, u64)>>>,
    every_secs: u64,
) {
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(every_secs));
        // Skip the immediate first tick (we already loaded the set once before spawning).
        interval.tick().await;
        loop {
            interval.tick().await;
            match ce.revoked().await {
                Ok(set) => {
                    if let Ok(mut guard) = revoked.lock() {
                        *guard = set;
                        tracing::debug!("revocation set refreshed");
                    }
                }
                Err(e) => tracing::warn!(error = %e, "revocation refresh failed; keeping last set"),
            }
        }
    });
}

/// Initialize tracing from `RUST_LOG` (default `info`), writing to stderr. Idempotent-safe: a second
/// call is a no-op because `try_init` returns an error we ignore.
fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
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
            m.subject()
        );
    }
}

fn save_snapshot(path: &std::path::Path, msgs: &[Message]) -> Result<()> {
    let snap: Vec<SnapMsg> = msgs
        .iter()
        .map(|m| SnapMsg {
            id: m.id(),
            from: m.envelope.body.from.clone(),
            subject: m.subject(),
            in_reply_to: m.envelope.body.in_reply_to.clone(),
            body: m.body_text(),
        })
        .collect();
    ce_mail::persist::atomic_write(path, &serde_json::to_vec_pretty(&snap)?)?;
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
    ce_mail::persist::atomic_write(path, cursor.to_string().as_bytes())?;
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
