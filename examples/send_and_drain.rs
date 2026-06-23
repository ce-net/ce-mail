//! Minimal example: build a mail client against the local CE node, send a message directly, then
//! drain a mailbox. Requires a running CE node (`ce start`) on the default port.
//!
//! Run: `cargo run --example send_and_drain -- <recipient-hex> [mailbox-hex]`

use ce_identity::Identity;
use ce_mail::client::{CeTransport, MailClient, SendOptions};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let to = args.next().expect("usage: send_and_drain <recipient-hex> [mailbox-hex]");
    let mailbox = args.next();

    // Use a throwaway identity dir for the example; in a real app this is your stable key.
    let dir = std::env::temp_dir().join("ce-mail-example");
    let identity = Identity::load_or_generate(&dir)?;
    println!("our address (NodeId): {}", identity.node_id_hex());

    let client = MailClient::new(identity, CeTransport::local());

    let mid = client
        .send(SendOptions {
            to: to.clone(),
            subject: "hello from ce-mail".into(),
            body: b"This message is signed by me and sealed to you.".to_vec(),
            mailbox: mailbox.clone(),
            ..Default::default()
        })
        .await?;
    println!("sent message {mid}");

    // If we drain our own mailbox (when we are the recipient), show what's waiting.
    if let Some(mb) = mailbox {
        let (msgs, cursor) = client.drain_inbox(&mb, 0, vec![]).await?;
        println!("inbox has {} message(s) (cursor now {cursor})", msgs.len());
        for m in &msgs {
            println!("  {} | {} | {}", &m.id()[..16], m.envelope.body.subject, m.body_text());
        }
    }
    Ok(())
}
