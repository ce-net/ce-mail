//! Thread / conversation modeling for ce-mail.
//!
//! Real email threads two ways: an explicit reply pointer (`In-Reply-To` / `References`) and a
//! subject heuristic (`Re:`/`Fwd:` stripping). ce-mail's envelope carries an explicit
//! [`EnvelopeBody::in_reply_to`](crate::envelope::EnvelopeBody::in_reply_to) pointing at the parent
//! [`MessageId`], which is the authoritative link. This module turns a flat bag of envelopes into
//! conversations:
//!
//! * [`normalize_subject`] strips reply/forward prefixes so subject-grouped threads coalesce.
//! * [`thread_root`] resolves the root [`MessageId`] of a single envelope within a set, walking the
//!   `in_reply_to` chain (cycle-safe) up to the earliest reachable ancestor.
//! * [`Conversation`] groups envelopes that share a root into one ordered, deduplicated thread.
//! * [`group_threads`] partitions a set of envelopes into conversations.
//!
//! Threading is **pure metadata** over already-verified envelopes — it never needs the body, so an
//! inbox can render a threaded view without fetching a single (lazy) blob.

use crate::envelope::{Envelope, MessageId};
use std::collections::{HashMap, HashSet};

/// Reply/forward subject prefixes we strip when normalizing a subject for grouping. Case-insensitive,
/// allows an optional bracketed count (`Re[2]:`) like real mail clients emit.
const REPLY_PREFIXES: &[&str] = &["re", "fwd", "fw", "aw", "sv", "vs"];

/// Normalize a subject for subject-based threading: trim, then repeatedly strip leading reply/forward
/// prefixes (`Re:`, `Fwd:`, `RE[2]:`, …) and collapse internal whitespace runs to single spaces.
///
/// `"Re: Re: [2]  Hello   World"` and `"Fwd: hello world"` both normalize toward the same core so a
/// reply and its parent group together even when an explicit pointer is absent.
pub fn normalize_subject(subject: &str) -> String {
    let mut s = subject.trim();
    loop {
        let lower = s.to_ascii_lowercase();
        let mut stripped = false;
        for p in REPLY_PREFIXES {
            if let Some(rest) = strip_prefix_token(&lower, s, p) {
                s = rest;
                stripped = true;
                break;
            }
        }
        if !stripped {
            break;
        }
    }
    // Collapse whitespace and lowercase for a stable grouping key.
    s.split_whitespace().collect::<Vec<_>>().join(" ").to_ascii_lowercase()
}

/// If `lower` (the lowercased view of `orig`) begins with the prefix token `p` followed by an optional
/// `[n]` count and a `:`, return the remainder of `orig` after the prefix (trimmed). Otherwise `None`.
fn strip_prefix_token<'a>(lower: &str, orig: &'a str, p: &str) -> Option<&'a str> {
    let rest = lower.strip_prefix(p)?;
    // Optional bracketed count e.g. "[2]".
    let rest = if let Some(after) = rest.strip_prefix('[') {
        let close = after.find(']')?;
        if !after[..close].chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        &after[close + 1..]
    } else {
        rest
    };
    let rest = rest.strip_prefix(':')?;
    // Map the lowercased remainder length back onto the original string (same byte length, ASCII ops).
    let consumed = orig.len() - rest.len();
    Some(orig[consumed..].trim_start())
}

/// Build a lookup from message id to its `in_reply_to` parent for the given envelopes.
fn parent_map(envelopes: &[Envelope]) -> HashMap<MessageId, MessageId> {
    let mut m = HashMap::new();
    for e in envelopes {
        if !e.body.in_reply_to.is_empty() {
            m.insert(e.message_id(), e.body.in_reply_to.clone());
        }
    }
    m
}

/// Resolve the thread-root message id for `target`, walking `in_reply_to` links present in `parents`
/// (the [`parent_map`]) until an ancestor with no in-set parent is reached. Cycle-safe: a malformed
/// chain that loops stops at the first repeated id rather than spinning forever. If `target`'s parent
/// is not in the set (a reply whose parent we have not seen), `target`'s own declared parent id is the
/// root — preserving threading even across partial inboxes.
pub fn resolve_root(target: &MessageId, parents: &HashMap<MessageId, MessageId>) -> MessageId {
    let mut current = target.clone();
    let mut seen: HashSet<MessageId> = HashSet::new();
    seen.insert(current.clone());
    loop {
        match parents.get(&current) {
            Some(parent) => {
                if !seen.insert(parent.clone()) {
                    // Cycle: stop at the current node, the best-known root.
                    return current;
                }
                // If the parent itself is in the set we keep climbing; if not, the parent id is the
                // root of the (possibly truncated) thread.
                if parents.contains_key(parent) {
                    current = parent.clone();
                } else {
                    return parent.clone();
                }
            }
            None => return current,
        }
    }
}

/// The root message id of a single envelope, given the full set it lives in.
pub fn thread_root(envelope: &Envelope, envelopes: &[Envelope]) -> MessageId {
    let parents = parent_map(envelopes);
    resolve_root(&envelope.message_id(), &parents)
}

/// One conversation: every envelope sharing a thread root, ordered by `sent_at` (ties broken by
/// message id for determinism) and deduplicated by message id.
#[derive(Debug, Clone)]
pub struct Conversation {
    /// The root message id this conversation threads on.
    pub root: MessageId,
    /// The envelopes in the conversation, oldest first.
    pub messages: Vec<Envelope>,
}

impl Conversation {
    /// The number of messages in the conversation.
    pub fn len(&self) -> usize {
        self.messages.len()
    }
    /// Whether the conversation is empty (never true for a conversation returned by
    /// [`group_threads`], but provided for completeness).
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
    /// The most recent `sent_at` in the conversation (0 if empty), for sorting an inbox by activity.
    pub fn last_activity(&self) -> u64 {
        self.messages.iter().map(|e| e.body.sent_at).max().unwrap_or(0)
    }
    /// The subject of the root message (normalized), the conventional conversation title.
    pub fn subject(&self) -> String {
        self.messages
            .first()
            .map(|e| normalize_subject(&e.body.subject))
            .unwrap_or_default()
    }
}

/// Partition `envelopes` into [`Conversation`]s by thread root. Envelopes are deduplicated by message
/// id first (idempotent: the same message appearing twice does not duplicate it in a thread).
/// Conversations are returned sorted by most-recent activity, newest first — the natural inbox order.
pub fn group_threads(envelopes: &[Envelope]) -> Vec<Conversation> {
    // Deduplicate by message id, keeping first occurrence.
    let mut deduped: Vec<Envelope> = Vec::new();
    let mut seen: HashSet<MessageId> = HashSet::new();
    for e in envelopes {
        let mid = e.message_id();
        if seen.insert(mid) {
            deduped.push(e.clone());
        }
    }
    let parents = parent_map(&deduped);
    let mut by_root: HashMap<MessageId, Vec<Envelope>> = HashMap::new();
    for e in &deduped {
        let root = resolve_root(&e.message_id(), &parents);
        by_root.entry(root).or_default().push(e.clone());
    }
    let mut convs: Vec<Conversation> = by_root
        .into_iter()
        .map(|(root, mut messages)| {
            messages.sort_by(|a, b| {
                a.body
                    .sent_at
                    .cmp(&b.body.sent_at)
                    .then_with(|| a.message_id().cmp(&b.message_id()))
            });
            Conversation { root, messages }
        })
        .collect();
    convs.sort_by(|a, b| {
        b.last_activity()
            .cmp(&a.last_activity())
            .then_with(|| a.root.cmp(&b.root))
    });
    convs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::EnvelopeBody;
    use ce_identity::Identity;

    fn id(tag: &str) -> Identity {
        let dir = std::env::temp_dir().join(format!("ce-mail-thread-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Identity::load_or_generate(&dir).unwrap()
    }

    fn env(sender: &Identity, to: &str, subject: &str, in_reply_to: &str, sent_at: u64) -> Envelope {
        Envelope::seal(
            sender,
            EnvelopeBody {
                from: String::new(),
                to: to.to_string(),
                subject: subject.to_string(),
                body_cid: String::new(),
                attachment_cids: vec![],
                in_reply_to: in_reply_to.to_string(),
                sent_at,
                postage_receipt: String::new(),
            },
        )
    }

    // ---- normalize_subject ----

    #[test]
    fn normalize_strips_single_reply_prefix() {
        assert_eq!(normalize_subject("Re: Hello"), "hello");
        assert_eq!(normalize_subject("Fwd: Hello"), "hello");
        assert_eq!(normalize_subject("FW: Hello"), "hello");
    }

    #[test]
    fn normalize_strips_stacked_prefixes() {
        assert_eq!(normalize_subject("Re: Re: Fwd: Project"), "project");
    }

    #[test]
    fn normalize_strips_bracketed_count() {
        assert_eq!(normalize_subject("Re[2]: Status"), "status");
        assert_eq!(normalize_subject("RE[10]: Status"), "status");
    }

    #[test]
    fn normalize_collapses_whitespace_and_lowercases() {
        assert_eq!(normalize_subject("  Hello   World  "), "hello world");
    }

    #[test]
    fn normalize_leaves_plain_subject() {
        assert_eq!(normalize_subject("Quarterly review"), "quarterly review");
    }

    #[test]
    fn normalize_does_not_strip_words_that_merely_start_with_re() {
        // "Reminder" must not be mistaken for "Re:".
        assert_eq!(normalize_subject("Reminder: pay rent"), "reminder: pay rent");
    }

    #[test]
    fn normalize_rejects_malformed_bracket() {
        // "Re[x]:" has a non-numeric count -> not a reply prefix.
        assert_eq!(normalize_subject("Re[x]: hi"), "re[x]: hi");
    }

    #[test]
    fn normalize_empty_subject() {
        assert_eq!(normalize_subject(""), "");
        assert_eq!(normalize_subject("Re:"), "");
    }

    // ---- threading invariants ----

    #[test]
    fn single_message_is_its_own_root() {
        let s = id("t-root1");
        let r = id("t-root1r");
        let e = env(&s, &r.node_id_hex(), "hi", "", 1);
        let root = thread_root(&e, std::slice::from_ref(&e));
        assert_eq!(root, e.message_id());
    }

    #[test]
    fn reply_resolves_to_parent_root() {
        let s = id("t-r2");
        let r = id("t-r2r");
        let root_env = env(&s, &r.node_id_hex(), "topic", "", 1);
        let root_id = root_env.message_id();
        let reply = env(&r, &s.node_id_hex(), "Re: topic", &root_id, 2);
        let set = vec![root_env.clone(), reply.clone()];
        assert_eq!(thread_root(&reply, &set), root_id);
        assert_eq!(thread_root(&root_env, &set), root_id);
    }

    #[test]
    fn deep_chain_resolves_to_original_root() {
        let s = id("t-deep");
        let r = id("t-deepr");
        let m0 = env(&s, &r.node_id_hex(), "c", "", 1);
        let id0 = m0.message_id();
        let m1 = env(&r, &s.node_id_hex(), "Re: c", &id0, 2);
        let id1 = m1.message_id();
        let m2 = env(&s, &r.node_id_hex(), "Re: Re: c", &id1, 3);
        let set = vec![m0.clone(), m1.clone(), m2.clone()];
        assert_eq!(thread_root(&m2, &set), id0);
    }

    #[test]
    fn reply_to_unknown_parent_uses_declared_parent_as_root() {
        // We only have the reply, not its parent. The declared parent id is the root.
        let s = id("t-orphan");
        let r = id("t-orphanr");
        let phantom_parent = "ab".repeat(32);
        let reply = env(&s, &r.node_id_hex(), "Re: ghost", &phantom_parent, 5);
        assert_eq!(thread_root(&reply, std::slice::from_ref(&reply)), phantom_parent);
    }

    #[test]
    fn cyclic_chain_does_not_loop() {
        // Construct a synthetic parent map with a cycle a->b->a and assert resolve_root terminates.
        let mut parents = HashMap::new();
        parents.insert("a".to_string(), "b".to_string());
        parents.insert("b".to_string(), "a".to_string());
        let root = resolve_root(&"a".to_string(), &parents);
        assert!(root == "a" || root == "b");
    }

    #[test]
    fn group_threads_partitions_by_root() {
        let s = id("t-grp");
        let r = id("t-grpr");
        let a0 = env(&s, &r.node_id_hex(), "alpha", "", 1);
        let a0id = a0.message_id();
        let a1 = env(&r, &s.node_id_hex(), "Re: alpha", &a0id, 2);
        let b0 = env(&s, &r.node_id_hex(), "beta", "", 3);
        let set = vec![a0.clone(), a1.clone(), b0.clone()];
        let convs = group_threads(&set);
        assert_eq!(convs.len(), 2);
        // The alpha thread has 2, beta has 1.
        let alpha = convs.iter().find(|c| c.root == a0id).unwrap();
        assert_eq!(alpha.len(), 2);
        // Conversations ordered by last activity: beta (sent_at 3) is most recent.
        assert_eq!(convs[0].root, b0.message_id());
    }

    #[test]
    fn group_threads_is_idempotent_under_duplicates() {
        let s = id("t-dup");
        let r = id("t-dupr");
        let e = env(&s, &r.node_id_hex(), "once", "", 1);
        let set = vec![e.clone(), e.clone(), e.clone()];
        let convs = group_threads(&set);
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].len(), 1, "duplicates must not inflate the thread");
    }

    #[test]
    fn conversation_orders_messages_chronologically() {
        let s = id("t-ord");
        let r = id("t-ordr");
        let m0 = env(&s, &r.node_id_hex(), "c", "", 10);
        let id0 = m0.message_id();
        let m1 = env(&r, &s.node_id_hex(), "Re: c", &id0, 20);
        let id1 = m1.message_id();
        let m2 = env(&s, &r.node_id_hex(), "Re: c", &id1, 30);
        // Feed out of order.
        let set = vec![m2.clone(), m0.clone(), m1.clone()];
        let convs = group_threads(&set);
        assert_eq!(convs.len(), 1);
        let c = &convs[0];
        assert_eq!(c.messages[0].body.sent_at, 10);
        assert_eq!(c.messages[1].body.sent_at, 20);
        assert_eq!(c.messages[2].body.sent_at, 30);
        assert_eq!(c.last_activity(), 30);
    }

    #[test]
    fn empty_input_yields_no_conversations() {
        assert!(group_threads(&[]).is_empty());
    }
}
