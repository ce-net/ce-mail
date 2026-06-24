//! Attachments for ce-mail — sealed, content-addressed file payloads fetched lazily by CID.
//!
//! An attachment is modeled exactly like the message body: a `(filename, content-type, bytes)` tuple
//! that is **sealed** (E2E-encrypted to the recipient) and stored as a CE blob. The envelope carries
//! only the resulting CIDs (in `attachment_cids`), so a mailbox holding the envelope never sees the
//! attachment plaintext and a recipient never downloads a 40 MB file until they actually open it.
//!
//! The seal wraps the *whole* [`Attachment`] (name + content-type + bytes), so the filename and MIME
//! type are confidential too — unlike legacy email, where they ride in cleartext MIME headers. The
//! recipient recovers them with [`crate::client::MailClient::open_attachment`].

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

/// A single attachment: a named, typed byte payload. Cheap metadata, but the `bytes` can be large —
/// the whole struct is sealed and stored as one blob, fetched only on open.
///
/// ```
/// use ce_mail::Attachment;
/// // The content type is guessed from the extension; supply it explicitly with `new`.
/// let a = Attachment::from_file("report.pdf", vec![0x25, 0x50, 0x44, 0x46]);
/// assert_eq!(a.content_type, "application/pdf");
/// // It round-trips through the (deterministic) wire form that gets sealed.
/// let back = Attachment::decode(&a.encode().unwrap()).unwrap();
/// assert_eq!(a, back);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attachment {
    /// The original filename (e.g. `report.pdf`). Confidential — it is sealed with the bytes.
    pub filename: String,
    /// The MIME content type (e.g. `application/pdf`). Defaults to `application/octet-stream`.
    pub content_type: String,
    /// The raw file bytes.
    pub bytes: Vec<u8>,
}

impl Attachment {
    /// A new attachment with an explicit content type.
    pub fn new(
        filename: impl Into<String>,
        content_type: impl Into<String>,
        bytes: Vec<u8>,
    ) -> Self {
        Attachment {
            filename: filename.into(),
            content_type: content_type.into(),
            bytes,
        }
    }

    /// A new attachment, guessing the content type from the filename extension (falling back to
    /// `application/octet-stream`). Covers the handful of types a mail client meets most often; a
    /// caller that knows better should use [`Attachment::new`].
    pub fn from_file(filename: impl Into<String>, bytes: Vec<u8>) -> Self {
        let filename = filename.into();
        let content_type = guess_content_type(&filename).to_string();
        Attachment { filename, content_type, bytes }
    }

    /// Serialize the attachment to deterministic bytes (the plaintext that gets sealed).
    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow!("failed to encode attachment: {e}"))
    }

    /// Deserialize an attachment from the decrypted blob bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow!("malformed attachment: {e}"))
    }

    /// The attachment's size in bytes (of the payload, not the sealed blob).
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the attachment payload is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Guess a MIME content type from a filename extension. Deliberately small — an explicit
/// [`Attachment::new`] is preferred when the caller knows the type.
fn guess_content_type(filename: &str) -> &'static str {
    let ext = filename.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "txt" | "log" | "md" => "text/plain",
        "html" | "htm" => "text/html",
        "json" => "application/json",
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "zip" => "application/zip",
        "csv" => "text/csv",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let a = Attachment::new("a.bin", "application/octet-stream", vec![1, 2, 3, 4]);
        let back = Attachment::decode(&a.encode().unwrap()).unwrap();
        assert_eq!(a, back);
    }

    #[test]
    fn from_file_guesses_type() {
        assert_eq!(Attachment::from_file("report.pdf", vec![]).content_type, "application/pdf");
        assert_eq!(Attachment::from_file("photo.JPG", vec![]).content_type, "image/jpeg");
        assert_eq!(Attachment::from_file("notes.txt", vec![]).content_type, "text/plain");
        assert_eq!(Attachment::from_file("data", vec![]).content_type, "application/octet-stream");
    }

    #[test]
    fn len_and_is_empty() {
        assert!(Attachment::new("e", "text/plain", vec![]).is_empty());
        assert_eq!(Attachment::new("n", "text/plain", vec![9; 5]).len(), 5);
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(Attachment::decode(&[0xff, 0x00, 0x12]).is_err());
    }
}
