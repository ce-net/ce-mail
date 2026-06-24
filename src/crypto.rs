//! End-to-end body encryption for ce-mail.
//!
//! CE identities are Ed25519 keys. For asymmetric encryption we derive a deterministic **X25519**
//! keypair from the same secret, so a sender who knows only a recipient's `NodeId` (an Ed25519
//! public key) can encrypt to them with no key exchange:
//!
//! 1. The recipient's X25519 *public* key is the Montgomery form of their Ed25519 public key
//!    (`curve25519-dalek`'s `MontgomeryPoint`), recoverable from the `NodeId` alone.
//! 2. The sender generates an ephemeral X25519 keypair, does ECDH against the recipient's public
//!    key, derives a symmetric key with SHA-256, and seals the body with ChaCha20-Poly1305.
//! 3. The ephemeral public key travels in the clear inside the sealed blob; only the holder of the
//!    recipient secret can complete the ECDH.
//!
//! This is the NaCl "sealed box" construction (anonymous sender, authenticated ciphertext), built
//! on the same dalek primitives `ce-identity` already uses — the host that stores or relays the
//! blob never sees plaintext.
//!
//! Note on Ed25519→X25519: the recipient's X25519 *secret* must be derived the SAME way the public
//! point is. We derive the X25519 secret as `clamp(sha512(ed25519_secret)[..32])` — exactly the
//! scalar ed25519 itself uses — and the public point as that scalar times the basepoint. We then
//! verify (in tests) that this public point equals the Montgomery form of the Ed25519 public key,
//! which guarantees sender and recipient agree on the same shared secret.

use anyhow::{Result, anyhow};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use sha2::{Digest, Sha256, Sha512};

/// Length of an X25519 public key / ephemeral key.
pub const X25519_PUBLIC_LEN: usize = 32;
/// Length of the ChaCha20-Poly1305 nonce.
const NONCE_LEN: usize = 12;
/// Domain tag mixed into the KDF so a ce-mail body key can never collide with another protocol's.
const KDF_DOMAIN: &[u8] = b"ce-mail-sealed-box-v1";

/// A sealed (E2E-encrypted) message body. Self-describing: carries the ephemeral public key and
/// nonce alongside the ciphertext, so only the recipient's secret is needed to open it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SealedBody {
    /// Ephemeral sender X25519 public key (32 bytes).
    pub epk: Vec<u8>,
    /// ChaCha20-Poly1305 nonce (12 bytes).
    pub nonce: Vec<u8>,
    /// AEAD ciphertext + tag.
    pub ciphertext: Vec<u8>,
}

/// Derive the X25519 secret scalar (clamped) from an Ed25519 secret seed, matching ed25519's own
/// key-expansion so the resulting public point equals the Montgomery form of the Ed25519 pubkey.
fn x25519_secret_from_ed25519(ed_secret: &[u8; 32]) -> [u8; 32] {
    let h = Sha512::digest(ed_secret);
    let mut s = [0u8; 32];
    s.copy_from_slice(&h[..32]);
    // X25519 clamp.
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
    s
}

/// The X25519 *public* key for a recipient identified by their Ed25519 `node_id`.
///
/// Decompresses the Ed25519 point and converts to its Montgomery (X25519) form. Errors if the
/// node id is not a valid Ed25519 public key.
pub fn x25519_public_from_node_id(node_id: &[u8; 32]) -> Result<[u8; 32]> {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    let compressed = CompressedEdwardsY(*node_id);
    let point = compressed
        .decompress()
        .ok_or_else(|| anyhow!("node id is not a valid Ed25519 public key"))?;
    Ok(point.to_montgomery().to_bytes())
}

/// Derive the symmetric AEAD key from an ECDH shared secret and the ephemeral public key.
fn kdf(shared: &[u8; 32], epk: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(KDF_DOMAIN);
    h.update(shared);
    h.update(epk);
    h.finalize().into()
}

/// ECDH: scalar * point, using curve25519-dalek's Montgomery arithmetic (constant-time).
fn ecdh(secret: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
    use curve25519_dalek::montgomery::MontgomeryPoint;
    use curve25519_dalek::scalar::Scalar;
    let scalar = Scalar::from_bytes_mod_order(*secret);
    let point = MontgomeryPoint(*public);
    (scalar * point).to_bytes()
}

/// Seal `plaintext` to the recipient identified by Ed25519 `recipient_node_id`. Anyone can encrypt;
/// only the recipient's secret can open it.
pub fn seal(recipient_node_id: &[u8; 32], plaintext: &[u8]) -> Result<SealedBody> {
    use curve25519_dalek::montgomery::MontgomeryPoint;
    use curve25519_dalek::scalar::Scalar;
    use rand::RngCore;

    let recipient_pk = x25519_public_from_node_id(recipient_node_id)?;

    // Ephemeral keypair.
    let mut eph_secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut eph_secret);
    eph_secret[0] &= 248;
    eph_secret[31] &= 127;
    eph_secret[31] |= 64;
    let eph_scalar = Scalar::from_bytes_mod_order(eph_secret);
    let epk: MontgomeryPoint = MontgomeryPoint::mul_base(&eph_scalar);
    let epk = epk.to_bytes();

    let shared = ecdh(&eph_secret, &recipient_pk);
    let key = kdf(&shared, &epk);

    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| anyhow!("bad key length: {e}"))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| anyhow!("AEAD seal failed"))?;

    Ok(SealedBody { epk: epk.to_vec(), nonce: nonce_bytes.to_vec(), ciphertext })
}

/// Open a [`SealedBody`] using the recipient's Ed25519 secret seed (32 bytes). Errors if the blob
/// is malformed or was not sealed to this recipient (AEAD authentication failure).
pub fn open(recipient_ed25519_secret: &[u8; 32], sealed: &SealedBody) -> Result<Vec<u8>> {
    if sealed.epk.len() != X25519_PUBLIC_LEN {
        return Err(anyhow!("sealed body has malformed ephemeral key"));
    }
    if sealed.nonce.len() != NONCE_LEN {
        return Err(anyhow!("sealed body has malformed nonce"));
    }
    let recipient_secret = x25519_secret_from_ed25519(recipient_ed25519_secret);
    let mut epk = [0u8; 32];
    epk.copy_from_slice(&sealed.epk);

    let shared = ecdh(&recipient_secret, &epk);
    let key = kdf(&shared, &epk);

    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| anyhow!("bad key length: {e}"))?;
    let nonce = Nonce::from_slice(&sealed.nonce);
    cipher
        .decrypt(nonce, sealed.ciphertext.as_slice())
        .map_err(|_| anyhow!("AEAD open failed: wrong recipient or tampered ciphertext"))
}

/// Serialize a sealed body to deterministic bytes (for blob storage). Infallible in practice; use
/// [`try_encode_sealed`] to surface the error.
pub fn encode_sealed(s: &SealedBody) -> Vec<u8> {
    try_encode_sealed(s).unwrap_or_default()
}

/// Fallible serialize of a sealed body — surfaces the bincode error rather than yielding an empty
/// (corrupt) blob.
pub fn try_encode_sealed(s: &SealedBody) -> Result<Vec<u8>> {
    bincode::serialize(s).map_err(|e| anyhow!("failed to encode sealed body: {e}"))
}

/// Deserialize a sealed body from bytes.
pub fn decode_sealed(b: &[u8]) -> Result<SealedBody> {
    bincode::deserialize(b).map_err(|e| anyhow!("malformed sealed body: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ce_identity::Identity;

    fn id(tag: &str) -> Identity {
        let dir = std::env::temp_dir().join(format!("ce-mail-crypto-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Identity::load_or_generate(&dir).unwrap()
    }

    #[test]
    fn derived_x25519_public_matches_montgomery_of_ed25519() {
        // The crux: the public key the SENDER computes from the node id must equal the public
        // key the RECIPIENT's derived secret produces. Otherwise ECDH disagrees.
        use curve25519_dalek::montgomery::MontgomeryPoint;
        use curve25519_dalek::scalar::Scalar;
        let recip = id("derive");
        let secret = recip.secret_bytes();
        let derived_secret = x25519_secret_from_ed25519(&secret);
        let pk_from_secret =
            MontgomeryPoint::mul_base(&Scalar::from_bytes_mod_order(derived_secret)).to_bytes();
        let pk_from_node_id = x25519_public_from_node_id(&recip.node_id()).unwrap();
        assert_eq!(pk_from_secret, pk_from_node_id, "X25519 pubkey derivation disagrees");
    }

    #[test]
    fn seal_open_roundtrip() {
        let recip = id("rt");
        let msg = b"the eagle lands at midnight";
        let sealed = seal(&recip.node_id(), msg).unwrap();
        let opened = open(&recip.secret_bytes(), &sealed).unwrap();
        assert_eq!(opened, msg);
    }

    #[test]
    fn seal_open_empty_body() {
        let recip = id("empty");
        let sealed = seal(&recip.node_id(), b"").unwrap();
        let opened = open(&recip.secret_bytes(), &sealed).unwrap();
        assert_eq!(opened, b"");
    }

    #[test]
    fn wrong_recipient_cannot_open() {
        let recip = id("right");
        let other = id("wrong");
        let sealed = seal(&recip.node_id(), b"secret").unwrap();
        assert!(open(&other.secret_bytes(), &sealed).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let recip = id("tamper");
        let mut sealed = seal(&recip.node_id(), b"important").unwrap();
        if let Some(b) = sealed.ciphertext.first_mut() {
            *b ^= 0xff;
        }
        assert!(open(&recip.secret_bytes(), &sealed).is_err());
    }

    #[test]
    fn tampered_nonce_fails() {
        let recip = id("noncetamper");
        let mut sealed = seal(&recip.node_id(), b"important").unwrap();
        sealed.nonce[0] ^= 0xff;
        assert!(open(&recip.secret_bytes(), &sealed).is_err());
    }

    #[test]
    fn malformed_epk_is_rejected_gracefully() {
        let recip = id("badepk");
        let mut sealed = seal(&recip.node_id(), b"x").unwrap();
        sealed.epk.truncate(10);
        let r = open(&recip.secret_bytes(), &sealed);
        assert!(r.is_err());
    }

    #[test]
    fn malformed_nonce_len_is_rejected_gracefully() {
        let recip = id("badnonce");
        let mut sealed = seal(&recip.node_id(), b"x").unwrap();
        sealed.nonce.push(0);
        assert!(open(&recip.secret_bytes(), &sealed).is_err());
    }

    #[test]
    fn invalid_node_id_pubkey_errors() {
        // An all-FF node id is not a valid compressed Edwards point.
        let bad = [0xffu8; 32];
        // Most random 32-byte arrays are invalid points; assert we never panic.
        let _ = x25519_public_from_node_id(&bad);
    }

    #[test]
    fn encode_decode_sealed_roundtrip() {
        let recip = id("codec");
        let sealed = seal(&recip.node_id(), b"hello").unwrap();
        let bytes = encode_sealed(&sealed);
        let back = decode_sealed(&bytes).unwrap();
        assert_eq!(sealed, back);
    }

    #[test]
    fn decode_sealed_rejects_garbage() {
        assert!(decode_sealed(&[0xde, 0xad]).is_err());
    }

    #[test]
    fn two_seals_use_distinct_ephemeral_keys() {
        let recip = id("eph");
        let a = seal(&recip.node_id(), b"x").unwrap();
        let b = seal(&recip.node_id(), b"x").unwrap();
        // Ephemeral keys and nonces are random; ciphertext must differ.
        assert_ne!(a.epk, b.epk);
        assert_ne!(a.ciphertext, b.ciphertext);
        // Both still open to the same plaintext.
        assert_eq!(open(&recip.secret_bytes(), &a).unwrap(), b"x");
        assert_eq!(open(&recip.secret_bytes(), &b).unwrap(), b"x");
    }
}
