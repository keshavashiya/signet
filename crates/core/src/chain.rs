//! TESLA hash chains — the cheap authentication path.
//!
//! # Why this exists
//!
//! A post-quantum signature costs 666 bytes (FN-DSA) to 2420 bytes (ML-DSA-44).
//! A LoRa frame carries about 200. Signing every message is not an option on
//! an off-grid mesh, which is why no off-grid mesh has post-quantum security
//! today.
//!
//! TESLA replaces the per-message signature with a MAC whose key is disclosed
//! *later*. The sender commits to the end of a one-way hash chain, MACs each
//! interval's traffic with a key only it knows, and reveals that key once the
//! interval has closed. A receiver that got the message before the key was
//! public knows nobody else could have forged it.
//!
//! Per-message cost: a 16-byte MAC, plus a 32-byte key disclosure on the first
//! frame of each interval. That trailer is **50x smaller** than an ML-DSA-44
//! signature, and it is post-quantum because it is nothing but SHA-256.
//!
//! # Chain orientation
//!
//! Generation hashes *down* from a secret seed; use walks *up*:
//!
//! ```text
//! seed ──H──> K[n] ──H──> K[n-1] ──H──> … ──H──> K[1] ──H──> K[0]
//!                                                            ▲
//!                                            commitment, published in the cert
//! ```
//!
//! Interval `i` uses `K[i]`. Disclosing `K[i]` lets anyone recompute every
//! `K[j]` for `j < i`, and nobody can compute `K[j]` for `j > i`.
//!
//! # Loss tolerance comes free
//!
//! Miss the disclosure for intervals 4, 5 and 6? Receiving `K[7]` recovers all
//! of them by hashing forward. That property is why TESLA fits a lossy
//! broadcast medium where a signature scheme would need retransmits.
//!
//! # What this does NOT give you
//!
//! TESLA is authenticated broadcast, **not** non-repudiation. Once `K[i]` is
//! public, anyone can forge interval `i` retroactively. It is correct for
//! routine traffic and wrong for authoritative traffic (evacuation orders,
//! credentials) — those take a real signature. See `PROTOCOL.md` §4.
//!
//! # Security condition
//!
//! Verification here is purely cryptographic. The *timing* half of TESLA —
//! rejecting a message that arrived after its key could have been public — is
//! the caller's job, because it depends on a clock this crate cannot see.
//! Skipping it makes the MAC meaningless. See `docs/src/protocol/time.md`.

use alloc::vec;
use alloc::vec::Vec;
use hmac::{Hmac, Mac as _};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

type HmacSha256 = Hmac<Sha256>;

/// Length of a chain key, in bytes.
pub const KEY_LEN: usize = 32;

/// Length of a truncated MAC on the wire, in bytes.
///
/// 16 bytes gives 128-bit forgery resistance, halved to 64 bits under a
/// Grover-style search — still far beyond what an attacker gains by forging a
/// single status beacon inside one disclosure interval.
pub const MAC_LEN: usize = 16;

/// A single link in a hash chain.
pub type ChainKey = [u8; KEY_LEN];

/// A truncated HMAC tag as carried on the wire.
pub type Mac = [u8; MAC_LEN];

/// Domain separator so a *disclosed* chain key can never be replayed as the
/// MAC key derived from it. Without this, publishing `K[i]` would publish the
/// key that authenticated interval `i`, and the whole scheme collapses.
const MAC_KEY_DOMAIN: &[u8] = b"signet/v1/mackey";

/// A generated one-way key chain, held by a sender.
///
/// Keys are stored rather than recomputed: a 4096-interval chain is 128 KiB,
/// which is nothing on a phone and affordable on an ESP32. Recomputing on
/// demand would cost O(n) hashes per send.
#[derive(Clone)]
pub struct Chain {
    /// `keys[0]` is the public commitment; `keys[i]` authenticates interval `i`.
    keys: Vec<ChainKey>,
}

impl Chain {
    /// Generate a chain of `intervals` usable keys from a secret seed.
    ///
    /// The seed must come from a CSPRNG. Chain length caps how long the
    /// identity can send before re-committing — at 30-second intervals, 4096
    /// intervals is a little over 34 hours.
    pub fn from_seed(seed: &[u8], intervals: u32) -> Self {
        let n = intervals as usize;
        let mut keys = vec![[0u8; KEY_LEN]; n + 1];
        keys[n] = Sha256::digest(seed).into();
        for i in (0..n).rev() {
            keys[i] = Sha256::digest(keys[i + 1]).into();
        }
        Self { keys }
    }

    /// The value published in the operational cert. Receivers anchor here.
    pub fn commitment(&self) -> ChainKey {
        self.keys[0]
    }

    /// Highest interval this chain can authenticate.
    pub fn max_interval(&self) -> u32 {
        (self.keys.len() - 1) as u32
    }

    /// The raw chain key for `interval`, which is what gets disclosed.
    pub fn key(&self, interval: u32) -> Result<ChainKey> {
        self.keys
            .get(interval as usize)
            .copied()
            .ok_or(Error::IntervalOutOfRange {
                interval,
                max: self.max_interval(),
            })
    }

    /// The MAC key for `interval`. Never disclose this — disclose [`key`] instead.
    ///
    /// [`key`]: Chain::key
    pub fn mac_key(&self, interval: u32) -> Result<ChainKey> {
        Ok(derive_mac_key(&self.key(interval)?))
    }
}

/// Derive the MAC key for an interval from its chain key.
pub fn derive_mac_key(k: &ChainKey) -> ChainKey {
    let mut h = Sha256::new();
    h.update(MAC_KEY_DOMAIN);
    h.update(k);
    h.finalize().into()
}

/// Authenticate `msg` under `mac_key`, truncated to [`MAC_LEN`].
pub fn mac(mac_key: &ChainKey, msg: &[u8]) -> Mac {
    let mut m = <HmacSha256 as hmac::KeyInit>::new_from_slice(mac_key)
        .expect("HMAC accepts keys of any length");
    m.update(msg);
    let full = m.finalize().into_bytes();
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&full[..MAC_LEN]);
    out
}

/// Constant-time check of a truncated MAC.
pub fn verify_mac(mac_key: &ChainKey, msg: &[u8], tag: &Mac) -> bool {
    let mut m = <HmacSha256 as hmac::KeyInit>::new_from_slice(mac_key)
        .expect("HMAC accepts keys of any length");
    m.update(msg);
    m.verify_truncated_left(tag).is_ok()
}

/// Verify a disclosed key against a previously trusted anchor.
///
/// `anchor` is either the commitment (`anchor_interval == 0`) or the most
/// recent key the receiver already verified. Hashing forward from `disclosed`
/// must land exactly on `anchor`, which simultaneously proves authenticity and
/// recovers every key skipped in between.
///
/// Returns `false` for a non-advancing interval: replaying an old disclosure
/// must never re-anchor a receiver backwards.
pub fn verify_disclosure(
    anchor: &ChainKey,
    anchor_interval: u32,
    interval: u32,
    disclosed: &ChainKey,
) -> bool {
    let Some(steps) = interval.checked_sub(anchor_interval).filter(|s| *s > 0) else {
        return false;
    };
    let mut cur = *disclosed;
    for _ in 0..steps {
        cur = Sha256::digest(cur).into();
    }
    // Chain keys become public by design, so a plain compare leaks nothing.
    cur == *anchor
}

/// Recover an earlier interval's key by hashing forward from a trusted anchor.
///
/// Once a receiver has verified `K[anchor_interval]`, every earlier key is
/// derivable — which is how buffered frames from intervals whose own
/// disclosure was lost still get verified. Returns `None` if `target` is not
/// earlier than the anchor, since future keys are exactly what the one-way
/// chain refuses to give up.
pub fn key_from_anchor(anchor: &ChainKey, anchor_interval: u32, target: u32) -> Option<ChainKey> {
    let steps = anchor_interval.checked_sub(target)?;
    let mut cur = *anchor;
    for _ in 0..steps {
        cur = Sha256::digest(cur).into();
    }
    Some(cur)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain() -> Chain {
        Chain::from_seed(b"test seed, not a real one", 64)
    }

    #[test]
    fn keys_recover_backwards_from_an_anchor() {
        let c = chain();
        let anchor = c.key(9).unwrap();
        assert_eq!(key_from_anchor(&anchor, 9, 9).unwrap(), c.key(9).unwrap());
        assert_eq!(key_from_anchor(&anchor, 9, 4).unwrap(), c.key(4).unwrap());
        assert_eq!(key_from_anchor(&anchor, 9, 0).unwrap(), c.commitment());
    }

    #[test]
    fn future_keys_are_not_derivable() {
        // The whole security property in one assertion.
        let c = chain();
        assert!(key_from_anchor(&c.key(9).unwrap(), 9, 10).is_none());
    }

    #[test]
    fn disclosure_verifies_against_commitment() {
        let c = chain();
        let k5 = c.key(5).unwrap();
        assert!(verify_disclosure(&c.commitment(), 0, 5, &k5));
    }

    #[test]
    fn gap_recovery_works() {
        // Receiver anchored at interval 3 misses 4, 5, 6 and receives 7.
        let c = chain();
        let anchor = c.key(3).unwrap();
        let k7 = c.key(7).unwrap();
        assert!(verify_disclosure(&anchor, 3, 7, &k7));
    }

    #[test]
    fn replay_and_rollback_rejected() {
        let c = chain();
        let anchor = c.key(9).unwrap();
        // Same interval — no advance.
        assert!(!verify_disclosure(&anchor, 9, 9, &anchor));
        // Older interval — must not re-anchor backwards.
        let k4 = c.key(4).unwrap();
        assert!(!verify_disclosure(&anchor, 9, 4, &k4));
    }

    #[test]
    fn forged_key_rejected() {
        let c = chain();
        assert!(!verify_disclosure(&c.commitment(), 0, 5, &[0xAA; KEY_LEN]));
    }

    #[test]
    fn keys_from_different_seeds_do_not_cross_verify() {
        let a = chain();
        let b = Chain::from_seed(b"a completely different seed", 64);
        assert!(!verify_disclosure(
            &a.commitment(),
            0,
            5,
            &b.key(5).unwrap()
        ));
    }

    #[test]
    fn mac_key_is_not_the_disclosed_key() {
        // If these were equal, disclosing an interval would hand an attacker
        // the key that authenticated it.
        let c = chain();
        assert_ne!(c.key(1).unwrap(), c.mac_key(1).unwrap());
    }

    #[test]
    fn mac_roundtrip_and_tamper_detection() {
        let c = chain();
        let mk = c.mac_key(2).unwrap();
        let tag = mac(&mk, b"bridge out at 5th st");
        assert!(verify_mac(&mk, b"bridge out at 5th st", &tag));
        assert!(!verify_mac(&mk, b"bridge open at 5th st", &tag));
        assert!(!verify_mac(
            &c.mac_key(3).unwrap(),
            b"bridge out at 5th st",
            &tag
        ));
    }

    #[test]
    fn interval_beyond_chain_is_an_error() {
        let c = chain();
        assert!(matches!(
            c.key(65),
            Err(Error::IntervalOutOfRange {
                interval: 65,
                max: 64
            })
        ));
    }
}
