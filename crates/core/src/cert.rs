//! Operational certificates.
//!
//! # Two tiers, because one cannot be both
//!
//! Root keys must be cold — paper-backed, offline, used a handful of times
//! ever. Operational keys must be hot — on a device that may be seized, lost,
//! or dropped in a river. A single tier cannot satisfy both, so a root signs
//! short-lived operational certs and stays in a drawer.
//!
//! Key loss becomes survivable: the root re-issues. Device seizure becomes
//! contained: the operational cert expires.
//!
//! # No signatures in this module
//!
//! This crate holds no post-quantum primitives, so [`Cert`] handles *encoding*
//! only. It produces the to-be-signed bytes via [`Cert::tbs`] and carries an
//! opaque signature; `signet-crypto` signs and verifies. That split is what
//! keeps this crate `no_std` and hash-only.
//!
//! # Certs never touch the hot path
//!
//! A cert is roughly 2.6 KiB. Frames carry an 8-byte [`Cert::fingerprint`]
//! instead; a receiver missing the cert requests it once and caches it
//! forever. Distribution is out-of-band where possible — QR, NFC, a
//! pre-deployment roster file — which costs no airtime at all.
//!
//! # Revocation
//!
//! There is none. Offline revocation needs a status list, which needs the
//! network that is missing. Signet substitutes 30-day expiry, the same dodge
//! short-lived TLS certificates use. A compromised operational key stays valid
//! until it expires; this is a real weakness, stated rather than hidden.

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

use crate::chain::{ChainKey, KEY_LEN};
use crate::{Error, Result};

/// Certificate format version.
pub const CERT_VERSION: u8 = 1;

/// Bytes of fixed-position header before the first length-prefixed field.
const FIXED_LEN: usize = 48;

/// Signature suite identifier.
///
/// Explicit and one byte wide because the choice is not settled: FIPS 206 is
/// still draft and nine NIST round-3 candidates are in play, one of which has
/// a 204-byte signature that would change this protocol's economics. Algorithm
/// agility here costs one byte and saves a wire-format break later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Alg {
    /// FN-DSA-512 (Falcon-512). 897-byte public key, 666-byte signature.
    FnDsa512 = 1,
}

impl Alg {
    /// Map a wire byte to a suite.
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Alg::FnDsa512),
            other => Err(Error::UnknownAlg(other)),
        }
    }
}

/// What a holder is claiming to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum Role {
    /// No claim of authority.
    Civilian = 0,
    /// Verified responder.
    Responder = 1,
    /// Emergency operations centre. May issue authoritative broadcasts.
    Eoc = 2,
}

impl Role {
    /// Map wire role bits to a role. Unknown values degrade to `Civilian`
    /// rather than erroring: a future role must not make an old node reject an
    /// otherwise valid cert, it must only fail to grant privilege.
    pub fn from_u16(v: u16) -> Self {
        match v {
            1 => Role::Responder,
            2 => Role::Eoc,
            _ => Role::Civilian,
        }
    }
}

/// A signed operational certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cert {
    /// Signature suite for `sign_pubkey` and `sig`.
    pub alg: Alg,
    /// Truncated SHA-256 of the issuing root's verifying key.
    pub issuer: [u8; 8],
    /// Claimed role.
    pub role: Role,
    /// Expiry, as a beacon round number rather than wall-clock time.
    pub valid_until: u32,
    /// TESLA chain commitment, `K[0]`.
    pub tesla_root: ChainKey,
    /// Public key that verifies this holder's `Signed` frames.
    pub sign_pubkey: Vec<u8>,
    /// KEM public key. Empty when the holder does not accept private messages.
    pub kem_pubkey: Vec<u8>,
    /// Root signature over [`Cert::tbs`].
    pub sig: Vec<u8>,
}

impl Cert {
    /// The to-be-signed bytes: everything except the signature itself.
    pub fn tbs(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(FIXED_LEN + 4 + self.sign_pubkey.len() + self.kem_pubkey.len());
        out.push(CERT_VERSION);
        out.push(self.alg as u8);
        out.extend_from_slice(&self.issuer);
        out.extend_from_slice(&(self.role as u16).to_be_bytes());
        out.extend_from_slice(&self.valid_until.to_be_bytes());
        out.extend_from_slice(&self.tesla_root);
        push_field(&mut out, &self.sign_pubkey);
        push_field(&mut out, &self.kem_pubkey);
        out
    }

    /// Full encoding: `tbs || len(sig) || sig`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.tbs();
        push_field(&mut out, &self.sig);
        out
    }

    /// Parse a cert from untrusted bytes.
    ///
    /// Structural validity only. A decoded cert is **not** a trusted cert —
    /// `signet-crypto::verify_cert` must check the signature against a root
    /// the receiver already pinned.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < FIXED_LEN {
            return Err(Error::Truncated {
                need: FIXED_LEN,
                got: buf.len(),
            });
        }
        if buf[0] != CERT_VERSION {
            return Err(Error::UnknownVersion(buf[0]));
        }
        let alg = Alg::from_u8(buf[1])?;

        let mut issuer = [0u8; 8];
        issuer.copy_from_slice(&buf[2..10]);

        let role = Role::from_u16(u16::from_be_bytes([buf[10], buf[11]]));
        let valid_until = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);

        let mut tesla_root = [0u8; KEY_LEN];
        tesla_root.copy_from_slice(&buf[16..48]);

        let mut rest = &buf[FIXED_LEN..];
        let sign_pubkey = take_field(&mut rest)?;
        let kem_pubkey = take_field(&mut rest)?;
        let sig = take_field(&mut rest)?;

        if !rest.is_empty() {
            return Err(Error::TrailingBytes(rest.len()));
        }

        Ok(Self {
            alg,
            issuer,
            role,
            valid_until,
            tesla_root,
            sign_pubkey,
            kem_pubkey,
            sig,
        })
    }

    /// The 8-byte sender identifier carried in frame headers.
    ///
    /// SHA-256 over the full encoding, truncated. Covers the signature, so two
    /// certs differing only in signature are distinct identities — a re-issued
    /// cert is a new fingerprint, which is what makes rotation observable.
    pub fn fingerprint(&self) -> [u8; 8] {
        let digest = Sha256::digest(self.encode());
        let mut out = [0u8; 8];
        out.copy_from_slice(&digest[..8]);
        out
    }

    /// Whether the cert has expired as of `round`.
    pub fn is_valid_at(&self, round: u32) -> bool {
        round <= self.valid_until
    }
}

/// Truncated SHA-256 of a public key — the form used for `issuer`.
pub fn key_id(public_key: &[u8]) -> [u8; 8] {
    let digest = Sha256::digest(public_key);
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

fn push_field(out: &mut Vec<u8>, field: &[u8]) {
    // Callers construct certs from real key material, which is never near
    // 64 KiB. Truncating silently would produce a cert that verifies against
    // the wrong bytes, so saturate loudly-wrong instead: a length that does
    // not match the data fails to decode.
    out.extend_from_slice(&(field.len().min(u16::MAX as usize) as u16).to_be_bytes());
    out.extend_from_slice(field);
}

fn take_field(rest: &mut &[u8]) -> Result<Vec<u8>> {
    if rest.len() < 2 {
        return Err(Error::Truncated {
            need: 2,
            got: rest.len(),
        });
    }
    let len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
    if rest.len() < 2 + len {
        return Err(Error::Truncated {
            need: 2 + len,
            got: rest.len(),
        });
    }
    let field = rest[2..2 + len].to_vec();
    *rest = &rest[2 + len..];
    Ok(field)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn cert() -> Cert {
        Cert {
            alg: Alg::FnDsa512,
            issuer: [9; 8],
            role: Role::Eoc,
            valid_until: 1234,
            tesla_root: [7; KEY_LEN],
            sign_pubkey: vec![1; 897],
            kem_pubkey: vec![2; 1184],
            sig: vec![3; 666],
        }
    }

    #[test]
    fn roundtrip_preserves_every_field() {
        let c = cert();
        assert_eq!(Cert::decode(&c.encode()).unwrap(), c);
    }

    #[test]
    fn absent_kem_key_roundtrips() {
        // Receive-only nodes omit it and save 1184 bytes.
        let c = Cert {
            kem_pubkey: Vec::new(),
            ..cert()
        };
        let decoded = Cert::decode(&c.encode()).unwrap();
        assert!(decoded.kem_pubkey.is_empty());
        assert_eq!(decoded, c);
    }

    #[test]
    fn tbs_is_a_prefix_of_encode_and_excludes_the_signature() {
        let c = cert();
        let (tbs, enc) = (c.tbs(), c.encode());
        assert!(enc.starts_with(&tbs));
        assert_eq!(enc.len(), tbs.len() + 2 + c.sig.len());
        // Changing the signature must not change what was signed, or the
        // signature would cover itself.
        let other = Cert {
            sig: vec![0; 666],
            ..c.clone()
        };
        assert_eq!(other.tbs(), tbs);
    }

    #[test]
    fn fingerprint_covers_the_signature() {
        let c = cert();
        let resigned = Cert {
            sig: vec![4; 666],
            ..c.clone()
        };
        assert_ne!(c.fingerprint(), resigned.fingerprint());
    }

    #[test]
    fn fingerprint_is_stable() {
        assert_eq!(cert().fingerprint(), cert().fingerprint());
    }

    #[test]
    fn truncated_buffers_rejected_at_every_stage() {
        let enc = cert().encode();
        for cut in [0, 10, 47, FIXED_LEN, FIXED_LEN + 1, enc.len() - 1] {
            assert!(
                Cert::decode(&enc[..cut]).is_err(),
                "accepted a {cut}-byte cert"
            );
        }
    }

    #[test]
    fn trailing_bytes_rejected() {
        // A cert with junk appended must not decode — otherwise an attacker
        // can vary the fingerprint of an otherwise valid cert at will.
        let mut enc = cert().encode();
        enc.push(0);
        assert!(matches!(Cert::decode(&enc), Err(Error::TrailingBytes(1))));
    }

    #[test]
    fn unknown_version_and_alg_rejected() {
        let mut enc = cert().encode();
        enc[0] = 9;
        assert!(matches!(Cert::decode(&enc), Err(Error::UnknownVersion(9))));

        let mut enc = cert().encode();
        enc[1] = 200;
        assert!(matches!(Cert::decode(&enc), Err(Error::UnknownAlg(200))));
    }

    #[test]
    fn oversized_length_prefix_rejected() {
        // Claiming a 60000-byte key in a 2600-byte buffer must fail, not read
        // past the end.
        let mut enc = cert().encode();
        enc[FIXED_LEN] = 0xEA;
        enc[FIXED_LEN + 1] = 0x60;
        assert!(Cert::decode(&enc).is_err());
    }

    #[test]
    fn unknown_roles_degrade_to_civilian() {
        // A future role must fail to grant privilege, never fail to decode.
        assert_eq!(Role::from_u16(999), Role::Civilian);
        assert_eq!(Role::from_u16(2), Role::Eoc);
    }

    #[test]
    fn expiry_is_inclusive_of_the_final_round() {
        let c = cert();
        assert!(c.is_valid_at(1234));
        assert!(!c.is_valid_at(1235));
    }

    #[test]
    fn key_id_matches_issuer_derivation() {
        assert_eq!(
            key_id(b"a root verifying key"),
            key_id(b"a root verifying key")
        );
        assert_ne!(key_id(b"root a"), key_id(b"root b"));
    }
}
