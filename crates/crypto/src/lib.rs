//! Post-quantum signatures and certificate operations.
//!
//! Everything in Signet that needs a primitive larger than a hash function
//! lives here, so that [`signet_core`] can stay `no_std` and dependency-light.
//! The split is the reason the cheap authentication path runs on hardware the
//! expensive one never could.
//!
//! # Why FN-DSA-512
//!
//! The airtime model measured it: on a 237-byte link at 20% loss, a 666-byte FN-DSA signature
//! costs 12x the effective airtime of a TESLA trailer, while ML-DSA-44's
//! 2420-byte signature costs 31x. FN-DSA is the smallest signature on NIST's
//! finalised track, which makes it the right primitive for the rare messages
//! that genuinely need non-repudiation.
//!
//! The implementation is [`fn_dsa`] — pure Rust, `no_std`, by the author of the
//! Falcon reference code. No C toolchain, so `cargo test` keeps working with no
//! system dependencies.
//!
//! # Stability warning
//!
//! **FIPS 206 is still draft.** The upstream crate warns that key encodings,
//! pre-hashing, and domain separation may all change before the standard is
//! published, and keys generated today may not interoperate with it. Signet
//! carries an explicit [`Alg`] byte in every cert precisely so this is a
//! one-byte migration rather than a wire-format break. Do not treat certs
//! issued now as durable.
//!
//! # Why this crate is `std`
//!
//! Only key generation needs an OS entropy source; verification would run
//! happily on an ESP32. Splitting the verify path out is worth doing when
//! firmware verification actually lands (the Radio phase), and is not worth
//! the feature plumbing before then.
//!
//! # Two tiers, one key type
//!
//! Root and operational keys are the same kind of object. The tiering is about
//! *usage*, not type: a root key is a [`KeyPair`] you keep cold and touch a
//! handful of times, an operational key is one that lives on a phone and
//! expires in 30 days. Nothing here enforces that discipline, because nothing
//! here can.

#![forbid(unsafe_code)]

use fn_dsa::{
    sign_key_size, signature_size, vrfy_key_size, DomainContext, KeyPairGenerator,
    KeyPairGeneratorStandard, SigningKey, SigningKeyStandard, VerifyingKey, VerifyingKeyStandard,
    FN_DSA_LOGN_512, HASH_ID_RAW,
};
use signet_core::cert::{key_id, Alg, Cert, Role};
use signet_core::chain::ChainKey;

/// Domain separator for root signatures over operational certificates.
///
/// Distinct from [`DOMAIN_MESSAGE`] so a certificate signature can never be
/// replayed as a message signature, or the reverse.
pub const DOMAIN_CERT: DomainContext = DomainContext(b"signet/v1/cert");

/// Domain separator for signatures over `Signed`-class frames.
pub const DOMAIN_MESSAGE: DomainContext = DomainContext(b"signet/v1/msg");

/// Public key length for the implemented suite, in bytes.
pub const VRFY_KEY_LEN: usize = vrfy_key_size(FN_DSA_LOGN_512);

/// Private key length for the implemented suite, in bytes.
pub const SIGN_KEY_LEN: usize = sign_key_size(FN_DSA_LOGN_512);

/// Signature length for the implemented suite, in bytes.
pub const SIG_LEN: usize = signature_size(FN_DSA_LOGN_512);

/// Something a key operation refused to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Key bytes were the wrong length or failed to decode.
    BadKey,
    /// Certificate names a signature suite this build does not implement.
    UnsupportedAlg(Alg),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::BadKey => write!(f, "malformed key"),
            Error::UnsupportedAlg(a) => write!(f, "unsupported signature suite {a:?}"),
        }
    }
}

impl std::error::Error for Error {}

/// An FN-DSA-512 key pair.
#[derive(Clone)]
pub struct KeyPair {
    signing: Vec<u8>,
    verifying: Vec<u8>,
}

impl KeyPair {
    /// Generate a fresh key pair from OS entropy.
    pub fn generate() -> Self {
        let mut signing = vec![0u8; SIGN_KEY_LEN];
        let mut verifying = vec![0u8; VRFY_KEY_LEN];
        KeyPairGeneratorStandard::default().keygen(
            FN_DSA_LOGN_512,
            &mut rand_core::OsRng,
            &mut signing,
            &mut verifying,
        );
        Self { signing, verifying }
    }

    /// Reconstruct from stored halves, checking both decode.
    pub fn from_parts(signing: Vec<u8>, verifying: Vec<u8>) -> Result<Self, Error> {
        SigningKeyStandard::decode(&signing).ok_or(Error::BadKey)?;
        VerifyingKeyStandard::decode(&verifying).ok_or(Error::BadKey)?;
        Ok(Self { signing, verifying })
    }

    /// The public half, published in certs.
    pub fn verifying_key(&self) -> &[u8] {
        &self.verifying
    }

    /// The private half. Back this up cold; it is the identity.
    pub fn signing_key(&self) -> &[u8] {
        &self.signing
    }

    /// Truncated SHA-256 of the public half — the `issuer` field in certs.
    pub fn id(&self) -> [u8; 8] {
        key_id(&self.verifying)
    }

    /// Sign a message in the given domain.
    ///
    /// The signing key is decoded per call so this can take `&self`. Decoding
    /// costs a small fraction of signing itself, and the alternative is
    /// threading `&mut` through every caller of a fundamentally read-only
    /// operation.
    pub fn sign(&self, domain: &DomainContext, msg: &[u8]) -> Vec<u8> {
        let mut sk = SigningKeyStandard::decode(&self.signing)
            .expect("signing key was validated on construction");
        let mut sig = vec![0u8; signature_size(sk.get_logn())];
        sk.sign(&mut rand_core::OsRng, domain, &HASH_ID_RAW, msg, &mut sig);
        sig
    }

    /// Issue an operational certificate for `holder`.
    ///
    /// `self` is the root; keep it cold. `valid_until` is a beacon round
    /// number, not wall-clock time — see PROTOCOL.md §2.3 on why expiry substitutes
    /// for revocation.
    pub fn issue(
        &self,
        holder: &KeyPair,
        tesla_root: ChainKey,
        role: Role,
        valid_until: u32,
    ) -> Cert {
        let mut cert = Cert {
            alg: Alg::FnDsa512,
            issuer: self.id(),
            role,
            valid_until,
            tesla_root,
            sign_pubkey: holder.verifying_key().to_vec(),
            kem_pubkey: Vec::new(),
            sig: Vec::new(),
        };
        cert.sig = self.sign(&DOMAIN_CERT, &cert.tbs());
        cert
    }
}

/// Check a detached signature.
pub fn verify(verifying_key: &[u8], domain: &DomainContext, msg: &[u8], sig: &[u8]) -> bool {
    VerifyingKeyStandard::decode(verifying_key)
        .is_some_and(|vk| vk.verify(sig, domain, &HASH_ID_RAW, msg))
}

/// Check that a certificate was issued by the holder of `issuer_verifying_key`.
///
/// Both halves matter. The signature proves the issuer signed these bytes; the
/// `issuer` field check proves the cert *claims* the key being tested. Without
/// the second, a cert signed by a key you trust could name a different issuer
/// and be accepted under the wrong identity.
///
/// This says nothing about whether you should trust the issuer — that is the
/// caller's pinning decision — nor about expiry, which needs a clock. Use
/// [`Cert::is_valid_at`] for that.
pub fn verify_cert(cert: &Cert, issuer_verifying_key: &[u8]) -> Result<bool, Error> {
    if cert.alg != Alg::FnDsa512 {
        return Err(Error::UnsupportedAlg(cert.alg));
    }
    if cert.issuer != key_id(issuer_verifying_key) {
        return Ok(false);
    }
    Ok(verify(
        issuer_verifying_key,
        &DOMAIN_CERT,
        &cert.tbs(),
        &cert.sig,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_sizes_match_the_spec() {
        // PROTOCOL.md §10.1 and docs/src/protocol/sizes.md quote these. If the upstream
        // draft moves, this test is where it surfaces.
        assert_eq!(VRFY_KEY_LEN, 897);
        assert_eq!(SIG_LEN, 666);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let k = KeyPair::generate();
        let sig = k.sign(&DOMAIN_MESSAGE, b"evacuate north of 5th");
        assert!(verify(
            k.verifying_key(),
            &DOMAIN_MESSAGE,
            b"evacuate north of 5th",
            &sig
        ));
    }

    #[test]
    fn tampered_message_rejected() {
        let k = KeyPair::generate();
        let sig = k.sign(&DOMAIN_MESSAGE, b"evacuate north of 5th");
        assert!(!verify(
            k.verifying_key(),
            &DOMAIN_MESSAGE,
            b"evacuate south of 5th",
            &sig
        ));
    }

    #[test]
    fn wrong_key_rejected() {
        let (a, b) = (KeyPair::generate(), KeyPair::generate());
        let sig = a.sign(&DOMAIN_MESSAGE, b"x");
        assert!(!verify(b.verifying_key(), &DOMAIN_MESSAGE, b"x", &sig));
    }

    #[test]
    fn domains_do_not_cross() {
        // A cert signature must not be replayable as a message signature.
        let k = KeyPair::generate();
        let sig = k.sign(&DOMAIN_CERT, b"payload");
        assert!(verify(k.verifying_key(), &DOMAIN_CERT, b"payload", &sig));
        assert!(!verify(
            k.verifying_key(),
            &DOMAIN_MESSAGE,
            b"payload",
            &sig
        ));
    }

    #[test]
    fn issued_cert_verifies_against_its_root() {
        let (root, holder) = (KeyPair::generate(), KeyPair::generate());
        let cert = root.issue(&holder, [7; 32], Role::Eoc, 1000);
        assert!(verify_cert(&cert, root.verifying_key()).unwrap());
        assert_eq!(cert.sign_pubkey, holder.verifying_key());
        assert_eq!(cert.issuer, root.id());
    }

    #[test]
    fn cert_survives_a_wire_roundtrip() {
        let (root, holder) = (KeyPair::generate(), KeyPair::generate());
        let cert = root.issue(&holder, [7; 32], Role::Responder, 1000);
        let decoded = Cert::decode(&cert.encode()).unwrap();
        assert!(verify_cert(&decoded, root.verifying_key()).unwrap());
        assert_eq!(decoded.fingerprint(), cert.fingerprint());
    }

    #[test]
    fn cert_from_another_root_rejected() {
        let (root, evil, holder) = (
            KeyPair::generate(),
            KeyPair::generate(),
            KeyPair::generate(),
        );
        let cert = evil.issue(&holder, [7; 32], Role::Eoc, 1000);
        assert!(!verify_cert(&cert, root.verifying_key()).unwrap());
    }

    #[test]
    fn tampering_with_a_signed_field_invalidates_the_cert() {
        let (root, holder) = (KeyPair::generate(), KeyPair::generate());
        let cert = root.issue(&holder, [7; 32], Role::Civilian, 1000);

        // Promoting yourself to EOC is the attack that matters most.
        let promoted = Cert {
            role: Role::Eoc,
            ..cert.clone()
        };
        assert!(!verify_cert(&promoted, root.verifying_key()).unwrap());

        let extended = Cert {
            valid_until: u32::MAX,
            ..cert.clone()
        };
        assert!(!verify_cert(&extended, root.verifying_key()).unwrap());

        let swapped = Cert {
            tesla_root: [9; 32],
            ..cert.clone()
        };
        assert!(!verify_cert(&swapped, root.verifying_key()).unwrap());

        let rekeyed = Cert {
            sign_pubkey: KeyPair::generate().verifying_key().to_vec(),
            ..cert
        };
        assert!(!verify_cert(&rekeyed, root.verifying_key()).unwrap());
    }

    #[test]
    fn relabelled_issuer_rejected() {
        // A cert genuinely signed by `root` but claiming a different issuer
        // must not verify against that other identity.
        let (root, other, holder) = (
            KeyPair::generate(),
            KeyPair::generate(),
            KeyPair::generate(),
        );
        let mut cert = root.issue(&holder, [7; 32], Role::Eoc, 1000);
        cert.issuer = other.id();
        assert!(!verify_cert(&cert, other.verifying_key()).unwrap());
        assert!(!verify_cert(&cert, root.verifying_key()).unwrap());
    }

    #[test]
    fn malformed_keys_rejected_rather_than_panicking() {
        assert!(!verify(&[0u8; 10], &DOMAIN_MESSAGE, b"x", &[0u8; SIG_LEN]));
        assert!(KeyPair::from_parts(vec![0; 10], vec![0; 10]).is_err());
    }
}
