//! The Signet frame header.
//!
//! 13 bytes, fixed, no options, no TLVs. Every byte here is a byte the payload
//! does not get, on a link where the whole frame is ~200 bytes — so the header
//! stays boring and small on purpose.
//!
//! ```text
//! ┌────────┬──────────────────────┬──────────────┬─────────────┐
//! │ 0      │ 1..9                 │ 9..13        │ 13..        │
//! │ ver|cls│ sender fingerprint   │ interval     │ payload     │
//! │ 1 byte │ 8 bytes              │ 4 bytes (BE) │ …           │
//! └────────┴──────────────────────┴──────────────┴─────────────┘
//! ```
//!
//! The sender field is an 8-byte truncation of the operational cert hash, not
//! the cert itself. Certs are fetched once and cached forever, which is what
//! keeps a 1.6 KiB credential off a 200-byte link. See `PROTOCOL.md` §2.

use crate::{Error, Result};

/// Protocol version encoded in the high nibble of byte 0.
pub const VERSION: u8 = 1;

/// Fixed header length in bytes.
pub const HEADER_LEN: usize = 13;

/// Length of the truncated cert fingerprint that identifies a sender.
pub const SENDER_LEN: usize = 8;

/// What kind of authentication trailer follows the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Class {
    /// Routine traffic. Trailer is a 16-byte MAC, plus a 32-byte disclosed key
    /// on the first frame of each interval.
    Tesla = 0,
    /// Authoritative traffic. Trailer is a post-quantum signature.
    ///
    /// Rare by design: only messages that must survive third-party scrutiny
    /// later (evacuation orders, credentials) pay the several-hundred-byte
    /// cost. TESLA cannot serve these — it is repudiable after disclosure.
    Signed = 1,
    /// One erasure-coded piece of a larger object (cert, KEM key, signature).
    ///
    /// Fragments are forward-error-corrected rather than retransmitted: on a
    /// broadcast medium with no reliable back-channel, sending redundancy
    /// beats negotiating repairs.
    Fragment = 2,
}

impl Class {
    /// Map the low nibble of byte 0 to a class.
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Class::Tesla),
            1 => Ok(Class::Signed),
            2 => Ok(Class::Fragment),
            other => Err(Error::UnknownClass(other)),
        }
    }
}

/// A decoded Signet frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Authentication class of this frame.
    pub class: Class,
    /// Truncated fingerprint of the sender's operational cert.
    pub sender: [u8; SENDER_LEN],
    /// TESLA interval index this frame belongs to.
    pub interval: u32,
}

impl Header {
    /// Build a header at the current protocol version.
    pub fn new(class: Class, sender: [u8; SENDER_LEN], interval: u32) -> Self {
        Self {
            class,
            sender,
            interval,
        }
    }

    /// Serialise to the fixed 13-byte on-air form.
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0] = (VERSION << 4) | (self.class as u8);
        out[1..9].copy_from_slice(&self.sender);
        out[9..13].copy_from_slice(&self.interval.to_be_bytes());
        out
    }

    /// Parse a header off untrusted bytes, returning it and the remaining slice.
    ///
    /// Every failure mode here is reachable from the radio, so all of them are
    /// errors rather than panics or silent truncation.
    pub fn decode(buf: &[u8]) -> Result<(Self, &[u8])> {
        if buf.len() < HEADER_LEN {
            return Err(Error::Truncated {
                need: HEADER_LEN,
                got: buf.len(),
            });
        }
        let version = buf[0] >> 4;
        if version != VERSION {
            return Err(Error::UnknownVersion(version));
        }
        let class = Class::from_u8(buf[0] & 0x0F)?;

        let mut sender = [0u8; SENDER_LEN];
        sender.copy_from_slice(&buf[1..9]);

        let interval = u32::from_be_bytes([buf[9], buf[10], buf[11], buf[12]]);

        Ok((
            Self {
                class,
                sender,
                interval,
            },
            &buf[HEADER_LEN..],
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn header() -> Header {
        Header::new(Class::Tesla, [1, 2, 3, 4, 5, 6, 7, 8], 0x0DEF_ACED)
    }

    #[test]
    fn roundtrip_preserves_every_field() {
        let h = header();
        let raw = h.encode();
        let (decoded, rest) = Header::decode(&raw).unwrap();
        assert_eq!(decoded, h);
        assert!(rest.is_empty());
    }

    #[test]
    fn payload_survives_decode() {
        let mut frame: Vec<u8> = header().encode().to_vec();
        frame.extend_from_slice(b"need water");
        let (_, payload) = Header::decode(&frame).unwrap();
        assert_eq!(payload, b"need water");
    }

    #[test]
    fn header_is_thirteen_bytes() {
        // Airtime budget is the whole design constraint — this is a real assert,
        // not a tautology. Growing the header must be a deliberate decision.
        assert_eq!(header().encode().len(), 13);
    }

    #[test]
    fn short_buffer_rejected() {
        assert!(matches!(
            Header::decode(&[0u8; 5]),
            Err(Error::Truncated { need: 13, got: 5 })
        ));
    }

    #[test]
    fn future_version_rejected() {
        let mut raw = header().encode();
        raw[0] = (9 << 4) | (Class::Tesla as u8);
        assert!(matches!(
            Header::decode(&raw),
            Err(Error::UnknownVersion(9))
        ));
    }

    #[test]
    fn unknown_class_rejected() {
        let mut raw = header().encode();
        raw[0] = (VERSION << 4) | 0x0F;
        assert!(matches!(Header::decode(&raw), Err(Error::UnknownClass(15))));
    }

    #[test]
    fn all_classes_roundtrip() {
        for class in [Class::Tesla, Class::Signed, Class::Fragment] {
            let h = Header::new(class, [0; 8], 1);
            assert_eq!(Header::decode(&h.encode()).unwrap().0.class, class);
        }
    }
}
