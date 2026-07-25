//! Signet core — the parts of the protocol that are pure logic.
//!
//! This crate deliberately contains **no cryptographic primitives beyond a
//! hash function**. That is not an oversight; it is the thesis. Signet's cheap
//! authentication path (see [`chain`]) is built entirely from SHA-256, which
//! makes it post-quantum by construction and lets it run on a microcontroller
//! that could never afford a lattice signature per message.
//!
//! Post-quantum signatures and KEMs (the expensive path) live outside this
//! crate and are selected by measurement — see `docs/roadmap`. Nothing here
//! depends on that choice.
//!
//! # Layout
//!
//! - [`chain`]   — TESLA hash chains: key derivation, disclosure, verification
//! - [`wire`]    — the 13-byte frame header shared by every Signet message
//! - [`cert`]    — operational certificate encoding (no signatures here)
//! - [`time`]    — clocks with explicit uncertainty, and the security condition
//! - [`frag`]    — erasure-coded fragmentation for multi-frame objects
//! - [`session`] — the composed send and receive path
//! - [`store`]   — author-owned last-write-wins fact store
//!
//! # no_std
//!
//! Everything here works under `no_std` + `alloc`. Do not add a `std`-only
//! dependency to this crate; the ESP32 target is a hard requirement, not an
//! aspiration.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod cert;
pub mod chain;
pub mod frag;
pub mod session;
pub mod store;
pub mod time;
pub mod wire;

pub use cert::{Alg, Cert, Role};
pub use chain::{Chain, ChainKey, Mac};
pub use session::{Outcome, Receiver, Reject, Sender};
pub use store::{AuthorId, Fact, Store};
pub use time::{Schedule, TimeBound};
pub use wire::{Class, Header, HEADER_LEN, VERSION};

/// Errors produced when decoding untrusted bytes off the air.
///
/// Everything that crosses the radio boundary is hostile until proven
/// otherwise, so decode failures are values, never panics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Buffer was shorter than the structure it claimed to hold.
    Truncated {
        /// Bytes required.
        need: usize,
        /// Bytes available.
        got: usize,
    },
    /// Protocol version is not one this build understands.
    UnknownVersion(u8),
    /// Message class byte does not map to a known [`Class`].
    UnknownClass(u8),
    /// Requested interval lies outside the generated chain.
    IntervalOutOfRange {
        /// Interval that was asked for.
        interval: u32,
        /// Highest interval this chain can serve.
        max: u32,
    },
    /// Signature suite identifier is not one this build understands.
    UnknownAlg(u8),
    /// Structure decoded correctly but bytes remained.
    ///
    /// Rejected rather than ignored: trailing junk would let an attacker vary
    /// a cert's fingerprint without touching what the signature covers.
    TrailingBytes(usize),
    /// Fragment header is self-inconsistent, or contradicts one already seen.
    BadFragment,
    /// Object exceeds the 64 KiB the fragment header can describe.
    ObjectTooLarge(usize),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Truncated { need, got } => {
                write!(f, "truncated frame: need {need} bytes, got {got}")
            }
            Error::UnknownVersion(v) => write!(f, "unknown protocol version {v}"),
            Error::UnknownClass(c) => write!(f, "unknown message class {c}"),
            Error::IntervalOutOfRange { interval, max } => {
                write!(f, "interval {interval} out of range (max {max})")
            }
            Error::UnknownAlg(a) => write!(f, "unknown signature suite {a}"),
            Error::TrailingBytes(n) => write!(f, "{n} trailing bytes after structure"),
            Error::BadFragment => write!(f, "inconsistent fragment header"),
            Error::ObjectTooLarge(n) => write!(f, "object of {n} bytes exceeds 65535"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Convenience alias for fallible decode paths.
pub type Result<T> = core::result::Result<T, Error>;
