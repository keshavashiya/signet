//! The TESLA send and receive path.
//!
//! This is where the pieces compose: [`crate::wire`] frames carrying
//! [`crate::chain`] authentication, gated by [`crate::time`]'s security
//! condition, merged into [`crate::store`].
//!
//! # Frame body
//!
//! ```text
//! [13B wire header][1B flags][4B seq][2B kind][payload][16B MAC][32B disclosure?]
//! ```
//!
//! The MAC covers everything before it — header included, so a relay cannot
//! rewrite the sender fingerprint or the interval and still verify.
//!
//! # Disclosure is per-interval, not per-message
//!
//! A sender emitting five frames in one interval would otherwise disclose the
//! same key five times. Instead the 32-byte disclosure rides on the first frame
//! of each interval and later frames carry the 16-byte MAC alone.
//!
//! Presence is signalled by an explicit flag bit, not inferred from frame
//! length. Length-based inference is ambiguous whenever the payload size is not
//! known in advance, and guessing wrong in a security-critical parser is how
//! authentication bypasses happen. One byte is cheap insurance.
//!
//! Receivers do not care which frames carry a disclosure: a missed one is
//! recovered from any later one by hashing forward.
//!
//! # Why chain keys are 32 bytes and not 16
//!
//! Forging interval `i+1` from a disclosed `K[i]` is a preimage attack, so
//! preimage resistance protects every future interval. A 128-bit chain value
//! gives 64-bit resistance under Grover — not a defensible number for a
//! protocol whose entire premise is post-quantum. 32 bytes it is, and the
//! per-message cost stays at 16 because disclosure amortises across the
//! interval.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::chain::{self, Chain, ChainKey, Mac, KEY_LEN, MAC_LEN};
use crate::store::{AuthorId, FactKind, Store};
use crate::time::{security_condition, Schedule, TimeBound};
use crate::wire::{Class, Header, HEADER_LEN};
use crate::{Error, Result};

/// Body header: 1-byte flags, 4-byte sequence number, 2-byte fact kind.
pub const BODY_LEN: usize = 7;

/// Flag bit: a 32-byte key disclosure follows the MAC.
pub const FLAG_DISCLOSURE: u8 = 0b0000_0001;

/// Trailer length when only a MAC is carried.
pub const TRAILER_MAC: usize = MAC_LEN;

/// Trailer length when a key disclosure is attached.
pub const TRAILER_MAC_DISCLOSURE: usize = MAC_LEN + KEY_LEN;

/// Frames buffered per peer while awaiting a disclosure.
///
/// ponytail: fixed cap, oldest dropped. Unbounded buffering is a
/// memory-exhaustion attack from anyone with a transmitter. Make it adaptive
/// only if a real deployment shows legitimate senders exceeding it.
pub const MAX_PENDING: usize = 64;

/// Why a frame was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// Not a TESLA-class frame; this path does not handle it.
    WrongClass,
    /// No pinned cert for this sender fingerprint.
    UnknownSender,
    /// Failed the security condition — its key could already be public.
    TooLate,
    /// Attached disclosure did not chain to the anchor, or did not advance it.
    BadDisclosure,
}

/// What happened to a received frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Refused before anything was buffered.
    Rejected(Reject),
    /// Taken in. A frame can buffer itself and release earlier frames at once.
    Accepted {
        /// Whether any frame is still awaiting its key.
        buffered: bool,
        /// Buffered frames verified and merged by this frame's disclosure.
        merged: usize,
        /// Buffered frames whose MAC failed — forgeries, dropped.
        failed_mac: usize,
    },
}

/// Sending side of a TESLA session.
pub struct Sender {
    id: AuthorId,
    chain: Chain,
    schedule: Schedule,
    seq: u32,
    disclosed_in: Option<u32>,
}

impl Sender {
    /// Build a sender from its identity, key chain, and schedule.
    pub fn new(id: AuthorId, chain: Chain, schedule: Schedule) -> Self {
        Self {
            id,
            chain,
            schedule,
            seq: 0,
            disclosed_in: None,
        }
    }

    /// The commitment peers must pin before they can verify anything.
    pub fn commitment(&self) -> ChainKey {
        self.chain.commitment()
    }

    /// Sequence number most recently used.
    pub fn seq(&self) -> u32 {
        self.seq
    }

    /// Build an authenticated beacon frame.
    ///
    /// Sequence numbers advance per message and are what let a receiver drop
    /// replays and out-of-order deliveries. They are 32 bits on the wire: at
    /// one message every 30 seconds, exhausting them takes about 4000 years.
    pub fn beacon(&mut self, kind: FactKind, payload: &[u8], now_ms: u64) -> Result<Vec<u8>> {
        let interval = self.schedule.interval_at(now_ms);
        self.seq = self.seq.wrapping_add(1);

        // Disclose once per interval, and only once the schedule has advanced
        // far enough that a closed interval exists to reveal.
        //
        // Target 0 is excluded: K[0] is the commitment, already public in the
        // cert. Disclosing it conveys nothing and cannot advance a receiver's
        // anchor, which starts there — a receiver would correctly reject it as
        // non-advancing and drop an otherwise valid frame.
        let disclose = (self.disclosed_in != Some(interval))
            .then(|| interval.checked_sub(self.schedule.disclosure_delay))
            .flatten()
            .filter(|target| *target > 0);

        let mut frame = Vec::with_capacity(HEADER_LEN + BODY_LEN + payload.len() + TRAILER_MAC);
        frame.extend_from_slice(&Header::new(Class::Tesla, self.id, interval).encode());
        frame.push(if disclose.is_some() {
            FLAG_DISCLOSURE
        } else {
            0
        });
        frame.extend_from_slice(&self.seq.to_be_bytes());
        frame.extend_from_slice(&kind.to_be_bytes());
        frame.extend_from_slice(payload);

        let tag = chain::mac(&self.chain.mac_key(interval)?, &frame);
        frame.extend_from_slice(&tag);

        if let Some(target) = disclose {
            frame.extend_from_slice(&self.chain.key(target)?);
            self.disclosed_in = Some(interval);
        }
        Ok(frame)
    }
}

struct Pending {
    interval: u32,
    /// The exact bytes the MAC covers.
    authed: Vec<u8>,
    tag: Mac,
}

struct Peer {
    anchor: ChainKey,
    anchor_interval: u32,
    pending: Vec<Pending>,
}

/// Receiving side: verifies frames and merges them into a [`Store`].
pub struct Receiver {
    schedule: Schedule,
    peers: BTreeMap<AuthorId, Peer>,
    store: Store,
}

impl Receiver {
    /// A receiver with no peers pinned. It rejects everything until one is.
    pub fn new(schedule: Schedule) -> Self {
        Self {
            schedule,
            peers: BTreeMap::new(),
            store: Store::new(),
        }
    }

    /// Pin a peer's TESLA commitment, taken from a cert verified out of band.
    ///
    /// Nothing from an unpinned sender is ever accepted. Pinning a commitment
    /// heard over the air without checking its cert signature would defeat the
    /// entire identity model.
    pub fn add_peer(&mut self, id: AuthorId, tesla_root: ChainKey) {
        self.peers.insert(
            id,
            Peer {
                anchor: tesla_root,
                anchor_interval: 0,
                pending: Vec::new(),
            },
        );
    }

    /// The merged view of everything verified so far.
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Frames currently buffered for a peer, awaiting disclosure.
    pub fn pending(&self, id: &AuthorId) -> usize {
        self.peers.get(id).map_or(0, |p| p.pending.len())
    }

    /// Process one received frame.
    ///
    /// `arrival` is the receiver's *bounded* estimate of when this frame
    /// arrived, on the sender's timeline. Supplying an over-confident bound
    /// silently disables the only thing making the MAC meaningful — see
    /// [`crate::time`].
    pub fn recv(&mut self, frame: &[u8], arrival: TimeBound) -> Result<Outcome> {
        let (header, body) = Header::decode(frame)?;
        if header.class != Class::Tesla {
            return Ok(Outcome::Rejected(Reject::WrongClass));
        }
        if !self.peers.contains_key(&header.sender) {
            return Ok(Outcome::Rejected(Reject::UnknownSender));
        }
        if !security_condition(&self.schedule, header.interval, &arrival) {
            return Ok(Outcome::Rejected(Reject::TooLate));
        }

        let (tag, disclosure) = split_trailer(body)?;
        let authed = &frame[..frame.len() - trailer_len(disclosure.is_some())];

        // Validate any disclosure before buffering, so a frame carrying a
        // forged key is dropped whole rather than half-accepted.
        let advance = match disclosure {
            None => None,
            Some(key) => {
                let Some(target) = header.interval.checked_sub(self.schedule.disclosure_delay)
                else {
                    return Ok(Outcome::Rejected(Reject::BadDisclosure));
                };
                let peer = &self.peers[&header.sender];
                if !chain::verify_disclosure(&peer.anchor, peer.anchor_interval, target, &key) {
                    return Ok(Outcome::Rejected(Reject::BadDisclosure));
                }
                Some((target, key))
            }
        };

        let peer = self.peers.get_mut(&header.sender).expect("checked above");
        if peer.pending.len() >= MAX_PENDING {
            peer.pending.remove(0);
        }
        peer.pending.push(Pending {
            interval: header.interval,
            authed: authed.to_vec(),
            tag,
        });

        let Some((target, key)) = advance else {
            return Ok(Outcome::Accepted {
                buffered: true,
                merged: 0,
                failed_mac: 0,
            });
        };
        peer.anchor = key;
        peer.anchor_interval = target;

        let (merged, failed_mac) = drain(peer, &mut self.store);
        Ok(Outcome::Accepted {
            buffered: !peer.pending.is_empty(),
            merged,
            failed_mac,
        })
    }
}

/// Verify and merge every buffered frame whose key is now derivable.
fn drain(peer: &mut Peer, store: &mut Store) -> (usize, usize) {
    let (mut merged, mut failed) = (0, 0);
    let anchor = peer.anchor;
    let anchor_interval = peer.anchor_interval;

    peer.pending.retain(|p| {
        let Some(key) = chain::key_from_anchor(&anchor, anchor_interval, p.interval) else {
            return true; // still in the future; keep waiting
        };
        if !chain::verify_mac(&chain::derive_mac_key(&key), &p.authed, &p.tag) {
            failed += 1;
            return false;
        }
        match parse_body(&p.authed) {
            Some((author, seq, kind, payload)) => {
                if store.merge(author, kind, seq as u64, payload) {
                    merged += 1;
                }
            }
            None => failed += 1,
        }
        false
    });
    (merged, failed)
}

fn trailer_len(has_disclosure: bool) -> usize {
    if has_disclosure {
        TRAILER_MAC_DISCLOSURE
    } else {
        TRAILER_MAC
    }
}

/// Split the trailer off a frame body using the flag byte.
fn split_trailer(body: &[u8]) -> Result<(Mac, Option<ChainKey>)> {
    if body.is_empty() {
        return Err(Error::Truncated {
            need: BODY_LEN + TRAILER_MAC,
            got: 0,
        });
    }
    let has_disclosure = body[0] & FLAG_DISCLOSURE != 0;
    let need = BODY_LEN + trailer_len(has_disclosure);
    if body.len() < need {
        return Err(Error::Truncated {
            need,
            got: body.len(),
        });
    }

    let cut = body.len() - trailer_len(has_disclosure);
    let mut tag = [0u8; MAC_LEN];
    tag.copy_from_slice(&body[cut..cut + MAC_LEN]);

    let disclosure = has_disclosure.then(|| {
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&body[cut + MAC_LEN..]);
        key
    });
    Ok((tag, disclosure))
}

/// Pull author, sequence, kind and payload out of the MAC'd bytes.
fn parse_body(authed: &[u8]) -> Option<(AuthorId, u32, FactKind, &[u8])> {
    let (header, body) = Header::decode(authed).ok()?;
    if body.len() < BODY_LEN {
        return None;
    }
    let seq = u32::from_be_bytes([body[1], body[2], body[3], body[4]]);
    let kind = u16::from_be_bytes([body[5], body[6]]);
    Some((header.sender, seq, kind, &body[BODY_LEN..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: AuthorId = [0xA1; 8];
    const STATUS: FactKind = 0;
    const EPOCH: u64 = 1_000_000;

    fn schedule() -> Schedule {
        Schedule::default_at(EPOCH)
    }

    fn at(interval: u32) -> u64 {
        schedule().interval_start_ms(interval) + 100
    }

    fn pair() -> (Sender, Receiver) {
        let chain = Chain::from_seed(b"alice seed", 128);
        let commitment = chain.commitment();
        let sender = Sender::new(ALICE, chain, schedule());
        let mut receiver = Receiver::new(schedule());
        receiver.add_peer(ALICE, commitment);
        (sender, receiver)
    }

    #[test]
    fn beacon_fits_in_one_frame() {
        // The whole design rests on routine traffic being single-frame.
        // Worst case, carrying a disclosure:
        //   13 header + 7 body + 30 payload + 16 MAC + 32 key = 98 bytes.
        // Typical case, MAC only: 66. Both well inside Meshtastic's 237.
        let (mut s, _) = pair();
        let with_key = s.beacon(STATUS, &[0u8; 30], at(4)).unwrap();
        let mac_only = s.beacon(STATUS, &[0u8; 30], at(4)).unwrap();
        assert_eq!(with_key.len(), 98);
        assert_eq!(mac_only.len(), 66);
        assert!(
            with_key.len() <= 237,
            "a beacon no longer fits in one frame"
        );
    }

    #[test]
    fn disclosure_attaches_once_per_interval() {
        let (mut s, _) = pair();
        let a = s.beacon(STATUS, b"x", at(3)).unwrap();
        let b = s.beacon(STATUS, b"x", at(3)).unwrap();
        let c = s.beacon(STATUS, b"x", at(4)).unwrap();
        assert_eq!(a.len() - b.len(), KEY_LEN);
        assert_eq!(a.len(), c.len());
    }

    #[test]
    fn full_path_buffers_then_verifies() {
        let (mut s, mut r) = pair();

        // Interval 2's frame cannot verify yet — its key is not disclosed
        // until interval 4.
        let f2 = s.beacon(STATUS, b"need water", at(2)).unwrap();
        let out = r.recv(&f2, TimeBound::exact(at(2))).unwrap();
        assert!(matches!(
            out,
            Outcome::Accepted {
                buffered: true,
                merged: 0,
                ..
            }
        ));
        assert!(r.store().is_empty());

        // Interval 4 discloses K[2], releasing it.
        let f4 = s.beacon(STATUS, b"still here", at(4)).unwrap();
        let out = r.recv(&f4, TimeBound::exact(at(4))).unwrap();
        assert!(
            matches!(
                out,
                Outcome::Accepted {
                    merged: 1,
                    failed_mac: 0,
                    ..
                }
            ),
            "{out:?}"
        );
        assert_eq!(
            r.store().get(&ALICE, STATUS).unwrap().payload,
            b"need water"
        );
    }

    #[test]
    fn tampered_payload_fails_the_mac() {
        let (mut s, mut r) = pair();
        let mut f2 = s.beacon(STATUS, b"need water", at(2)).unwrap();
        f2[HEADER_LEN + BODY_LEN] ^= 0xFF;
        r.recv(&f2, TimeBound::exact(at(2))).unwrap();

        let f4 = s.beacon(STATUS, b"ok", at(4)).unwrap();
        let out = r.recv(&f4, TimeBound::exact(at(4))).unwrap();
        assert!(
            matches!(out, Outcome::Accepted { failed_mac: 1, .. }),
            "{out:?}"
        );
        assert!(r.store().get(&ALICE, STATUS).is_none());
    }

    #[test]
    fn rewriting_the_header_fails_the_mac() {
        // The MAC covers the header, so a relay cannot change the claimed
        // interval to slip a frame past the security condition.
        let (mut s, mut r) = pair();
        let mut f = s.beacon(STATUS, b"need water", at(2)).unwrap();
        f[12] = 3; // interval 2 -> 3
        r.recv(&f, TimeBound::exact(at(3))).unwrap();
        let f5 = s.beacon(STATUS, b"ok", at(5)).unwrap();
        let out = r.recv(&f5, TimeBound::exact(at(5))).unwrap();
        assert!(
            matches!(out, Outcome::Accepted { failed_mac: 1, .. }),
            "{out:?}"
        );
    }

    #[test]
    fn stripping_the_disclosure_flag_fails_the_mac() {
        // The flag byte is inside the MAC'd region, so flipping it to make the
        // parser mis-split the trailer cannot also produce a valid tag.
        let (mut s, mut r) = pair();
        let f2 = s.beacon(STATUS, b"need water", at(2)).unwrap();
        r.recv(&f2, TimeBound::exact(at(2))).unwrap();

        let mut f4 = s.beacon(STATUS, b"ok", at(4)).unwrap();
        f4[HEADER_LEN] &= !FLAG_DISCLOSURE;
        let out = r.recv(&f4, TimeBound::exact(at(4))).unwrap();
        // Parsed as MAC-only: no disclosure, so nothing is released and the
        // frame simply buffers. It can never verify — its own MAC now covers
        // different bytes than the sender signed.
        assert!(
            matches!(out, Outcome::Accepted { merged: 0, .. }),
            "{out:?}"
        );
        assert!(r.store().is_empty());
    }

    #[test]
    fn frame_arriving_after_disclosure_is_refused() {
        // The attack the whole security condition exists for.
        let (mut s, mut r) = pair();
        let f2 = s.beacon(STATUS, b"evacuate", at(2)).unwrap();
        let late = TimeBound::exact(schedule().disclosure_ms(2));
        assert_eq!(
            r.recv(&f2, late).unwrap(),
            Outcome::Rejected(Reject::TooLate)
        );
        assert_eq!(r.pending(&ALICE), 0);
    }

    #[test]
    fn unknown_sender_refused() {
        let (mut s, _) = pair();
        let mut r = Receiver::new(schedule());
        let f = s.beacon(STATUS, b"x", at(2)).unwrap();
        assert_eq!(
            r.recv(&f, TimeBound::exact(at(2))).unwrap(),
            Outcome::Rejected(Reject::UnknownSender)
        );
    }

    #[test]
    fn forged_disclosure_refused() {
        let (mut s, mut r) = pair();
        let mut f = s.beacon(STATUS, b"x", at(4)).unwrap();
        let n = f.len();
        f[n - KEY_LEN..].copy_from_slice(&[0xEE; KEY_LEN]);
        assert_eq!(
            r.recv(&f, TimeBound::exact(at(4))).unwrap(),
            Outcome::Rejected(Reject::BadDisclosure)
        );
    }

    #[test]
    fn a_different_chain_cannot_impersonate() {
        let (_, mut r) = pair();
        let evil = Chain::from_seed(b"mallory seed", 128);
        let mut s = Sender::new(ALICE, evil, schedule());
        let f = s.beacon(STATUS, b"evacuate north", at(4)).unwrap();
        assert_eq!(
            r.recv(&f, TimeBound::exact(at(4))).unwrap(),
            Outcome::Rejected(Reject::BadDisclosure)
        );
        assert!(r.store().is_empty());
    }

    #[test]
    fn lost_disclosures_recover_from_a_later_one() {
        // The key property: interval 2's disclosure is never received. Every
        // frame that would have carried it is lost, and K[2] is recovered by
        // hashing forward from a disclosure four intervals later.
        let (mut s, mut r) = pair();
        let f2 = s.beacon(STATUS, b"need water", at(2)).unwrap();
        for i in 3..=6 {
            let _ = s.beacon(STATUS, b"lost", at(i)).unwrap();
        }
        let f7 = s.beacon(STATUS, b"final", at(7)).unwrap();

        r.recv(&f2, TimeBound::exact(at(2))).unwrap();
        assert_eq!(r.pending(&ALICE), 1);

        // f7 discloses K[5]; hashing forward three times reaches K[2].
        let out = r.recv(&f7, TimeBound::exact(at(7))).unwrap();
        assert!(
            matches!(
                out,
                Outcome::Accepted {
                    merged: 1,
                    failed_mac: 0,
                    ..
                }
            ),
            "{out:?}"
        );
        assert_eq!(
            r.store().get(&ALICE, STATUS).unwrap().payload,
            b"need water"
        );
        // f7 itself is from interval 7, past the anchor at 5 — still waiting.
        assert_eq!(r.pending(&ALICE), 1);
    }

    #[test]
    fn out_of_order_frames_converge_on_the_newest() {
        let (mut s, mut r) = pair();
        let old = s.beacon(STATUS, b"ok", at(2)).unwrap();
        let new = s.beacon(STATUS, b"need help", at(3)).unwrap();
        let release = s.beacon(STATUS, b"x", at(6)).unwrap();

        // Deliver newest first, as a flood mesh routinely does.
        r.recv(&new, TimeBound::exact(at(3))).unwrap();
        r.recv(&old, TimeBound::exact(at(3))).unwrap();
        r.recv(&release, TimeBound::exact(at(6))).unwrap();

        // release discloses K[4], freeing intervals 2 and 3. Both verify, and
        // last-write-wins keeps the higher sequence number regardless of the
        // order they arrived in.
        assert_eq!(r.store().get(&ALICE, STATUS).unwrap().payload, b"need help");
        assert_eq!(r.pending(&ALICE), 1);
    }

    #[test]
    fn interval_zero_is_never_disclosed() {
        // K[0] is the commitment: already public, and non-advancing for a
        // receiver anchored there. Disclosing it would get the frame dropped.
        let (mut s, mut r) = pair();
        for i in 0..=2 {
            let f = s.beacon(STATUS, b"x", at(i)).unwrap();
            assert_eq!(f.len(), HEADER_LEN + BODY_LEN + 1 + TRAILER_MAC);
            let out = r.recv(&f, TimeBound::exact(at(i))).unwrap();
            assert!(
                matches!(out, Outcome::Accepted { merged: 0, .. }),
                "{out:?}"
            );
        }
        // Interval 3 discloses K[1] and is the first that can advance anything.
        let f3 = s.beacon(STATUS, b"x", at(3)).unwrap();
        assert_eq!(f3.len(), HEADER_LEN + BODY_LEN + 1 + TRAILER_MAC_DISCLOSURE);
    }

    #[test]
    fn pending_buffer_is_bounded() {
        let (mut s, mut r) = pair();
        for _ in 0..MAX_PENDING * 3 {
            let f = s.beacon(STATUS, b"x", at(2)).unwrap();
            r.recv(&f, TimeBound::exact(at(2))).unwrap();
        }
        assert_eq!(r.pending(&ALICE), MAX_PENDING);
    }

    #[test]
    fn structurally_truncated_frames_rejected() {
        let (mut s, mut r) = pair();
        let f = s.beacon(STATUS, b"x", at(4)).unwrap();
        for cut in [0, 5, HEADER_LEN, HEADER_LEN + 1, HEADER_LEN + BODY_LEN] {
            assert!(
                r.recv(&f[..cut], TimeBound::exact(at(4))).is_err(),
                "accepted a {cut}-byte frame"
            );
        }
    }

    #[test]
    fn a_one_byte_truncation_fails_authentication() {
        // Losing a single trailing byte is not structurally detectable — the
        // frame still parses. Authentication is what must catch it, and does.
        let (mut s, mut r) = pair();
        let f2 = s.beacon(STATUS, b"need water", at(2)).unwrap();
        r.recv(&f2, TimeBound::exact(at(2))).unwrap();

        let f4 = s.beacon(STATUS, b"ok", at(4)).unwrap();
        let out = r
            .recv(&f4[..f4.len() - 1], TimeBound::exact(at(4)))
            .unwrap();
        assert_eq!(out, Outcome::Rejected(Reject::BadDisclosure));
        assert!(r.store().is_empty());
    }

    #[test]
    fn wrong_class_rejected() {
        let (_, mut r) = pair();
        let mut frame = Header::new(Class::Signed, ALICE, 2).encode().to_vec();
        frame.extend_from_slice(&[0u8; BODY_LEN + MAC_LEN]);
        assert_eq!(
            r.recv(&frame, TimeBound::exact(at(2))).unwrap(),
            Outcome::Rejected(Reject::WrongClass)
        );
    }
}
