//! Erasure-coded fragmentation.
//!
//! # Why not retransmission
//!
//! A broadcast mesh has no reliable back-channel. Asking for a repair means a
//! round trip through a flood network that may not have a return path at all,
//! and every published post-quantum-over-LoRa handshake that does this pays for
//! it: 28 to 62 frames for a single key exchange.
//!
//! Sending redundancy instead is strictly better here. Split an object into `k`
//! shards, transmit `n > k`, and **any `k` that arrive reconstruct it.** No
//! negotiation, no state at the sender, no round trip.
//!
//! # What gets fragmented
//!
//! Certs (~2.6 KiB) and `Signed` trailers (666 bytes at FN-DSA-512). Routine
//! TESLA traffic never fragments — that is the point of it fitting in one
//! frame.
//!
//! # Reed–Solomon, not hand-rolled XOR
//!
//! Single-parity XOR recovers exactly one erasure, which is a ceiling this
//! would hit immediately at realistic loss rates. GF(2⁸) Reed–Solomon handles
//! arbitrary redundancy, and it is the one piece of maths here where a subtle
//! bug corrupts silently rather than failing loudly — so it comes from a
//! reviewed crate rather than this file.
//!
//! Note that erasure coding is availability, not integrity: a wrongly
//! reconstructed object still fails its MAC or signature check. Nothing here
//! is load-bearing for security.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use reed_solomon_erasure::galois_8::ReedSolomon;

use crate::{Error, Result};

/// Bytes of fragment header preceding each shard.
///
/// ```text
/// [2B object_id][1B index][1B data_shards][1B total_shards][2B object_len]
/// ```
pub const FRAG_HEADER_LEN: usize = 7;

/// Hard cap from the 1-byte shard index.
pub const MAX_SHARDS: usize = 255;

/// Concurrent partially-received objects a [`Reassembler`] will track.
///
/// ponytail: fixed cap with lowest-id eviction. A real deployment that sees
/// more than eight objects in flight per peer should key eviction on arrival
/// order instead — but an unbounded map here is a trivial memory-exhaustion
/// attack from anyone with a radio.
pub const MAX_OBJECTS_IN_FLIGHT: usize = 8;

/// Split an object into transmittable fragments.
///
/// `shard_len` is the usable payload per frame after both the Signet header
/// and [`FRAG_HEADER_LEN`]. `redundancy_pct` of 30 sends roughly 30% extra
/// shards; at least one parity shard is always produced, because a coding
/// scheme with no redundancy is just fragmentation with extra steps.
pub fn split(
    object_id: u16,
    object: &[u8],
    shard_len: usize,
    redundancy_pct: u32,
) -> Result<Vec<Vec<u8>>> {
    if shard_len == 0 {
        return Err(Error::BadFragment);
    }
    if object.len() > u16::MAX as usize {
        return Err(Error::ObjectTooLarge(object.len()));
    }

    let data_shards = object.len().div_ceil(shard_len).max(1);
    let parity_shards = (data_shards * redundancy_pct as usize).div_ceil(100).max(1);
    if data_shards + parity_shards > MAX_SHARDS {
        return Err(Error::BadFragment);
    }

    let mut shards: Vec<Vec<u8>> = Vec::with_capacity(data_shards + parity_shards);
    for i in 0..data_shards {
        let start = i * shard_len;
        let end = (start + shard_len).min(object.len());
        let mut shard = vec![0u8; shard_len];
        shard[..end - start].copy_from_slice(&object[start..end]);
        shards.push(shard);
    }
    shards.extend((0..parity_shards).map(|_| vec![0u8; shard_len]));

    let rs = ReedSolomon::new(data_shards, parity_shards).map_err(|_| Error::BadFragment)?;
    rs.encode(&mut shards).map_err(|_| Error::BadFragment)?;

    let total = (data_shards + parity_shards) as u8;
    Ok(shards
        .into_iter()
        .enumerate()
        .map(|(i, shard)| {
            let mut out = Vec::with_capacity(FRAG_HEADER_LEN + shard_len);
            out.extend_from_slice(&object_id.to_be_bytes());
            out.push(i as u8);
            out.push(data_shards as u8);
            out.push(total);
            out.extend_from_slice(&(object.len() as u16).to_be_bytes());
            out.extend_from_slice(&shard);
            out
        })
        .collect())
}

/// A parsed fragment header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FragHeader {
    object_id: u16,
    index: u8,
    data_shards: u8,
    total_shards: u8,
    object_len: u16,
}

impl FragHeader {
    fn decode(buf: &[u8]) -> Result<(Self, &[u8])> {
        if buf.len() <= FRAG_HEADER_LEN {
            return Err(Error::Truncated {
                need: FRAG_HEADER_LEN + 1,
                got: buf.len(),
            });
        }
        let h = Self {
            object_id: u16::from_be_bytes([buf[0], buf[1]]),
            index: buf[2],
            data_shards: buf[3],
            total_shards: buf[4],
            object_len: u16::from_be_bytes([buf[5], buf[6]]),
        };
        // Every field is attacker-controlled. Reject anything self-inconsistent
        // before it reaches the allocator or the decoder.
        if h.data_shards == 0
            || h.total_shards < h.data_shards
            || h.index >= h.total_shards
            || h.object_len == 0
        {
            return Err(Error::BadFragment);
        }
        Ok((h, &buf[FRAG_HEADER_LEN..]))
    }
}

struct Partial {
    data_shards: u8,
    total_shards: u8,
    object_len: u16,
    shard_len: usize,
    shards: Vec<Option<Vec<u8>>>,
    have: usize,
}

/// Collects fragments until an object can be reconstructed.
#[derive(Default)]
pub struct Reassembler {
    objects: BTreeMap<u16, Partial>,
}

impl Reassembler {
    /// An empty reassembler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one fragment payload.
    ///
    /// Returns the object once enough shards have arrived, `None` while still
    /// waiting. A fragment whose header contradicts one already seen for the
    /// same object id is rejected rather than allowed to corrupt the set.
    pub fn push(&mut self, payload: &[u8]) -> Result<Option<Vec<u8>>> {
        let (h, shard) = FragHeader::decode(payload)?;

        let entry = match self.objects.get_mut(&h.object_id) {
            Some(p) => {
                if p.data_shards != h.data_shards
                    || p.total_shards != h.total_shards
                    || p.object_len != h.object_len
                    || p.shard_len != shard.len()
                {
                    return Err(Error::BadFragment);
                }
                p
            }
            None => {
                if self.objects.len() >= MAX_OBJECTS_IN_FLIGHT {
                    // Evict the lowest id to keep the map bounded. See the
                    // ponytail note on MAX_OBJECTS_IN_FLIGHT.
                    if let Some(&oldest) = self.objects.keys().next() {
                        self.objects.remove(&oldest);
                    }
                }
                self.objects.entry(h.object_id).or_insert(Partial {
                    data_shards: h.data_shards,
                    total_shards: h.total_shards,
                    object_len: h.object_len,
                    shard_len: shard.len(),
                    shards: vec![None; h.total_shards as usize],
                    have: 0,
                })
            }
        };

        if entry.shards[h.index as usize].is_none() {
            entry.shards[h.index as usize] = Some(shard.to_vec());
            entry.have += 1;
        }
        if entry.have < entry.data_shards as usize {
            return Ok(None);
        }

        let mut p = self.objects.remove(&h.object_id).expect("just borrowed it");
        let rs = ReedSolomon::new(
            p.data_shards as usize,
            (p.total_shards - p.data_shards) as usize,
        )
        .map_err(|_| Error::BadFragment)?;
        rs.reconstruct(&mut p.shards)
            .map_err(|_| Error::BadFragment)?;

        let mut object = Vec::with_capacity(p.object_len as usize);
        for shard in p.shards.iter().take(p.data_shards as usize) {
            object.extend_from_slice(shard.as_ref().ok_or(Error::BadFragment)?);
        }
        object.truncate(p.object_len as usize);
        Ok(Some(object))
    }

    /// Number of objects currently partially received.
    pub fn in_flight(&self) -> usize {
        self.objects.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn roundtrip_with_no_loss() {
        let obj = object(666);
        let frags = split(1, &obj, 200, 30).unwrap();
        let mut r = Reassembler::new();
        let mut out = None;
        for f in &frags {
            if let Some(o) = r.push(f).unwrap() {
                out = Some(o);
                break;
            }
        }
        assert_eq!(out.unwrap(), obj);
    }

    #[test]
    fn recovers_from_dropped_shards() {
        // 666 bytes at 200/shard = 4 data shards, 30% -> 2 parity, 6 total.
        // Dropping any 2 must still reconstruct.
        let obj = object(666);
        let frags = split(1, &obj, 200, 30).unwrap();
        assert_eq!(frags.len(), 6);

        for (a, b) in [(0, 1), (0, 5), (2, 3), (4, 5)] {
            let mut r = Reassembler::new();
            let mut out = None;
            for (i, f) in frags.iter().enumerate() {
                if i == a || i == b {
                    continue;
                }
                if let Some(o) = r.push(f).unwrap() {
                    out = Some(o);
                }
            }
            assert_eq!(out.expect("dropped {a},{b}"), obj, "dropping {a} and {b}");
        }
    }

    #[test]
    fn parity_only_is_enough() {
        // The strongest property: shards are interchangeable. Receiving the
        // last k of n reconstructs exactly as well as receiving the first k.
        let obj = object(600);
        let frags = split(7, &obj, 200, 100).unwrap(); // 3 data, 3 parity
        let mut r = Reassembler::new();
        let mut out = None;
        for f in frags.iter().skip(3) {
            if let Some(o) = r.push(f).unwrap() {
                out = Some(o);
            }
        }
        assert_eq!(out.unwrap(), obj);
    }

    #[test]
    fn too_much_loss_yields_nothing_rather_than_garbage() {
        let obj = object(666);
        let frags = split(1, &obj, 200, 30).unwrap();
        let mut r = Reassembler::new();
        for f in frags.iter().take(3) {
            assert!(r.push(f).unwrap().is_none());
        }
        assert_eq!(r.in_flight(), 1);
    }

    #[test]
    fn objects_smaller_than_one_shard_still_work() {
        let obj = object(10);
        let frags = split(1, &obj, 200, 30).unwrap();
        assert_eq!(frags.len(), 2); // 1 data + 1 forced parity
        let mut r = Reassembler::new();
        // Lose the data shard entirely; parity alone must rebuild it.
        assert_eq!(r.push(&frags[1]).unwrap().unwrap(), obj);
    }

    #[test]
    fn interleaved_objects_do_not_mix() {
        let (a, b) = (object(500), object(700));
        let (fa, fb) = (
            split(1, &a, 200, 30).unwrap(),
            split(2, &b, 200, 30).unwrap(),
        );
        let mut r = Reassembler::new();
        let (mut got_a, mut got_b) = (None, None);
        for i in 0..fa.len().max(fb.len()) {
            if let Some(f) = fa.get(i) {
                got_a = r.push(f).unwrap().or(got_a);
            }
            if let Some(f) = fb.get(i) {
                got_b = r.push(f).unwrap().or(got_b);
            }
        }
        assert_eq!(got_a.unwrap(), a);
        assert_eq!(got_b.unwrap(), b);
    }

    #[test]
    fn in_flight_map_is_bounded() {
        // An attacker sending one shard each for thousands of object ids must
        // not grow the map without limit.
        let mut r = Reassembler::new();
        for id in 0..1000u16 {
            let frags = split(id, &object(600), 200, 30).unwrap();
            r.push(&frags[0]).unwrap();
        }
        assert!(r.in_flight() <= MAX_OBJECTS_IN_FLIGHT);
    }

    #[test]
    fn inconsistent_headers_for_one_object_rejected() {
        let a = split(1, &object(600), 200, 30).unwrap();
        let b = split(1, &object(1200), 200, 30).unwrap();
        let mut r = Reassembler::new();
        r.push(&a[0]).unwrap();
        assert!(matches!(r.push(&b[0]), Err(Error::BadFragment)));
    }

    #[test]
    fn malformed_headers_rejected() {
        let mut f = split(1, &object(600), 200, 30).unwrap()[0].clone();
        assert!(Reassembler::new().push(&f[..FRAG_HEADER_LEN]).is_err());

        f[3] = 0; // data_shards = 0
        assert!(matches!(
            Reassembler::new().push(&f),
            Err(Error::BadFragment)
        ));

        let mut f = split(1, &object(600), 200, 30).unwrap()[0].clone();
        f[2] = 250; // index beyond total_shards
        assert!(matches!(
            Reassembler::new().push(&f),
            Err(Error::BadFragment)
        ));

        let mut f = split(1, &object(600), 200, 30).unwrap()[0].clone();
        f[3] = 200; // data_shards > total_shards
        assert!(matches!(
            Reassembler::new().push(&f),
            Err(Error::BadFragment)
        ));
    }

    #[test]
    fn oversized_objects_rejected() {
        let huge = vec![0u8; u16::MAX as usize + 1];
        assert!(matches!(
            split(1, &huge, 200, 30),
            Err(Error::ObjectTooLarge(_))
        ));
    }

    #[test]
    fn duplicate_shards_are_idempotent() {
        // A flood mesh delivers the same frame by several paths.
        let obj = object(600);
        let frags = split(1, &obj, 200, 30).unwrap();
        let mut r = Reassembler::new();
        assert!(r.push(&frags[0]).unwrap().is_none());
        assert!(r.push(&frags[0]).unwrap().is_none());
        assert!(r.push(&frags[1]).unwrap().is_none());
        assert_eq!(r.push(&frags[2]).unwrap().unwrap(), obj);
    }
}
