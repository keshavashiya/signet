//! Author-owned last-write-wins fact store.
//!
//! # Why this is not a CRDT library
//!
//! Merging shared state across partitioned devices usually means Automerge,
//! Yjs, vector clocks, and a few thousand lines of machinery. Signet needs
//! none of it, because of one rule:
//!
//! > **An author may only write keys it owns.**
//!
//! Keys are `(author, kind)`. Nobody else can write your keys, so two writes
//! to the same key always come from the same author and are totally ordered by
//! that author's sequence number. Conflicts are structurally impossible. The
//! merge function is `seq > existing.seq`.
//!
//! This is also the *right* model for the domain, not just the cheap one.
//! "Bridge out at 5th St" is not global truth — it is Alice's claim. The UI
//! renders "3 people report bridge out", which is exactly the misinformation
//! resistance an emergency network needs. A CRDT that let three authors
//! collapse into one authoritative value would be actively worse.
//!
//! # Deliberate limits
//!
//! - No eviction. A long-lived node grows without bound; the app layer is
//!   expected to drop facts past their TTL. Move eviction in here once a real
//!   deployment shows the app layer getting it wrong.
//! - No persistence. Callers own durability.
//! - Sequence numbers are trusted only *after* the frame's authentication has
//!   been checked. This module has no crypto in it; feeding it unverified
//!   frames voids the ordering guarantee along with everything else.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Truncated cert fingerprint identifying who authored a fact.
pub type AuthorId = [u8; crate::wire::SENDER_LEN];

/// What a fact is about — status, position, resource need, and so on.
///
/// Kept as a plain `u16` rather than an enum so that a node running an older
/// build relays and stores kinds it does not understand. On a mesh you cannot
/// roll every device forward at once.
pub type FactKind = u16;

/// One author's current value for one kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fact {
    /// Author-local monotonic counter. Higher wins.
    pub seq: u64,
    /// Opaque payload. Encoding is the app layer's business.
    pub payload: Vec<u8>,
}

/// A merged view of every fact this node has heard.
#[derive(Debug, Clone, Default)]
pub struct Store {
    facts: BTreeMap<(AuthorId, FactKind), Fact>,
}

impl Store {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Merge an incoming fact.
    ///
    /// Returns `true` if it was applied, `false` if a same-or-newer value was
    /// already held. Rejecting equal sequence numbers keeps a replayed frame
    /// from resetting anything, and makes merge idempotent — which is what
    /// lets the same fact arrive by three different mesh paths harmlessly.
    pub fn merge(&mut self, author: AuthorId, kind: FactKind, seq: u64, payload: &[u8]) -> bool {
        match self.facts.get_mut(&(author, kind)) {
            Some(existing) if seq <= existing.seq => false,
            Some(existing) => {
                existing.seq = seq;
                existing.payload.clear();
                existing.payload.extend_from_slice(payload);
                true
            }
            None => {
                self.facts.insert(
                    (author, kind),
                    Fact {
                        seq,
                        payload: payload.to_vec(),
                    },
                );
                true
            }
        }
    }

    /// Current value for one author's fact kind.
    pub fn get(&self, author: &AuthorId, kind: FactKind) -> Option<&Fact> {
        self.facts.get(&(*author, kind))
    }

    /// Every author reporting a given kind, with their value.
    ///
    /// This is the "3 people report bridge out" query — the store never
    /// collapses independent claims into one, so the caller sees all of them.
    pub fn by_kind(&self, kind: FactKind) -> impl Iterator<Item = (&AuthorId, &Fact)> {
        self.facts
            .iter()
            .filter(move |((_, k), _)| *k == kind)
            .map(|((a, _), f)| (a, f))
    }

    /// Total number of stored facts.
    pub fn len(&self) -> usize {
        self.facts.len()
    }

    /// Whether the store holds nothing.
    pub fn is_empty(&self) -> bool {
        self.facts.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: AuthorId = [1; 8];
    const BOB: AuthorId = [2; 8];
    const STATUS: FactKind = 0;
    const POSITION: FactKind = 1;

    #[test]
    fn first_write_applies() {
        let mut s = Store::new();
        assert!(s.merge(ALICE, STATUS, 1, b"ok"));
        assert_eq!(s.get(&ALICE, STATUS).unwrap().payload, b"ok");
    }

    #[test]
    fn newer_sequence_wins() {
        let mut s = Store::new();
        s.merge(ALICE, STATUS, 1, b"ok");
        assert!(s.merge(ALICE, STATUS, 2, b"need help"));
        assert_eq!(s.get(&ALICE, STATUS).unwrap().payload, b"need help");
    }

    #[test]
    fn older_sequence_never_overwrites() {
        // The flood mesh delivers out of order routinely; a late-arriving
        // "I'm ok" must not erase a newer "need help".
        let mut s = Store::new();
        s.merge(ALICE, STATUS, 5, b"need help");
        assert!(!s.merge(ALICE, STATUS, 3, b"ok"));
        assert_eq!(s.get(&ALICE, STATUS).unwrap().payload, b"need help");
    }

    #[test]
    fn replay_of_same_sequence_rejected() {
        let mut s = Store::new();
        s.merge(ALICE, STATUS, 7, b"need help");
        assert!(!s.merge(ALICE, STATUS, 7, b"ok"));
        assert_eq!(s.get(&ALICE, STATUS).unwrap().payload, b"need help");
    }

    #[test]
    fn merge_is_idempotent_across_paths() {
        // Same fact arriving three ways must converge, not oscillate.
        let mut a = Store::new();
        let mut b = Store::new();
        for seq in [1, 3, 2] {
            a.merge(ALICE, STATUS, seq, b"x");
        }
        for seq in [3, 2, 1] {
            b.merge(ALICE, STATUS, seq, b"x");
        }
        assert_eq!(a.get(&ALICE, STATUS), b.get(&ALICE, STATUS));
    }

    #[test]
    fn authors_do_not_collide() {
        let mut s = Store::new();
        s.merge(ALICE, STATUS, 1, b"ok");
        s.merge(BOB, STATUS, 1, b"injured");
        assert_eq!(s.get(&ALICE, STATUS).unwrap().payload, b"ok");
        assert_eq!(s.get(&BOB, STATUS).unwrap().payload, b"injured");
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn kinds_do_not_collide() {
        let mut s = Store::new();
        s.merge(ALICE, STATUS, 1, b"ok");
        s.merge(ALICE, POSITION, 1, b"51.5,-0.1");
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn by_kind_preserves_independent_claims() {
        let mut s = Store::new();
        s.merge(ALICE, STATUS, 1, b"bridge out");
        s.merge(BOB, STATUS, 1, b"bridge out");
        assert_eq!(s.by_kind(STATUS).count(), 2);
        assert_eq!(s.by_kind(POSITION).count(), 0);
    }
}
