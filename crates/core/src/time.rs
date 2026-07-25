//! Clocks, intervals, and the TESLA security condition.
//!
//! # The check that everything rests on
//!
//! TESLA's security is not in the MAC. It is in knowing that a message arrived
//! **before** its authenticating key could have been public. Without that
//! check, an attacker waits for the sender to disclose `K[i]`, then forges
//! anything they like for interval `i`, and every receiver verifies it
//! perfectly.
//!
//! > Skipping the security condition makes the MAC meaningless.
//!
//! # What is here and what is not
//!
//! This module implements the *check* and the interval arithmetic it needs. It
//! does **not** implement the sources that produce a good time bound — GNSS,
//! peer exchange, beacon floors. That is Clock work. The bound arrives as an
//! input, and a caller supplying a dishonest one gets what it asked for.
//!
//! Splitting it this way is deliberate: the check is small, testable, and
//! finished, while the sources are an open research problem. Coupling them
//! would mean neither could be finished.
//!
//! See `docs/src/protocol/time.md`.

/// A bound on when something happened, in milliseconds on a shared timeline.
///
/// Never a point. Off-grid there is no source that yields one, and a protocol
/// that pretends otherwise is lying about its own security. `earliest` and
/// `latest` are the receiver's honest interval; the width is its uncertainty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeBound {
    /// Earliest possible instant.
    pub earliest_ms: u64,
    /// Latest possible instant.
    pub latest_ms: u64,
}

impl TimeBound {
    /// A bound of `center ± uncertainty`.
    pub fn new(center_ms: u64, uncertainty_ms: u64) -> Self {
        Self {
            earliest_ms: center_ms.saturating_sub(uncertainty_ms),
            latest_ms: center_ms.saturating_add(uncertainty_ms),
        }
    }

    /// A bound with no uncertainty at all.
    ///
    /// Only honest in tests and on a node with a live GNSS fix. Using this
    /// because a real bound was inconvenient defeats the entire mechanism.
    pub fn exact(t_ms: u64) -> Self {
        Self {
            earliest_ms: t_ms,
            latest_ms: t_ms,
        }
    }

    /// Width of the bound — the caller's uncertainty.
    pub fn width_ms(&self) -> u64 {
        self.latest_ms.saturating_sub(self.earliest_ms)
    }

    /// Intersect two bounds, keeping the tighter constraint from each side.
    ///
    /// This is how a peer with a GNSS fix tightens a peer without one.
    /// Intersection, not averaging: a lying peer can only widen the result or
    /// be ignored, never drag it. Returns `None` if the bounds are disjoint,
    /// which means at least one source is wrong and neither should be trusted.
    pub fn intersect(&self, other: &Self) -> Option<Self> {
        let earliest = self.earliest_ms.max(other.earliest_ms);
        let latest = self.latest_ms.min(other.latest_ms);
        (earliest <= latest).then_some(Self {
            earliest_ms: earliest,
            latest_ms: latest,
        })
    }
}

/// The interval and disclosure schedule a sender publishes and receivers follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Schedule {
    /// Timeline origin — interval 0 starts here.
    pub epoch_ms: u64,
    /// Length of one interval.
    pub interval_ms: u32,
    /// How many intervals a key is held before disclosure.
    ///
    /// Widening this buys tolerance for clock uncertainty at the cost of
    /// delaying verification. It is the knob Clock turns dynamically.
    pub disclosure_delay: u32,
}

impl Schedule {
    /// A schedule with 30-second intervals and a 2-interval delay.
    ///
    /// Provisional. Nobody has measured what interval length is right for a
    /// real mesh — too short wastes airtime on disclosures, too long delays
    /// verification past usefulness. See PROTOCOL.md §12.
    pub fn default_at(epoch_ms: u64) -> Self {
        Self {
            epoch_ms,
            interval_ms: 30_000,
            disclosure_delay: 2,
        }
    }

    /// Which interval contains `t_ms`. Times before the epoch clamp to 0.
    pub fn interval_at(&self, t_ms: u64) -> u32 {
        let elapsed = t_ms.saturating_sub(self.epoch_ms);
        (elapsed / self.interval_ms as u64).min(u32::MAX as u64) as u32
    }

    /// When interval `i` begins.
    pub fn interval_start_ms(&self, interval: u32) -> u64 {
        self.epoch_ms + interval as u64 * self.interval_ms as u64
    }

    /// The earliest instant at which the sender may disclose `K[interval]`.
    ///
    /// Everything after this moment is forgeable by anyone, which is exactly
    /// what [`security_condition`] exists to keep out.
    pub fn disclosure_ms(&self, interval: u32) -> u64 {
        self.interval_start_ms(interval + self.disclosure_delay)
    }
}

/// The TESLA security condition.
///
/// Accept a frame claiming `interval` only if it certainly arrived before the
/// sender could have disclosed that interval's key. Uncertainty counts against
/// the receiver: the *latest* possible arrival must still beat disclosure.
///
/// A receiver with no usable time bound cannot evaluate this and MUST treat
/// the frame as unauthenticated. Not "probably fine", not "accepted with a
/// warning" — unauthenticated.
pub fn security_condition(schedule: &Schedule, interval: u32, arrival: &TimeBound) -> bool {
    arrival.latest_ms < schedule.disclosure_ms(interval)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sched() -> Schedule {
        Schedule {
            epoch_ms: 1_000_000,
            interval_ms: 30_000,
            disclosure_delay: 2,
        }
    }

    #[test]
    fn interval_arithmetic_round_trips() {
        let s = sched();
        assert_eq!(s.interval_at(s.epoch_ms), 0);
        assert_eq!(s.interval_at(s.epoch_ms + 29_999), 0);
        assert_eq!(s.interval_at(s.epoch_ms + 30_000), 1);
        assert_eq!(s.interval_start_ms(3), s.epoch_ms + 90_000);
    }

    #[test]
    fn times_before_epoch_clamp() {
        // A node whose clock is behind the sender's epoch must not underflow
        // into a huge interval index.
        assert_eq!(sched().interval_at(0), 0);
    }

    #[test]
    fn fresh_frame_accepted() {
        let s = sched();
        // Sent during interval 5, arrives immediately. Disclosure is at the
        // start of interval 7.
        let arrival = TimeBound::exact(s.interval_start_ms(5) + 100);
        assert!(security_condition(&s, 5, &arrival));
    }

    #[test]
    fn frame_arriving_after_disclosure_rejected() {
        // This is the attack: replay a frame for interval 5 once K[5] is
        // public. It must not verify no matter how good the MAC is.
        let s = sched();
        let arrival = TimeBound::exact(s.disclosure_ms(5));
        assert!(!security_condition(&s, 5, &arrival));
        assert!(!security_condition(
            &s,
            5,
            &TimeBound::exact(s.disclosure_ms(5) + 1)
        ));
    }

    #[test]
    fn uncertainty_counts_against_the_receiver() {
        let s = sched();
        // Arrived one second before disclosure, but the receiver's clock could
        // be five seconds slow. It cannot rule out the unsafe case, so it must
        // reject.
        let center = s.disclosure_ms(5) - 1_000;
        assert!(security_condition(&s, 5, &TimeBound::exact(center)));
        assert!(!security_condition(&s, 5, &TimeBound::new(center, 5_000)));
    }

    #[test]
    fn wider_disclosure_delay_tolerates_more_uncertainty() {
        // The Clock knob: buy tolerance by holding keys longer.
        let tight = sched();
        let loose = Schedule {
            disclosure_delay: 10,
            ..tight
        };
        let arrival = TimeBound::new(tight.interval_start_ms(5) + 1_000, 60_000);
        assert!(!security_condition(&tight, 5, &arrival));
        assert!(security_condition(&loose, 5, &arrival));
    }

    #[test]
    fn intersect_takes_the_tighter_constraint() {
        let wide = TimeBound::new(1_000, 500);
        let tight = TimeBound::new(1_100, 50);
        let both = wide.intersect(&tight).unwrap();
        assert_eq!(
            both,
            TimeBound {
                earliest_ms: 1_050,
                latest_ms: 1_150
            }
        );
        assert!(both.width_ms() < wide.width_ms());
    }

    #[test]
    fn disjoint_bounds_intersect_to_nothing() {
        // One of these sources is lying or badly broken. Trust neither.
        let a = TimeBound::new(1_000, 10);
        let b = TimeBound::new(9_000, 10);
        assert!(a.intersect(&b).is_none());
    }
}
