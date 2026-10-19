# Time & the Security Condition

This is the hardest unsolved part of Signet and its main open research
question. It is documented at length because it is the piece an implementer is
most likely to get wrong, and the piece most worth attacking.

## Why TESLA needs a clock

TESLA's entire security rests on one fact: a receiver must know that a message
arrived **before** its authenticating key could have been public.

Without that check the scheme authenticates nothing. An attacker waits for the sender to disclose `K[i]`, then forges any message they
like for interval `i` and injects it. Every receiver verifies it perfectly.

> **Skipping the security condition makes the MAC meaningless.**

`signet-core::time` implements the check and the receive path in
`signet-core::session` runs it, but the time bound comes from the caller,
because the crate cannot see a clock. A caller that claims more certainty than
it has disables the check without any error.

## The condition

A receiver accepts a frame claiming interval `i` only if:

```text
t_arrival + uncertainty  <  t_interval_start(i) + d · interval_length
```

Where:

- `t_arrival` is the receiver's local timestamp on the frame
- `uncertainty` is the receiver's bound on its clock error *relative to the
  sender*
- `d` is the disclosure delay in intervals

If `uncertainty` cannot be bounded, the condition cannot be evaluated, and the
frame **must** be treated as unauthenticated, not accepted with a warning.

## Why this is hard off-grid

| Assumption that normally holds | Off-grid reality |
|---|---|
| NTP is reachable | No network at all; that is the premise |
| GNSS gives you time | Unavailable indoors and in urban canyons; spoofable outdoors |
| Device RTCs are roughly right | Phone RTCs drift; a cold-booted ESP32 has no idea what year it is |
| Clocks only move forward | A user can set the clock manually |

## Bounding uncertainty

Signet keeps a local monotonic clock and an explicit uncertainty interval,
tightened opportunistically from whatever sources are available. The interval
arithmetic is implemented; acquiring bounds from these sources is Clock work
and not built yet.

| Source | Bound | Availability | Trust |
|---|---|---|---|
| GNSS fix | ±µs | Outdoors, unjammed | Spoofable, but expensive to spoof locally |
| Peer exchange | Interval intersection | On any radio contact | Safe only among honest peers (see below) |
| Public beacon | Monotonic floor | Anyone who touched the internet recently | See caveat below |
| Local monotonic | Widens with elapsed time | Always | Self-consistent, absolutely unanchored |

### Peer exchange

This is the mesh-native answer. When two nodes come into range, which they must
do to exchange messages at all, they trade clock estimates *with their
uncertainty intervals* and take the intersection.

A node with a GNSS fix has a very tight interval and spreads that tightness to
the nodes it meets as it moves. A node that has been in a basement for two days has a
wide one and defers.

**That is only safe between honest peers.** Intersection never widens a bound
and never leaves your own, but inside your own a lying peer chooses where you
land, including somewhere the true time is not. Take a node whose honest bound
is the true time ±60 s, with the true time 10 s past the disclosure of `K[i]`:
it correctly refuses frames for interval `i`. A peer claiming a tight bound
that ends just before that disclosure overlaps it, so the intersection is not
empty, and it passes the security condition. One liar has reopened the
forgery window; averaging would be no better. Tolerating up to
`f` liars takes Marzullo's algorithm, which keeps the hull of the points that
at least `n − f` of the `n` bounds contain. Sybils leave `f` unbounded unless
only peers whose certs chain to a pinned root count as sources.

### Beacons

A public randomness beacon ([drand](https://drand.love), NIST's Randomness
Beacon, or the Bell-test-based [CURBy](https://random.colorado.edu)) publishes
unpredictable values on a fixed schedule. Because a value cannot be known
before its round, holding one proves **time has passed**:

```text
now ≥ round_time(latest beacon value I hold)
```

It is a *floor*, never a ceiling. It cannot prove that time has not passed.
Any node that touches the internet carries the newest value into the mesh,
where it floods as a public good.

> **Known gap.** drand signs with BLS12-381, which is not post-quantum. A
> quantum adversary could forge future beacon values. Fed to a receiver, a
> forged floor only makes it refuse frames too early: denial of service, not
> forgery, because a floor never lowers the `latest` bound the security
> condition reads. Fed to a sender, it moves the sender's clock forward, so the
> sender discloses keys while receivers with correct clocks still accept that
> interval, and that does break the security condition. Mitigation today: the
> beacon is never a sole authority, only one input intersected with local
> monotonic time. A hash-chain beacon would close this properly and is worth
> building.

## Degradation (planned)

Tracking uncertainty explicitly lets the protocol respond to it. This is the
planned behaviour; today `d` is fixed and a receiver without a usable bound
refuses the frame (`TooLate`), because the `Signed` send path the fallback
needs is not built.

```text
uncertainty small      →  d stays tight, TESLA, 16-48 bytes
uncertainty growing    →  widen d, buffering window lengthens
uncertainty > threshold →  fall back to Signed class, 666 bytes
no bound at all        →  send Signed; accept incoming as unauthenticated
```

The aim is to degrade rather than fail closed or, worse, silently accept
forgeries.

## The measurement that matters

Everything above is design. The number that decides whether it was a good
design is:

> **What fraction of real-world messages get the cheap path?**

If it is 95%, Signet's routine traffic is nearly free and the design holds. If
it is 40%, the fallback dominates, and a compact post-quantum signature should
be the default with TESLA as the optimisation.

That measurement is the Clock deliverable, and it needs real devices in real
conditions: indoors, moving, with GNSS coming and going. It cannot be simulated
convincingly, which is why it is not in `signet sim`.

## Open sub-problems

1. **Interval length.** 30 s is a provisional guess. Too short wastes airtime
   on disclosures; too long widens the buffering window and delays
   verification past usefulness.
2. **Cold start.** A device that has never had GNSS, a peer, or a beacon has
   no bound at all. It could send `Signed` frames but cannot verify any `Tesla`
   frame it receives. How long does that state last in practice?
3. **Adversarial peers.** One liar can steer an intersection anywhere inside
   your own bound (see [Peer exchange](#peer-exchange)). Marzullo's algorithm
   tolerates up to `f` liars, but only while `f` is bounded, and sybils
   unbound it. Which peers count as time sources, and what is the honest
   assumption about `f`?
4. **Clock rollback attacks.** If an attacker controls a device's RTC, do the
   monotonic guarantees survive a reboot?
