# Time & the Security Condition

This is the hardest unsolved part of Signet and the project's main research
contribution. It is documented here at length because it is the piece most
likely to be got wrong by an implementer, and the piece most worth attacking.

## Why TESLA needs a clock

TESLA's entire security rests on one fact: a receiver must know that a message
arrived **before** its authenticating key could have been public.

Without that check, the scheme is not merely weaker — it is worthless. An
attacker waits for the sender to disclose `K[i]`, then forges any message they
like for interval `i` and injects it. Every receiver verifies it perfectly.

> **Skipping the security condition makes the MAC meaningless.**

`signet-core::chain` deliberately does not implement this check, because it
depends on a clock the crate cannot see. The caller owns it. The module
documentation says so loudly, and so does this page.

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
frame **must** be treated as unauthenticated. Not "probably fine". Not
"accepted with a warning icon". Unauthenticated.

## Why this is hard off-grid

| Assumption that normally holds | Off-grid reality |
|---|---|
| NTP is reachable | No network at all — that is the premise |
| GNSS gives you time | Unavailable indoors and in urban canyons; spoofable outdoors |
| Device RTCs are roughly right | Phone RTCs drift; a cold-booted ESP32 has no idea what year it is |
| Clocks only move forward | A user can set the clock manually |

## Bounding uncertainty

Signet keeps a local monotonic clock and an explicit uncertainty interval,
tightened opportunistically from whatever sources present themselves.

| Source | Bound | Availability | Trust |
|---|---|---|---|
| GNSS fix | ±µs | Outdoors, unjammed | Spoofable, but expensive to spoof locally |
| Peer exchange | Interval arithmetic | On any radio contact | As good as the tightest honest peer |
| Public beacon | Monotonic floor | Anyone who touched the internet recently | See caveat below |
| Local monotonic | Widens with elapsed time | Always | Self-consistent, absolutely unanchored |

### Peer exchange

This is the mesh-native answer. When two nodes come into range — which they
must, to exchange messages at all — they trade clock estimates *with their
uncertainty intervals*. The intersection is taken, tightest bound wins.

A node with a GNSS fix has a very tight interval and "infects" the network with
tightness as it moves. A node that has been in a basement for two days has a
wide one and defers.

This is interval arithmetic over Marzullo-style bounds, not averaging. Averaging
would let a lying peer drag the estimate; intersection lets it only widen or
be ignored.

### Beacons

A public randomness beacon — [drand](https://drand.love), NIST's Randomness
Beacon, or the Bell-test-based [CURBy](https://random.colorado.edu) — publishes
unpredictable values on a fixed schedule. Because a value cannot be known
before its round, holding one proves **time has passed**:

```text
now ≥ round_time(latest beacon value I hold)
```

It is a *floor*, never a ceiling. It cannot prove that time has not passed.
Any node that touches the internet carries the newest value into the mesh,
where it floods as a public good.

> **Known gap.** drand signs with BLS12-381, which is not post-quantum. A
> quantum adversary could forge future beacon values and push a receiver's
> floor forward, which is exactly the direction that breaks the security
> condition. Mitigation today: the beacon is never a sole authority, only one
> input intersected with local monotonic time. A hash-chain beacon would close
> this properly and is worth building.

## Degradation

The whole point of tracking uncertainty explicitly is that the protocol can
respond to it instead of pretending it does not exist.

```text
uncertainty small      →  d stays tight, TESLA, 16-48 bytes
uncertainty growing    →  widen d, buffering window lengthens
uncertainty > threshold →  fall back to Signed class, 666 bytes
no bound at all        →  send Signed; accept incoming as unauthenticated
```

The system degrades rather than failing closed or, far worse, silently
accepting forgeries.

## The measurement that matters

Everything above is design. The number that decides whether it was a good
design is:

> **What fraction of real-world messages get the cheap path?**

If it is 95%, Signet's routine traffic is essentially free and the thesis
holds. If it is 40%, the fallback dominates and the honest conclusion is that a
compact post-quantum signature should be the default with TESLA as the
optimisation.

That measurement is the Clock deliverable, and it needs real devices in real
conditions — indoors, moving, with GNSS coming and going. It cannot be simulated
convincingly, which is why it is not in `signet sim`.

## Open sub-problems

1. **Interval length.** 30 s is a provisional guess. Too short wastes airtime
   on disclosures; too long widens the buffering window and delays
   verification past usefulness.
2. **Cold start.** A device that has never had GNSS, a peer, or a beacon has
   no bound at all. It can send `Signed` frames but cannot verify any `Tesla`
   frame it receives. How long does that state last in practice?
3. **Adversarial peers.** A liar cannot tighten a bound through intersection,
   but a *majority* of liars in a partition could. What is the honest
   assumption here?
4. **Clock rollback attacks.** If an attacker controls a device's RTC, do the
   monotonic guarantees survive a reboot?
