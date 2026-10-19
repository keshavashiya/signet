# Signet wire protocol, v1 (draft)

**Status:** draft. Wire format is unstable until v1.0.0 and may change without
a compatibility path. Implementations should pin a commit.

---

## Table of Contents

- [0. Conventions](#0-conventions)
- [1. Scope](#1-scope)
- [2. Identity](#2-identity)
- [3. Frame format](#3-frame-format)
- [4. Message classes](#4-message-classes)
- [5. TESLA operation](#5-tesla-operation)
- [6. Time](#6-time)
- [7. Fragmentation](#7-fragmentation)
- [8. Confidentiality](#8-confidentiality-planned) (planned)
- [9. Fact payloads](#9-fact-payloads)
- [10. Receiving a frame](#10-receiving-a-frame)
- [11. Errors and rejections](#11-errors-and-rejections)
- [12. Constants](#12-constants)
- [13. Versioning](#13-versioning)
- [14. Open questions](#14-open-questions)
- [Appendix A. Normative requirements](#appendix-a-normative-requirements)

---

## 0. Conventions

### 0.1 Requirement levels

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this
document are to be interpreted as described in
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174), and only when they appear
in all capitals.

Every normative requirement is also listed in
[Appendix A](#appendix-a-normative-requirements), so an implementer can work
from a checklist instead of scanning prose.

### 0.2 Notation

| Notation | Meaning |
|---|---|
| `K[i]` | Chain key for interval `i` ([Section 5.1](#51-chain-construction)) |
| `H(x)` | SHA-256 of `x` |
| `H^n(x)` | `H` applied `n` times; `H^0(x) = x` |
| `a \|\| b` | Concatenation |
| `0x1F` | Hexadecimal |
| `0b0000_0001` | Binary |
| `n B` | `n` bytes |

Multi-byte integers are **big-endian**. Byte offsets are zero-based. Slice
ranges are half-open: `[1..9]` means bytes 1 through 8 inclusive.

### 0.3 Section status

| Marker | Meaning |
|---|---|
| *(none)* | Specified and implemented. An interoperable counterpart exists. |
| **[PLANNED]** | Specified, not implemented. Nothing to interoperate with yet, and the design may still move. |

---

## 1. Scope

Signet specifies **authenticity for messages carried over a constrained,
lossy, infrastructure-free broadcast link**. It assumes a host transport that
already moves opaque payloads between nodes (Meshtastic, BLE mesh, Reticulum,
raw LoRa) and adds nothing to routing, discovery or delivery.

### 1.1 Design constraints

These are inherited from the medium, not chosen:

| Constraint | Value | Consequence |
|---|---|---|
| Frame payload | ~200–237 bytes | An ML-DSA signature spans 11 frames |
| Loss | 10–50%, bursty | No reliable back-channel; ARQ is expensive |
| Topology | Broadcast flood | One sender, many unsynchronised receivers |
| Clock | No NTP, no guaranteed GNSS | Anything time-dependent must degrade safely |
| Power | 72h on a dying battery | Airtime is the dominant cost, not CPU |

### 1.2 Goals

1. Every message is attributable to a verifiable sender.
2. Post-quantum authentication throughout. Payloads are plaintext; when
   confidentiality is added it must be post-quantum too ([Section 8](#8-confidentiality-planned)).
3. Routine traffic costs a small constant number of bytes, independent of the
   signature scheme in use.
4. Verification works with no network access whatsoever.
5. When a check cannot be made, fall back to a weaker state that says so
   rather than failing closed or claiming more than it knows.

### 1.3 Non-goals

Routing, delivery guarantees, mandatory confidentiality, voice/video,
group key agreement, and anonymity. Signet is not an anonymity system: sender
fingerprints are stable and linkable by design, because an emergency network
needs to know who is talking.

---

## 2. Identity

### 2.1 Two tiers

Root keys must be cold (paper-backed, offline). Operational keys must be hot
(on a device that may be seized or lost). One tier cannot be both, so there
are two.

```text
Root key  ──signs──>  Operational cert  ──authenticates──>  messages
(cold, ~5 uses ever)  (hot, 30-day life)
```

Key loss is survivable: the root re-issues. Device seizure is contained: the
operational cert expires.

### 2.2 Operational cert

| Offset | Field | Size | Notes |
|---|---|---|---|
| 0 | `version` | 1 B | 1 |
| 1 | `alg` | 1 B | Signature suite ([Section 2.5](#25-signature-suite-registry)) |
| 2 | `issuer_id` | 8 B | Truncated SHA-256 of the root public key |
| 10 | `role_bits` | 2 B | Civilian / responder / EOC |
| 12 | `valid_until` | 4 B | Beacon round number, not wall clock |
| 16 | `tesla_root` | 32 B | Chain commitment, `K[0]` ([Section 5](#5-tesla-operation)) |
| 48 | `sign_pubkey` | 2 + n B | Length-prefixed. 897 B at FN-DSA-512 |
| … | `kem_pubkey` | 2 + n B | Length-prefixed. 0 = absent; 1184 B at ML-KEM-768 |
| … | `sig` | 2 + n B | Length-prefixed. 666 B at FN-DSA-512 |

The signed region (the *to-be-signed* bytes) is every field from `version`
through `kem_pubkey`. `sig` covers those bytes and is not itself signed. A cert
with an FN-DSA-512 key and no KEM key is **1617 bytes**.

The three cryptographic fields are length-prefixed rather than fixed-width
because the signature suite is not settled: FIPS 206 is draft, and a NIST
round-3 candidate with a 200-byte signature would change these sizes entirely.
Six bytes of framing on an object that travels out of band is cheap
protection against a wire-format break.

Certs are **never sent on the hot path.** Frames carry an 8-byte fingerprint
(SHA-256 over the full encoding, truncated). A receiver that does not hold the
cert has to obtain it once and can then cache it; an over-the-air cert request
is not specified yet. Out-of-band distribution (QR, NFC, a roster file handed
out in advance) is preferred and costs no airtime.

Decoders MUST reject trailing bytes. Junk after a cert would otherwise let an
attacker vary its fingerprint without touching what the signature covers.

### 2.3 Revocation

There is none. Offline revocation is an unsolved problem: status lists require
a network to fetch, which is precisely what is missing. Signet substitutes
**short expiry**, as short-lived TLS certificates do.

A compromised operational key stays valid until its `valid_until`. This is a
real weakness.

### 2.4 Trust establishment

Trust-on-first-use, upgraded out-of-band:

| Level | How | Badge |
|---|---|---|
| Unverified | Heard on the mesh | ⚪ |
| Known | QR/NFC scanned in person | 🔑 |
| Responder / EOC | Cert chains to a root pinned before deployment | ✅ |

Organisational roots are distributed during onboarding, while the network
still works, which an emergency operations centre can organise. Pinning is
implemented; the QR and NFC exchange and the badges belong to the host app and
are not built ([Integration](docs/src/roadmap/index.md)).

### 2.5 Signature suite registry

| Value | Suite | Public key | Signature |
|---|---|---|---|
| 0 | Reserved | | |
| 1 | FN-DSA-512 | 897 B | 666 B |

Verifiers MUST reject a suite they do not implement rather than attempting the
signature with a different one.

---

## 3. Frame format

Fixed 13-byte header, with no options or TLVs, because every header byte is a
payload byte lost on a 237-byte link.

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| ver   | class |                                               |
+-+-+-+-+-+-+-+-+          sender fingerprint (8 bytes)         |
|                                                               |
+                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
|                    interval (u32, big-endian)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    body, then trailer                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Offset | Size | Field |
|---|---|---|
| 0 | 4 bits | `version`, value 1 |
| 0 | 4 bits | `class`, see [Section 4](#4-message-classes) |
| 1 | 8 B | `sender`, the truncated operational cert hash |
| 9 | 4 B | `interval`, the TESLA interval index, big-endian |
| 13 | … | body, then trailer (class-specific, [Section 4](#4-message-classes)) |

Decoders MUST reject a short buffer, an unknown version, and an unknown class.
Everything crossing the radio boundary is hostile until authenticated.

### 3.1 `Tesla` body

```text
[13B header][1B flags][4B seq][2B kind][payload][16B MAC][32B disclosure?]
```

| Field | Size | Notes |
|---|---|---|
| `flags` | 1 B | Bit 0: a 32-byte disclosure follows the MAC |
| `seq` | 4 B | Author-local counter, big-endian ([Section 9.2](#92-merge-semantics)) |
| `kind` | 2 B | Fact kind ([Section 9.1](#91-fact-kinds)) |

A 30-byte status beacon is **66 bytes**, or **98** on the frame that carries a
disclosure. Both fit one Meshtastic frame with room to spare.

Disclosure presence is signalled by an explicit flag bit, never inferred from
frame length: length inference is ambiguous whenever the payload size is not
known in advance, and guessing wrong in a security-critical parser is how
authentication bypasses happen. The flag byte is inside the MAC'd region, so
flipping it to make a receiver mis-split the trailer cannot also produce a
valid tag.

Reference: [`crates/core/src/wire.rs`](crates/core/src/wire.rs),
[`crates/core/src/session.rs`](crates/core/src/session.rs).

---

## 4. Message classes

| Class | Value | Trailer | Use |
|---|---|---|---|
| `Tesla` | 0 | 16 B MAC, + 32 B disclosed key on the first frame of each interval | Routine traffic |
| `Signed` | 1 | PQ signature (666 B at FN-DSA-512) | Authoritative traffic |
| `Fragment` | 2 | Fragment header + coded shard | Objects exceeding one frame |

### 4.1 Choosing a class

**This choice is the protocol's central design decision.**

TESLA provides authenticated broadcast but **not non-repudiation**: after the
key for interval `i` is disclosed, anyone can forge interval `i` retroactively.
That is acceptable for live coordination and unacceptable for anything a third
party must be able to verify later.

Senders MUST use `Signed` for:

- Evacuation orders and other directives that move people
- Any message asserting authority (`role_bits` ≠ civilian)
- Cert issuance and key material

Senders SHOULD use `Tesla` for everything else. Receivers MUST NOT display an
authority badge on a `Tesla` frame.

---

## 5. TESLA operation

TESLA is the broadcast authentication scheme of Perrig, Canetti, Tygar and
Song (IEEE S&P 2000), specified in [RFC 4082](https://www.rfc-editor.org/rfc/rfc4082).
This section is Signet's profile of it.

### 5.1 Chain construction

Generate down from a secret seed; use walks up:

```text
seed ──H──> K[n] ──H──> K[n-1] ──H──> … ──H──> K[1] ──H──> K[0]
                                                           ▲
                                          commitment, published in the cert
```

`H` is SHA-256. Interval `i` is authenticated by `K[i]`. Disclosing `K[i]`
reveals every `K[j]` for `j < i` and nothing for `j > i`.

Chain values **MUST** be 32 bytes, not truncated. Forging interval `i+1` from a
disclosed `K[i]` is a preimage attack, so preimage resistance is what protects
every future interval; a 128-bit chain value would give 64-bit resistance under
Grover, which is not defensible for a protocol whose premise is post-quantum.
The 16-byte MAC is a different case: guessing a tag needs a receiver to check
each guess, so Grover does not apply, while a chain preimage can be searched
offline for as long as a receiver hears nothing newer.
The per-message cost stays at 16 bytes because disclosure amortises ([Section 5.3](#53-sending)).

`K[0]` is the commitment. It is published in the cert, already public, and MUST
NOT be disclosed: a receiver anchored there would correctly reject it as
non-advancing and drop an otherwise valid frame. Disclosure targets are ≥ 1.

### 5.2 MAC key separation

The MAC key **MUST NOT** be the chain key. It is derived from it:

```text
mac_key[i] = SHA-256("signet/v1/mackey" || K[i])
```

Without this domain separation, disclosing `K[i]` would disclose the key that
authenticated interval `i`, and the scheme would authenticate nothing.

### 5.3 Sending

During interval `i`, for each message:

1. `tag = HMAC-SHA256(mac_key[i], header || body)`, truncated to 16 bytes.
   The MAC covers the frame header, so a relay cannot rewrite the sender
   fingerprint or the claimed interval and still verify.
2. Append `tag`.
3. On the **first** frame of interval `i` only, set the disclosure flag and
   append `K[i - d]`, where `d` is the disclosure delay ([Section 6.3](#63-bounding-uncertainty)) and `i - d ≥ 1`.

Disclosure is per-interval, not per-message. A sender emitting five frames in
one interval would otherwise repeat the same 32 bytes five times; instead the
remaining four carry the 16-byte MAC alone. Receivers do not care which frames
carry it, because a missed disclosure is recovered from any later one ([Section 5.5](#55-loss-tolerance)).

### 5.4 Receiving

1. **Check the security condition ([Section 6.2](#62-the-security-condition)). If it fails, discard.** Skipping this
   step makes the MAC meaningless: an attacker waits for disclosure, then forges.
2. Buffer the message; it cannot be verified yet.
3. On receiving `K[j]`: verify `H^(j - anchor_interval)(K[j]) == anchor`. This
   simultaneously authenticates `K[j]` and recovers every skipped key.
4. Re-anchor to `(j, K[j])`. A disclosure that does not advance the interval
   MUST be rejected, so a replay cannot roll a receiver backwards.
5. Verify buffered MACs with the recovered keys.

### 5.5 Loss tolerance

Gap recovery costs no airtime: a receiver anchored at interval 3 that misses 4, 5 and 6
recovers all of them from `K[7]`. This is why TESLA suits a lossy broadcast
medium where a signature scheme needs retransmits.

Reference: [`crates/core/src/chain.rs`](crates/core/src/chain.rs).

---

## 6. Time

### 6.1 The problem

TESLA's security rests entirely on a receiver knowing that a message arrived
*before* its key could have been public. Off-grid there is no NTP, phone RTCs
drift, and GNSS is unavailable indoors and spoofable outdoors.

This is the hardest unsolved part of the protocol, and the research question
of the Clock phase.

### 6.2 The security condition

A receiver accepts a frame for interval `i` only if, at arrival, the sender
could not yet have disclosed `K[i]`:

```text
t_arrival + uncertainty  <  t_interval_start(i) + d · interval_length
```

`uncertainty` is the receiver's own bound on clock error relative to the
sender. When it cannot be bounded, the condition cannot be evaluated, and the
frame MUST be treated as unauthenticated.

### 6.3 Bounding uncertainty

A local monotonic clock, tightened opportunistically. Only the interval
arithmetic and the check are implemented
([`time.rs`](crates/core/src/time.rs)); acquiring bounds from the sources below
is Clock work **[PLANNED]**.

| Source | Bound | Availability |
|---|---|---|
| GNSS fix | ±µs | Outdoors, unjammed |
| Peer exchange | Intersection, safe only among honest peers | On any contact |
| Public beacon (drand, CURBy) | Monotonic floor: "time ≥ T" | Anyone who touched the internet |
| Local monotonic | Widens over time | Always |

Nodes with tight bounds propagate tightness through the mesh on contact, and a
liar's bound propagates the same way, so intersection is only as safe as every
peer in it ([Section 14](#14-open-questions)). A beacon value proves time has *passed*,
never that it has not. It is a floor, combined with local monotonic time,
never a sole authority.

### 6.4 Degradation [PLANNED]

The disclosure delay `d` widens to cover current uncertainty. When uncertainty
exceeds the threshold at which `d` would become impractical, the sender falls
back to `Signed` for that message.

Not implemented: `d` is a fixed schedule parameter today (2 intervals by
default), and the fallback needs the `Signed` send path. A receiver that cannot
bound its clock refuses the frame as `TooLate`. Measuring what fraction of
real-world messages get the cheap path is the Clock deliverable.

---

## 7. Fragmentation

Objects exceeding one frame (certs, KEM keys, `Signed` trailers) are
**erasure coded, not retransmitted**. On a broadcast medium with no reliable
back-channel, sending redundancy beats negotiating repairs.

- Split into `k` shards; transmit `n = ceil(k × (1 + r))` with `r` ≈ 0.3
- Any `k` received shards reconstruct the object
- Reed–Solomon over GF(2⁸); at these values of `k`, fountain codes carry
  overhead they cannot repay
- At least one parity shard is always produced

Published ML-KEM-over-LoRa handshakes that need 28–62 frames use
retransmission instead.

### 7.1 Fragment header

Seven bytes preceding each shard, inside a `Fragment`-class frame body:

| Offset | Field | Size |
|---|---|---|
| 0 | `object_id` | 2 B |
| 2 | `index` | 1 B |
| 3 | `data_shards` | 1 B |
| 4 | `total_shards` | 1 B |
| 5 | `object_len` | 2 B |

Every field is attacker-controlled. Receivers MUST reject a header that is
self-inconsistent (`data_shards` of 0, `index ≥ total_shards`,
`total_shards < data_shards`, `object_len` of 0) and MUST reject a fragment
whose header contradicts one already seen for the same `object_id`.

Objects are capped at 65535 bytes by `object_len`. Receivers MUST bound the
number of partially-received objects they track; an unbounded map is a trivial
memory-exhaustion attack from anyone with a transmitter.

Erasure coding provides **availability, not integrity**. A wrongly
reconstructed object still fails its MAC or signature check, so fragmentation
is not part of the security argument.

---

## 8. Confidentiality [PLANNED]

Not implemented. No counterpart exists to interoperate with, and the design may
still move.

Optional, and deliberately the rare path. Most emergency traffic *should* be
plaintext broadcast: "need water at 123 Main" is meant to be readable by
anyone who can help.

When required: hybrid **X25519 + ML-KEM-768**, Noise-style, as current TLS and
Signal deployments do. Three properties keep it affordable:

1. **Peer KEM public keys are cached forever.** Only the first exchange with a
   given peer pays the 1184-byte cost.
2. **Fragments are erasure coded** ([Section 7](#7-fragmentation)).
3. **Handshake fragments piggyback on routine beacons.** The exchange completes
   in the background over minutes; the user never waits.

---

## 9. Fact payloads

Payloads are CBOR maps with single-character keys. The store
([Section 9.2](#92-merge-semantics)) treats them as opaque; only the app layer
interprets them.

> **[PLANNED]** The schema below is not yet encoded or decoded anywhere. The
> store handles payloads as opaque bytes today, so the merge semantics in
> [Section 9.2](#92-merge-semantics) are implemented but this schema is not.

```json
{ "t": 0, "s": 2, "p": [51.50, -0.12, 30], "n": 4, "r": [1, 3], "ttl": 12 }
```

| Key | Meaning |
|---|---|
| `t` | Fact kind |
| `s` | Status enum: 0 ok, 1 need-help, 2 injured, 3 evacuating, 4 has-resources |
| `p` | `[lat, lon, accuracy_m]` |
| `n` | People at this location |
| `r` | Resource needs, as enum values |
| `ttl` | Remaining hops or hours |

About 30 bytes. With framing and a TESLA trailer that is 66 bytes, or 98 when
a disclosure is attached ([Section 3.1](#31-tesla-body)), one frame either way.

### 9.1 Fact kinds

`FactKind` is a `u16`, not an enum, so a node running an older build relays and
stores kinds it does not understand. You cannot roll every device on a mesh
forward at once.

### 9.2 Merge semantics

Keys are `(author, kind)`, and **an author may only write keys it owns.**
Two writes to one key therefore always come from the same author and are
totally ordered by that author's sequence number. Conflicts cannot occur, and
the merge rule is `seq > existing.seq`, with no CRDT machinery.

Equal sequence numbers are rejected, which makes merge idempotent: the same
fact arriving by three mesh paths is harmless.

Independent claims are **never collapsed**. "Bridge out at 5th St" is Alice's
claim, not global truth, and the UI renders "3 people report bridge out".
Showing agreement between independent reporters, rather than a single answer,
is how the store resists misinformation.

Sequence numbers **MUST NOT** be trusted before authentication. Feeding
unverified frames to the store voids every guarantee above.

Reference: [`crates/core/src/store.rs`](crates/core/src/store.rs).

---

## 10. Receiving a frame

Everything before this section describes pieces. This is the order they run in.

A receiver **MUST** process every inbound frame in the order below. The order is
normative, not stylistic: each step establishes a precondition the next one
relies on. In particular, **the security condition (step 6) MUST be evaluated
before any MAC is trusted.** An implementation that verifies the MAC first and
checks the clock afterwards has no security at all: an attacker waits for the
key to be disclosed and forges freely.

```text
 1. Decode the 13-byte header                                          Section 3
      buffer too short ................................. Truncated
      version != 1 .................................... UnknownVersion
      class not in {0, 1, 2} .......................... UnknownClass

 2. Look up `sender` among pinned peers                                Section 2.4
      not pinned ...................................... UnknownSender

 3. Dispatch on class                                                  Section 4
      Tesla ......... step 4        Signed ....... step 10
      Fragment ...... step 12       other ........ WrongClass

 ── Tesla ────────────────────────────────────────────────────────────
 4. Read the flags byte; derive trailer length                         Section 3.1
 5. Split body from trailer
      fewer bytes than the flags imply ................ Truncated
 6. Evaluate the security condition                                    Section 6.2
      fails, or no usable time bound .................. TooLate
 7. If a disclosure is attached, verify it chains and advances         Section 5.4
      does not chain, or does not advance ............. BadDisclosure
 8. Buffer the frame, awaiting its key
 9. If step 7 produced a valid disclosure: re-anchor, then for every
    buffered frame whose key is now derivable, verify its MAC and
    merge into the store                                               Section 9.2
      MAC fails ....................................... silent drop    Section 11.3

 ── Signed ───────────────────────────────────────────── [PLANNED] ───
10. Reassemble if fragmented, then verify the signature against the
    sender's `sign_pubkey`                                             Section 2.2
11. Merge. No buffering and no security condition: a signature is
    verifiable on arrival.

 ── Fragment ─────────────────────────────────────────────────────────
12. Parse and validate the fragment header                             Section 7.1
      self-inconsistent, or contradicts a fragment already
      seen for this `object_id` ....................... BadFragment
13. Store the shard. If fewer than `data_shards` are held, stop.
14. Reconstruct, then re-enter at step 1 with the recovered object.
      A reconstructed object is NOT trusted: it re-enters the same
      pipeline and passes the same checks as anything off the air.     Section 7.1
```

Three requirements that are easy to miss and expensive to get wrong:

- A receiver **MUST NOT** accept a frame from a sender whose cert it has not
  verified against a root it already trusted. Pinning a `tesla_root` heard over
  the air defeats the entire identity model.
- A frame carrying an invalid disclosure **MUST** be discarded whole. It
  **MUST NOT** be buffered; half-accepting it lets an attacker fill the buffer
  with frames that can never verify.
- Receivers **MUST** bound the per-peer buffer. Unbounded buffering is a
  memory-exhaustion attack available to anyone with a transmitter.

---

## 11. Errors and rejections

Two outcomes, and implementations **MUST NOT** conflate them. A **decode error**
means the bytes are malformed. A **rejection** means a well-formed frame is not
acceptable. Both discard the frame; they differ in what a receiver may
legitimately count, log, or surface to a user.

### 11.1 Decode errors

| Error | Raised when |
|---|---|
| `Truncated{need, got}` | Buffer is shorter than the structure claims |
| `UnknownVersion(v)` | Version nibble is not 1 ([Section 13](#13-versioning)) |
| `UnknownClass(c)` | Class nibble is not 0, 1 or 2 ([Section 4](#4-message-classes)) |
| `UnknownAlg(a)` | Cert names a suite absent from [Section 2.5](#25-signature-suite-registry) |
| `TrailingBytes(n)` | Bytes remain after a complete structure ([Section 2.2](#22-operational-cert)) |
| `IntervalOutOfRange` | Requested interval lies beyond the generated chain |
| `BadFragment` | Fragment header is self-inconsistent or contradicts one already seen ([Section 7.1](#71-fragment-header)) |
| `ObjectTooLarge(n)` | Object exceeds the 65535-byte ceiling of `object_len` |

Decoding untrusted input **MUST NOT** panic, abort, or allocate in proportion to
an attacker-supplied length before that length has been checked against the
bytes actually held.

### 11.2 Rejections

| Rejection | Meaning | Section |
|---|---|---|
| `WrongClass` | Well-formed, but not the class this path handles | [Section 4](#4-message-classes) |
| `UnknownSender` | No pinned cert for this fingerprint | [Section 2.4](#24-trust-establishment) |
| `TooLate` | Failed the security condition: the key could already be public | [Section 6.2](#62-the-security-condition) |
| `BadDisclosure` | Disclosure does not chain to the anchor, or does not advance it | [Section 5.4](#54-receiving) |

### 11.3 Silent drops

A buffered frame whose MAC fails is dropped **without** an error. It is a
forgery attempt, not a malformed frame, and surfacing it per-frame hands an
attacker a channel straight into the user interface. Implementations **SHOULD**
count them and **SHOULD NOT** display them individually.

---

## 12. Constants

| Name | Value |
|---|---|
| `VERSION` | 1 |
| `HEADER_LEN` | 13 bytes |
| `SENDER_LEN` | 8 bytes |
| `BODY_LEN` | 7 bytes (flags + seq + kind) |
| `FLAG_DISCLOSURE` | `0b0000_0001` |
| `KEY_LEN` | 32 bytes |
| `MAC_LEN` | 16 bytes |
| `FRAG_HEADER_LEN` | 7 bytes |
| `CERT_VERSION` | 1 |
| `MAC_KEY_DOMAIN` | `"signet/v1/mackey"` |
| Cert signing domain | `"signet/v1/cert"` |
| Message signing domain | `"signet/v1/msg"` |
| Interval length | 30 s (provisional; Clock decides) |
| Disclosure delay `d` | 2 intervals by default; widening with uncertainty is planned ([Section 6.4](#64-degradation-planned)) |
| Chain length | 4096 intervals ≈ 34 h |
| Cert lifetime | 30 days |
| Erasure redundancy `r` | 0.30 |
| Max shards per object | 255 |
| Max object size | 65535 bytes |

Signature domains are separated so a certificate signature can never be
replayed as a message signature, or the reverse.

### 12.1 Published primitive sizes

Security level 1, in bytes:

| Scheme | Public key | Signature / ct | Standard |
|---|---|---|---|
| Ed25519 | 32 | 64 | classical, **not PQ** |
| SQIsign-I | 83 | 200 | NIST round 3 |
| MAYO-1 | 1456 | 464 | NIST round 3 |
| FN-DSA-512 | 897 | 666 | FIPS 206 (draft) |
| ML-DSA-44 | 1312 | 2420 | FIPS 204 |
| SLH-DSA-128s | 32 | 7856 | FIPS 205 |
| ML-KEM-768 | 1184 | 1088 | FIPS 203 |

---

## 13. Versioning

The 4-bit `version` nibble **MUST** be checked before anything else, and
unknown versions **MUST** be rejected rather than best-effort parsed.

Four bits allows 16 versions, which should be ample for a protocol on this
medium.

---

## 14. Open questions

Known open problems, numbered so other documents can cite them:

1. **Beacon signatures are not post-quantum.** drand uses BLS12-381. A quantum
   adversary could forge future beacon values. Fed to a receiver, a forged
   floor only causes early refusal; fed to a sender, it moves the sender's
   clock forward, which breaks the security condition (item 8). Mitigation:
   never treat the beacon as sole authority. A hash-chain beacon
   would close this properly.
2. **Interval length is unmeasured.** 30 s is a guess. Too short wastes airtime
   on disclosures; too long widens the buffering window and delays verification.
3. **Burst loss is unmodelled.** The redundancy in [Section 7](#7-fragmentation)
   assumes independent loss. Real links lose consecutive frames, which erasure
   coding across a small `k` handles poorly. Interleaving may be required.
4. **FN-DSA is a draft standard.** FIPS 206 is not final. If a round-3 candidate
   with a 200-byte signature is standardised, the `Signed` class becomes
   much cheaper and some of the tiering in [Section 4.1](#41-choosing-a-class) may
   become unnecessary.
5. **SQIsign signing latency is unmeasured on target hardware.** A compact
   signature helps little if signing takes seconds on a phone with a dying
   battery. This is Radio work.
6. **Sybil resistance is absent.** Nothing stops an attacker generating
   unlimited unverified identities and flooding the mesh. Rate limiting that
   survives sybils without infrastructure is unsolved.
7. **Peer time is not liar-safe.** The intersection in
   [Section 6.3](#63-bounding-uncertainty) never leaves a node's own bound, but one
   overlapping liar chooses where inside it the node lands, which can turn a
   correct `TooLate` into an acceptance. Marzullo's algorithm tolerates up to
   `f` liars only while `f` is bounded, and item 6's sybils unbound it.
   Candidate: count only peers whose certs chain to a pinned root.
8. **The sender's half of the security condition is unspecified.**
   [Section 6.2](#62-the-security-condition) bounds the receiver's clock. A sender whose clock runs fast
   discloses `K[i]` while receivers with correct clocks still accept interval
   `i`, and a forged beacon floor (item 1) pushes a sender's clock exactly that
   way. `Sender::beacon` takes a single clock reading. Candidate: disclose only
   once the sender's *earliest* possible time has passed the disclosure instant.
9. **The chain outlives neither the event nor the cert.** 4096 intervals at
   30 s is about 34 hours; a cert lives 30 days and its root signs a handful of
   times ever. No re-commitment is specified, so a sender's `Tesla` path ends at
   hour 34 of a 72-hour event. Candidate: the operational key signs the next
   chain's commitment, one `Signed` message per chain.
10. **The last message never verifies.** A `Tesla` frame verifies only once its
    sender transmits again at least `d` intervals later. The message sent just
    before a battery dies, often the one that matters most, never does.
    Candidate: a sender that knows it is going down sends `Signed`.
11. **A stale but valid disclosure drops its whole frame.** When a flood mesh
    delivers interval 5's frame before interval 4's, the older frame's
    disclosure no longer advances the anchor, so [Section 5.4](#54-receiving) and R16–R17 discard it,
    payload included, although it would have verified later. Candidate: hash
    the anchor down to check the disclosure, ignore it and buffer the frame if
    it matches, and discard only on a mismatch. That changes R16 and R17.
12. **The airtime model ignores per-fragment framing.** `signet sim` divides a
    multi-frame object by the full 237-byte frame, but every fragment frame
    spends 13 + 7 bytes on headers ([Section 7.1](#71-fragment-header)), so a fragment holds 217. The fix
    waits on one `Signed` framing decision: whether a fragmented `Signed`
    object carries its own 13-byte header.
13. **Trust roots beyond emergency services.** Any root a receiver pins works
    today, but the roles are civilian, responder and EOC, and the ✅ badge reads
    as official authority. In a shutdown the trusted sources are groups people
    chose beforehand, such as a students' union, volunteer medics or a
    newsroom, and the badge does not say which one. Candidate: the badge
    carries the name the receiver gave the root when pinning it, so a warning
    reads as verified by that group.
14. **Corroboration is unspecified.** The store keeps independent claims apart
    ([Section 9.2](#92-merge-semantics)), the right base for "where is the danger": several people the
    receiver knows reporting the same place. Nothing defines when two reports
    concern the same place and time, or which reporters count, and item 6's
    sybils make counts of strangers meaningless. Facts are keyed by author and
    kind, so each reporter holds one current report per kind and a second
    danger report replaces the first. There is also no fact kind for danger at
    a location: the planned status values are ok, need help, injured,
    evacuating and has resources ([Section 9](#9-fact-payloads)). Candidate: a danger kind carrying
    location and time, counted only from reporters verified in person (🔑) or
    chained to a pinned root (✅).
15. **Forwarded messages need signatures.** Reaching many people means
    messages get passed on: relayed across meshes, carried by hand, copied into
    SMS or another app. A `Tesla` frame that arrives after its key is disclosed
    fails the security condition ([Section 6.2](#62-the-security-condition)), so a forwarded copy cannot be
    checked. A `Signed` message can be checked by whoever receives it,
    whenever. For this scenario the unbuilt `Signed` send path is the main gap,
    and signature size decides whether a verified warning fits the messages
    people actually forward.
16. **Reporting danger can endanger the reporter.** A signed report names its
    sender ([Section 1.3](#13-non-goals)), which is what makes it credible and also what identifies
    the person who sent it. In a shutdown that can put them at risk. A report
    verifiable as coming from some member of a group, without saying which
    member, needs group or ring signatures or anonymous credentials. Open
    research, not a planned feature.

---

## Appendix A. Normative requirements

Every `MUST`, `MUST NOT`, `SHOULD` and `SHOULD NOT` in this document, in one
place. An implementer can work down this list; a reviewer can check it against
a codebase. Requirement text is compressed; the section is authoritative.

### Decoding

| ID | Requirement | Section |
|---|---|---|
| **R1** | Decoders MUST reject a short buffer | [Section 3](#3-frame-format) |
| **R2** | Decoders MUST reject an unknown version | [Section 3](#3-frame-format), [Section 13](#13-versioning) |
| **R3** | Decoders MUST reject an unknown class | [Section 3](#3-frame-format) |
| **R4** | The version nibble MUST be checked before anything else | [Section 13](#13-versioning) |
| **R5** | Decoders MUST reject trailing bytes after a complete cert | [Section 2.2](#22-operational-cert) |
| **R6** | Decoding untrusted input MUST NOT panic or abort | [Section 11.1](#111-decode-errors) |
| **R7** | Decoders MUST NOT allocate on an attacker-supplied length before checking it against the bytes held | [Section 11.1](#111-decode-errors) |

### Identity

| ID | Requirement | Section |
|---|---|---|
| **R8** | Verifiers MUST reject a signature suite they do not implement | [Section 2.5](#25-signature-suite-registry) |
| **R9** | Receivers MUST NOT accept a frame from a sender whose cert has not been verified against an already-trusted root | [Section 10](#10-receiving-a-frame) |

### Message classes

| ID | Requirement | Section |
|---|---|---|
| **R10** | Senders MUST use `Signed` for directives that move people, for any message asserting authority, and for cert issuance and key material | [Section 4.1](#41-choosing-a-class) |
| **R11** | Senders SHOULD use `Tesla` for all other traffic | [Section 4.1](#41-choosing-a-class) |
| **R12** | Receivers MUST NOT display an authority badge on a `Tesla` frame | [Section 4.1](#41-choosing-a-class) |

### TESLA

| ID | Requirement | Section |
|---|---|---|
| **R13** | Chain values MUST be 32 bytes, not truncated | [Section 5.1](#51-chain-construction) |
| **R14** | `K[0]` MUST NOT be disclosed; disclosure targets are ≥ 1 | [Section 5.1](#51-chain-construction) |
| **R15** | The MAC key MUST NOT be the chain key; it is domain-separated from it | [Section 5.2](#52-mac-key-separation) |
| **R16** | A disclosure that does not advance the interval MUST be rejected | [Section 5.4](#54-receiving) |
| **R17** | A frame carrying an invalid disclosure MUST be discarded whole and MUST NOT be buffered | [Section 10](#10-receiving-a-frame) |

### Time

| ID | Requirement | Section |
|---|---|---|
| **R18** | The security condition MUST be evaluated before any MAC is trusted | [Section 10](#10-receiving-a-frame) |
| **R19** | When clock uncertainty cannot be bounded, the frame MUST be treated as unauthenticated | [Section 6.2](#62-the-security-condition) |

### Fragmentation

| ID | Requirement | Section |
|---|---|---|
| **R20** | Receivers MUST reject a self-inconsistent fragment header | [Section 7.1](#71-fragment-header) |
| **R21** | Receivers MUST reject a fragment contradicting one already seen for the same `object_id` | [Section 7.1](#71-fragment-header) |
| **R22** | Receivers MUST bound the number of partially-received objects tracked | [Section 7.1](#71-fragment-header) |

### Processing and state

| ID | Requirement | Section |
|---|---|---|
| **R23** | Receivers MUST process inbound frames in the order given | [Section 10](#10-receiving-a-frame) |
| **R24** | Receivers MUST bound the per-peer frame buffer | [Section 10](#10-receiving-a-frame) |
| **R25** | Sequence numbers MUST NOT be trusted before authentication | [Section 9.2](#92-merge-semantics) |
| **R26** | Implementations MUST NOT conflate decode errors with rejections | [Section 11](#11-errors-and-rejections) |
| **R27** | Implementations SHOULD count MAC failures and SHOULD NOT display them individually | [Section 11.3](#113-silent-drops) |
