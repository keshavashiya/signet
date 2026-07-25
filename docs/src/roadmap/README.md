# Roadmap

**Airtime, Protocol and Radio are the project.** Everything after is contingent
on the hardware numbers holding up. If Radio says the simulation lied, the
right response is to change the design, not to keep building on it.

| Phase | Delivers | State | Artefact |
|---|---|---|---|
| **Airtime** | What authenticity costs on a 200-byte lossy link | ✅ done | `signet sim` |
| **Protocol** | Chains, certs, clocks, fragmentation, sessions | ✅ done | `signet demo`, 101 tests |
| **Radio** | Meshtastic over real LoRa hardware | ⬜ next | Measured airtime on two T-Beams |
| **App** | The thing a person holds | ⬜ | Five buttons, offline map |
| **Clock** | Time sync without infrastructure | ⬜ | The research contribution |
| **Bluetooth** | Phone-to-phone, no hardware at all | ⬜ | BLE transport |

---

## Airtime ✅

**Question:** what does authenticity actually cost on a 200-byte lossy link?

Answered without writing a line of post-quantum code, because airtime is a
function of bytes and the bytes are published constants. Semtech time-on-air,
closed-form binomial delivery, erasure-coded fragmentation, eight schemes.

**Result:** TESLA costs 1129 ms of effective airtime per delivered message
against 35 323 ms for ML-DSA-44. A **31x** difference, 95x for SLH-DSA-128s.
That decides the design: hash chains for routine traffic, signatures reserved
for messages that move people.

---

## Protocol ✅

Everything that is pure logic, testable on a laptop, with no radio involved.

- ✅ TESLA chains — generation, disclosure, gap recovery, rollback rejection
- ✅ Frame codec — total decoding, every failure a value
- ✅ Fact store — author-owned last-write-wins
- ✅ `signet-crypto` — FN-DSA-512 keygen, signing, verification
- ✅ Operational certs — encode, decode, issue, verify against a pinned root
- ✅ Erasure-coded fragmentation (Reed–Solomon over GF(2⁸))
- ✅ Clocks with explicit uncertainty and the TESLA security condition
- ✅ Two nodes exchanging verified messages over a simulated lossy channel

**Exit criterion met:** `crates/crypto/tests/e2e.rs` — nine tests running the
full path from cert issuance to verified store, every one of which fails if
authentication breaks anywhere along it.

**Three things this phase changed in the spec**, all found by writing the code:

1. Chain values are 32 bytes, not 16. A 128-bit chain value gives 64-bit
   preimage resistance under Grover, which is indefensible here. Disclosure
   moved to once per interval to absorb the cost.
2. Disclosure presence is an explicit flag bit. Inferring it from trailer
   length is ambiguous, and ambiguity in that parser is an authentication
   bypass.
3. `K[0]` is never disclosed — it is the commitment, and a receiver anchored
   there correctly rejects it as non-advancing. Found by the end-to-end test.

Measured, on an M-series laptop: FN-DSA keygen 4.9 ms, sign 277 µs, verify
27 µs. A cert is 1617 bytes; a status beacon is 66, or 98 with a disclosure.

Not yet built: a `Signed`-class send path (the primitive exists, the framing
does not), ML-KEM confidentiality, and any transport at all.

---

## Radio ⬜

Where the simulation meets physics.

- Private portnum, protobuf over the phone API, **unmodified firmware**
- Two LilyGo T-Beams (~$25 each) on a desk, then 1 km apart
- Measure: actual airtime, actual loss distribution, actual battery draw
- Split `signet-crypto`'s verify path out for on-device verification

**Exit criterion:** measured numbers next to modelled ones, with the deltas
explained.

Expect burst loss to be worse than the independent-loss model predicts. The
model says so itself — every Airtime figure flatters the large-signature
schemes. If the gap is large enough, interleaving becomes mandatory rather
than an open question.

---

## App ⬜

The thing a person actually holds.

- Flutter, `flutter_map`, **pre-downloaded MBTiles** — offline map tiles are
  the detail everyone forgets, and without them the demo is a grey rectangle
- Five buttons: **I'm OK · Need Help · Injured · Evacuating · Have Resources**
- Trust badges on every pin: ✅ verified / 🔑 known / ⚪ unverified / ⚠️ unverifiable
- "Carrying 23 messages for others" — sneakernet made visible

**Exit criterion:** dogfooded on a hike with no signal.

The badge is the product. Strip it and this is a chat app with a map.

---

## Clock ⬜

The research contribution, and the hardest open problem. See
[Time & the Security Condition](../protocol/time.md).

- Uncertainty tracking with interval arithmetic
- Opportunistic tightening: GNSS, peer exchange, beacon floor
- Dynamic disclosure delay, with fallback to `Signed` past threshold

The *check* already exists in `signet-core::time`. What is missing is the
sources that produce a good bound.

**Exit criterion — the measurement that decides whether the thesis holds:**

> What fraction of real-world messages get the cheap path?

95% and TESLA is essentially free. 40% and the honest conclusion is that a
compact post-quantum signature should be the default with TESLA as the
optimisation. That result gets published either way.

This cannot be simulated convincingly — it needs real devices, indoors and
moving, with GNSS coming and going. Which is why it is not in `signet sim`.

---

## Bluetooth ⬜

Phone-to-phone with no hardware at all — the widest possible reach, and the
hardest thing to make reliable. Deliberately last.

Bitchat went native for BLE for good reasons. If Flutter's BLE story proves
inadequate here, that tradeoff gets revisited rather than papered over.

---

## Explicitly not on the roadmap

Covered by the [hard rules](../development/README.md#hard-rules): no blockchain
or token, no custom cryptographic primitives, no revocation PKI, no CRDT
library, no new mesh routing, no servers or accounts, and no voice or video.
