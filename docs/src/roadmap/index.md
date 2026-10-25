# Roadmap

Signet is for one situation: the network is down, after a disaster or during
a shutdown, and people cannot tell which warnings are true or where the danger
is. This page covers how much of that Signet takes on and where each part
stands. Some parts are not built yet and some may never be, so they are listed
as gaps where nobody can mistake them for solved.

## Scope

Signet's job is to make a message checkable: who sent it, whether anyone
altered it, and whether people you trust report the same thing. The
proof has to be cheap enough for the links that are left, and post-quantum so
that keys pinned today stay sound for as long as they are trusted.

It is for people who have to act on a warning, and for the groups they rely
on. In a disaster that is usually an emergency service. In a shutdown it is
whoever people chose in advance, such as volunteer medics, a newsroom or a
students' union.

The rest is left to other projects, and Signet depends on them without
rebuilding them. Radios, mesh routing and the apps people already use carry
the messages. Signet does not encrypt, so secrecy is the host app's business.
It offers no anonymity, because a signed message names its sender
([threat model](../protocol/threat-model.md)). And it does not decide what is
true: it shows who said what and who agrees, and people judge.

The scope is met when a warning from a group you trust reaches you through
an app you already have while the network is down, you can check it, and
independent reports of the same danger show as agreeing.

## How it is solved

Item numbers point to
[PROTOCOL.md Section 14](https://github.com/keshavashiya/signet/blob/main/PROTOCOL.md#14-open-questions).

| The problem | Signet's answer | Where it stands |
|---|---|---|
| A fake warning looks like a real one | Every message carries proof of its sender: a post-quantum signature for warnings that matter, a hash-chain MAC for routine traffic | ✅ chains, certs and signatures · ⬜ the `Signed` send path, in Warnings |
| The proof is too big for the link | Routine traffic costs 16–48 bytes; signatures are kept for the messages that matter | ✅ modelled in Airtime · ⬜ measured in Radio |
| Nothing says whom to trust | Keys pinned in advance, by QR code or a roster, from groups people choose | ✅ certs and pinning · ⬜ badges that name the group, in Warnings (item 13) |
| Nobody knows where the danger is | Independent reports kept apart, so agreement among known reporters shows | ✅ the store · ⬜ danger reports and corroboration, in Warnings (item 14) |
| Warnings have to reach people | Inside the mesh apps people already use, with no app of our own | ⬜ Integration |
| Warnings get forwarded | Signatures stay checkable after forwarding; hash-chain MACs do not | ⬜ the `Signed` send path, in Warnings (item 15) |
| There is no network time | Clocks kept as ranges, with a fallback to signatures when the range is too wide | ✅ the check · ⬜ the sources, in Clock |
| A reporter can be identified | Not solved: a signed report names its sender | Open research (item 16) |

## The shutdown scenario

A disaster breaks the network. A shutdown switches it off on purpose, often
during a protest. Both leave people needing accurate warnings, above all about
where the danger is, but they differ in almost everything around the message.
The protocol is the same for both. What changes:

| | Disaster | Shutdown |
|---|---|---|
| Whom people trust | An emergency operations centre | Groups they chose beforehand: a students' union, volunteer medics, a newsroom |
| How danger is known | An official warning | Several independent people reporting the same place |
| How messages travel | LoRa radios that responders carry | Phones: Bluetooth mesh apps, and SMS where it still works |
| What must stay verifiable | A message checked as it arrives | A message forwarded hand to hand, checked by whoever gets it later |
| Who is at risk for sending | Rarely the sender | The person who reports the danger |
| Time sources | Power and GPS are often lost, indoors especially | The internet is cut; GPS usually still works unless it is jammed |

Each difference is a phase's job or an open question in
[PROTOCOL.md Section 14](https://github.com/keshavashiya/signet/blob/main/PROTOCOL.md#14-open-questions):

- **Trust.** Any pinned root already works, but the roles and the badges assume
  an emergency service (item 13).
- **Corroboration.** The store keeps independent claims apart, the right base
  for "where is the danger". Corroboration itself is unspecified, and sybils
  make counts of strangers meaningless (items 6 and 14).
- **Reach and forwarding.** Phones are what people have, so phone hosts matter
  most here (Integration), and only a `Signed` message survives being forwarded
  (item 15).
- **The reporter's safety.** A signed report names its sender (item 16, and the
  [threat model](../protocol/threat-model.md)).
- **Time.** The Clock measurement runs in both scenarios.

## Phases

Each phase is named for what it delivers. The core comes first: Warnings builds
what both scenarios need before any work that serves only one of them.

| Phase | Delivers | State | Artefact |
|---|---|---|---|
| **Airtime** | What authenticity costs on a 233-byte lossy link | ✅ done | `signet sim` |
| **Protocol** | Chains, certs, clocks, fragmentation, sessions | ✅ done | `signet demo`, 105 tests |
| **Warnings** | Verified warnings that work in a disaster and in a shutdown | ⬜ next | One end-to-end test per scenario |
| **Radio** | Meshtastic over real LoRa hardware | ⬜ | Measured airtime on two T-Beams |
| **Clock** | Time sync without infrastructure | ⬜ | The research contribution |
| **Integration** | Signet inside the mesh apps people already use | ⬜ | Bindings, one host app showing the badge |

---

## Airtime ✅

**Question:** what does authenticity cost on a 233-byte lossy link?

Answered without writing a line of post-quantum code, because airtime is a
function of bytes and the bytes are published constants. Semtech time-on-air,
closed-form binomial delivery, erasure-coded fragmentation, seven schemes.

**Result:** TESLA costs 1416 ms of effective airtime per delivered message
against 43 226 ms for ML-DSA-44. A **31x** difference, 94x for SLH-DSA-128s.
That decides the design: hash chains for routine traffic, and signatures only
for messages that must stay attributable.

---

## Protocol ✅

Everything that is pure logic, testable on a laptop, with no radio involved.

- ✅ TESLA chains: generation, disclosure, gap recovery, rollback rejection
- ✅ Frame codec: total decoding, every failure a value
- ✅ Fact store: author-owned last-write-wins
- ✅ `signet-crypto`: FN-DSA-512 keygen, signing, verification
- ✅ Operational certs: encode, decode, issue, verify against a pinned root
- ✅ Erasure-coded fragmentation (Reed–Solomon over GF(2⁸))
- ✅ Clocks with explicit uncertainty and the TESLA security condition
- ✅ Two nodes exchanging verified messages over a simulated lossy channel

**Exit criterion met:** `crates/crypto/tests/e2e.rs`, nine tests running the
full path from cert issuance to verified store, every one of which fails if
authentication breaks anywhere along it.

**Three things this phase changed in the spec**, all found by writing the code:

1. Chain values are 32 bytes, not 16. A 128-bit chain value gives 64-bit
   preimage resistance under Grover, too weak for a protocol meant to be
   post-quantum. Disclosure
   moved to once per interval to absorb the cost.
2. Disclosure presence is an explicit flag bit. Inferring it from trailer
   length is ambiguous, and ambiguity in that parser risks an authentication
   bypass.
3. `K[0]` is never disclosed: it is the commitment, and a receiver anchored
   there correctly rejects it as non-advancing. Found by the end-to-end test.

Measured, on an M-series laptop: FN-DSA keygen 4.9 ms, sign 277 µs, verify
27 µs. A cert is 1617 bytes; a status beacon is 66, or 98 with a disclosure.

Not yet built: a `Signed`-class send path (the primitive exists, the framing
does not), ML-KEM confidentiality, and any transport at all.

---

## Warnings ⬜

One protocol that carries verified warnings in both scenarios. It comes before
any work that serves only one of them and builds only what the two tests below
need, so it adds no transport, app or new layer.

- The `Signed` send path, with its framing decided
  ([Section 14](https://github.com/keshavashiya/signet/blob/main/PROTOCOL.md#14-open-questions) item 12)
- Both halves of the security condition: the sender discloses on its earliest
  possible time (item 8)
- Chain rollover signed by the operational key (item 9), and `Signed` for a
  sender's last message (item 10)
- A stale but valid disclosure ignored instead of dropping its frame (item 11)
- Badges that name the group whose root the receiver pinned (item 13)
- A danger report with place and time, and a rule for when reports agree that
  counts only reporters the receiver has verified (item 14)

**Exit criterion:** one end-to-end test per scenario.

- *Disaster:* an emergency service's evacuation order arrives as a `Signed`
  message over a lossy channel and verifies, while routine beacons ride TESLA.
- *Shutdown:* a group's danger report arrives long after it was sent, passed on
  by others, and still verifies because it is signed. Three reporters the
  receiver has verified agree on a place, and reports from unknown identities
  do not count.

Out of scope here: clock sources (Clock), hosts (Integration), and a report
verifiable without naming its reporter (item 16, open research).

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
model states this: every Airtime figure flatters the large-signature
schemes. If the gap is large enough, interleaving becomes mandatory rather
than an open question. And if Radio shows the simulation was wrong, the
design changes rather than building on it.

---

## Clock ⬜

The main open research question, and the hardest problem. See
[Time & the Security Condition](../protocol/time.md).

- Uncertainty tracking with interval arithmetic
- Opportunistic tightening: GNSS, peer exchange, beacon floor
- Dynamic disclosure delay, with fallback to `Signed` past threshold

The *check* already exists in `signet-core::time`. What is missing is the
sources that produce a good bound.

**Exit criterion:** the measurement that decides whether the design holds.

> What fraction of real-world messages get the cheap path?

At 95%, TESLA is nearly free. At 40%, a compact post-quantum signature should
be the default, with TESLA as the optimisation. The result gets published
either way.

This cannot be simulated convincingly, which is why it is not in `signet sim`:
it needs real devices, indoors and moving, with GNSS coming and going.
Run it in both [scenarios](#the-shutdown-scenario): a shutdown usually leaves
GPS working unless it is jammed, while a disaster can cut power and push people
indoors.

---

## Integration ⬜

Signet ends inside the mesh apps people already use. Meshtastic, Bitchat and
Reticulum's Sideband already have the users and the screens. What they lack is
a way to say who sent a message. The badge is what Signet adds; the chat app
with a map already exists.

- Bindings: UniFFI generates Swift and Kotlin from the same Rust core, so a
  host's integration is [a few calls](../guide/integration.md)
- Meshtastic first, on the private portnum Radio already uses, with the verify
  call and the badges inside the Meshtastic app
- Phone-to-phone reach through Bluetooth mesh apps that already exist, so
  Signet builds no Bluetooth transport of its own
- No single host: an app can be pulled from app stores or blocked by a
  government, so the core stays host-agnostic and hosts are chosen partly for
  staying available where they are needed
  ([threat model](../protocol/threat-model.md))
- The badge rules travel with the library: ✅ verified / 🔑 known / ⚪ unverified /
  ⚠️ unverifiable, and never an authority badge on a `Tesla` frame

**Exit criterion:** a host app renders Signet badges on real mesh traffic, and
the change is offered upstream.

This is the first phase that needs someone else to say yes. If no host will
carry Signet, the fallback is a companion app of our own, kept to the badge: it
verifies and shows who sent what, and it is not a new messenger.

---

## Explicitly not on the roadmap

Covered by the [hard rules](../development/index.md#hard-rules): no blockchain
or token, no custom cryptographic primitives, no revocation PKI, no CRDT
library, no new mesh routing, no servers or accounts, and no voice or video.
