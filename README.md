# Signet 🕯

[![CI](https://github.com/keshavashiya/signet/actions/workflows/ci.yml/badge.svg)](https://github.com/keshavashiya/signet/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Status: alpha](https://img.shields.io/badge/status-alpha-orange.svg)](#status)

**In a disaster, you cannot tell whether the evacuation order is real.**

Signet is a post-quantum authenticity layer for off-grid mesh networks. It rides
inside whatever payload your radio already gives you — Meshtastic, Bluetooth
mesh, Reticulum, plain LoRa — and answers one question the existing stacks
cannot: *did this message really come from who it claims?*

A signet ring is a seal pressed into wax: the oldest authentication technology
there is, requiring no infrastructure at all, and proving the sender **without
hiding the letter**. That is exactly this protocol's design — authenticity
first, confidentiality optional. It is also why Signet is legal on amateur
bands, where encryption is prohibited but signing is not.

*No servers. No accounts. No internet. No blockchain.*

👉 **[Full documentation](https://keshavashiya.github.io/signet)** — protocol
spec, architecture, integration guides.

---

## Quick Start

```bash
git clone https://github.com/keshavashiya/signet.git
cd signet
cargo test --workspace     # 105 tests, no network, no hardware, no C toolchain

# What does authenticity cost on a 200-byte lossy link?
cargo run --bin signet -- sim

# Two nodes with real FN-DSA keys over a lossy channel
cargo run --bin signet -- demo --loss 30
```

```text
Signet airtime model — SF11 BW250kHz, MTU 237B, payload 30B, loss 20%, redundancy 30%
scheme             pq  trailer  frames    air ms  deliver    eff ms  note
----------------------------------------------------------------------------------------------------
Ed25519            NO       64       1      1026    80.0%      1283  1x  what every mesh ships today
TESLA (SHA-256)   yes       48       1       903    80.0%      1129  1x  16B MAC + 32B disclosed key
SQIsign-I         yes      204     3/2      5904    89.6%      6590  6x  NIST round 3; slow to sign
MAYO-1            yes      392     3/2      5904    89.6%      6590  6x  NIST round 3
HAWK-512          yes      555     4/3      7873    81.9%      9610  9x  NIST round 3
FN-DSA-512        yes      666     6/4     11809    90.1%     13105  12x  FIPS 206 draft
ML-DSA-44         yes     2420   15/11     29522    83.6%     35323  31x  FIPS 204, the safe default
SLH-DSA-128s      yes     7856   45/34     88566    82.6%    107238  95x  FIPS 205, hash-based root
```

Read that bottom half again. **Making an off-grid mesh post-quantum the obvious
way costs 31x the airtime per message.** That is why nobody has done it, and
why this project exists.

---

## The problem

| System | Crypto today | Post-quantum? |
|---|---|---|
| [Bitchat](https://github.com/permissionlesstech/bitchat) | Curve25519 (Noise XX) | ❌ |
| [Meshtastic](https://meshtastic.org) | Curve25519 + AES-256-CTR | ❌ |
| [Reticulum](https://reticulum.network) | X25519 / Ed25519 / AES-256 | ❌ |
| [Briar](https://briarproject.org) | Ed25519 / X25519 | ❌ |

Meshtastic's own documentation states it plainly: quantum-resistant key exchange
*"doesn't fit LoRa packet constraints."* The incumbent concedes the gap in its
own docs.

Radio traffic is trivially interceptable — the textbook
harvest-now-decrypt-later target. But the sharper problem is not confidentiality:

- **Encryption already survives.** AES-256 only loses half its margin to Grover.
- **Key exchange is a one-time, cacheable cost.** Ugly, amortises to nothing.
- **Per-message authenticity is what breaks.** And in a disaster, authenticity
  matters *more* than secrecy — misinformation kills, and "this bridge is out"
  needs to provably come from the county EOC.

## How it works

Two message classes, and choosing between them is the whole contribution.

### Class A — TESLA hash chains (routine traffic, 16–48 bytes)

A sender commits to the end of a one-way hash chain, MACs each interval's
traffic with a key only it holds, and discloses that key once the interval
closes. A receiver that got the message *before* the key went public knows
nobody else could have forged it.

```text
[16B MAC]                       typical
[16B MAC] [32B disclosed key]   first frame of each interval
```

**50x smaller than an ML-DSA-44 signature**, post-quantum by construction (it is
nothing but SHA-256), and natively loss-tolerant — miss three disclosures and
the fourth recovers all of them by hashing forward. Disclosure is per-interval,
so a sender bursting several messages pays 32 bytes once.
See [`chain.rs`](crates/core/src/chain.rs) and [`session.rs`](crates/core/src/session.rs).

### Class B — post-quantum signature (authoritative traffic, 666 bytes)

TESLA gives authenticated broadcast, **not** non-repudiation: once a key is
disclosed, anyone can forge that interval retroactively. So the design tiers by
consequence.

| Message | Class | Cost |
|---|---|---|
| Status beacon, chat, sensor reading | TESLA | 16–48 B |
| Evacuation order, official alert, credential | PQ signature | 666 B |

Authoritative messages are rare. Six frames is affordable when it is the
message that moves people.

### The hard part: time

TESLA needs a loose upper bound on the sender's clock, and off-grid there is no
NTP. Signet tightens a local monotonic clock opportunistically — GPS where
available, interval arithmetic on peer contact, a public randomness beacon as a
monotonic floor — then **widens the disclosure delay to cover the remaining
uncertainty, falling back to Class B when uncertainty exceeds threshold.**

The security condition and the uncertainty arithmetic are implemented
([`time.rs`](crates/core/src/time.rs)); the *sources* of a good bound are the
Clock phase.
The system degrades instead of failing — run
`signet demo --uncertainty-ms 600000` to watch every frame get correctly
refused. See [`docs/protocol/time.md`](docs/src/protocol/time.md).

---

## Table of Contents

- [Status](#status)
- [Using the library](#using-the-library)
- [Integration](#integration)
- [The simulator](#the-simulator)
- [Hard rules](#hard-rules)
- [Roadmap](#roadmap)
- [Development](#development)
- [Security](#security)
- [Architecture](#architecture)

---

## Status

**Alpha — Airtime and Protocol complete.** The protocol is specified and
implemented end to end: real FN-DSA-512 certificates, TESLA chains, the
security condition, erasure-coded fragmentation, and a verified fact store.
105 tests, no radio yet.

| Phase | Delivers | State | Artefact |
|---|---|---|---|
| **Airtime** | What authenticity costs on a lossy link | ✅ done | `signet sim` |
| **Protocol** | Chains, certs, clocks, fragmentation, sessions | ✅ done | `signet demo`, 105 tests |
| **Radio** | Meshtastic over real LoRa hardware | ⬜ next | two T-Beams |
| **App** | The thing a person holds | ⬜ | five buttons, offline map |
| **Clock** | Time sync without infrastructure | ⬜ | the research contribution |
| **Bluetooth** | Phone-to-phone, no hardware | ⬜ | BLE transport |

What Protocol does **not** have: a `Signed`-class send path (the primitive is
there, the framing is not), ML-KEM confidentiality, and any transport at all.

## Using the library

`signet-core` is `no_std` + `alloc`, so the same code runs on a phone and on an
ESP32 inside Meshtastic firmware.

```rust
use signet_core::{chain::{self, Chain}, Schedule};

// Sender: commit once, publish the commitment in your operational cert.
let chain = Chain::from_seed(&seed, 4096);
let commitment = chain.commitment();

// Each interval: MAC the payload, disclose the key from `disclosure_delay` ago.
let schedule = Schedule::default_at(epoch_ms);
let interval = schedule.interval_at(now_ms);
let tag = chain::mac(&chain.mac_key(interval)?, payload);
let disclosed_interval = interval - schedule.disclosure_delay;
let disclosed = chain.key(disclosed_interval)?;

// Receiver: verify the disclosure advances the chain, then check the MAC.
if chain::verify_disclosure(&anchor, anchor_interval, disclosed_interval, &disclosed) {
    let ok = chain::verify_mac(&chain::derive_mac_key(&disclosed), buffered, &tag);
}
```

The store merges verified facts without a server, without a CRDT library:

```rust
use signet_core::Store;

let mut store = Store::new();
store.merge(alice, STATUS, 5, b"need water");
store.merge(alice, STATUS, 3, b"ok");     // false — older, ignored

// Independent claims are never collapsed into one "truth".
let reports = store.by_kind(BRIDGE_OUT).count();   // "3 people report…"
```

## Integration

**An end user cannot add a crypto layer to a compiled app.** Bitchat has no
plugin API. What actually works, ranked by realism:

| You are | What you do |
|---|---|
| **Meshtastic owner** | Install the Signet app. Private portnum over the phone API — **no firmware change, no fork**. |
| **Any app, any OS** | Share-sheet companion. Compose in Signet → Share → Bitchat. Native OS primitive, zero cooperation needed. |
| **Bitchat user, Android** | Share sheet, or sideload a Signet-enabled fork. |
| **Bitchat user, iOS** | Share sheet, or wait for upstream. Nothing else is honest. |
| **A maintainer** | Three lines. |

For maintainers, integration is deliberately trivial — UniFFI generates the
Swift and Kotlin bindings from the same Rust core:

```swift
let payload = signet.sign(text)                 // send path
if let v = signet.verify(payload) {             // receive path
    badge = v.trustLevel                        // .eoc / .known / .unverified
}
```

Make it a protocol negotiation and nobody adopts it. Make it a function call
that returns a badge and there is a chance.

Signet is also designed to survive being carried as ordinary text through a
transport that knows nothing about it:

```text
Evacuate north of 5th St
--signet:1 from=GzJbRFwL2FM auth=n0wqfhHThbBsk_ohSOfQWw
```

A vanilla client shows the text plus one footer line; a Signet client verifies,
hides the footer, and renders ✅ **EOC verified**. The marker is plain ASCII and
says what it is, so someone who has never heard of Signet can search the word
and find out rather than seeing line noise.

TESLA's 16-byte MAC encodes to 22 base64url characters, so a typical footer is
~55 characters — tolerable in a chat bubble. A 666-byte signature is ~900 and
is not, which is one more argument for the two-tier design. Format is specified
in [the integration guide](docs/src/guide/integration.md#footer-format).

## The simulator

```bash
signet sim                                  # single point
signet sim --loss 0.4 --payload 100         # harsher link, bigger message
signet sim --sweep --csv sim-out/air.csv    # 0-50% loss, machine-readable
signet sim --sf 7 --bw 125                  # a different LoRa preset
```

The model is analytic, not Monte Carlo — closed-form binomials are exact and one
dependency lighter. Two honest caveats:

- Loss is modelled as independent. Real meshes lose bursts, which makes
  multi-frame messages *worse* than shown — every number here flatters the
  large-signature schemes.
- Multi-frame objects are erasure coded, not retransmitted. On a broadcast
  medium with no back-channel this beats ARQ, and it is why published
  ML-KEM-over-LoRa handshakes needing 28–62 frames are worse than necessary.

## Hard rules

Ten non-negotiables that keep the scope honest and the code deployable. Full
text and reasoning in [CONTRIBUTING.md](CONTRIBUTING.md#hard-rules):

1. `signet-core` stays `no_std` — it has to run on an ESP32.
2. `signet-core` stays hash-only — no post-quantum primitive in `core`.
3. Never implement a cryptographic primitive.
4. No C toolchain — `cargo test` works with zero system dependencies.
5. Parsers never panic on untrusted input.
6. Every rejection path gets a test.
7. Wire changes update `PROTOCOL.md` in the same PR.
8. New crates need a boundary that already hurts.
9. Phases are named for what they deliver.
10. The refused list: no blockchain or token, no revocation PKI, no CRDT
    library, no new mesh routing, no servers or accounts, no voice or video.

## Roadmap

See [`docs/src/roadmap`](docs/src/roadmap/README.md). Short version: **Airtime,
Protocol and Radio are the project.** Everything after is contingent on the
hardware numbers holding up.

## Development

```bash
just              # list tasks
just ci           # fmt + clippy + no_std check + tests — run before pushing
just sim          # the airtime cost model
just demo         # two nodes over a lossy channel
just docsserve    # mdbook with live reload
```

Workspace layout:

```text
crates/
  core/    signet-core   — wire format, chains, certs, time, frag, store (no_std)
  crypto/  signet-crypto — FN-DSA-512 signatures and cert operations
  cli/     signet        — CLI: `sim` and `demo`
docs/      mdbook source
PROTOCOL.md    the wire protocol
```

Three crates. `core` stays `no_std` and hash-only so it can run inside
Meshtastic firmware on an ESP32; `crypto` holds everything that needs more than
a hash function. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Signet is **alpha and unaudited**. Do not rely on it where being wrong has
consequences. The design is documented in [PROTOCOL.md](PROTOCOL.md) precisely so it can
be attacked on paper before anyone trusts it in the field.

Known gaps are tracked openly in [`docs/src/protocol/threat-model.md`](docs/src/protocol/threat-model.md)
— including the one where a public randomness beacon's own signature is not
post-quantum.

To report a vulnerability, do not open a public issue — use GitHub's private
reporting via the Security tab. See [SECURITY.md](SECURITY.md).

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the layer model, crate boundaries,
and the reasoning behind each design decision.

## License

MIT — see [LICENSE](LICENSE).
