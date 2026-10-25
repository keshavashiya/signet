# Signet

[![CI](https://github.com/keshavashiya/signet/actions/workflows/ci.yml/badge.svg)](https://github.com/keshavashiya/signet/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Status: alpha](https://img.shields.io/badge/status-alpha-orange.svg)](#status)

By Keshav Ashiya

**When a flood, an earthquake or a shutdown takes the network down, people cannot tell which warnings are real.**

Signet is a post-quantum authenticity layer for off-grid mesh networks, written
in Rust. It is designed to ride inside the payload of a mesh people already use
(Meshtastic, Bluetooth mesh, Reticulum, plain LoRa) and let a receiver check
who sent a message, with keys a quantum computer cannot forge. It needs no
servers, accounts or internet connection.

Signet authenticates messages and does not encrypt them, so the text stays
readable. That also keeps it usable on amateur radio bands, where rules in many
countries forbid encoding a message to hide its meaning. The name comes from
the signet ring: a seal that shows who sent a letter without hiding what it
says.

[Full documentation](https://keshavashiya.github.io/signet): protocol spec,
architecture, integration guides.

---

## Quick start

```bash
git clone https://github.com/keshavashiya/signet.git
cd signet
cargo test --workspace     # 105 tests, no network, no hardware, no C toolchain

# What does authenticity cost on a 233-byte lossy link?
cargo run --bin signet -- sim

# Two nodes with real FN-DSA keys over a lossy channel
cargo run --bin signet -- demo --loss 30
```

```text
Signet airtime model — SF11 BW250kHz, MTU 233B, payload 30B, loss 20%, redundancy 30%
scheme             pq  trailer  frames    air ms  deliver    eff ms  note
----------------------------------------------------------------------------------------------------
Ed25519            NO       64       1      1255    80.0%      1569  1x  what every mesh ships today
TESLA (SHA-256)   yes       48       1      1133    80.0%      1416  1x  16B MAC + 32B disclosed key
SQIsign-I         yes      200     3/2      6470    89.6%      7221  5x  NIST round 3; slow to sign
MAYO-1            yes      464     4/3      8626    81.9%     10530  7x  NIST round 3
FN-DSA-512        yes      666     6/4     12939    90.1%     14359  10x  FIPS 206 draft
ML-DSA-44         yes     2420   16/12     34505    79.8%     43226  31x  FIPS 204, the safe default
SLH-DSA-128s      yes     7856   50/38    107827    81.4%    132475  94x  FIPS 205, hash-based root
```

On this link, signing every message with ML-DSA-44 costs 31 times the effective
airtime of a TESLA tag, and SLH-DSA-128s costs 94 times. That cost is the
problem Signet's design answers. The figures are computed from published
signature sizes and the Semtech LoRa time-on-air formula; no radio has measured
them yet, and [the simulator](#the-simulator) lists what the model leaves out.

---

## The problem

| System | Crypto today | Post-quantum? |
|---|---|---|
| [Bitchat](https://github.com/permissionlesstech/bitchat) | Curve25519 (Noise XX) | ❌ |
| [Meshtastic](https://meshtastic.org) | Curve25519 + AES-256-CTR | ❌ |
| [Reticulum](https://reticulum.network) | X25519 / Ed25519 / AES-256 | ❌ |
| [Briar](https://briarproject.org) | Ed25519 / X25519 | ❌ |

Meshtastic's documentation says quantum-resistant key exchange *"doesn't fit
LoRa packet constraints."*

Of the three jobs a mesh's cryptography does, per-message authentication is the
one that becomes unaffordable on a radio link once it has to be post-quantum:

- **Encryption mostly survives.** Grover's algorithm halves AES-256's security
  margin, which still leaves 128 bits.
- **Key exchange is paid once** per pair of nodes and can be cached.
- **Per-message signatures are what break.** A post-quantum signature is 3 to
  120 times larger than Ed25519's 64 bytes, and it is paid on every message.

When the network is down, knowing who sent a message matters more than hiding
it. "This bridge is out" has to come provably from the emergency operations
centre, and "the danger is on this street" from someone the reader already
trusts.

## How it works

Signet has two message classes and picks one per message, by how much is at
stake.

### Class A: TESLA hash chains (routine traffic, 16–48 bytes)

A sender commits to the end of a one-way hash chain, MACs each interval's
traffic with a key only it holds, and discloses that key once the interval
closes. A receiver that got the message *before* the key went public knows
nobody else could have forged it. This is TESLA (Perrig, Canetti, Tygar and
Song, 2000; [RFC 4082](https://www.rfc-editor.org/rfc/rfc4082)), which μTESLA
later fitted to sensor radios and Galileo's OSNMA uses to authenticate
satellite navigation messages.

```text
[16B MAC]                       typical
[16B MAC] [32B disclosed key]   first frame of each interval
```

The 48-byte form is 50 times smaller than an ML-DSA-44 signature. It is
post-quantum because it uses nothing but SHA-256, and it tolerates loss: a
receiver that misses three disclosures recovers all of them from the fourth by
hashing forward. A sender pays the 32-byte disclosure once per interval,
however many messages it sends in it. See [`chain.rs`](crates/core/src/chain.rs)
and [`session.rs`](crates/core/src/session.rs).

### Class B: post-quantum signature (authoritative traffic, 666 bytes)

TESLA authenticates broadcast but gives no non-repudiation: once a key is
disclosed, anyone can forge that interval after the fact. Messages that must
stay attributable get an FN-DSA-512 signature instead.

| Message | Class | Cost |
|---|---|---|
| Status beacon, chat, sensor reading | TESLA | 16–48 B |
| Evacuation order, official alert, credential | PQ signature | 666 B |

Authoritative messages are rare, so their six frames are affordable. The
signature and certificate code is built; the `Signed` send path is not yet
([Status](#status)).

### The hard part: time

TESLA needs a bound on the sender's clock, and off-grid there is no NTP. Signet
keeps a local monotonic clock and tightens it when it can: from a GPS fix, from
peers' bounds, and from a public randomness beacon used as a floor. The
disclosure delay widens to cover the uncertainty that remains, and when that is
too much the design falls back to Class B.

The security condition and the interval arithmetic are built
([`time.rs`](crates/core/src/time.rs)). The time sources, the Class B fallback,
and peer bounds that stay safe when some peers lie are open work (the Clock
phase, and [PROTOCOL.md Section 14](PROTOCOL.md#14-open-questions)). Until then a
receiver refuses what it cannot check: `signet demo --uncertainty-ms 600000`
shows every frame correctly refused. See
[`docs/protocol/time.md`](docs/src/protocol/time.md).

---

## Status

**Alpha: Airtime and Protocol are done.** The protocol is specified and
implemented: real FN-DSA-512 certificates, TESLA chains, the security
condition, erasure-coded fragmentation and a verified fact store, with 105
tests. Nothing has run on a radio yet.

| Phase | Delivers | State | Artefact |
|---|---|---|---|
| **Airtime** | What authenticity costs on a lossy link | ✅ done | `signet sim` |
| **Protocol** | Chains, certs, clocks, fragmentation, sessions | ✅ done | `signet demo`, 105 tests |
| **Warnings** | Verified warnings that work in a disaster and in a shutdown | ⬜ next | one end-to-end test per scenario |
| **Radio** | Meshtastic over real LoRa hardware | ⬜ | two T-Beams |
| **Clock** | Time sync without infrastructure | ⬜ | the research contribution |
| **Integration** | Signet inside the mesh apps people already use | ⬜ | bindings, one host app showing the badge |

There is no Signet app on the roadmap. Meshtastic, Bitchat and Reticulum
already have the apps people use, so Signet goes into them. An app of our own
is the fallback if no host will carry it.

Not built yet: the `Signed` send path (the primitive is there, the framing is
not; Warnings builds it), ML-KEM confidentiality, any radio transport, and the
bindings and text footer described under [Integration](#integration).

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

A user cannot add a cryptographic layer to a compiled app, and Bitchat has no
plugin API. So Signet is meant to go in through the apps people already use,
and every path except the fallback needs that app's maintainers to agree.
**None of these paths is built yet.**

| You are | Planned path |
|---|---|
| **An app maintainer** | Call Signet's sign and verify functions. The roadmap is built on this path. |
| **Meshtastic user** | A Meshtastic app with Signet in it, using a private portnum over the phone API, so the node's firmware does not change. |
| **Bitchat user, Android** | Upstream support, or a Signet-enabled fork installed by hand. |
| **Bitchat user, iOS** | Upstream support. |
| **Fallback** | A Signet companion app that needs no one's cooperation: paired with a Meshtastic node, or used through the share sheet with any app. Built only if no host takes Signet. |

The planned maintainer API is two calls, with Swift and Kotlin bindings
generated from the Rust core by UniFFI:

```swift
let payload = signet.sign(text)                 // send path
if let v = signet.verify(payload) {             // receive path
    badge = v.trustLevel                        // .eoc / .known / .unverified
}
```

A message may also have to cross an app that knows nothing about Signet, so
the integration guide specifies a plain-text footer:

```text
Need water at 12 Main St, 4 people
--signet:1 from=GzJbRFwL2FM auth=n0wqfhHThbBsk_ohSOfQWw
```

An app without Signet shows the text plus one footer line. A Signet client
verifies it, hides the footer and shows a badge, here 🔑 **known sender**. The
marker is plain ASCII and names itself, so someone who has never heard of
Signet can search for it.

A 16-byte MAC makes a footer of about 55 characters; a 666-byte signature
would need about 900, so only routine `Tesla` traffic uses a footer. An
evacuation order must be `Signed` ([PROTOCOL.md Section 4.1](PROTOCOL.md#41-choosing-a-class))
and never travels this way. A footer also keeps TESLA's timing: a Signet client
has to see it before that interval's key is disclosed, 30–60 s at the default
schedule, and it verifies once a later message brings the key. The format is in
[the integration guide](docs/src/guide/integration.md#footer-format).

## The simulator

```bash
signet sim                                  # single point
signet sim --loss 0.4 --payload 100         # harsher link, bigger message
signet sim --sweep --csv sim-out/air.csv    # 0-50% loss, machine-readable
signet sim --sf 7 --bw 125                  # a different LoRa preset
```

The model is analytic (closed-form binomials), not Monte Carlo. What it leaves
out:

- **Burst loss.** Loss is modelled as independent, but real meshes lose
  bursts, which makes multi-frame messages worse than shown. Every number here
  flatters the large-signature schemes.
- **Retransmission.** Multi-frame objects are erasure coded, not
  retransmitted. On a broadcast medium with no back-channel this beats ARQ.
- **Duty cycle and multi-hop.** Airtime is counted for one transmission on
  one hop. Rebroadcasts multiply it, and regional duty-cycle limits are not
  applied.

## Hard rules

The project's ten rules; the full text and the reasons are in
[CONTRIBUTING.md](CONTRIBUTING.md#hard-rules):

1. `signet-core` stays `no_std`, so it can run on an ESP32.
2. `signet-core` uses only hash functions; post-quantum primitives live in
   `signet-crypto`.
3. Never implement a cryptographic primitive.
4. No C toolchain: `cargo test` needs no system dependencies.
5. Parsers never panic on untrusted input.
6. Every rejection path gets a test.
7. Wire changes update `PROTOCOL.md` in the same PR.
8. New crates need a boundary that already hurts.
9. Phases are named for what they deliver.
10. The refused list: no blockchain or token, no revocation PKI, no CRDT
    library, no new mesh routing, no servers or accounts, no voice or video.

## Roadmap

See [`docs/src/roadmap`](docs/src/roadmap/index.md). In short, Signet makes a
warning checkable while the network is down and leaves carrying it to the apps
people already use. The roadmap page also lists what is still open.

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
consequences. [PROTOCOL.md](PROTOCOL.md) documents the design in full so it can
be reviewed before anyone uses it in the field.

Known gaps are listed in
[`docs/src/protocol/threat-model.md`](docs/src/protocol/threat-model.md),
including a public randomness beacon whose own signature is not post-quantum.

To report a vulnerability, use GitHub's private reporting (the Security tab),
not a public issue. See [SECURITY.md](SECURITY.md).

## Architecture

[ARCHITECTURE.md](ARCHITECTURE.md) covers the layer model, the crate
boundaries and the reasoning behind each design decision.

## License

MIT. See [LICENSE](LICENSE).
