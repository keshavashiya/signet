# Signet

**When a flood, an earthquake or a shutdown takes the network down, people cannot tell which warnings are real.**

Signet is a post-quantum authenticity layer for off-grid mesh networks, written
in Rust. It is designed to ride inside the payload of a mesh people already use
(Meshtastic, Bluetooth mesh, Reticulum, raw LoRa) and let a receiver check who
sent a message, with keys a quantum computer cannot forge.

## The name

A signet ring is a seal pressed into wax. It shows who sent a letter without
hiding what the letter says, and it needs no infrastructure.

Signet works the same way: it authenticates messages and does not encrypt them.
That keeps it usable on amateur radio bands, where rules in many countries
forbid encoding a message to hide its meaning. The name also reads as SIG + NET.

## The gap

The off-grid meshes in wide use authenticate with classical elliptic-curve
cryptography, which a quantum computer would break. Meshtastic's documentation
says quantum-resistant key exchange *"doesn't fit LoRa packet constraints."*

Of the three jobs a mesh's cryptography does, per-message authentication is the
one that becomes unaffordable on a radio link once it has to be post-quantum:

- **Encryption mostly survives.** Grover's algorithm halves AES-256's security
  margin, which still leaves 128 bits.
- **Key exchange is paid once** per pair of nodes and can be cached.
- **Per-message signatures are what break.** ML-DSA-44's 2420-byte signature
  spans twelve frames on a 233-byte link.

When the network is down, knowing who sent a message matters more than hiding
it. "This bridge is out" has to come provably from the county emergency
operations centre, and "the danger is on this street" from someone the reader
already trusts.

## What it costs

The [simulator](guide/index.md) is where to start. At Meshtastic's LongFast
preset with 20% frame loss:

| Scheme | Post-quantum | Effective airtime | Ratio |
|---|---|---|---|
| Ed25519 | ❌ | 1 569 ms | 1x |
| TESLA (SHA-256) | ✅ | **1 416 ms** | **1x** |
| SQIsign-I | ✅ | 7 221 ms | 5x |
| FN-DSA-512 | ✅ | 14 359 ms | 10x |
| ML-DSA-44 | ✅ | 43 226 ms | 31x |
| SLH-DSA-128s | ✅ | 132 475 ms | 94x |

Signing every message with ML-DSA-44 costs 31 times the airtime of TESLA.
Signet keeps routine traffic at 16 to 48 bytes and reserves signatures for the
messages that must stay attributable. These figures are computed from published
sizes and the Semtech time-on-air formula; no radio has measured them yet.

## Where to go next

- [Quick Start](guide/index.md): build it, run the model
- [Protocol overview](protocol/index.md): how the two message classes work
- [Time & the Security Condition](protocol/time.md): the hardest open problem
- [Threat Model](protocol/threat-model.md): including what Signet does *not* defend
- [Roadmap](roadmap/index.md): what Signet takes on, and what is built

## Status

Alpha and unaudited, with no radio yet. Do not rely on it where being wrong has
consequences. The design is written down in full so it can be reviewed before
anyone uses it in the field.
