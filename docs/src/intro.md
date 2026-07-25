# Signet

**In a disaster, you cannot tell whether the evacuation order is real.**

Signet is a post-quantum authenticity layer for off-grid mesh networks. It
rides inside whatever payload your radio already carries — Meshtastic,
Bluetooth mesh, Reticulum, raw LoRa — and answers the one question the existing
stacks cannot: *did this message really come from who it claims?*

## The name

A signet ring is a seal pressed into wax. The oldest authentication technology
there is, it requires no infrastructure at all, and it proves the sender
**without hiding the letter**.

That is not a loose metaphor. It is the design decision: authenticity first,
confidentiality optional. It is also why Signet is legal on amateur radio
bands, where encryption is prohibited but signing is not — which happens to
make ham radio the most capable long-range disaster network that has never had
verifiable senders.

It reads as SIG + NET, which was free.

## The gap

Every off-grid mesh in production uses classical elliptic-curve cryptography.
Meshtastic's own documentation concedes why: quantum-resistant key exchange
*"doesn't fit LoRa packet constraints."*

Radio traffic is trivially interceptable — the textbook
harvest-now-decrypt-later target. But the sharper problem is not
confidentiality:

- **Encryption already survives.** AES-256 only loses half its margin to Grover.
- **Key exchange is a one-time, cacheable cost.** Ugly, but it amortises away.
- **Per-message authenticity is what breaks.** ML-DSA-44's 2420-byte signature
  spans eleven frames on a 237-byte link.

And in an emergency, authenticity matters *more* than secrecy. Misinformation
kills, and "this bridge is out" needs to provably come from the county
emergency operations centre.

## What it costs

The [simulator](guide/README.md) is where to start. At Meshtastic's LongFast
preset with 20% frame loss:

| Scheme | Post-quantum | Effective airtime | Ratio |
|---|---|---|---|
| Ed25519 | ❌ | 1 283 ms | 1x |
| TESLA (SHA-256) | ✅ | **1 129 ms** | **1x** |
| SQIsign-I | ✅ | 6 590 ms | 6x |
| FN-DSA-512 | ✅ | 13 105 ms | 12x |
| ML-DSA-44 | ✅ | 35 323 ms | 31x |
| SLH-DSA-128s | ✅ | 107 238 ms | 95x |

Making an off-grid mesh post-quantum the obvious way costs 31x the airtime per
message. Signet's answer is to make routine traffic cost 16 to 48 bytes and
reserve signatures for the messages that move people.

## Where to go next

- [Quick Start](guide/README.md) — build it, run the model
- [Protocol overview](protocol/README.md) — how the two message classes work
- [Time & the Security Condition](protocol/time.md) — the hardest open problem
- [Threat Model](protocol/threat-model.md) — including what Signet does *not* defend
- [Roadmap](roadmap/README.md) — what is built and what is not

## Status

Alpha and unaudited. Do not rely on it where being wrong has consequences.
The design is written down in detail precisely so it can be attacked on paper
before anyone trusts it in the field.
