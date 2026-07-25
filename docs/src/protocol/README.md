# Protocol Overview

The normative wire specification is
[PROTOCOL.md](https://github.com/keshavashiya/signet/blob/main/PROTOCOL.md) in the repo
root. It is kept there, not duplicated here, so it cannot drift out of sync
with the implementation it sits next to. This page is the shape of it.

## The central decision

Signet has two message classes, and choosing between them is the whole
contribution.

```text
┌─────────────────────────────────────────────────────────────┐
│  Class A — Tesla                             16–48 bytes    │
│  16B MAC, +32B disclosed key once per interval              │
│  routine: status beacons, chat, sensor readings             │
│  authenticated broadcast, NOT non-repudiable                │
├─────────────────────────────────────────────────────────────┤
│  Class B — Signed                              666 bytes    │
│  post-quantum signature                                     │
│  authoritative: evacuation orders, credentials              │
│  verifiable by a third party, later                         │
└─────────────────────────────────────────────────────────────┘
```

The tiering exists because TESLA is repudiable after key disclosure. That is
acceptable for live coordination and unacceptable for anything anyone must be
able to verify afterwards.

## Why TESLA is post-quantum

It is nothing but SHA-256. No lattices, no isogenies, no assumptions that a
quantum computer disturbs. Grover's algorithm halves the effective security of
a hash, which is why chain values are 256 bits and MACs are truncated to 128.

This is the least fashionable answer to "make it post-quantum" and, on a
237-byte link, the only one that works.

## Why it suits a lossy link

Gap recovery is free. A receiver anchored at interval 3 that misses the
disclosures for 4, 5 and 6 recovers all three from `K[7]` by hashing forward:

```text
K[7] ──H──> K[6] ──H──> K[5] ──H──> K[4] ──H──> K[3]  ✓ matches anchor
```

A signature scheme in the same position needs retransmits, and there is no
reliable back-channel to negotiate them on.

## The frame

Thirteen bytes, fixed, no options.

```text
byte 0      version (4 bits) | class (4 bits)
bytes 1-8   sender fingerprint — truncated operational cert hash
bytes 9-12  interval index, big-endian u32
byte 13     flags — bit 0 signals an attached key disclosure
bytes 14-19 sequence number (4B) and fact kind (2B)
bytes 20+   payload, then the class-specific trailer
```

Certs are never sent on the hot path. Frames carry an 8-byte fingerprint; a
receiver missing the cert requests it once and caches it forever. That is what
keeps a 1.6 KiB credential off a 200-byte link.

## What is specified elsewhere

| Topic | Where |
|---|---|
| Full wire format, identity, fragmentation, payloads | [PROTOCOL.md](https://github.com/keshavashiya/signet/blob/main/PROTOCOL.md) |
| The clock problem and how it degrades | [Time & the Security Condition](time.md) |
| What is and is not defended | [Threat Model](threat-model.md) |
| Every byte count with its source | [Primitive Sizes](sizes.md) |

## Stability

Draft. Before v1.0.0 the wire format may change without a compatibility path.
Pin a commit.
