# Threat Model

Signet is alpha and unaudited. This page states what it is trying to defend,
what it is not, and where it is currently known to be weak.

## Adversaries

| Adversary | Capability | In scope |
|---|---|---|
| **Passive listener** | Records all radio traffic, stores it indefinitely | ✅ |
| **Active injector** | Transmits arbitrary frames on the same band | ✅ |
| **Impersonator** | Claims to be a responder or the EOC | ✅ |
| **Future quantum adversary** | Breaks classical public-key crypto: forges its signatures, decrypts recorded traffic | ✅ |
| **Device thief** | Physically seizes a phone with hot keys | Partially |
| **Jammer** | Denies the channel outright | ❌ |
| **Global traffic analyst** | Correlates who talks to whom | ❌ |

Jamming is out of scope because no cryptographic layer can answer it; it is a
physical-layer problem. Traffic analysis is out of scope because sender
fingerprints are stable *by design*: an emergency network needs to know who is
talking.

## What Signet defends

| Threat | Defence | Where |
|---|---|---|
| Forged authority ("fake evacuation order") | `Signed` class, cert chains to a root pinned before deployment | [PROTOCOL.md §4.1](https://github.com/keshavashiya/signet/blob/main/PROTOCOL.md#41-choosing-a-class) |
| Message tampering | HMAC-SHA256 over header and payload | `chain::mac` |
| Replay of an old disclosure | Non-advancing intervals rejected | `chain::verify_disclosure` |
| State rollback ("mark them safe again") | Store rejects same-or-older sequence numbers | `store::merge` |
| Forgery by a quantum adversary | SHA-256 chains for `Tesla`, FN-DSA for `Signed` and certs; the time sources are the exception (below) | [PROTOCOL.md §12.1](https://github.com/keshavashiya/signet/blob/main/PROTOCOL.md#121-published-primitive-sizes) |
| Harvest-now-decrypt-later | Nothing to decrypt: payloads are plaintext by design. Planned confidentiality is hybrid ML-KEM | [PROTOCOL.md §8](https://github.com/keshavashiya/signet/blob/main/PROTOCOL.md#8-confidentiality-planned) |
| Impersonation via node ID | Identity is a key, never a MAC address | [PROTOCOL.md §2](https://github.com/keshavashiya/signet/blob/main/PROTOCOL.md#2-identity) |
| Disclosed key reused as MAC key | Domain-separated derivation | `chain::derive_mac_key` |
| Malformed frames from the radio | Total decoding; every failure is a value | `wire::Header::decode` |

### Identity

Meshtastic derives node IDs from the hardware MAC address, which a transmitter
can claim falsely. Signet's identity is a key with a cert chain, and the badge
a host app shows is how users see the difference:

| Badge | Meaning |
|---|---|
| ✅ | Cert chains to a root you pinned in advance |
| 🔑 | You scanned this person's QR in person |
| ⚪ | Heard on the mesh, unverified |
| ⚠️ | Cannot verify: shown greyed, never hidden |

## What Signet does not defend

### Sybil flooding: unsolved

Nothing prevents an attacker generating unlimited unverified identities and
saturating the channel. Rate limiting that survives sybils without
infrastructure is an open problem. Current partial answer: unverified
identities render ⚪ and the app can deprioritise them, which limits impact on
*users* while doing nothing about airtime exhaustion.

### Revocation: substituted, not solved

There is none. Offline revocation requires fetching a status list, which
requires the network that is missing. Signet substitutes 30-day cert expiry.

**A compromised operational key remains valid until it expires.** This is a
real weakness. It is preferable to shipping revocation infrastructure that
cannot function in the deployment scenario, but it is not equivalent to having
revocation.

### Non-repudiation on `Tesla` frames: not possible

Once `K[i]` is disclosed, anyone can forge interval `i` retroactively, so TESLA
frames are not evidence after the fact. This is why the `Signed`
class exists and why receivers must never render an authority badge on a
`Tesla` frame.

### Beacon forgery by a quantum adversary: known gap

drand signs beacon rounds with BLS12-381, which is not post-quantum. A quantum
adversary could forge future beacon values. A receiver that takes one only
refuses frames too early, which is denial of service. A sender that takes one
moves its clock forward and discloses keys while receivers with correct clocks
still accept that interval, which breaks TESLA's security condition.

Mitigated by never treating the beacon as sole authority (see
[Time](time.md)). Properly closed by a hash-chain beacon, which does not exist
yet.

### Coercion and device seizure: partially

The two-tier identity contains the damage: the root key is cold and paper-backed,
so seizure yields an operational key that expires. It does not protect messages
already sent, and it does not protect a user compelled to unlock a device.

### Denial of service by airtime exhaustion

LoRa duty-cycle limits mean a single misbehaving transmitter can consume a
disproportionate share of the channel. Signet's 16-to-48-byte trailer uses far
less airtime than a 2420-byte signature would, but that does not solve this.

### A blocked host: outside Signet's control

Signet rides inside other apps, so it is only as available as they are. A host
app can be pulled from app stores or blocked by a government, and Signet loses
that channel with it. The protocol and the core stay host-agnostic, so the same
messages can move to another host, and no single app is a dependency.

### Anonymity: not offered, by design

A signed message names its sender, and sender fingerprints are stable and
linkable ([PROTOCOL.md §1.3](https://github.com/keshavashiya/signet/blob/main/PROTOCOL.md#13-non-goals)).
That suits coordination with known responders. It is the wrong tool for anyone
who must keep their identity hidden, including from authorities: Signet does
not hide who is talking, and a host app's own encryption is separate from it.

## Trust boundaries

Two, both enforced in code rather than convention.

### 1. The radio

Everything arriving is hostile until authenticated. `Header::decode` returns
`Result` and rejects short buffers, unknown versions and unknown classes before
reading any field. `signet-core` sets `#![forbid(unsafe_code)]`.

### 2. Authentication

`Store::merge` trusts sequence numbers for ordering. That trust is earned only
after the verification in
[PROTOCOL.md §5.4](https://github.com/keshavashiya/signet/blob/main/PROTOCOL.md#54-receiving).
**A caller that merges unverified frames silently voids every ordering
guarantee the store provides,** including replay and rollback protection. This
is the most likely integration bug, and nothing reports it when it happens.

## Reporting

Do not open a public issue for a vulnerability. Report it privately through
GitHub's [Security tab](https://github.com/keshavashiya/signet/security/advisories/new).

Critique of the design in [PROTOCOL.md](https://github.com/keshavashiya/signet/blob/main/PROTOCOL.md)
is welcome as a public issue. The specification is published so it can be
reviewed before anyone uses it in the field.
