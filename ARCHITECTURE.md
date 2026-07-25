# Signet — Architecture

This document explains how Signet is put together and, more importantly, *why*
each piece is the shape it is. The wire-level normative detail lives in
[PROTOCOL.md](PROTOCOL.md); this is the reasoning around it.

## Table of Contents

- [Design principle: one layer, not a stack](#design-principle-one-layer-not-a-stack)
- [Layer model](#layer-model)
- [Crate map](#crate-map)
- [Data flow](#data-flow)
- [Key types](#key-types)
- [Transport adapters](#transport-adapters)
- [Security model](#security-model)
- [Rejected alternatives](#rejected-alternatives)
- [Extending Signet](#extending-signet)

---

## Design principle: one layer, not a stack

Three good off-grid mesh networks already exist. Signet does not compete with
them, replace them, or wrap them. It supplies the one thing all three are
missing and rides inside the payload they already carry.

Concretely, Signet is **a payload format plus a key state machine**. It has no
opinion about routing, no discovery protocol, no delivery semantics, and no
network of its own. Every one of those is a place where a new project normally
dies re-solving a solved problem.

This constrains the design hard, which is the point:

- The frame header is 13 bytes, because every header byte is a payload byte
  lost on a 237-byte link.
- The core crate has three dependencies, all pure Rust, none of them a network
  or a runtime.
- Nothing requires cooperation from the host transport beyond "carries opaque
  bytes".

---

## Layer model

```text
┌──────────────────────────────────────────────────────────┐
│  Application                                             │
│  five buttons · offline map · trust badges               │   Flutter (App)
├──────────────────────────────────────────────────────────┤
│  Fact store                                              │
│  author-owned last-write-wins merge                      │   core::store
├──────────────────────────────────────────────────────────┤
│  ★ AUTHENTICITY LAYER — the project                      │
│  send/receive state machines                             │   core::session
│  TESLA chains · security condition                       │   core::chain, ::time
│  certificates · fragmentation · framing                  │   core::cert, ::frag, ::wire
│  FN-DSA-512 signatures                                   │   signet-crypto
├──────────────────────────────────────────────────────────┤
│  Transport adapters                                      │
│  Meshtastic · BLE · Reticulum · UDP multicast            │   (Radio, Bluetooth)
├──────────────────────────────────────────────────────────┤
│  Someone else's radio and mesh routing                   │   not ours
└──────────────────────────────────────────────────────────┘
```

Everything below the star already exists in the world. Rebuilding it would be
the single fastest way to fail.

---

## Crate map

Three crates, split along one line: what needs more than a hash function.

| Crate | Package | Role | Deps |
|---|---|---|---|
| `crates/core` | `signet-core` | Wire format, chains, certs, time, fragmentation, store | `sha2`, `hmac`, `reed-solomon-erasure` |
| `crates/crypto` | `signet-crypto` | FN-DSA-512 signatures, cert issue/verify | `signet-core`, `fn-dsa`, `rand_core` |
| `crates/cli` | `signet` | CLI: `sim` and `demo` | the above, `clap`, `anyhow` |

### Why `core` is `no_std`

Not aspiration — requirement. The same authenticity logic has to run inside
Meshtastic firmware on an ESP32 and inside a Flutter app on a phone. A `std`
dependency in `core` forecloses half the deployment targets, so CI checks
`--no-default-features` on every push and `just ci` runs it locally.

This is also why `core` contains **no cryptographic primitives beyond a hash
function**. That is the thesis, not a gap: the cheap authentication path is
built from SHA-256 alone, which makes it post-quantum by construction and lets
it run where a lattice signature never could.

### Why `crypto` is separate

The boundary is load-bearing, not decorative: `core` must run on an ESP32, and
FN-DSA key generation needs an OS entropy source. Splitting them means the
cheap authentication path — the one that has to work on a microcontroller —
carries none of the expensive path's baggage.

It shows up concretely in `cert.rs`: certificate *encoding* lives in `core`,
which produces the to-be-signed bytes and carries an opaque signature, while
signing and verification live in `crypto`. Neither crate needs the other's
dependencies.

The crate did not exist during Airtime and was not created in anticipation. Crates are
extracted when a boundary already hurts.

---

## Data flow

### Sending a routine status beacon

```text
app: "Need help, 4 people"
  │
  ├─> Header::new(Class::Tesla, sender_fp, interval)         13 B
  ├─> flags | seq | kind                                      7 B
  ├─> encode CBOR payload                                    ~30 B
  ├─> tag = mac(chain.mac_key(i), everything above)          16 B
  ├─> once per interval: disclose chain.key(i - d)           32 B
  │
  └─> transport.send(frame)                            66 or 98 B, 1 frame
```

### Receiving

```text
frame from radio
  │
  ├─> Header::decode  ──────────────> reject: truncated / bad version / bad class
  ├─> peer pinned?             ─────> reject: UnknownSender
  ├─> check security condition ─────> reject: TooLate — key could be public
  ├─> validate attached disclosure ─> reject: BadDisclosure (before buffering)
  ├─> buffer, awaiting its key
  │
  ├─> re-anchor to (j, K[j])
  ├─> key_from_anchor(anchor, j, i) for each buffered frame
  │     └─> hashes forward, recovering every skipped key
  ├─> verify_mac                ────> drop: failed_mac (a forgery)
  │
  └─> store.merge(author, kind, seq, payload)  ──> false: older or duplicate seq
```

The security condition is the step implementations get wrong. **Skipping it
makes the MAC meaningless** — an attacker simply waits for disclosure and
forges freely. `core::time` implements the check but not the *sources* of a
good time bound; the caller supplies the bound, and a caller that claims more
certainty than it has silently disables the whole mechanism. There is a test
named after exactly that.

---

## Key types

| Type | Definition | Why |
|---|---|---|
| `AuthorId` | `[u8; 8]` | Truncated cert hash. Full certs never touch the hot path. |
| `FactKind` | `u16` | Not an enum — old nodes must relay kinds they cannot parse. |
| `ChainKey` | `[u8; 32]` | SHA-256 output width. |
| `Mac` | `[u8; 16]` | Truncated. 128-bit forgery resistance, 64-bit under Grover. |
| `Class` | enum | The one place a `u8` becomes a decision, so it validates on decode. |
| `TimeBound` | `{earliest, latest}` | Never a point. No off-grid source yields one, and pretending otherwise is lying about the security. |
| `Alg` | enum | One byte of signature agility, because FIPS 206 is draft. |
| `Role` | enum | Unknown values degrade to `Civilian` — a future role must fail to grant privilege, not fail to decode. |
| `Error` | enum | Every decode failure is a value. Radio input never panics. |

---

## Transport adapters

Adapters are thin — roughly 150 lines each — and exist only to move opaque
frames. Priority order is by *extension surface*, not by technical merit:

| Order | Transport | Why this rank |
|---|---|---|
| 1 | **Meshtastic** | The only system with a real plugin surface. Private portnums over the phone API mean **no firmware change and no fork**, with a large already-deployed hardware base. Solves cold-start. |
| 2 | **Phone BLE** | No hardware to buy, so actual adoption is possible. Hardest to get right — done last. |
| 3 | **Reticulum** | Free WAN, packet-radio and LoRa reach as an RNS interface. |
| 4 | **UDP multicast** | A neighbourhood with a working router and a dead tower is a real scenario. |

### The integration ceiling

An end user cannot add a cryptographic layer to a compiled app. Bitchat has no
plugin API. This is a fact about mobile app distribution, not a gap to engineer
around, and the architecture accepts it:

- Signet must survive being carried as **ordinary text** by a transport that
  knows nothing about it — the inline `--signet:1` footer, specified in the
  integration guide.
- The library API must be small enough that upstream integration is a three-line
  diff, because that is the only integration anyone accepts unprompted.
- UniFFI generates Swift and Kotlin from the same core, so "three lines" is
  three lines on every platform.

---

## Security model

### What Signet defends against

| Threat | Defence |
|---|---|
| Forged authority ("fake evacuation order") | `Signed` class, cert chains to a pre-pinned root |
| Message tampering | HMAC over header and payload |
| Replay | Non-advancing intervals rejected; `seq` monotonic per author |
| Harvest-now-decrypt-later | Post-quantum throughout |
| Impersonation via node ID | Identity is a key, never a MAC address |
| State rollback | Store rejects same-or-older sequence numbers |

### What it does not

| Gap | Status |
|---|---|
| Sybil flooding | **Unsolved.** Infrastructure-free rate limiting is an open problem. |
| Revocation | Substituted with 30-day expiry. A compromised key is valid until then. |
| Traffic analysis | Out of scope. Fingerprints are stable and linkable by design. |
| Non-repudiation on `Tesla` frames | Structural — that is why `Signed` exists. |
| Beacon forgery by a quantum adversary | Known gap; drand's BLS12-381 is not PQ. |

### Trust boundaries

Two, and both are enforced in code rather than convention:

1. **The radio.** Everything arriving is hostile. `Header::decode` returns
   `Result`, never panics, and rejects short buffers, unknown versions and
   unknown classes before any field is read.
2. **Authentication.** `Store::merge` trusts sequence numbers. That trust is
   only earned after the verification in
   [PROTOCOL.md §5.4](PROTOCOL.md#54-receiving). The module documents this because a
   caller that merges unverified frames silently voids every ordering
   guarantee the store provides.

---

## Rejected alternatives

Recorded so they are not re-litigated.

| Considered | Rejected because |
|---|---|
| ML-DSA for all messages | 2420-byte signature = 11 frames = 31x the effective airtime. Measured, not assumed. |
| A CRDT library (Automerge, Yjs) | Author-owned keys make conflicts structurally impossible. Thousands of lines for a problem the key scheme deletes. |
| ARQ for multi-frame objects | No reliable back-channel on a broadcast medium. Erasure coding wins; this is why published ML-KEM-over-LoRa work needs 28–62 frames. |
| A revocation/status-list PKI | Requires the network that is missing. Short expiry is the honest dodge. |
| QKD | Needs fibre or line-of-sight optics. Anyone proposing it for disaster mesh is marketing. |
| Building a new mesh | Three exist. Adoption, not protocol, is the scarce resource. |
| Blockchain / token | Solves nothing here. The standing trap in this problem space. |
| Chat as the primary primitive | Disasters need mergeable structured state, not a message log. |
| Fountain codes (RaptorQ) | At the small `k` these objects produce, the overhead outweighs the benefit. Reed–Solomon is enough. |

---

## Extending Signet

### Adding a transport

Implement send and receive of opaque frames. Nothing else. If an adapter needs
to understand the frame body, the abstraction has leaked.

### Adding a fact kind

Pick an unused `u16`, document it in [PROTOCOL.md §9.1](PROTOCOL.md#91-fact-kinds), encode in CBOR.
Old nodes relay it without understanding it — that is why `FactKind` is not an
enum.

### Adding a signature scheme

Sizes go in `SCHEMES` in `crates/cli/src/sim.rs`, so the airtime consequence is
visible before the implementation exists. Add a variant to `cert::Alg` and the
registry in [PROTOCOL.md §2.5](PROTOCOL.md#25-signature-suite-registry). Then wrap the
primitive in `crates/crypto` — never in `core`, which must stay `no_std` and
hash-only.

### Adding a crate

Only when a boundary is already load-bearing. Three crates today is not an
accident to be corrected, and the `core`/`crypto` line in particular is load
bearing: it is what lets the cheap path run on a microcontroller.
