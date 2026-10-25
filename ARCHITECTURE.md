# Signet architecture

This document explains how Signet is put together and why each piece has the
shape it has. The wire-level normative detail lives in
[PROTOCOL.md](PROTOCOL.md); this is the reasoning around it.

## Design principle: one layer, not a stack

Meshtastic, Bluetooth mesh apps and Reticulum already move messages off-grid.
Signet does not replace or wrap them. It adds post-quantum sender
authentication, which none of them has, inside the payload they already carry.

Signet is **a payload format plus a key state machine**. It does no routing,
discovery or delivery and has no network of its own, because those problems
are already solved by the meshes it rides on.

That constrains the design:

- The frame header is 13 bytes, because every header byte is a payload byte
  lost on a 233-byte link.
- The core crate has three dependencies, all pure Rust, none of them a network
  or a runtime.
- Nothing requires cooperation from the host transport beyond "carries opaque
  bytes".

---

## Layer model

```text
┌──────────────────────────────────────────────────────────┐
│  Application                                             │
│  the host's app · trust badges                           │   (Integration)
├──────────────────────────────────────────────────────────┤
│  Fact store                                              │
│  author-owned last-write-wins merge                      │   core::store
├──────────────────────────────────────────────────────────┤
│  AUTHENTICITY LAYER (this project)                       │
│  send/receive state machines                             │   core::session
│  TESLA chains · security condition                       │   core::chain, ::time
│  certificates · fragmentation · framing                  │   core::cert, ::frag, ::wire
│  FN-DSA-512 signatures                                   │   signet-crypto
├──────────────────────────────────────────────────────────┤
│  Transport adapters                                      │
│  Meshtastic · BLE · Reticulum · UDP multicast            │   (Radio, Integration)
├──────────────────────────────────────────────────────────┤
│  Someone else's radio and mesh routing                   │   not ours
└──────────────────────────────────────────────────────────┘
```

Everything below the authenticity layer already exists, and Signet does not
rebuild it.

---

## Crate map

Three crates, split along one line: what needs more than a hash function.

| Crate | Package | Role | Deps |
|---|---|---|---|
| `crates/core` | `signet-core` | Wire format, chains, certs, time, fragmentation, store | `sha2`, `hmac`, `reed-solomon-erasure` |
| `crates/crypto` | `signet-crypto` | FN-DSA-512 signatures, cert issue/verify | `signet-core`, `fn-dsa`, `rand_core` |
| `crates/cli` | `signet` | CLI: `sim` and `demo` | the above, `clap`, `anyhow` |

### Why `core` is `no_std`

The same authenticity logic has to run inside Meshtastic firmware on an ESP32
and inside a host app on a phone. A `std` dependency in `core` would rule out
the microcontroller targets, so CI checks
`--no-default-features` on every push and `just ci` runs it locally.

This is also why `core` contains **no cryptographic primitive beyond a hash
function**. The cheap authentication path is built from SHA-256 alone, which
makes it post-quantum by construction and lets it run on hardware where a
lattice signature would not fit.

### Why `crypto` is separate

`core` must run on an ESP32, and FN-DSA key generation needs an OS entropy
source. Keeping them apart means the cheap authentication path, which has to
work on a microcontroller, carries none of the signature path's dependencies.

The split shows in `cert.rs`: certificate *encoding* lives in `core`,
which produces the to-be-signed bytes and carries an opaque signature, while
signing and verification live in `crypto`. Neither crate needs the other's
dependencies.

The crate was extracted during Protocol, when the boundary was needed, not
before.

---

## Data flow

### Sending a routine status beacon

```text
app: "Need help, 4 people"
  │
  ├─> Header::new(Class::Tesla, sender_fp, interval)         13 B
  ├─> flags | seq | kind                                      7 B
  ├─> payload (CBOR per PROTOCOL.md Section 9; encoder not built)  ~30 B
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
  ├─> check security condition ─────> reject: TooLate (key may be public)
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
makes the MAC meaningless:** an attacker waits for the key to be disclosed and
then forges freely. `core::time` implements the check but not the *sources* of a
good time bound; the caller supplies the bound, and a caller that claims more
certainty than it has silently disables the whole mechanism. A test covers
exactly that case.

---

## Key types

| Type | Definition | Why |
|---|---|---|
| `AuthorId` | `[u8; 8]` | Truncated cert hash. Full certs never touch the hot path. |
| `FactKind` | `u16` | Not an enum, because old nodes must relay kinds they cannot parse. |
| `ChainKey` | `[u8; 32]` | SHA-256 output width. |
| `Mac` | `[u8; 16]` | Truncated. A blind forgery lands with probability 2⁻¹²⁸ per try; Grover does not help, because a receiver checks each guess. |
| `Class` | enum | The one place a `u8` becomes a decision, so it validates on decode. |
| `TimeBound` | `{earliest, latest}` | Never a point, because no off-grid source gives one, and a point would overstate the security. |
| `Alg` | enum | One byte of signature agility, because FIPS 206 is draft. |
| `Role` | enum | Unknown values degrade to `Civilian`: a future role must fail to grant privilege, not fail to decode. |
| `Error` | enum | Every decode failure is a value. Radio input never panics. |

---

## Transport adapters

None is written yet. An adapter is meant to be thin and only move opaque
frames. Priority order is by *extension surface*, not by technical merit:

| Order | Transport | Why this rank |
|---|---|---|
| 1 | **Meshtastic** | The only system with a real plugin surface. Private portnums over the phone API mean **no firmware change and no fork**, with a large already-deployed hardware base. Solves cold-start. |
| 2 | **Phone BLE** | No hardware to buy, so actual adoption is possible. It arrives by integrating with Bluetooth mesh apps that already exist, more than one, since any single app can be blocked. |
| 3 | **Reticulum** | Free WAN, packet-radio and LoRa reach as an RNS interface. |
| 4 | **UDP multicast** | A neighbourhood with a working router and a dead tower is a real scenario. |

### The integration ceiling

An end user cannot add a cryptographic layer to a compiled app, and Bitchat has
no plugin API. The design accepts that, and plans for it (none of this is
built yet):

- Signet must survive being carried as **ordinary text** by a transport that
  knows nothing about it: the inline `--signet:1` footer, specified in the
  integration guide.
- The library API must be small enough that upstream integration is a few
  lines, because maintainers rarely accept anything larger unprompted.
- UniFFI would generate Swift and Kotlin from the same core, so the calls are
  the same on every platform.

---

## Security model

### What Signet defends against

| Threat | Defence |
|---|---|
| Forged authority ("fake evacuation order") | `Signed` class, cert chains to a pre-pinned root |
| Message tampering | HMAC over header and payload |
| Replay | Non-advancing intervals rejected; `seq` monotonic per author |
| Forgery by a quantum adversary | SHA-256 chains and FN-DSA; no classical signature on the authentication path |
| Harvest-now-decrypt-later | Nothing to decrypt: plaintext by design; planned confidentiality is hybrid ML-KEM |
| Impersonation via node ID | Identity is a key, never a MAC address |
| State rollback | Store rejects same-or-older sequence numbers |

### What it does not

| Gap | Status |
|---|---|
| Sybil flooding | **Unsolved.** Infrastructure-free rate limiting is an open problem. |
| Revocation | Substituted with 30-day expiry. A compromised key is valid until then. |
| Traffic analysis | Out of scope. Fingerprints are stable and linkable by design. |
| Non-repudiation on `Tesla` frames | Not possible by construction; that is why `Signed` exists. |
| Beacon forgery by a quantum adversary | Known gap; drand's BLS12-381 is not PQ. |
| A blocked host app | Outside Signet's control. The core stays host-agnostic, so messages can move to another host. |

### Trust boundaries

Two, and both are enforced in code rather than convention:

1. **The radio.** Everything arriving is hostile. `Header::decode` returns
   `Result`, never panics, and rejects short buffers, unknown versions and
   unknown classes before any field is read.
2. **Authentication.** `Store::merge` trusts sequence numbers. That trust is
   only earned after the verification in
   [PROTOCOL.md Section 5.4](PROTOCOL.md#54-receiving). The module documents this because a
   caller that merges unverified frames silently voids every ordering
   guarantee the store provides.

---

## Rejected alternatives

Recorded so they are not argued again.

| Considered | Rejected because |
|---|---|
| ML-DSA for all messages | 2420-byte signature = 11 frames = 31x the effective airtime. Computed by the airtime model from published sizes, not assumed; no radio measurement yet. |
| A CRDT library (Automerge, Yjs) | Each fact is keyed by its author, so two writers never conflict. A CRDT library would add thousands of lines for a problem the key scheme removes. |
| ARQ for multi-frame objects | No reliable back-channel on a broadcast medium, so erasure coding is used instead. Published ML-KEM-over-LoRa work that retransmits needs 28–62 frames. |
| A revocation/status-list PKI | Requires the network that is missing. Short expiry is used instead. |
| QKD | Needs fibre or line-of-sight optics, which a disaster mesh does not have. |
| Building a new mesh | Several exist. Getting people to adopt one is harder than designing one. |
| Blockchain / token | Needs consensus over a network that is down, and solves no problem here. |
| Chat as the primary primitive | Disasters need mergeable structured state, not a message log. |
| Fountain codes (RaptorQ) | At the small `k` these objects produce, the overhead outweighs the benefit. Reed–Solomon is enough. |

---

## Extending Signet

### Adding a transport

Implement send and receive of opaque frames. Nothing else. If an adapter needs
to understand the frame body, the abstraction has leaked.

### Adding a fact kind

Pick an unused `u16`, document it in [PROTOCOL.md Section 9.1](PROTOCOL.md#91-fact-kinds), encode in CBOR.
Old nodes relay it without understanding it, which is why `FactKind` is not an
enum.

### Adding a signature scheme

Sizes go in `SCHEMES` in `crates/cli/src/sim.rs`, so the airtime cost is
visible before the implementation exists. Add a variant to `cert::Alg` and the
registry in [PROTOCOL.md Section 2.5](PROTOCOL.md#25-signature-suite-registry). Then wrap the
primitive in `crates/crypto`, never in `core`, which must stay `no_std` and
hash-only.

### Adding a crate

Only when a boundary is already needed. Three crates is deliberate, and the
`core`/`crypto` line is what lets the cheap path run on a microcontroller.
