# Architecture Overview

The full document is
[ARCHITECTURE.md](https://github.com/keshavashiya/signet/blob/main/ARCHITECTURE.md)
in the repo root: layer model, crate boundaries, data flow, security model,
and a record of rejected alternatives. This page is the summary.

## One layer, not a stack

Meshtastic, Bluetooth mesh apps and Reticulum already move messages off-grid.
Signet does not replace or wrap them. It adds post-quantum sender
authentication, which none of them has, inside the payload they already carry.

Signet is **a payload format plus a key state machine.** It does no routing,
discovery or delivery and has no network of its own, because the meshes it
rides on already solve those problems.

```text
┌──────────────────────────────────────────────────────────┐
│  Application — the host's app, with Signet's badges      │  (Integration)
├──────────────────────────────────────────────────────────┤
│  Fact store — author-owned last-write-wins               │  core::store
├──────────────────────────────────────────────────────────┤
│  AUTHENTICITY LAYER (this project)                       │  core::session
│    TESLA · certs · time · fragmentation · framing        │  core::{chain,cert}
│    FN-DSA-512 signatures                                 │  signet-crypto
├──────────────────────────────────────────────────────────┤
│  Transport adapters — Meshtastic · BLE · Reticulum · UDP │  (Radio, Integration)
├──────────────────────────────────────────────────────────┤
│  Someone else's radio and mesh routing                   │  not ours
└──────────────────────────────────────────────────────────┘
```

Everything below the authenticity layer already exists.

## Crates

Three, split along one line: what needs more than a hash function.

| Crate | Package | Role | Deps |
|---|---|---|---|
| `crates/core` | `signet-core` | Wire format, chains, certs, time, fragmentation, store | `sha2`, `hmac`, `reed-solomon-erasure` |
| `crates/crypto` | `signet-crypto` | FN-DSA-512 signatures, cert issue/verify | `signet-core`, `fn-dsa`, `rand_core` |
| `crates/cli` | `signet` | CLI: `sim` and `demo` | the above, `clap`, `anyhow` |

`core` is `no_std` + `alloc` and sets `#![forbid(unsafe_code)]`, because the
same logic has to run inside Meshtastic firmware on an ESP32 and in a phone
app. CI checks `--no-default-features` on every push.

It also contains **no cryptographic primitive beyond a hash function**. The
cheap authentication path is SHA-256 alone, which makes it post-quantum by
construction and lets it run on hardware where a lattice signature would not
fit.

`signet-crypto` holds everything that needs more than a hash function:
FN-DSA-512 signing, verification and certificate issuance. `core` must run on
an ESP32, and key generation needs an OS entropy source, so the two are kept
apart. Crates are extracted when a boundary is needed, not before.

## The two trust boundaries

Both enforced in code rather than convention.

1. **The radio.** Everything arriving is hostile until authenticated.
   `Header::decode` returns `Result` and rejects short buffers, unknown
   versions and unknown classes before reading any field.

2. **Authentication.** `Store::merge` trusts sequence numbers for ordering,
   and that trust is earned only after verification. A caller that merges
   unverified frames silently voids replay protection, rollback protection,
   and every ordering guarantee the store provides.

## Where the design refuses to grow

Recorded in ARCHITECTURE.md so they are not argued again: ML-DSA for all
messages (modelled at 31x the airtime), a CRDT library (facts are keyed by
author, so writers never conflict), ARQ instead of erasure coding (no
back-channel), a revocation PKI (needs the missing network), QKD (needs fibre),
building a new mesh (several exist), and blockchain (needs consensus over a
network that is down).
