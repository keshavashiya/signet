# Architecture Overview

The full document is
[ARCHITECTURE.md](https://github.com/keshavashiya/signet/blob/main/ARCHITECTURE.md)
in the repo root — layer model, crate boundaries, data flow, security model,
and a record of rejected alternatives. This page is the summary.

## One layer, not a stack

Three good off-grid mesh networks already exist. Signet does not compete with,
replace, or wrap them. It supplies the one thing all three are missing and
rides inside the payload they already carry.

Concretely: **a payload format plus a key state machine.** No routing, no
discovery, no delivery semantics, no network of its own — every one of which is
a place where a new project normally dies re-solving a solved problem.

```text
┌──────────────────────────────────────────────────────────┐
│  Application — five buttons, offline map, trust badges   │  Flutter (App)
├──────────────────────────────────────────────────────────┤
│  Fact store — author-owned last-write-wins               │  core::store
├──────────────────────────────────────────────────────────┤
│  ★ AUTHENTICITY LAYER — the project                      │  core::session
│    TESLA · certs · time · fragmentation · framing        │  core::{chain,cert}
│    FN-DSA-512 signatures                                 │  signet-crypto
├──────────────────────────────────────────────────────────┤
│  Transport adapters — Meshtastic · BLE · Reticulum · UDP │  (Radio, Bluetooth)
├──────────────────────────────────────────────────────────┤
│  Someone else's radio and mesh routing                   │  not ours
└──────────────────────────────────────────────────────────┘
```

Everything below the star already exists in the world.

## Crates

Three, split along one line: what needs more than a hash function.

| Crate | Package | Role | Deps |
|---|---|---|---|
| `crates/core` | `signet-core` | Wire format, chains, certs, time, fragmentation, store | `sha2`, `hmac`, `reed-solomon-erasure` |
| `crates/crypto` | `signet-crypto` | FN-DSA-512 signatures, cert issue/verify | `signet-core`, `fn-dsa`, `rand_core` |
| `crates/cli` | `signet` | CLI: `sim` and `demo` | the above, `clap`, `anyhow` |

`core` is `no_std` + `alloc` and sets `#![forbid(unsafe_code)]`. Not an
aspiration — the same logic has to run inside Meshtastic firmware on an ESP32
and in a phone app. CI gates `--no-default-features` on every push.

It also contains **no cryptographic primitives beyond a hash function**. That
is the thesis rather than a gap: the cheap authentication path is SHA-256 alone,
which is what makes it post-quantum by construction and lets it run where a
lattice signature never could.

`signet-crypto` holds everything that needs more than a hash function —
FN-DSA-512 signing, verification, and certificate issuance. The boundary is
load-bearing rather than decorative: `core` must run on an ESP32, and key
generation needs an OS entropy source. Crates get extracted when a boundary
becomes load-bearing, never in anticipation of one.

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

Recorded in ARCHITECTURE.md so they are not re-litigated: ML-DSA for all
messages (measured at 31x), a CRDT library (author-owned keys delete the
problem), ARQ instead of erasure coding (no back-channel), a revocation PKI
(needs the missing network), QKD (needs fibre), building a new mesh (three
exist), and blockchain (solves nothing here).
