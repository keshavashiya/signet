# Contributing

The full guide is
[CONTRIBUTING.md](https://github.com/keshavashiya/signet/blob/main/CONTRIBUTING.md)
in the repo root. This page is the parts you need before your first patch.

## Setup

```bash
git clone https://github.com/keshavashiya/signet.git
cd signet
cargo test --workspace
```

Building and testing need no network, hardware or C toolchain. Keep it that
way, so anyone can run the suite.

## Before pushing

```bash
just ci
```

Which is:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo check -p signet-core --no-default-features   # the no_std gate
cargo test --workspace
```

## Hard rules

A PR that breaks one is rejected. The reasons are in
[CONTRIBUTING.md](https://github.com/keshavashiya/signet/blob/main/CONTRIBUTING.md#hard-rules).

1. `signet-core` stays `no_std`, so it can run on an ESP32.
2. `signet-core` uses only hash functions; post-quantum primitives live in
   `signet-crypto`.
3. Never implement a cryptographic primitive.
4. No C toolchain: `cargo test` needs no system dependencies.
5. Parsers never panic on untrusted input.
6. Every rejection path gets a test.
7. Wire changes update `PROTOCOL.md` in the same PR.
8. New crates need a boundary that already hurts.
9. Phases are named for what they deliver: `Airtime`, `Protocol`, `Warnings`,
   `Radio`, `Clock`, `Integration`.
10. The refused list: no blockchain, no revocation PKI, no CRDT library, no new
    mesh routing, no servers or accounts, no voice or video.

## Testing standard

Cryptographic and merge logic needs tests for the **adversarial** cases, not
just the happy path. The existing suite sets the standard:

| Module | Cases covered |
|---|---|
| `chain.rs` | Replay, rollback, forged keys, cross-seed verification, MAC key ≠ disclosed key |
| `store.rs` | Out-of-order delivery, replay, idempotence, author and kind isolation |
| `wire.rs` | Truncation, unknown version, unknown class, all classes round-trip |
| `cert.rs` | Truncation, trailing bytes, oversized length prefixes, tampering with signed fields |
| `frag.rs` | Shard loss, parity-only recovery, bounded in-flight map, contradictory headers |
| `time.rs` | Uncertainty counting against the receiver, disjoint bounds |
| `session.rs` | Header rewriting, flag stripping, forged disclosure, impersonation |
| `tests/e2e.rs` | Unpinned roots, stolen fingerprints, replay after disclosure, over-confident clocks |

There are no property tests or fuzz targets yet. Both (`proptest`, `bolero`)
are welcome on the parsers.

## Dependencies

Signet is a security library, so every transitive dependency is attack
surface. `core` has three (`sha2`, `hmac`, `reed-solomon-erasure`) and should
stay close to that. A PR adding one should say in a line why it beats writing
the code.

**No C toolchain.** `cargo test` must keep working with no system
dependencies; that is why the FN-DSA implementation is pure Rust.

## Security

Do not open a public issue for a vulnerability. Report it privately through
GitHub's [Security tab](https://github.com/keshavashiya/signet/security/advisories/new).

Critique of the [protocol](../protocol/index.md) design is welcome as a public
issue. The specification is written down in full so it can be reviewed before
anyone uses it in the field.
