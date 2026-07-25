# Contributing to Signet

Thanks for your interest. Signet is a post-quantum authenticity layer for
off-grid mesh networks, written in Rust. This guide covers the workflow for
patches, the conventions CI enforces, and how to run the full validation suite
locally before opening a PR.

## Quick start

```bash
git clone https://github.com/keshavashiya/signet.git
cd signet
cargo check --workspace
cargo test --workspace
cargo run --bin signet -- sim      # the airtime model — start here
cargo run --bin signet -- demo     # the full path, two nodes over a lossy link
```

No network access, no hardware, and no C toolchain are needed to build or test.
Keep it that way: a contributor who cannot run the suite will not contribute.

## Hard rules

Non-negotiable. A PR that breaks one of these is rejected without discussion —
not because the rule is sacred, but because each of them is load-bearing for
something the project cannot give up.

1. **`signet-core` stays `no_std`.** It has to run inside Meshtastic firmware on
   an ESP32. Convenience is not an argument; CI gates `--no-default-features`
   on every push.
2. **`signet-core` stays hash-only.** No post-quantum primitive in `core`. That
   split is the entire reason the cheap authentication path runs on hardware
   the expensive one never could. Certificates are the pattern: `core` owns the
   encoding, `signet-crypto` signs and verifies.
3. **Never implement a cryptographic primitive.** Wrap a reviewed
   implementation or do not ship the feature.
4. **No C toolchain.** `cargo test` must work with zero system dependencies. A
   contributor who cannot run the suite will not contribute — that is why the
   FN-DSA implementation is pure Rust.
5. **Parsers never panic on untrusted input.** Everything off the radio is
   hostile. No `unwrap`, no slice indexing that can go out of bounds, no `as`
   casts that truncate silently. Decode failures are values.
6. **Every rejection path gets a test.** A parser without its truncation test is
   unfinished. `crates/core/src/wire.rs` sets the expected density.
7. **Wire changes update `PROTOCOL.md` in the same PR.** A spec that trails its
   implementation is worse than no spec at all.
8. **New crates need a boundary that already hurts.** Extract when it hurts,
   never in anticipation. Three crates today is deliberate.
9. **Phases are named for what they deliver.** `Airtime`, `Protocol`, `Radio`,
   `App`, `Clock`, `Bluetooth`. The name is the deliverable, and it is used
   everywhere: code comments, docs, commits, branches, and issues.
10. **The refused list.** No blockchain or token. No revocation PKI — offline
    revocation is unsolved and short expiry is the honest substitute. No CRDT
    library — author-owned keys delete the problem. No new mesh routing, no
    servers, no accounts, no phone numbers, no voice or video.

## Workflow

1. **Open or claim an issue.** Anything touching the wire format or the
   security model must start with an issue — those changes are expensive to
   reverse once someone has deployed against them.
2. **Branch from `main`.** Name branches descriptively, e.g.
   `cert-encoding`, `fix-disclosure-rollback`, `radio-portnum-adapter`.
3. **Make focused commits.** One logical change per commit, with messages that
   explain *why*.
4. **Update `CHANGELOG.md`.** Any user-visible change needs an entry under
   `[Unreleased]`.
5. **Update `PROTOCOL.md` in the same PR** if you changed anything on the wire.
   A spec that trails the implementation is worse than no spec.
6. **Run the local CI parity check** before pushing (below).
7. **Open a PR** against `main`. Fill in the template; link the issue.

## Commit messages

Conventional Commits, loosely:

- `feat(scope):` — new functionality
- `fix(scope):` — bug fix
- `refactor(scope):` — restructure, no behaviour change
- `docs(scope):` — documentation only
- `spec(scope):` — protocol specification change
- `chore(scope):` — tooling, deps, workspace, CI
- `test(scope):` — adding or fixing tests

Scope is a crate name (`core`, `crypto`, `cli`) or a protocol area (`chain`,
`wire`, `cert`, `frag`, `time`, `session`, `store`, `sim`).

## Local CI parity

CI runs these gates on Linux and macOS. Run them locally first — much faster
than discovering a break in Actions:

```bash
# Everything at once
just ci

# Or individually
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo check -p signet-core --no-default-features   # no_std gate
cargo test --workspace

# MSRV (install once: `rustup toolchain install 1.91`)
cargo +1.91 check --workspace --locked

# License + advisory (install once: `cargo install cargo-deny --locked`)
cargo deny check all
```

## Conventions

- **Crate naming.** Folder names are single lowercase words — no underscores,
  no hyphens. Package names are `signet-<folder>`, except the binary crate
  which is plain `signet`.
- **Workspace lints.** Clippy is `deny`-by-default at the workspace root.
  Any `allow` lives in the root `Cargo.toml` with a comment justifying it.
- **Naming.** Branches and issues use the phase name, not an index.

The crate-boundary and `no_std` conventions are [hard rules](#hard-rules), not
preferences.

## Writing code that touches the radio

Hard rules 5 and 6 apply in full. `#![forbid(unsafe_code)]` is set in `core`
and `crypto` and stays. In practice that means: bounds-check before you slice,
return `Result` rather than defaulting, and write the truncation test before
you write the parser.

## Testing

Tests are colocated with the code and run by `cargo test --workspace`.
Non-trivial logic leaves a runnable check behind — the smallest thing that
fails if the logic breaks.

Cryptographic and merge logic needs tests for the **adversarial** cases, not
just the happy path. The existing suite is the standard to match:

- `chain.rs` — replay, rollback, forged keys, cross-seed verification, and
  that the MAC key is never the disclosed key
- `store.rs` — out-of-order delivery, replay, idempotence across mesh paths,
  author and kind isolation
- `wire.rs` — truncation, unknown version, unknown class
- `cert.rs` — truncation at every stage, trailing bytes, oversized length
  prefixes, unknown algorithm, tampering with any signed field
- `frag.rs` — shard loss, parity-only recovery, bounded in-flight map,
  contradictory headers for one object
- `time.rs` — uncertainty counting against the receiver, disjoint bounds,
  arrival after disclosure
- `session.rs` — header rewriting, flag stripping, forged disclosure,
  impersonation by fingerprint, bounded buffering
- `crates/crypto/tests/e2e.rs` — the full path: unpinned roots, stolen
  fingerprints, replay after disclosure, corrupted certs, over-confident clocks

Property tests (`proptest`) and fuzz targets (`bolero`) are welcome on the
parsers and are the natural next addition.

## Changing the protocol

Wire format changes are the expensive kind. In one PR:

1. Update `PROTOCOL.md` — including the constants table
2. Update the implementation
3. Add tests for the rejection paths the change creates
4. Note it in `CHANGELOG.md` under `[Unreleased]`

Before v1.0.0 the wire format may change without a compatibility path. After
v1.0.0 it may not, so land breaking changes now rather than regretting them.

## Reporting issues

- **Bugs:** use the bug report template. Include `signet --version`, OS, and a
  minimal reproduction.
- **Features:** use the feature request template. State the user problem before
  the proposed solution.
- **Security:** do not open a public issue. Use GitHub's private reporting via
  the Security tab — see [SECURITY.md](SECURITY.md). Signet is alpha and
  unaudited — design critique of `PROTOCOL.md` is genuinely welcome and is best
  filed publicly.

## Dependency hygiene

Signet is a security library, so every transitive dependency is attack surface
for the thing it exists to protect. `core` has three (`sha2`, `hmac`,
`reed-solomon-erasure`) and should gain approximately none.

Declare new dependencies once in root `[workspace.dependencies]` and reference
them with `{ workspace = true }`. The license must already be on the
`deny.toml` allow-list. A PR that adds a dependency should say in one line why
it beats writing the code. Reed–Solomon earns its place because GF(2⁸) coding
corrupts silently when subtly wrong, and because it is availability rather
than integrity — a bad reconstruction still fails its MAC.

**No C toolchain.** `cargo test` must keep working with no system
dependencies; that is why the FN-DSA implementation is pure Rust. A PR
introducing a `cc`-building dependency needs a strong argument.

## License

By contributing, you agree your contributions will be licensed under the
project's MIT license (see [LICENSE](LICENSE)).
