# Contributing to Signet

Signet is a post-quantum authenticity layer for off-grid mesh networks,
written in Rust. This guide covers how to send a patch, the conventions CI
enforces, and how to run the same checks locally before opening a PR.

## Quick start

```bash
git clone https://github.com/keshavashiya/signet.git
cd signet
cargo check --workspace
cargo test --workspace
cargo run --bin signet -- sim      # the airtime model; start here
cargo run --bin signet -- demo     # the full path, two nodes over a lossy link
```

Building and testing need no network access, hardware or C toolchain. Keep it
that way, so anyone can run the suite.

## Hard rules

A PR that breaks one of these is rejected, because each protects something
the project depends on.

1. **`signet-core` stays `no_std`.** It has to run inside Meshtastic firmware on
   an ESP32. CI checks `--no-default-features` on every push.
2. **`signet-core` stays hash-only.** No post-quantum primitive in `core`. That
   split is what lets the cheap authentication path run on hardware where a
   signature would not fit. Certificates are the pattern: `core` owns the
   encoding, `signet-crypto` signs and verifies.
3. **Never implement a cryptographic primitive.** Wrap a reviewed
   implementation or do not ship the feature.
4. **No C toolchain.** `cargo test` must work with no system dependencies, so
   anyone can run the suite. That is why the FN-DSA implementation is pure
   Rust.
5. **Parsers never panic on untrusted input.** Treat everything off the radio
   as hostile. No `unwrap`, no slice indexing that can go out of bounds, no `as`
   casts that truncate silently. Decode failures are values.
6. **Every rejection path gets a test.** A parser without its truncation test is
   unfinished. `crates/core/src/wire.rs` sets the expected density.
7. **Wire changes update `PROTOCOL.md` in the same PR.** A spec that lags its
   implementation misleads anyone building against it.
8. **New crates need a boundary that already hurts.** Extract when it hurts,
   never in anticipation. Three crates today is deliberate.
9. **Phases are named for what they deliver.** `Airtime`, `Protocol`,
   `Warnings`, `Radio`, `Clock`, `Integration`. The name is the deliverable,
   and it is used everywhere: code comments, docs, commits, branches, and
   issues.
10. **The refused list.** No blockchain or token. No revocation PKI: offline
    revocation is unsolved, so certificates expire quickly instead. No CRDT
    library: facts are keyed by author, so writers never conflict. No new mesh routing, no
    servers, no accounts, no phone numbers, no voice or video.

## Workflow

1. **Open or claim an issue.** Anything touching the wire format or the
   security model must start with an issue, because those changes are expensive
   to reverse once someone has deployed against them.
2. **Branch from `main`.** Name branches descriptively, e.g.
   `cert-encoding`, `fix-disclosure-rollback`, `radio-portnum-adapter`.
3. **Make focused commits.** One logical change per commit, with messages that
   explain *why*.
4. **Update `CHANGELOG.md`.** Any user-visible change needs an entry under
   `[Unreleased]`.
5. **Update `PROTOCOL.md` in the same PR** if you changed anything on the wire.
6. **Run the local CI parity check** before pushing (below).
7. **Open a PR** against `main`. Fill in the template; link the issue.

## Commit messages

Conventional Commits, loosely:

- `feat(scope):` new functionality
- `fix(scope):` bug fix
- `refactor(scope):` restructure, no behaviour change
- `docs(scope):` documentation only
- `spec(scope):` protocol specification change
- `chore(scope):` tooling, dependencies, workspace, CI
- `test(scope):` adding or fixing tests

Scope is a crate name (`core`, `crypto`, `cli`) or a protocol area (`chain`,
`wire`, `cert`, `frag`, `time`, `session`, `store`, `sim`).

## Local CI parity

CI runs tests on Linux, macOS and Windows. Run the same checks locally first;
it is faster than finding a break in Actions:

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

- **Crate naming.** Folder names are single lowercase words, with no
  underscores or hyphens. Package names are `signet-<folder>`, except the binary crate
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
Non-trivial logic leaves a runnable check behind: the smallest test that fails
if the logic breaks.

Cryptographic and merge logic needs tests for the **adversarial** cases, not
just the happy path. The existing suite is the standard to match:

- `chain.rs`: replay, rollback, forged keys, cross-seed verification, and
  that the MAC key is never the disclosed key
- `store.rs`: out-of-order delivery, replay, idempotence across mesh paths,
  author and kind isolation
- `wire.rs`: truncation, unknown version, unknown class
- `cert.rs`: truncation at every stage, trailing bytes, oversized length
  prefixes, unknown algorithm, tampering with any signed field
- `frag.rs`: shard loss, parity-only recovery, bounded in-flight map,
  contradictory headers for one object
- `time.rs`: uncertainty counting against the receiver, disjoint bounds,
  arrival after disclosure
- `session.rs`: header rewriting, flag stripping, forged disclosure,
  impersonation by fingerprint, bounded buffering
- `crates/crypto/tests/e2e.rs`: the full path: unpinned roots, stolen
  fingerprints, replay after disclosure, corrupted certs, over-confident clocks

There are no property tests or fuzz targets yet. Both (`proptest`, `bolero`)
are welcome on the parsers.

## Changing the protocol

Wire format changes are the expensive kind. In one PR:

1. Update `PROTOCOL.md`, including the constants table
2. Update the implementation
3. Add tests for the rejection paths the change creates
4. Note it in `CHANGELOG.md` under `[Unreleased]`

Before v1.0.0 the wire format may change without a compatibility path. After
v1.0.0 it may not, so breaking changes should land now.

## Reporting issues

- **Bugs:** use the bug report template. Include `signet --version`, OS, and a
  minimal reproduction.
- **Features:** use the feature request template. State the user problem before
  the proposed solution.
- **Security:** do not open a public issue. Use GitHub's private reporting via
  the Security tab (see [SECURITY.md](SECURITY.md)). Critique of the design in
  `PROTOCOL.md` is welcome as a public issue.

## Dependency hygiene

Signet is a security library, so every transitive dependency is attack
surface. `core` has three (`sha2`, `hmac`, `reed-solomon-erasure`) and should
stay close to that.

Declare new dependencies once in root `[workspace.dependencies]` and reference
them with `{ workspace = true }`. The license must already be on the
`deny.toml` allow-list. A PR that adds a dependency should say in one line why
it beats writing the code. Reed–Solomon is a dependency rather than our own code because GF(2⁸) coding
corrupts silently when subtly wrong. It is also an availability concern, not an
integrity one: a bad reconstruction still fails its MAC.

**No C toolchain.** `cargo test` must keep working with no system
dependencies; that is why the FN-DSA implementation is pure Rust. A PR
introducing a `cc`-building dependency needs a strong argument.

## License

By contributing, you agree your contributions will be licensed under the
project's MIT license (see [LICENSE](LICENSE)).
