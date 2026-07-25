# Changelog

All notable changes to Signet are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

Before v1.0.0 the wire format may change without a compatibility path.
Implementations should pin a commit.

## [Unreleased]

### Added

- **`signet-crypto` — the first post-quantum primitive.** FN-DSA-512 key
  generation, signing, verification, and certificate issuance, wrapping the
  pure-Rust `fn-dsa` crate. No C toolchain, so `cargo test` still runs with no
  system dependencies. Measured on an M-series laptop: keygen 4.9 ms, sign
  277 µs, verify 27 µs; 897-byte public key, 666-byte signature — matching the
  figures [PROTOCOL.md §12.1](PROTOCOL.md#121-published-primitive-sizes) was written
  against.

  Certificate and message signatures use separate domain contexts, so a cert
  signature can never be replayed as a message signature or the reverse.
  `verify_cert` checks both that the signature is valid **and** that the cert's
  `issuer` field names the key being tested — without the second check, a cert
  signed by a trusted key could be accepted under a different identity.

- **`signet-core::cert` — operational certificates.** Two-tier identity: a cold
  root signs short-lived hot operational certs. Encoding only; signatures live
  in `signet-crypto`, which is what keeps `core` `no_std` and hash-only. An
  FN-DSA-512 cert with no KEM key is 1617 bytes. Decoding rejects trailing
  bytes, since junk after a cert would let an attacker vary its fingerprint
  without touching what the signature covers.

- **`signet-core::time` — clocks with explicit uncertainty.** `TimeBound` is an
  interval, never a point, because off-grid there is no source that yields one.
  Includes the TESLA security condition, interval arithmetic, and
  Marzullo-style intersection so a peer with a GNSS fix can tighten one
  without. The *sources* of a good bound remain Clock work; the check is finished.

- **`signet-core::frag` — erasure-coded fragmentation.** Reed–Solomon over
  GF(2⁸): split into `k` shards, transmit `n > k`, reconstruct from any `k`.
  No retransmission, no back-channel, no sender state. The reassembler bounds
  the number of in-flight objects, rejects self-inconsistent headers, and
  rejects fragments contradicting one already seen for the same object.

- **`signet-core::session` — the composed send and receive path.** `Sender`
  builds authenticated beacons; `Receiver` enforces the security condition,
  buffers, verifies disclosures, recovers skipped keys by hashing forward, and
  merges into the store. Per-peer buffering is capped.

- **`signet demo`.** Two nodes with real FN-DSA keys exchanging verified
  beacons over a deterministic lossy channel. `--uncertainty-ms` demonstrates
  graceful degradation: widen the receiver's admitted clock error past the
  disclosure window and every frame is correctly refused.

- **End-to-end test suite (`crates/crypto/tests/e2e.rs`).** The Protocol exit
  criterion. Nine tests covering cert issuance through to a verified store,
  including: a valid-but-unpinned root never joins; stealing a fingerprint
  does not steal the identity; replay after disclosure is refused; a corrupted
  fragment yields an unverifiable cert rather than a trusted one; and an
  over-confident clock accepts what an honest one refuses — the integration
  bug most likely to be made, pinned as a test so it is at least documented.

### Changed

- **The inline footer is specified, and its marker is plain ASCII.**
  `--signet:1 from=… auth=…` replaces a bare `§` prefix. The old marker was
  non-ASCII (two bytes in UTF-8, and mangled by transports careless with
  encoding), collided with the section sign used for spec cross-references, and
  told a reader nothing. The new one names itself, labels its fields, and is
  documented well enough to implement — see the integration guide.

- **Hard rules are written down.** Ten non-negotiables consolidated into
  `CONTRIBUTING.md`, previously scattered as prose across several documents:
  the `no_std` and hash-only constraints on `signet-core`, never implementing a
  primitive, no C toolchain, parsers that cannot panic, tested rejection paths,
  spec-with-implementation, crate-extraction discipline, phase naming, and the
  refused-feature list. A PR breaking one is rejected without discussion.

  Phases are named for what they deliver — `Airtime`, `Protocol`, `Radio`,
  `App`, `Clock`, `Bluetooth` — throughout the codebase, docs, and spec.

- **TESLA chain values are 32 bytes, not 16.** The draft spec quoted a 32-byte
  trailer (16 B MAC + 16 B key). That was wrong: forging interval `i+1` from a
  disclosed `K[i]` is a preimage attack, and a 128-bit chain value gives only
  64-bit resistance under Grover — indefensible for a protocol whose premise is
  post-quantum. Chain values are now full-width and the trailer is 48 bytes.

  Disclosure moved to once per interval rather than once per message to absorb
  the cost, so the typical per-message trailer is 16 bytes and only the first
  frame of each interval pays 48. The Airtime conclusion is unchanged: TESLA at 48
  bytes still costs 1129 ms of effective airtime against ML-DSA-44's 35 323 ms,
  a **31x** difference (previously stated as 38x, at the incorrect 32-byte
  trailer and without the 7-byte body header the simulator now models).

- **Disclosure presence is an explicit flag bit.** The first implementation
  inferred it from trailer length, which is ambiguous whenever payload size is
  not known in advance — a parsing ambiguity in the one code path where
  guessing wrong is an authentication bypass. `BODY_LEN` grew from 6 to 7 bytes
  to carry the flag, which sits inside the MAC'd region so it cannot be flipped
  undetected.

- **`K[0]` is never disclosed.** It is the commitment, already public in the
  cert, and cannot advance a receiver's anchor — which starts there. A sender
  disclosing it would have had its own frames correctly rejected as
  non-advancing. Found by the end-to-end test, not by inspection.

- **Certificate crypto fields are length-prefixed and carry an `alg` byte.**
  FIPS 206 is draft and a NIST round-3 candidate with a 204-byte signature
  would change every size in the cert. Six bytes of framing on an object that
  travels out of band is the cheapest available insurance against a
  wire-format break.

- **`signet-core` gained one dependency** (`reed-solomon-erasure`, no-default
  features) for GF(2⁸) coding. Taken rather than hand-rolled because that is
  the one piece of maths here which corrupts silently when subtly wrong. It is
  availability, not integrity — a bad reconstruction still fails its MAC.

### Added (Airtime)

- **Protocol specification (`PROTOCOL.md`).** The v1 draft wire format: two-tier
  identity, the 13-byte frame header, the `Tesla`/`Signed`/`Fragment` message
  classes, TESLA chain operation, the time-synchronisation problem and its
  degradation path, erasure-coded fragmentation, and the fact payload schema.
  Open questions are tracked in [§14](PROTOCOL.md#14-open-questions) rather than
  deferred silently.

- **`signet-core` — TESLA hash chains (`chain`).** Chain generation from a
  secret seed, commitment extraction, per-interval key and MAC-key derivation
  with domain separation, truncated HMAC-SHA256 authentication with
  constant-time verification, and disclosure verification with gap recovery.
  A receiver anchored at interval 3 that misses 4, 5 and 6 recovers all of
  them from `K[7]` — the property that makes this fit a lossy broadcast
  medium. Non-advancing disclosures are rejected so a replay cannot roll a
  receiver backwards.

- **`signet-core` — frame codec (`wire`).** The fixed 13-byte header: version
  and class nibbles, 8-byte sender fingerprint, big-endian interval index.
  Decoding is total — truncation, unknown versions and unknown classes are
  values, never panics.

- **`signet-core` — fact store (`store`).** Author-owned last-write-wins merge
  over `(author, kind)` keys. Because an author may only write keys it owns,
  conflicts are structurally impossible and the merge rule is a sequence
  comparison; no CRDT machinery is required. Equal sequence numbers are
  rejected, making merge idempotent across redundant mesh paths. Independent
  claims from different authors are never collapsed.

- **`signet` CLI — airtime simulator (`signet sim`).** The Airtime deliverable.
  Models authentication cost over a constrained lossy link using Semtech LoRa
  time-on-air, closed-form binomial delivery probability, and erasure-coded
  fragmentation, across eight signature schemes from Ed25519 to SLH-DSA-128s.
  Supports `--sweep` and `--csv` for machine-readable output.

  Headline result at Meshtastic LongFast, 237-byte MTU, 30-byte payload,
  20% loss: TESLA costs **1129 ms** of effective airtime per delivered message
  against **35 323 ms** for ML-DSA-44 — a **31x** difference, and 95x for
  SLH-DSA-128s. This is why no off-grid mesh has post-quantum security, and it
  is the measurement the rest of the design rests on.
  (Originally reported as 38x; corrected under *Changed* when the chain-value
  width was fixed.)

- **Project documentation.** `README.md`, `ARCHITECTURE.md` (layer model,
  crate boundaries, security model, and a record of rejected alternatives),
  `CONTRIBUTING.md`, and an mdBook under `docs/`.

### Notes

- `signet-core` is `no_std` + `alloc` with three dependencies (`sha2`, `hmac`,
  `reed-solomon-erasure`) and `#![forbid(unsafe_code)]`. CI gates
  `--no-default-features` on every push; the ESP32 target is a requirement,
  not an aspiration.
- `signet-crypto` is `std`-only for now. Only key generation needs an OS
  entropy source; splitting the verify path out for firmware is Radio work.
- **FN-DSA is a draft standard.** Upstream warns that key encodings,
  pre-hashing and domain separation may all change before FIPS 206 is
  published. Certs issued today are not durable. The `alg` byte makes this a
  one-byte migration rather than a wire-format break.
