# Changelog

All notable changes to Signet are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

Before v1.0.0 the wire format may change without a compatibility path.
Implementations should pin a commit.

## [Unreleased]

### Changed

- **The airtime model follows Meshtastic's firmware.** `signet sim` now uses a
  233-byte frame (`DATA_PAYLOAD_LEN` since protobufs v2.6.0; 237 was v2.5), a
  16-symbol preamble (`RadioInterface.h`), the 22 bytes Meshtastic puts on air
  around the payload, and fragments that carry 213 bytes after the 13 + 7 bytes
  of Signet and fragment headers. ML-DSA-44 stays at 31x TESLA's effective
  airtime and now needs 12 frames; SLH-DSA-128s is 94x, FN-DSA-512 10x, MAYO-1
  7x and SQIsign-I 5x, with SQIsign fitting one frame at payloads up to 13 bytes.
- **SQIsign-I and MAYO-1 use their round-3 sizes.** SQIsign-I has an 83-byte
  key and 200-byte signature (v3.0 specification), not the 2020 paper's 64 and
  204; MAYO-1 is 1456 and 464, not 614 and 392. `signet sim`, README, PROTOCOL
  Section 12.1 and the book follow: MAYO-1 now needs three frames (9x TESLA), and
  SQIsign fits one frame at payloads up to 17 bytes.
- **Every document separates what is built from what is planned.** The
  integration paths, UniFFI bindings, text footer, transport adapters and
  over-the-air cert requests are marked as not built; the dynamic disclosure
  delay and the `Signed` fallback ([PROTOCOL.md Section 6.4](PROTOCOL.md#64-degradation-planned))
  and the time sources (Section 6.3) as planned; the airtime figures as computed. Goal
  2 of Section 1.2 now claims post-quantum authentication, not protection against
  harvest-now-decrypt-later, since nothing is encrypted. Section 14 item 1 names the
  sender as the victim of a forged beacon, matching item 8. The cert size in
  the `cert` and `frag` docs is 1617 bytes without a KEM key, not 2.6 KiB.
  Claims nobody can check (the oldest authentication technology, ham radio's
  best disaster network, adapters of about 150 lines, no published cost
  model) are gone, and CONTRIBUTING lists Windows among the CI platforms.

- **A new `Warnings` phase, before Radio.** It builds what a disaster and a
  shutdown both need: the `Signed` send
  path, both halves of the security condition, chain rollover, `Signed` for a
  sender's last message, tolerant handling of stale disclosures, badges that
  name the group, and danger reports with a rule for when they agree. Its exit
  criterion is one end-to-end test per scenario. Radio and Clock follow it.

- **The roadmap opens with its scope.** Signet takes on proof of who sent a
  message, cheap enough for the links that are left. The section says whom that
  serves, what is left to other projects (carrying messages, secrecy,
  anonymity, judging what is true) and when the scope counts as met. A table
  maps each part of the problem to Signet's answer and its status, and the
  phases follow.

- **The shutdown scenario is written up.** The roadmap compares a shutdown
  with a disaster: whom people trust, how danger is known, how messages travel
  and stay verifiable, who is at risk for sending, and which time sources
  survive. PROTOCOL.md Section 14 gains four open questions: trust roots beyond
  emergency services, corroboration, forwarded messages needing signatures,
  and the reporter's safety.

- **Shutdowns are named alongside disasters.** The README and the docs now
  say the network can be down because of a flood, an earthquake or a
  shutdown, and that a warning can come from any group people already trust,
  not only an emergency operations centre.

- **The roadmap ends inside other people's apps.** `Integration` replaces the
  standalone `App` phase and the `Bluetooth` transport phase, and comes after
  `Clock`. Signet goes into Meshtastic, Bitchat and Sideband instead of shipping
  a mesh app of its own, and phone-to-phone reach comes through existing
  Bluetooth mesh apps. No single host carries the phase, because a host app can
  be blocked. A companion app of our own is the fallback if no host will carry
  Signet. The threat model now covers a blocked host and states that Signet
  offers no anonymity.

- **The clock security reasoning is corrected.** The docs said a lying peer
  could only widen an intersection of time bounds. Intersection never widens,
  and one overlapping liar steers it anywhere inside a node's own bound, which
  can turn a correct `TooLate` into an acceptance;
  `intersect_takes_the_tighter_constraint` now pins that case. The beacon
  caveat named the wrong victim: a forged future floor only makes a receiver
  refuse early, but it makes a sender disclose early, which is the dangerous
  direction. Both are open questions in PROTOCOL.md Section 14 now, with four more
  found in the same pass: chain lifetime against cert lifetime, the last
  message before a battery dies, stale disclosures under reordering, and the
  airtime model's missing per-fragment framing.

- **The MAC's quantum margin is stated correctly.** It read "halved to 64 bits
  under Grover". Guessing a tag needs a receiver to check each guess, so Grover
  does not apply and the 16-byte tag stays at 2⁻¹²⁸ per attempt. Chain values
  keep 32 bytes because a preimage can be searched offline.

- **HAWK-512 is out of the airtime model.** Its team withdrew it from NIST's
  round 3 on 29 July 2026. Seven schemes remain and no other figure moved.

- **The footer example is a routine status message, not an evacuation order.**
  An evacuation order must be `Signed` (R10), and a `Tesla` frame may not carry
  an authority badge (R12); the old example broke both. The footer's timing
  constraint is now stated.

- **Smaller corrections.** The airtime model is called computed, not measured:
  no radio has run it yet. SQIsign at a 12-byte payload costs 2.5x TESLA's
  airtime, not "within a few percent". The threat model no longer lists
  harvest-now-decrypt-later as defended, since nothing is encrypted. TESLA is
  attributed to Perrig et al. and RFC 4082. The quick-start guide's test count
  is current.

- **`sha2` 0.10 to 0.11 and `hmac` 0.12 to 0.13** (RustCrypto `digest` 0.11).
  `new_from_slice` moved from the `Mac` trait to `KeyInit`; that rename is the
  entire migration. Both crates are used only by `signet-core` and nothing
  transitive depends on them, so there is no duplicate-version fallout. MSRV
  1.91 still holds.

  Verified byte-for-byte: the commitment, disclosed key, derived MAC key and
  truncated tag are identical before and after. **Nothing on the wire changed.**

### Added

- **Known-answer tests for the wire values (`crates/core/tests/vectors.rs`).**
  The existing tests check that the code agrees with itself, which stays green
  if a change moves every derived value together — a swapped domain separator, a
  different truncation end, a dependency major that alters an output. These pin
  the absolute bytes of the commitment, the disclosed key, the derived MAC key
  and the tag, so that class of silent wire drift fails loudly instead.

- **`signet-crypto` — the first post-quantum primitive.** FN-DSA-512 key
  generation, signing, verification, and certificate issuance, wrapping the
  pure-Rust `fn-dsa` crate. No C toolchain, so `cargo test` still runs with no
  system dependencies. Measured on an M-series laptop: keygen 4.9 ms, sign
  277 µs, verify 27 µs; 897-byte public key, 666-byte signature — matching the
  figures [PROTOCOL.md Section 12.1](PROTOCOL.md#121-published-primitive-sizes) was written
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
  Includes the TESLA security condition, interval arithmetic, and pairwise
  intersection so a peer with a GNSS fix can tighten one without. The *sources* of a good bound remain Clock work; the check is finished.

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

  Phases are named for what they deliver (`Airtime`, `Protocol`, `Warnings`,
  `Radio`, `Clock`, `Integration`) throughout the codebase, docs, and spec.

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
  Open questions are tracked in [Section 14](PROTOCOL.md#14-open-questions) rather than
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
  fragmentation, across seven signature schemes from Ed25519 to SLH-DSA-128s.
  Supports `--sweep` and `--csv` for machine-readable output.

  Headline result at Meshtastic LongFast, 237-byte MTU, 30-byte payload,
  20% loss: TESLA costs **1129 ms** of effective airtime per delivered message
  against **35 323 ms** for ML-DSA-44 — a **31x** difference, and 95x for
  SLH-DSA-128s. This is why no off-grid mesh has post-quantum security, and it
  is the computed result the rest of the design rests on.
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
