# Primitive Sizes

Every number the simulator uses, with its source. All figures are NIST security
level 1 (roughly AES-128 equivalent) in bytes.

## Signatures

| Scheme | Public key | Signature | Standard | Status |
|---|---|---|---|---|
| Ed25519 | 32 | 64 | RFC 8032 | Classical, **not post-quantum** |
| SQIsign-I | 83 | 200 | NIST additional signatures | Round 3 (May 2026) |
| MAYO-1 | 1456 | 464 | NIST additional signatures | Round 3 |
| FN-DSA-512 | 897 | 666 | FIPS 206 | **Draft**; final expected late 2026 |
| ML-DSA-44 | 1312 | 2420 | FIPS 204 | Final, Aug 2024 |
| SLH-DSA-128s | 32 | 7856 | FIPS 205 | Final, Aug 2024 |

## Key encapsulation

| Scheme | Public key | Ciphertext | Standard |
|---|---|---|---|
| X25519 | 32 | 32 | RFC 7748 (classical) |
| ML-KEM-768 | 1184 | 1088 | FIPS 203 |

## Symmetric

| Primitive | Size | Note |
|---|---|---|
| SHA-256 output | 32 | Chain key width |
| HMAC-SHA256, truncated | 16 | On-wire tag |
| TESLA chain value | 32 | Full width; see [PROTOCOL.md Section 5.1](https://github.com/keshavashiya/signet/blob/main/PROTOCOL.md#51-chain-construction) on why not 16 |
| AES-256 key | 32 | Quantum-resistant; Grover halves the margin |

## How these map to frames

At Meshtastic's 237-byte application payload, with a 13-byte Signet header,
a 7-byte body header, and a 30-byte status beacon:

| Trailer | Total | Frames | Comment |
|---|---|---|---|
| 16 (TESLA, typical) | 66 | 1 | Fits with room to spare |
| 48 (TESLA, with disclosure) | 98 | 1 | First frame of each interval |
| 200 (SQIsign) | 250 | 2 | Just over; a 17-byte payload would fit in one |
| 464 (MAYO-1) | 514 | 3 | |
| 666 (FN-DSA) | 716 | 4 | |
| 2420 (ML-DSA) | 2470 | 11 | |
| 7856 (SLH-DSA) | 7906 | 34 | Root certs only, never on the hot path |

The SQIsign row matters most: **a 200-byte signature misses a single frame by
13 bytes**, and with a 17-byte payload it fits. If SQIsign were standardised,
per-message post-quantum signatures would become viable here and this design
would change substantially.

Verify with `signet sim --payload 17`: SQIsign drops to one frame and its
effective airtime to 2.4x TESLA's (2460 against 1027 ms), from 6x at a 30-byte
payload.

## Why the simulator hardcodes these

Airtime is a function of bytes, and these bytes are published constants.
Implementing ML-DSA to discover that its signature is 2420 bytes would tell us
nothing FIPS 204 does not already say.

CPU time, memory and energy **do** require real implementations, and they
matter: a compact signature helps little if signing takes seconds on a phone
with a dying battery. SQIsign in particular trades speed for size. That
measurement is Radio work, on real hardware.

## Caveats

- **FN-DSA is not final.** FIPS 206 was submitted for approval in August 2025;
  final publication is expected late 2026 or early 2027. Signet treats it as
  the default `Signed` primitive on the assumption it lands, and the choice is
  a config enum precisely so that assumption is cheap to revise.
- **Round-3 candidates may not be standardised at all.** Nine advanced in May
  2026. HAWK's team withdrew it on 29 July 2026, leaving FAEST, MAYO, MQOM,
  QR-UOV, SDitH, SNOVA, SQIsign and UOV, and NIST expects the round to take
  about two years. Building on one today is a bet.
- **Parameter sets vary by implementation.** Figures above are from the
  specification documents. Real libraries add framing overhead; measure before
  trusting.

## Sources

- [FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205: SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [FIPS 206: FN-DSA (draft status)](https://www.digicert.com/blog/quantum-ready-fndsa-nears-draft-approval)
- [NIST IR 8610: round 2 status report and round 3 selections](https://csrc.nist.gov/pubs/ir/8610/final)
- [NIST: nine candidates advance to round 3, and HAWK's withdrawal](https://www.nist.gov/news-events/news/2026/05/nine-candidates-advance-third-round-additional-digital-signatures-pqc)
- [SQIsign round-3 specification, v3.0](https://csrc.nist.gov/csrc/media/Projects/pqc-dig-sig/documents/sqisign_specification.pdf)
- [MAYO round-3 specification](https://csrc.nist.gov/csrc/media/Projects/pqc-dig-sig/documents/mayo_specification.pdf)
- [Cloudflare: why we cannot wait for better post-quantum signatures](https://blog.cloudflare.com/ml-dsa-will-have-to-do/)
