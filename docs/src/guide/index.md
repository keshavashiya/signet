# Quick Start

You need no network, hardware or C toolchain.

```bash
git clone https://github.com/keshavashiya/signet.git
cd signet
cargo test --workspace
```

105 tests. If they pass, everything below will work.

## Run the model

```bash
cargo run --bin signet -- sim
```

```text
Signet airtime model — SF11 BW250kHz, MTU 233B, payload 30B, loss 20%, redundancy 30%
scheme             pq  trailer  frames    air ms  deliver    eff ms  note
----------------------------------------------------------------------------------------------------
Ed25519            NO       64       1      1255    80.0%      1569  1x  what every mesh ships today
TESLA (SHA-256)   yes       48       1      1133    80.0%      1416  1x  16B MAC + 32B disclosed key
SQIsign-I         yes      200     3/2      6470    89.6%      7221  5x  NIST round 3; slow to sign
MAYO-1            yes      464     4/3      8626    81.9%     10530  7x  NIST round 3
FN-DSA-512        yes      666     6/4     12939    90.1%     14359  10x  FIPS 206 draft
ML-DSA-44         yes     2420   16/12     34505    79.8%     43226  31x  FIPS 204, the safe default
SLH-DSA-128s      yes     7856   50/38    107827    81.4%    132475  94x  FIPS 205, hash-based root
```

**`eff ms`** is the column that matters: the expected airtime to deliver one
message, counting resends of the whole object. Large signatures grow fastest
here, and it is the number that sets battery life and duty-cycle limits.

## Reading the output

| Column | Meaning |
|---|---|
| `pq` | Survives a cryptographically relevant quantum computer |
| `trailer` | Authentication bytes added per message |
| `frames` | `sent/needed`; the difference is erasure-coding redundancy |
| `air ms` | Time on air for one transmission attempt |
| `deliver` | Probability the object reconstructs at this loss rate |
| `eff ms` | `air ms ÷ deliver`, the expected cost per delivered message |

## Explore

```bash
# A harsher link
signet sim --loss 0.4

# A bigger message: the payload dominates and the ratios shrink
signet sim --payload 100

# A faster, shorter-range LoRa preset
signet sim --sf 7 --bw 125

# Sweep 0-50% loss, machine-readable
signet sim --sweep --csv sim-out/airtime.csv
```

Try `--payload 13`. SQIsign's 200-byte signature drops to a single frame and
its effective airtime falls from 5x TESLA's to 2.1x. That boundary is why the
NIST round-3 compact-signature candidates matter for this use case (see
[Primitive Sizes](../protocol/sizes.md)).

## Using the library

`signet-core` is `no_std` + `alloc`, so the same code runs on a phone and on an
ESP32 inside Meshtastic firmware.

```rust
use signet_core::{chain::{self, Chain}, wire::{Class, Header}};

// Sender: commit once. The commitment goes in your operational cert.
let chain = Chain::from_seed(&seed, 4096);
let commitment = chain.commitment();

// Each interval: MAC the payload, disclose the key from `d` intervals ago.
let tag = chain::mac(&chain.mac_key(interval)?, payload);
let disclosed = chain.key(interval - DISCLOSURE_DELAY)?;

// Receiver: check the security condition FIRST, then buffer.
// Skipping it makes the MAC meaningless; see docs/src/protocol/time.md.
if chain::verify_disclosure(&anchor, anchor_interval, older, &disclosed) {
    let key = chain::derive_mac_key(&disclosed);
    let ok = chain::verify_mac(&key, buffered_frame, &tag);
}
```

The fact store merges verified state without a server and without a CRDT
library:

```rust
use signet_core::Store;

let mut store = Store::new();
store.merge(alice, STATUS, 5, b"need water");   // true
store.merge(alice, STATUS, 3, b"ok");           // false — older, ignored
store.merge(alice, STATUS, 5, b"ok");           // false — replay, ignored

// Independent claims are never collapsed into one "truth".
let reports = store.by_kind(BRIDGE_OUT).count();  // "3 people report…"
```

## Next

- [Integration](integration.md): getting this into an app that already exists
- [Protocol overview](../protocol/index.md): how the two classes work
- [Roadmap](../roadmap/index.md): what is built and what is not
