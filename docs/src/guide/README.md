# Quick Start

No network, no hardware, no C toolchain.

```bash
git clone https://github.com/keshavashiya/signet.git
cd signet
cargo test --workspace
```

28 tests. If they pass, everything below will work.

## Run the model

```bash
cargo run --bin signet -- sim
```

```text
Signet airtime model — SF11 BW250kHz, MTU 237B, payload 30B, loss 20%, redundancy 30%
scheme             pq  trailer  frames    air ms  deliver    eff ms  note
----------------------------------------------------------------------------------
Ed25519            NO       64       1      1026    80.0%      1283  1x
TESLA (SHA-256)   yes       48       1       903    80.0%      1129  1x
SQIsign-I         yes      204     3/2      5904    89.6%      6590  6x
MAYO-1            yes      392     3/2      5904    89.6%      6590  6x
HAWK-512          yes      555     4/3      7873    81.9%      9610  9x
FN-DSA-512        yes      666     6/4     11809    90.1%     13105  12x
ML-DSA-44         yes     2420   15/11     29522    83.6%     35323  31x
SLH-DSA-128s      yes     7856   45/34     88566    82.6%    107238  95x
```

**`eff ms`** is the column that matters: expected airtime to land one message,
counting retries of the whole object. It is where large signatures fall off a
cliff, and it is the number that determines battery life and duty-cycle
compliance.

## Reading the output

| Column | Meaning |
|---|---|
| `pq` | Survives a cryptographically relevant quantum computer |
| `trailer` | Authentication bytes added per message |
| `frames` | `sent/needed` — the gap is erasure-coding redundancy |
| `air ms` | Time on air for one transmission attempt |
| `deliver` | Probability the object reconstructs at this loss rate |
| `eff ms` | `air ms ÷ deliver` — expected cost per delivered message |

## Explore

```bash
# A harsher link
signet sim --loss 0.4

# A bigger message — watch SQIsign cross the one-frame boundary
signet sim --payload 100

# A faster, shorter-range LoRa preset
signet sim --sf 7 --bw 125

# Sweep 0-50% loss, machine-readable
signet sim --sweep --csv sim-out/airtime.csv
```

Try `--payload 12`. SQIsign's 204-byte signature drops to a single frame and
its effective airtime collapses to TESLA's. That one boundary is why the NIST
round-3 compact-signature candidates matter so much for this use case — see
[Primitive Sizes](../protocol/sizes.md).

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
// Skipping it makes the MAC meaningless — see docs/src/protocol/time.md.
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

- [Integration](integration.md) — getting this into an app that already exists
- [Protocol overview](../protocol/README.md) — how the two classes work
- [Roadmap](../roadmap/README.md) — what is built and what is not
