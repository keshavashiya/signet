# Integration

## The honest constraint

**An end user cannot add a cryptographic layer to a compiled app.** Bitchat has
no plugin API, no extension points, no scripting. Nothing installed alongside it
changes what it does with bytes.

This is a fact about mobile app distribution, not a gap to engineer around. The
architecture accepts it and works with what actually exists.

## Paths that work, ranked by realism

### 1. Meshtastic node owner — works today, zero cooperation

Meshtastic reserves **private portnums** for exactly this, and its phone API
(protobuf over BLE or serial) lets any third-party app send and receive on
them.

```text
[ Signet app ] ──BLE──> [ unmodified Meshtastic node ] ──LoRa──> mesh
```

No firmware change. No fork. No pull request to get merged. The user installs
Signet, pairs it with the node they already own, and it works.

This is the entire reason Meshtastic is transport priority #1 — it is the only
system in the landscape with a real extension surface, and it comes with a
large already-deployed hardware base, which solves cold-start.

### 2. Share-sheet companion — works in any app, including Bitchat

A native OS primitive, requiring nothing from the host app:

```text
Compose in Signet → Share → Bitchat → sends a signed blob
Long-press a Bitchat message → Share → Signet → verifies, shows the badge
```

iOS Share Extensions and Android Intents both do this. Two taps rather than
zero, but it is the only path that works against an unmodified App Store
binary.

> A keyboard extension would be smoother — sign inside any app as you type —
> but full-access keyboards are precisely what security-aware users are trained
> never to enable. Bad look for a security tool. Not pursued.

### 3. Inline footer — degrade through transports that know nothing

A design requirement, not a workaround: a Signet message must survive being
carried as ordinary text by an app that has never heard of Signet.

```text
Evacuate north of 5th St
--signet:1 from=GzJbRFwL2FM auth=n0wqfhHThbBsk_ohSOfQWw
```

- A vanilla client shows the text plus one footer line
- A Signet client verifies, hides the footer, renders ✅ **EOC verified**

#### Footer format

The footer is a single line, plain ASCII, appended after the message body:

```text
--signet:<version> from=<sender> auth=<trailer>
```

| Part | Meaning |
|---|---|
| `--signet:1` | Marker and protocol version. `--` at line start is the long-standing convention for "everything below is a footer, not content" |
| `from=` | The 8-byte cert fingerprint, base64url without padding — 11 characters |
| `auth=` | The authentication trailer, base64url without padding — the 16-byte MAC, plus the 32-byte key disclosure when one is attached |

Design choices worth stating:

- **ASCII only.** Non-ASCII markers cost extra bytes in UTF-8 and get mangled
  by transports that are careless with encoding.
- **It says its own name.** Someone who has never heard of Signet can search
  the word rather than staring at line noise. That matters — most people who
  see this footer will be using a client that cannot read it.
- **Fields are labelled.** `from=` and `auth=` cost nine characters and are the
  difference between a structured footer and a blob.
- **Everything after `auth=` to end-of-line is the trailer.** No length prefix,
  no escaping, nothing to get wrong in a hand-written parser.

A typical footer is about 55 characters — tolerable in a chat bubble. With a
key disclosure attached it is ~97. A 666-byte `Signed` signature would be ~900
and is not tolerable, which is one more argument for the two-tier design: only
TESLA-class traffic travels this way.

### 4. Fork — real, and ugly

Bitchat's source is public, so a Signet-enabled fork is legal. Verify the
license before shipping one. Android users sideload an APK; iOS users need
TestFlight or a developer account, which realistically caps reach at
hobbyists.

Forks fragment the mesh and rot when upstream moves. Treat a fork as a demo
vehicle, never as a distribution strategy.

## For maintainers: a three-line diff

You do not get integrations by asking. You get them by making the cost
approximately zero.

```swift
// send path
let payload = signet.sign(text)

// receive path
if let v = signet.verify(payload) {
    badge = v.trustLevel        // .eoc / .known / .unverified
}
```

That is the whole integration. UniFFI generates Swift and Kotlin from the same
Rust core, so those three lines are three lines on every platform — Bitchat
(Swift and Kotlin), the Meshtastic apps, Sideband.

Make it a protocol negotiation and nobody adopts it. Make it a function call
that returns a badge and there is a chance.

## Transport priority

Ranked by extension surface, not by technical merit:

| Order | Transport | Why |
|---|---|---|
| 1 | Meshtastic | Real plugin surface, deployed hardware, no fork needed |
| 2 | Phone BLE | No hardware to buy, so adoption is possible. Hardest to build — done last |
| 3 | Reticulum | Free WAN, packet-radio and LoRa reach as an RNS interface |
| 4 | UDP multicast | A neighbourhood with a live router and a dead tower is a real scenario |

## Writing an adapter

An adapter moves opaque frames. That is all. If it needs to understand the
frame body, the abstraction has leaked and the adapter is doing too much.

Roughly 150 lines each. See
[ARCHITECTURE.md](https://github.com/keshavashiya/signet/blob/main/ARCHITECTURE.md).

## The integration bug to avoid

`Store::merge` trusts sequence numbers for ordering. That trust is earned only
after authentication.

**A caller that merges unverified frames silently voids replay protection,
rollback protection, and every ordering guarantee the store provides.** It
fails quietly, which is the worst way to fail. Verify first, always.
