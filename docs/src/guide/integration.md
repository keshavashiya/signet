# Integration

**Nothing on this page is built yet.** It describes the planned integration
paths. The Rust core they would call is built; the bindings, the Signet app,
the footer codec and the transport adapters are not.

## The constraint

**An end user cannot add a cryptographic layer to a compiled app.** Bitchat has
no plugin API, extension points or scripting, so nothing installed alongside it
changes what it does with bytes. Signet's design works with that instead of
around it.

## Planned paths, most realistic first

The roadmap starts from the last section here, the maintainers' three-line
diff. Paths 1 and 2 need a Signet app of our own, so they are the fallback if
no host will carry Signet ([Roadmap](../roadmap/index.md)).

### 1. Meshtastic node owner: needs no one's cooperation

Meshtastic reserves **private portnums** for exactly this, and its phone API
(protobuf over BLE or serial) lets any third-party app send and receive on
them.

```text
[ Signet app ] ──BLE──> [ unmodified Meshtastic node ] ──LoRa──> mesh
```

It would need no firmware change, fork or merged pull request: the user would
install a Signet app and pair it with the node they already own.

This is why Meshtastic is transport priority 1. It is the only system here with
a real extension surface, and its large installed hardware base solves the
cold-start problem.

### 2. Share-sheet companion: any app, including Bitchat

A native OS primitive, requiring nothing from the host app:

```text
Compose in Signet → Share → Bitchat → sends a signed blob
Long-press a Bitchat message → Share → Signet → verifies, shows the badge
```

iOS Share Extensions and Android Intents both support this. It costs two taps
per message, but it is the only path that works with an unmodified App Store
binary.

> A keyboard extension that signs as you type would be smoother, but it needs
> full keyboard access, which security-aware users are taught never to grant.
> Not pursued.

### 3. Inline footer: through transports that know nothing about Signet

A Signet message must survive being carried as ordinary text by an app that
has never heard of Signet.

```text
Need water at 12 Main St, 4 people
--signet:1 from=GzJbRFwL2FM auth=n0wqfhHThbBsk_ohSOfQWw
```

- A vanilla client shows the text plus one footer line
- A Signet client verifies, hides the footer, renders 🔑 **known sender**
- Only routine `Tesla` traffic travels this way. An evacuation order must be
  `Signed` ([PROTOCOL.md §4.1](https://github.com/keshavashiya/signet/blob/main/PROTOCOL.md#41-choosing-a-class))
  and never rides in a footer
- A footer keeps TESLA's timing ([Time](../protocol/time.md)): a Signet client
  has to see it before that interval's key goes public, 30–60 s at the default
  schedule, and it verifies once a later message brings the key

#### Footer format

The footer is a single line, plain ASCII, appended after the message body:

```text
--signet:<version> from=<sender> auth=<trailer>
```

| Part | Meaning |
|---|---|
| `--signet:1` | Marker and protocol version. `--` at line start is the long-standing convention for "everything below is a footer, not content" |
| `from=` | The 8-byte cert fingerprint, base64url without padding, 11 characters |
| `auth=` | The authentication trailer, base64url without padding: the 16-byte MAC, plus the 32-byte key disclosure when one is attached |

Design choices:

- **ASCII only.** Non-ASCII markers cost extra bytes in UTF-8 and get mangled
  by transports that are careless with encoding.
- **It says its own name.** Most people who see this footer will use a client
  that cannot read it, and they can search the word.
- **Fields are labelled.** `from=` and `auth=` cost nine characters and are the
  difference between a structured footer and a blob.
- **Everything after `auth=` to end-of-line is the trailer.** No length prefix,
  no escaping, nothing to get wrong in a hand-written parser.

A typical footer is about 55 characters, which fits in a chat bubble. With a
key disclosure attached it is ~97. A 666-byte `Signed` signature would be ~900
and is not tolerable, which is one more argument for the two-tier design: only
TESLA-class traffic travels this way.

### 4. Fork: possible, but a last resort

Bitchat's source is public, so its license may allow a Signet-enabled fork.
Verify the license before shipping one, and check where the app itself is
blocked: a fork inherits that. Android users sideload an APK; iOS users need
TestFlight or a developer account, which realistically caps reach at
hobbyists.

Forks fragment the mesh and rot when upstream moves. Treat a fork as a demo
vehicle, never as a distribution strategy.

## For maintainers: the planned API

The aim is to make integration cost almost nothing, so maintainers can say yes:

```swift
// send path
let payload = signet.sign(text)

// receive path
if let v = signet.verify(payload) {
    badge = v.trustLevel        // .eoc / .known / .unverified
}
```

UniFFI would generate the Swift and Kotlin bindings from the same Rust core,
so the same calls work in Bitchat (Swift and Kotlin), the Meshtastic apps and
Sideband. A function that returns a badge is far easier to adopt than a
protocol negotiation.

## Transport priority

Ranked by extension surface, not by technical merit:

| Order | Transport | Why |
|---|---|---|
| 1 | Meshtastic | Real plugin surface, deployed hardware, no fork needed |
| 2 | Phone BLE | No hardware to buy, so adoption is possible. Arrives through existing Bluetooth mesh apps, not a transport of our own |
| 3 | Reticulum | Free WAN, packet-radio and LoRa reach as an RNS interface |
| 4 | UDP multicast | A neighbourhood with a live router and a dead tower is a real scenario |

## Writing an adapter

An adapter moves opaque frames. That is all. If it needs to understand the
frame body, the abstraction has leaked and the adapter is doing too much.

None is written yet. See
[ARCHITECTURE.md](https://github.com/keshavashiya/signet/blob/main/ARCHITECTURE.md).

## The integration bug to avoid

`Store::merge` trusts sequence numbers for ordering. That trust is earned only
after authentication.

**A caller that merges unverified frames silently voids replay protection,
rollback protection and every ordering guarantee the store provides,** and
nothing reports the failure. Verify first, always.
