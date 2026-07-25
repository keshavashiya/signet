//! End-to-end: two nodes, real keys, a lossy channel.
//!
//! This is the Protocol exit criterion. Every test here fails if authentication
//! breaks anywhere along the path — cert issuance, out-of-band pinning,
//! fragmentation, the security condition, chain disclosure, MAC verification,
//! or the store merge.
//!
//! The channel is a deterministic LCG rather than a real RNG so a failure
//! reproduces exactly. Loss is independent; real links lose bursts, which is
//! harsher. That gap closes on hardware during Radio.

use signet_core::cert::{Cert, Role};
use signet_core::chain::Chain;
use signet_core::frag::{Reassembler, FRAG_HEADER_LEN};
use signet_core::session::{Outcome, Receiver, Reject, Sender};
use signet_core::store::FactKind;
use signet_core::time::{Schedule, TimeBound};
use signet_core::wire::HEADER_LEN;
use signet_crypto::{verify_cert, KeyPair};

const STATUS: FactKind = 0;
const EPOCH: u64 = 1_700_000_000_000;
const MTU: usize = 237;

fn schedule() -> Schedule {
    Schedule::default_at(EPOCH)
}

fn at(interval: u32) -> u64 {
    schedule().interval_start_ms(interval) + 100
}

/// A node with a cold root, a hot operational key, and a TESLA chain.
struct Node {
    root: KeyPair,
    cert: Cert,
    sender: Sender,
}

impl Node {
    fn new(seed: &[u8], role: Role) -> Self {
        let root = KeyPair::generate();
        let operational = KeyPair::generate();
        let chain = Chain::from_seed(seed, 256);
        let cert = root.issue(&operational, chain.commitment(), role, 9_999);
        let sender = Sender::new(cert.fingerprint(), chain, schedule());
        Self { root, cert, sender }
    }
}

/// Pin a peer after verifying its cert against a root known before deployment.
///
/// This is the whole trust model in four lines: no network, no CA, no
/// revocation — just a root you already had and a signature over the cert.
fn pin(receiver: &mut Receiver, cert_bytes: &[u8], trusted_root: &KeyPair) -> bool {
    let Ok(cert) = Cert::decode(cert_bytes) else {
        return false;
    };
    if !verify_cert(&cert, trusted_root.verifying_key()).unwrap_or(false) {
        return false;
    }
    receiver.add_peer(cert.fingerprint(), cert.tesla_root);
    true
}

/// Deterministic loss so a failure reproduces exactly.
struct Channel {
    state: u64,
    loss_pct: u32,
}

impl Channel {
    fn new(seed: u64, loss_pct: u32) -> Self {
        Self {
            state: seed,
            loss_pct,
        }
    }

    fn delivers(&mut self) -> bool {
        self.state = self
            .state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.state >> 33) % 100 >= self.loss_pct as u64
    }
}

#[test]
fn full_flow_from_cert_issuance_to_verified_store() {
    let mut alice = Node::new(b"alice chain seed", Role::Eoc);
    let mut bob = Receiver::new(schedule());

    // Bob got Alice's root at onboarding, before anything went wrong.
    assert!(pin(&mut bob, &alice.cert.encode(), &alice.root));

    // Interval 2: no disclosure is possible yet, so the frame buffers.
    let f2 = alice.sender.beacon(STATUS, b"need water", at(2)).unwrap();
    let out = bob.recv(&f2, TimeBound::exact(at(2))).unwrap();
    assert!(
        matches!(out, Outcome::Accepted { merged: 0, .. }),
        "{out:?}"
    );
    assert!(bob.store().is_empty());

    // Interval 4 discloses K[2] and releases it.
    let f4 = alice.sender.beacon(STATUS, b"ok", at(4)).unwrap();
    let out = bob.recv(&f4, TimeBound::exact(at(4))).unwrap();
    assert!(
        matches!(
            out,
            Outcome::Accepted {
                merged: 1,
                failed_mac: 0,
                ..
            }
        ),
        "{out:?}"
    );

    let fact = bob.store().get(&alice.cert.fingerprint(), STATUS).unwrap();
    assert_eq!(fact.payload, b"need water");
}

#[test]
fn store_converges_across_a_lossy_channel() {
    let mut alice = Node::new(b"alice chain seed", Role::Civilian);
    let mut bob = Receiver::new(schedule());
    assert!(pin(&mut bob, &alice.cert.encode(), &alice.root));

    let mut channel = Channel::new(0xC0FFEE, 30);
    let mut last_delivered: Option<Vec<u8>> = None;

    for interval in 2..40u32 {
        let payload = format!("status {interval}").into_bytes();
        let frame = alice.sender.beacon(STATUS, &payload, at(interval)).unwrap();
        if channel.delivers() {
            let out = bob.recv(&frame, TimeBound::exact(at(interval))).unwrap();
            assert!(
                !matches!(out, Outcome::Rejected(_)),
                "interval {interval}: {out:?}"
            );
            last_delivered = Some(payload);
        }
    }

    // Whatever survived the channel, the store holds a genuine Alice fact and
    // never a forged or garbled one.
    let fact = bob
        .store()
        .get(&alice.cert.fingerprint(), STATUS)
        .expect("30% loss over 38 intervals should still deliver something");
    let last = last_delivered.unwrap();
    assert!(
        fact.payload.starts_with(b"status "),
        "store holds garbage: {:?}",
        fact.payload
    );
    assert!(
        fact.payload <= last,
        "store ran ahead of what was delivered"
    );
}

#[test]
fn a_cert_from_an_unpinned_root_never_joins() {
    // Mallory has a perfectly valid, self-consistent identity claiming EOC.
    // The only thing she lacks is a root Bob already trusted, and that is
    // sufficient — her broadcasts are never even considered.
    let mut mallory = Node::new(b"mallory chain seed", Role::Eoc);
    let alice = Node::new(b"alice chain seed", Role::Eoc);

    let mut bob = Receiver::new(schedule());
    assert!(pin(&mut bob, &alice.cert.encode(), &alice.root));

    // Mallory's cert is internally valid but does not chain to Alice's root.
    assert!(verify_cert(&mallory.cert, mallory.root.verifying_key()).unwrap());
    assert!(!pin(&mut bob, &mallory.cert.encode(), &alice.root));

    let forged = mallory
        .sender
        .beacon(STATUS, b"EVACUATE NORTH IMMEDIATELY", at(4))
        .unwrap();
    assert_eq!(
        bob.recv(&forged, TimeBound::exact(at(4))).unwrap(),
        Outcome::Rejected(Reject::UnknownSender)
    );
    assert!(bob.store().is_empty());
}

#[test]
fn stealing_a_fingerprint_does_not_steal_the_identity() {
    // Mallory copies Alice's cert fingerprint into her own frames. The header
    // matches a pinned peer, so she gets past the first check — and fails at
    // the chain, because she cannot produce keys under Alice's commitment.
    let alice = Node::new(b"alice chain seed", Role::Eoc);
    let mut bob = Receiver::new(schedule());
    assert!(pin(&mut bob, &alice.cert.encode(), &alice.root));

    let mut mallory = Sender::new(
        alice.cert.fingerprint(),
        Chain::from_seed(b"mallory chain seed", 256),
        schedule(),
    );
    let forged = mallory
        .beacon(STATUS, b"EVACUATE NORTH IMMEDIATELY", at(4))
        .unwrap();
    assert_eq!(
        bob.recv(&forged, TimeBound::exact(at(4))).unwrap(),
        Outcome::Rejected(Reject::BadDisclosure)
    );
    assert!(bob.store().is_empty());
}

#[test]
fn replaying_a_frame_after_disclosure_is_refused() {
    // The attack the security condition exists for, end to end: capture a
    // genuine frame, wait for its key to go public, replay it.
    let mut alice = Node::new(b"alice chain seed", Role::Eoc);
    let mut bob = Receiver::new(schedule());
    assert!(pin(&mut bob, &alice.cert.encode(), &alice.root));

    let captured = alice.sender.beacon(STATUS, b"all clear", at(2)).unwrap();
    let too_late = TimeBound::exact(schedule().disclosure_ms(2));
    assert_eq!(
        bob.recv(&captured, too_late).unwrap(),
        Outcome::Rejected(Reject::TooLate)
    );
    assert!(bob.store().is_empty());
}

#[test]
fn an_over_confident_clock_is_the_dangerous_case() {
    // Documents the integration bug most likely to be made: a receiver that
    // claims certainty it does not have accepts a frame a truthful one refuses.
    let mut alice = Node::new(b"alice chain seed", Role::Eoc);
    let mut bob = Receiver::new(schedule());
    assert!(pin(&mut bob, &alice.cert.encode(), &alice.root));

    let frame = alice.sender.beacon(STATUS, b"all clear", at(2)).unwrap();
    let arrival = schedule().disclosure_ms(2) - 1_000;

    // Honest about 5 seconds of uncertainty: refuses, because it cannot rule
    // out that the key was already public.
    let mut honest = Receiver::new(schedule());
    assert!(pin(&mut honest, &alice.cert.encode(), &alice.root));
    assert_eq!(
        honest.recv(&frame, TimeBound::new(arrival, 5_000)).unwrap(),
        Outcome::Rejected(Reject::TooLate)
    );

    // Claiming a perfect clock: accepts. Nothing in the library can catch this.
    assert!(matches!(
        bob.recv(&frame, TimeBound::exact(arrival)).unwrap(),
        Outcome::Accepted { .. }
    ));
}

#[test]
fn a_cert_fragments_over_the_link_and_reassembles() {
    // Certs are ~1.6 KiB against a 237-byte MTU. They travel out of band where
    // possible, but a peer that missed onboarding has to fetch one over the air.
    let alice = Node::new(b"alice chain seed", Role::Responder);
    let encoded = alice.cert.encode();
    assert!(encoded.len() > MTU * 4, "cert unexpectedly small");

    let shard_len = MTU - HEADER_LEN - FRAG_HEADER_LEN;
    let fragments = signet_core::frag::split(1, &encoded, shard_len, 30).unwrap();

    // Drop the first two shards entirely; parity must cover them.
    let mut reassembler = Reassembler::new();
    let mut recovered = None;
    for f in fragments.iter().skip(2) {
        if let Some(obj) = reassembler.push(f).unwrap() {
            recovered = Some(obj);
            break;
        }
    }

    let cert = Cert::decode(&recovered.expect("reassembly failed")).unwrap();
    assert!(verify_cert(&cert, alice.root.verifying_key()).unwrap());
    assert_eq!(cert.fingerprint(), alice.cert.fingerprint());
    assert_eq!(cert.role, Role::Responder);
}

#[test]
fn a_corrupted_fragment_yields_an_unverifiable_cert_not_a_trusted_one() {
    // Erasure coding is availability, not integrity. A wrongly reconstructed
    // cert must fail its signature check rather than be quietly accepted.
    let alice = Node::new(b"alice chain seed", Role::Eoc);
    let encoded = alice.cert.encode();
    let shard_len = MTU - HEADER_LEN - FRAG_HEADER_LEN;
    let mut fragments = signet_core::frag::split(1, &encoded, shard_len, 30).unwrap();
    fragments[0][FRAG_HEADER_LEN + 5] ^= 0xFF;

    let mut reassembler = Reassembler::new();
    let mut recovered = None;
    for f in &fragments {
        if let Some(obj) = reassembler.push(f).unwrap() {
            recovered = Some(obj);
            break;
        }
    }

    let bytes = recovered.expect("reassembly failed");
    assert_ne!(bytes, encoded);
    // It may or may not still parse as a cert; either way it must not verify.
    let verified = Cert::decode(&bytes)
        .ok()
        .and_then(|c| verify_cert(&c, alice.root.verifying_key()).ok())
        .unwrap_or(false);
    assert!(!verified, "a corrupted cert verified");
}

#[test]
fn two_peers_do_not_interfere() {
    let mut alice = Node::new(b"alice chain seed", Role::Eoc);
    let mut carol = Node::new(b"carol chain seed", Role::Civilian);
    let mut bob = Receiver::new(schedule());
    assert!(pin(&mut bob, &alice.cert.encode(), &alice.root));
    assert!(pin(&mut bob, &carol.cert.encode(), &carol.root));

    for interval in 2..8u32 {
        let a = alice
            .sender
            .beacon(STATUS, b"alice ok", at(interval))
            .unwrap();
        let c = carol
            .sender
            .beacon(STATUS, b"carol hurt", at(interval))
            .unwrap();
        bob.recv(&a, TimeBound::exact(at(interval))).unwrap();
        bob.recv(&c, TimeBound::exact(at(interval))).unwrap();
    }

    let store = bob.store();
    assert_eq!(
        store
            .get(&alice.cert.fingerprint(), STATUS)
            .unwrap()
            .payload,
        b"alice ok"
    );
    assert_eq!(
        store
            .get(&carol.cert.fingerprint(), STATUS)
            .unwrap()
            .payload,
        b"carol hurt"
    );
    // Independent claims, never collapsed into one truth.
    assert_eq!(store.by_kind(STATUS).count(), 2);
}
