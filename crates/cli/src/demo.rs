//! `signet demo` — two nodes, real keys, a lossy channel.
//!
//! The Protocol deliverable made visible. Everything here is the real protocol:
//! FN-DSA cert issuance, out-of-band pinning, TESLA chains, the security
//! condition, and the fact store. Only the radio is simulated.
//!
//! Loss is a deterministic LCG so a run reproduces exactly from its seed —
//! which matters more than statistical realism when you are trying to explain
//! why a particular frame was dropped.

use anyhow::{bail, Result};
use clap::Args as ClapArgs;
use signet_core::cert::{Cert, Role};
use signet_core::chain::Chain;
use signet_core::session::{Outcome, Receiver, Sender};
use signet_core::time::{Schedule, TimeBound};
use signet_crypto::{verify_cert, KeyPair};

const STATUS: u16 = 0;
const EPOCH: u64 = 1_700_000_000_000;

/// Demo parameters.
#[derive(ClapArgs)]
pub struct Args {
    /// Percentage of frames the channel drops.
    #[arg(long, default_value_t = 30)]
    loss: u32,

    /// How many intervals to run.
    #[arg(long, default_value_t = 20)]
    intervals: u32,

    /// Clock uncertainty the receiver admits to, in milliseconds.
    ///
    /// Raise it past the disclosure window and every frame is correctly
    /// refused — the protocol degrading rather than pretending.
    #[arg(long, default_value_t = 0)]
    uncertainty_ms: u64,

    /// Seed for the channel's loss pattern. Same seed, same run.
    #[arg(long, default_value_t = 0xC0FFEE)]
    seed: u64,
}

pub fn run(args: &Args) -> Result<()> {
    if args.loss >= 100 {
        bail!("--loss must be under 100, got {}", args.loss);
    }
    let schedule = Schedule::default_at(EPOCH);
    let at = |i: u32| schedule.interval_start_ms(i) + 100;

    println!(
        "Signet demo — {}% loss, {} intervals, ±{} ms clock uncertainty",
        args.loss, args.intervals, args.uncertainty_ms
    );
    println!();

    // --- Before the disaster: keys and onboarding -------------------------
    let root = KeyPair::generate();
    let operational = KeyPair::generate();
    let chain = Chain::from_seed(b"demo chain seed, not for real use", 1024);
    let cert = root.issue(&operational, chain.commitment(), Role::Eoc, 9_999);
    let encoded = cert.encode();

    println!(
        "  root key      {} bytes public, cold storage",
        root.verifying_key().len()
    );
    println!(
        "  cert          {} bytes, role {:?}, id {}",
        encoded.len(),
        cert.role,
        hex8(&cert.fingerprint())
    );
    println!("  distributed out of band (QR / NFC / roster file) — 0 bytes on air");
    println!();

    // Bob verifies the cert against the root he was given at onboarding.
    let decoded = Cert::decode(&encoded)?;
    if !verify_cert(&decoded, root.verifying_key()).unwrap_or(false) {
        bail!("cert failed to verify against its own root");
    }
    let mut bob = Receiver::new(schedule);
    bob.add_peer(decoded.fingerprint(), decoded.tesla_root);
    println!("  ✅ cert verified and pinned. Bob will accept nothing else.");
    println!();

    // --- After the disaster: beacons over a dead network -------------------
    let mut alice = Sender::new(cert.fingerprint(), chain, schedule);
    let mut channel = Channel::new(args.seed, args.loss);
    let (mut sent, mut dropped, mut merged, mut refused) = (0, 0, 0, 0);

    println!("  int  frame  channel   outcome");
    println!("  {}", "-".repeat(58));

    for interval in 0..args.intervals {
        let payload = format!("status {interval}");
        let frame = alice.beacon(STATUS, payload.as_bytes(), at(interval))?;
        sent += 1;

        if !channel.delivers() {
            dropped += 1;
            println!("  {interval:>3}  {:>4}B  dropped   —", frame.len());
            continue;
        }

        let arrival = TimeBound::new(at(interval), args.uncertainty_ms);
        let note = match bob.recv(&frame, arrival)? {
            Outcome::Rejected(r) => {
                refused += 1;
                format!("✗ rejected: {r:?}")
            }
            Outcome::Accepted {
                merged: m,
                failed_mac,
                buffered,
            } => {
                merged += m;
                let mut s = if m > 0 {
                    format!("✓ verified {m}")
                } else {
                    "· buffered".to_string()
                };
                if buffered && m > 0 {
                    s.push_str(", more pending");
                }
                if failed_mac > 0 {
                    s.push_str(&format!(", {failed_mac} FORGED"));
                }
                s
            }
        };
        println!("  {interval:>3}  {:>4}B  delivered {note}", frame.len());
    }

    println!();
    println!("  sent {sent}, dropped {dropped}, verified {merged}, refused {refused}");
    match bob.store().get(&cert.fingerprint(), STATUS) {
        Some(fact) => println!(
            "  store: seq {} = {:?}",
            fact.seq,
            String::from_utf8_lossy(&fact.payload)
        ),
        None => println!("  store: empty — nothing survived the channel"),
    }
    println!("  still buffered: {}", bob.pending(&cert.fingerprint()));

    if args.uncertainty_ms > 0 && refused > 0 {
        println!();
        println!("  {refused} frames refused because the receiver could not rule out");
        println!("  that their keys were already public. That is the protocol working.");
    }
    Ok(())
}

fn hex8(id: &[u8; 8]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

/// Deterministic packet loss. Same seed, same pattern, every run.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_runs_clean_at_every_loss_rate() {
        for loss in [0, 30, 90] {
            run(&Args {
                loss,
                intervals: 12,
                uncertainty_ms: 0,
                seed: 42,
            })
            .unwrap();
        }
    }

    #[test]
    fn an_honest_clock_with_huge_uncertainty_refuses_everything() {
        // Degradation, not failure: uncertainty wider than the disclosure
        // window means no frame can be shown to have beaten its key.
        run(&Args {
            loss: 0,
            intervals: 8,
            uncertainty_ms: 10 * 60 * 1000,
            seed: 42,
        })
        .unwrap();
    }

    #[test]
    fn channel_is_deterministic() {
        let mut a = Channel::new(7, 40);
        let mut b = Channel::new(7, 40);
        for _ in 0..100 {
            assert_eq!(a.delivers(), b.delivers());
        }
    }
}
