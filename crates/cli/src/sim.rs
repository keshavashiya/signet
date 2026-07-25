//! Airtime — the constrained-link cost model.
//!
//! # What this answers
//!
//! Every off-grid mesh in existence uses classical signatures. Nobody has
//! published what it costs to make one post-quantum, because the honest answer
//! depends on a link nobody models: ~200 bytes per frame, lossy, broadcast, no
//! reliable back-channel.
//!
//! This is that model. It exists to decide, with numbers, whether Signet's
//! routine path should be TESLA hash chains or a compact post-quantum
//! signature — *before* any post-quantum code is written.
//!
//! # Why there is no cryptography here
//!
//! Airtime is a function of bytes, and the byte counts are published constants
//! (FIPS 204/205/206 and the NIST round-3 candidates). Implementing ML-DSA to
//! discover that its signature is 2420 bytes would tell us nothing the standard
//! does not. CPU and battery cost *do* need real implementations — that is
//! Radio work, on hardware, where measuring them is meaningful.
//!
//! # Model
//!
//! - Frames are lost independently with probability `p`. Real meshes have
//!   correlated loss (a passing truck kills a burst), which makes multi-frame
//!   messages worse than modelled — so every result here is optimistic for the
//!   large-signature schemes. Burst loss lands with the hardware run.
//! - Multi-frame objects are erasure coded, not retransmitted: send `n` frames
//!   with `redundancy` extra, recover from any `n`. On a broadcast medium with
//!   no back-channel this beats ARQ, and it is why published ML-KEM-over-LoRa
//!   handshakes needing 28-62 frames are worse than they have to be.
//! - Time-on-air uses the Semtech LoRa formula at Meshtastic's LongFast preset.
//!   Per-frame preamble and header are why a 10-frame message costs far more
//!   than 10x a 1-frame message's payload — counting bytes alone understates it.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use signet_core::session::BODY_LEN;
use signet_core::wire::HEADER_LEN;
use std::fmt::Write as _;

/// One authentication scheme's on-wire cost.
struct Scheme {
    name: &'static str,
    /// Bytes of authentication trailer per message.
    trailer: usize,
    /// Whether this survives a cryptographically relevant quantum computer.
    pq: bool,
    note: &'static str,
}

/// Published sizes at NIST security level 1. Sources in `docs/src/protocol/sizes.md`.
const SCHEMES: &[Scheme] = &[
    Scheme {
        name: "Ed25519",
        trailer: 64,
        pq: false,
        note: "what every mesh ships today",
    },
    // Worst case: every message carries a key disclosure, which is the truth
    // for a beacon sent once per interval. A sender bursting several messages
    // in one interval discloses once and pays 16 bytes for the rest.
    Scheme {
        name: "TESLA (SHA-256)",
        trailer: 48,
        pq: true,
        note: "16B MAC + 32B disclosed key",
    },
    Scheme {
        name: "SQIsign-I",
        trailer: 204,
        pq: true,
        note: "NIST round 3; slow to sign",
    },
    Scheme {
        name: "MAYO-1",
        trailer: 392,
        pq: true,
        note: "NIST round 3",
    },
    Scheme {
        name: "HAWK-512",
        trailer: 555,
        pq: true,
        note: "NIST round 3",
    },
    Scheme {
        name: "FN-DSA-512",
        trailer: 666,
        pq: true,
        note: "FIPS 206 draft",
    },
    Scheme {
        name: "ML-DSA-44",
        trailer: 2420,
        pq: true,
        note: "FIPS 204, the safe default",
    },
    Scheme {
        name: "SLH-DSA-128s",
        trailer: 7856,
        pq: true,
        note: "FIPS 205, hash-based root",
    },
];

/// Simulator parameters.
#[derive(ClapArgs)]
pub struct Args {
    /// Usable payload bytes per frame (Meshtastic caps app data near 237).
    #[arg(long, default_value_t = 237)]
    mtu: usize,

    /// Application payload bytes, on top of the 13-byte frame header and
    /// 7-byte body header (a status beacon is about 30).
    #[arg(long, default_value_t = 30)]
    payload: usize,

    /// Per-frame loss probability.
    #[arg(long, default_value_t = 0.20)]
    loss: f64,

    /// Fraction of extra erasure-coded frames sent with multi-frame objects.
    #[arg(long, default_value_t = 0.30)]
    redundancy: f64,

    /// LoRa spreading factor (Meshtastic LongFast is 11).
    #[arg(long, default_value_t = 11)]
    sf: u32,

    /// LoRa bandwidth in kHz (Meshtastic LongFast is 250).
    #[arg(long, default_value_t = 250)]
    bw: u32,

    /// Sweep loss from 0 to 50% instead of running a single point.
    #[arg(long)]
    sweep: bool,

    /// Also write results to this CSV path.
    #[arg(long)]
    csv: Option<String>,
}

/// One scheme's modelled cost at one loss rate.
struct Row {
    name: &'static str,
    pq: bool,
    trailer: usize,
    data_frames: usize,
    sent_frames: usize,
    airtime_ms: f64,
    delivery: f64,
    effective_ms: f64,
    note: &'static str,
}

pub fn run(args: &Args) -> Result<()> {
    if !(0.0..1.0).contains(&args.loss) {
        anyhow::bail!("--loss must be in [0, 1), got {}", args.loss);
    }
    if args.mtu <= HEADER_LEN + BODY_LEN {
        anyhow::bail!(
            "--mtu must exceed the {} bytes of framing",
            HEADER_LEN + BODY_LEN
        );
    }

    let losses: Vec<f64> = if args.sweep {
        (0..=10).map(|i| i as f64 * 0.05).collect()
    } else {
        vec![args.loss]
    };

    let mut csv =
        String::from("loss,scheme,pq,trailer_bytes,frames,airtime_ms,delivery,effective_ms\n");

    for (i, &loss) in losses.iter().enumerate() {
        let rows: Vec<Row> = SCHEMES.iter().map(|s| model(s, args, loss)).collect();
        if i > 0 {
            println!();
        }
        print_table(args, loss, &rows);
        for r in &rows {
            writeln!(
                csv,
                "{loss:.2},{},{},{},{},{:.1},{:.4},{:.1}",
                r.name, r.pq, r.trailer, r.sent_frames, r.airtime_ms, r.delivery, r.effective_ms
            )?;
        }
    }

    if let Some(path) = &args.csv {
        if let Some(dir) = std::path::Path::new(path).parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)
                    .with_context(|| format!("creating {}", dir.display()))?;
            }
        }
        std::fs::write(path, &csv).with_context(|| format!("writing {path}"))?;
        println!("\nwrote {path}");
    }

    Ok(())
}

fn model(s: &Scheme, args: &Args, loss: f64) -> Row {
    let total = HEADER_LEN + BODY_LEN + args.payload + s.trailer;
    let data_frames = total.div_ceil(args.mtu);

    // Single-frame messages get no erasure coding — there is nothing to code
    // across. Multi-frame objects pay for redundancy and recover from any k.
    let sent_frames = if data_frames == 1 {
        1
    } else {
        (data_frames as f64 * (1.0 + args.redundancy)).ceil() as usize
    };

    let per_frame_ms = lora_toa_ms(args.sf, args.bw * 1000, total.min(args.mtu) as u32);
    let airtime_ms = per_frame_ms * sent_frames as f64;

    let delivery = at_least_k_of_n(sent_frames, data_frames, 1.0 - loss);
    // Expected airtime to land one message, counting retries of the whole
    // object. This is the number that actually matters for battery and duty
    // cycle, and it is where large signatures fall off a cliff.
    let effective_ms = if delivery > 0.0 {
        airtime_ms / delivery
    } else {
        f64::INFINITY
    };

    Row {
        name: s.name,
        pq: s.pq,
        trailer: s.trailer,
        data_frames,
        sent_frames,
        airtime_ms,
        delivery,
        effective_ms,
        note: s.note,
    }
}

fn print_table(args: &Args, loss: f64, rows: &[Row]) {
    println!(
        "Signet airtime model — SF{} BW{}kHz, MTU {}B, payload {}B, loss {:.0}%, redundancy {:.0}%",
        args.sf,
        args.bw,
        args.mtu,
        args.payload,
        loss * 100.0,
        args.redundancy * 100.0
    );
    println!(
        "{:<16} {:>4} {:>8} {:>7} {:>9} {:>8} {:>9}  note",
        "scheme", "pq", "trailer", "frames", "air ms", "deliver", "eff ms"
    );
    println!("{}", "-".repeat(100));

    let baseline = rows
        .iter()
        .find(|r| r.name.starts_with("TESLA"))
        .map(|r| r.effective_ms)
        .unwrap_or(1.0);

    for r in rows {
        let frames = if r.sent_frames == r.data_frames {
            format!("{}", r.sent_frames)
        } else {
            format!("{}/{}", r.sent_frames, r.data_frames)
        };
        let eff = if r.effective_ms.is_finite() {
            format!("{:.0}", r.effective_ms)
        } else {
            "never".to_string()
        };
        let ratio = if r.effective_ms.is_finite() && baseline > 0.0 {
            format!("{:.0}x  ", r.effective_ms / baseline)
        } else {
            String::new()
        };
        println!(
            "{:<16} {:>4} {:>8} {:>7} {:>9.0} {:>7.1}% {:>9}  {}{}",
            r.name,
            if r.pq { "yes" } else { "NO" },
            r.trailer,
            frames,
            r.airtime_ms,
            r.delivery * 100.0,
            eff,
            ratio,
            r.note
        );
    }
}

/// LoRa time-on-air in milliseconds (Semtech AN1200.13).
///
/// Assumes explicit header, CRC on, 8-symbol preamble, CR 4/5 — Meshtastic's
/// configuration. Low-data-rate optimisation switches on where the radio
/// mandates it, which is what makes SF11/SF12 disproportionately expensive.
fn lora_toa_ms(sf: u32, bw_hz: u32, payload_bytes: u32) -> f64 {
    const PREAMBLE_SYMS: f64 = 8.0;
    const CR: f64 = 1.0; // 4/5
    const CRC: f64 = 1.0;
    const IH: f64 = 0.0; // explicit header

    let sf_f = sf as f64;
    let t_sym = (1u64 << sf) as f64 / bw_hz as f64; // seconds
    let t_preamble = (PREAMBLE_SYMS + 4.25) * t_sym;

    // Low data rate optimisation is required at long symbol times.
    let de = if t_sym > 0.016 { 1.0 } else { 0.0 };

    let num = 8.0 * payload_bytes as f64 - 4.0 * sf_f + 28.0 + 16.0 * CRC - 20.0 * IH;
    let den = 4.0 * (sf_f - 2.0 * de);
    let payload_syms = 8.0 + (num / den).ceil().max(0.0) * (CR + 4.0);

    (t_preamble + payload_syms * t_sym) * 1000.0
}

/// P(at least `k` of `n` frames arrive), each arriving with probability `p`.
///
/// Iterative binomial: the pmf is stepped by a ratio rather than computing
/// factorials, which keeps it stable for the frame counts a 7856-byte
/// signature produces.
fn at_least_k_of_n(n: usize, k: usize, p: f64) -> f64 {
    if k == 0 {
        return 1.0;
    }
    if k > n {
        return 0.0;
    }
    if p >= 1.0 {
        return 1.0;
    }
    if p <= 0.0 {
        return 0.0;
    }

    let q = 1.0 - p;
    let mut pmf = q.powi(n as i32); // i = 0
    let mut acc = if k == 0 { pmf } else { 0.0 };
    for i in 0..n {
        // pmf(i+1) = pmf(i) * (n-i)/(i+1) * p/q
        pmf *= (n - i) as f64 / (i + 1) as f64 * (p / q);
        if i + 1 >= k {
            acc += pmf;
        }
    }
    acc.clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binomial_endpoints() {
        assert!((at_least_k_of_n(5, 5, 1.0) - 1.0).abs() < 1e-9);
        assert!(at_least_k_of_n(5, 5, 0.0) < 1e-9);
        assert!((at_least_k_of_n(5, 0, 0.5) - 1.0).abs() < 1e-9);
        assert_eq!(at_least_k_of_n(3, 4, 0.9), 0.0);
    }

    #[test]
    fn binomial_all_of_n_matches_closed_form() {
        // k == n reduces to p^n.
        let got = at_least_k_of_n(6, 6, 0.8);
        assert!((got - 0.8f64.powi(6)).abs() < 1e-9, "got {got}");
    }

    #[test]
    fn redundancy_beats_bare_transmission() {
        // 10 data frames at 20% loss: sending 13 and needing any 10 must be
        // strictly better than sending 10 and needing all 10. This is the
        // erasure-coding claim the design rests on.
        let bare = at_least_k_of_n(10, 10, 0.8);
        let coded = at_least_k_of_n(13, 10, 0.8);
        assert!(coded > bare, "coded {coded} should beat bare {bare}");
    }

    #[test]
    fn tesla_fits_in_one_frame() {
        // 13B header + 7B body + 30B payload + 48B trailer = 98B. If this
        // ever needs two frames the cheap path stopped being cheap.
        let args = Args {
            mtu: 237,
            payload: 30,
            loss: 0.2,
            redundancy: 0.3,
            sf: 11,
            bw: 250,
            sweep: false,
            csv: None,
        };
        let tesla = SCHEMES
            .iter()
            .find(|s| s.name.starts_with("TESLA"))
            .unwrap();
        assert_eq!(model(tesla, &args, 0.2).data_frames, 1);

        let mldsa = SCHEMES.iter().find(|s| s.name == "ML-DSA-44").unwrap();
        assert!(model(mldsa, &args, 0.2).data_frames > 1);
    }

    #[test]
    fn airtime_grows_with_payload() {
        let small = lora_toa_ms(11, 250_000, 20);
        let large = lora_toa_ms(11, 250_000, 200);
        assert!(large > small);
        // LongFast is slow: a full frame is on the order of a second.
        assert!((100.0..3000.0).contains(&large), "got {large} ms");
    }
}
