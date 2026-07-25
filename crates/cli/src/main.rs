//! Signet CLI.
//!
//! Two commands:
//!
//! - `signet sim` — the Airtime model. What does authenticity cost on a
//!   200-byte lossy link? Answered from published sizes alone.
//! - `signet demo` — the Protocol path. Two nodes with real FN-DSA keys
//!   exchanging verified beacons over a simulated lossy channel.

mod demo;
mod sim;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "signet", version, about = "Signet protocol tools", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Model authentication airtime over a constrained, lossy link.
    Sim(sim::Args),
    /// Run two nodes over a simulated lossy channel, with real keys.
    Demo(demo::Args),
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Sim(args) => sim::run(&args),
        Command::Demo(args) => demo::run(&args),
    }
}
