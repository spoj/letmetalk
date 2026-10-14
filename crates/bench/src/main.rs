//! The native bench. `serve` and `dial` run letmetalk through a forwarder; the `iroh-*` roles are the baseline, and
//! `pubkey` prints a key file's public key. Results are JSON lines on stdout.

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;

use letmetalk_bench::letmetalk::{Dial, serve};
use clap::{Parser, Subcommand};
use letmetalk::PublicKey;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Pubkey {
        #[arg(long)]
        key: PathBuf,
    },
    Serve {
        #[arg(long)]
        url: String,
        #[arg(long)]
        key: PathBuf,
    },
    Dial {
        #[arg(long)]
        url: String,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        peer: PublicKey,
        #[arg(long)]
        pair: String,
        /// MiB in each bulk transfer.
        #[arg(long, default_value_t = 256)]
        bulk_mib: usize,
    },
    #[cfg(feature = "iroh")]
    IrohRelay {
        #[arg(long)]
        listen: SocketAddr,
    },
    #[cfg(feature = "iroh")]
    IrohServe {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        relay: Option<iroh::RelayUrl>,
    },
    #[cfg(feature = "iroh")]
    IrohDial {
        #[arg(long)]
        key: PathBuf,
        /// The JSON address that `iroh-serve` printed.
        #[arg(long)]
        addr: PathBuf,
        #[arg(long)]
        relay: Option<iroh::RelayUrl>,
        #[arg(long)]
        pair: String,
        /// MiB in each bulk transfer.
        #[arg(long, default_value_t = 256)]
        bulk_mib: usize,
    },
}

fn read_key(path: &PathBuf) -> io::Result<letmetalk::SecretKey> {
    letmetalk_bench::secret_key(&std::fs::read_to_string(path)?)
}

#[cfg(feature = "iroh")]
fn iroh_key(path: &PathBuf) -> io::Result<iroh::SecretKey> {
    Ok(iroh::SecretKey::from_bytes(&read_key(path)?.to_bytes()))
}

fn peak_rss_kib() -> io::Result<u64> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:")).ok_or(io::ErrorKind::NotFound)?;
    line.split_whitespace().nth(1).ok_or(io::ErrorKind::InvalidData)?.parse().map_err(io::Error::other)
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let print = |line: String| println!("{line}");
    match Cli::parse().command {
        Command::Pubkey { key } => println!("{}", read_key(&key)?.public()),
        Command::Serve { url, key } => serve(&url, &read_key(&key)?, &print).await?,
        Command::Dial { url, key, peer, pair, bulk_mib } => {
            let dial = Dial { url, key: read_key(&key)?, peer };
            letmetalk_bench::dial_all(&dial, &pair, bulk_mib << 20, &print).await?;
            print(serde_json::json!({ "pair": pair, "scenario": "rss", "peak_rss_kib": peak_rss_kib().ok() }).to_string());
        }
        #[cfg(feature = "iroh")]
        Command::IrohRelay { listen } => letmetalk_bench::iroh::relay(listen).await?,
        #[cfg(feature = "iroh")]
        Command::IrohServe { key, relay } => letmetalk_bench::iroh::serve(&iroh_key(&key)?, relay, &print).await?,
        #[cfg(feature = "iroh")]
        Command::IrohDial { key, addr, relay, pair, bulk_mib } => {
            let addr = serde_json::from_str(&std::fs::read_to_string(addr)?).map_err(io::Error::other)?;
            let dial = letmetalk_bench::iroh::Dial { key: iroh_key(&key)?, addr, relay };
            letmetalk_bench::dial_all(&dial, &pair, bulk_mib << 20, &print).await?;
            print(serde_json::json!({ "pair": pair, "scenario": "rss", "peak_rss_kib": peak_rss_kib().ok() }).to_string());
        }
    }
    Ok(())
}
