use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use letmetalk::PublicKey;
use letmetalk_signal::{Config, Forwarder, Turn};
use tokio::net::TcpListener;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,
    /// The host name clients log in to. It goes into the login MAC.
    #[arg(long)]
    host: String,
    /// PEM certificate and key. Without them the server speaks plain ws://.
    #[arg(long, requires = "tls_key")]
    tls_cert: Option<PathBuf>,
    #[arg(long, requires = "tls_cert")]
    tls_key: Option<PathBuf>,
    /// TURN URLs for members, from the coturn instance with the full quota.
    #[arg(long, required = true)]
    member_turn: Vec<String>,
    #[arg(long, env = "MEMBER_SECRET")]
    member_secret: String,
    /// TURN URLs for everyone else, from the coturn instance with the small quota.
    #[arg(long, required = true)]
    stranger_turn: Vec<String>,
    #[arg(long, env = "STRANGER_SECRET")]
    stranger_secret: String,
    /// Hex keys, one per line. Listed keys get member TURN; without a file every key is a routing member
    /// and gets stranger TURN.
    #[arg(long)]
    allowlist: Option<PathBuf>,
    /// Lifetime of TURN credentials in seconds. They are renewed at half their life.
    #[arg(long, default_value_t = 24 * 3600)]
    turn_ttl: u64,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();
    let allowlist = match args.allowlist {
        Some(path) => Some(
            std::fs::read_to_string(path)?
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| PublicKey::from_str(line.trim()))
                .collect::<io::Result<HashSet<_>>>()?,
        ),
        None => None,
    };
    let forwarder = Forwarder::new(Config {
        host: args.host,
        allowlist,
        member_turn: Turn {
            urls: args.member_turn,
            secret: args.member_secret,
        },
        stranger_turn: Turn {
            urls: args.stranger_turn,
            secret: args.stranger_secret,
        },
        turn_ttl: Duration::from_secs(args.turn_ttl),
    });
    let app = forwarder
        .router()
        .into_make_service_with_connect_info::<SocketAddr>();
    match (args.tls_cert, args.tls_key) {
        (Some(cert), Some(key)) => {
            rustls::crypto::ring::default_provider()
                .install_default()
                .expect("first provider");
            let tls = RustlsConfig::from_pem_file(cert, key).await?;
            axum_server::bind_rustls(args.listen, tls).serve(app).await
        }
        _ => axum::serve(TcpListener::bind(args.listen).await?, app).await,
    }
}
