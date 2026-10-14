//! iroh 1.3 as the baseline: the same scenarios over its connections, direct or through a relay only.

use std::io;
use std::net::SocketAddr;

use iroh::endpoint::{Connection, Incoming, RecvStream, SendStream, presets};
use iroh::{Endpoint, EndpointAddr, RelayMode, RelayUrl, SecretKey};
use iroh_relay::server::{RelayConfig, Server, ServerConfig};
use tokio::io::{AsyncReadExt, Join, join};
use tokio::sync::OnceCell;

use crate::{Dialer, Route, handle};

const ALPN: &[u8] = b"letmetalk-bench/1";

/// Direct on loopback, or relay-only through `relay`, which is what a browser's path would be.
async fn bind(key: &SecretKey, relay: Option<&RelayUrl>) -> io::Result<Endpoint> {
    let builder = Endpoint::builder(presets::Minimal).secret_key(key.clone()).alpns(vec![ALPN.to_vec()]);
    let builder = match relay {
        Some(url) => builder.relay_mode(RelayMode::Custom(url.clone().into())).clear_ip_transports(),
        None => builder.relay_mode(RelayMode::Disabled).bind_addr("127.0.0.1:0").map_err(io::Error::other)?,
    };
    builder.bind().await.map_err(io::Error::other)
}

pub struct Dial {
    pub key: SecretKey,
    pub addr: EndpointAddr,
    pub relay: Option<RelayUrl>,
}

pub struct Link {
    endpoint: Endpoint,
    connection: OnceCell<Connection>,
}

impl Dialer for Dial {
    type Link = Link;
    type Stream = Join<RecvStream, SendStream>;

    async fn fresh(&self) -> io::Result<Link> {
        Ok(Link { endpoint: bind(&self.key, self.relay.as_ref()).await?, connection: OnceCell::new() })
    }

    async fn open(&self, link: &Link, protocol: &str) -> io::Result<Self::Stream> {
        let connection = link
            .connection
            .get_or_try_init(|| async {
                link.endpoint.connect(self.addr.clone(), ALPN).await.map_err(io::Error::other)
            })
            .await?;
        let (mut send, recv) = connection.open_bi().await.map_err(io::Error::other)?;
        send.write_all(&[protocol.len() as u8]).await?;
        send.write_all(protocol.as_bytes()).await?;
        Ok(join(recv, send))
    }

    async fn path(&self, link: &Link) -> Option<Route> {
        let paths = link.connection.get()?.paths();
        let path = paths.iter().find(|path| path.is_selected())?;
        Some(Route {
            relayed: path.is_relay(),
            local: format!("{:?}", path.local_addr()),
            remote: path.remote_addr().to_string(),
            rtt_ms: path.rtt().as_secs_f64() * 1e3,
        })
    }

    async fn close(&self, link: Link) {
        if let Some(connection) = link.connection.get() {
            connection.close(0u32.into(), b"done");
        }
        link.endpoint.close().await;
    }
}

/// Serves on `key`, printing its address as JSON once it is reachable, then every stream by its protocol.
pub async fn serve(key: &SecretKey, relay: Option<RelayUrl>, ready: &dyn Fn(String)) -> io::Result<()> {
    let endpoint = bind(key, relay.as_ref()).await?;
    let addr = match &relay {
        Some(url) => {
            endpoint.online().await;
            EndpointAddr::new(endpoint.id()).with_relay_url(url.clone())
        }
        None => {
            let port = endpoint.bound_sockets()[0].port();
            EndpointAddr::new(endpoint.id()).with_ip_addr(SocketAddr::from(([127, 0, 0, 1], port)))
        }
    };
    ready(serde_json::to_string(&addr).map_err(io::Error::other)?);
    while let Some(incoming) = endpoint.accept().await {
        n0_future::task::spawn(async move {
            if let Err(e) = connection(incoming).await {
                eprintln!("connection: {e}");
            }
        });
    }
    Ok(())
}

async fn connection(incoming: Incoming) -> io::Result<()> {
    let connection = incoming.accept().map_err(io::Error::other)?.await.map_err(io::Error::other)?;
    loop {
        let (send, recv) = connection.accept_bi().await.map_err(io::Error::other)?;
        n0_future::task::spawn(async move {
            if let Err(e) = stream(join(recv, send)).await {
                eprintln!("stream: {e}");
            }
        });
    }
}

async fn stream(mut stream: Join<RecvStream, SendStream>) -> io::Result<()> {
    let mut len = [0];
    stream.read_exact(&mut len).await?;
    let mut name = vec![0; len[0] as usize];
    stream.read_exact(&mut name).await?;
    let protocol = String::from_utf8(name).map_err(io::Error::other)?;
    handle(stream, &protocol).await
}

/// A relay on `listen`, over plain HTTP. It runs until the process is killed.
pub async fn relay(listen: SocketAddr) -> io::Result<()> {
    let mut config = ServerConfig::default();
    config.relay = Some(RelayConfig::new(listen));
    let _server = Server::spawn(config).await.map_err(io::Error::other)?;
    std::future::pending().await
}
