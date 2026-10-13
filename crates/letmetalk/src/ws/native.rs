//! The native socket: tokio-tungstenite over TLS, with the webpki roots.

use std::io;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use rustls::ClientConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};

use super::wire::MAX_DOWN;

pub(super) struct Socket(WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>);

impl Socket {
    pub(super) async fn connect(url: &str) -> io::Result<Socket> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("ring supports the default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        let config = WebSocketConfig::default()
            .max_message_size(Some(MAX_DOWN))
            .max_frame_size(Some(MAX_DOWN));
        let (ws, _) = tokio_tungstenite::connect_async_tls_with_config(
            url,
            Some(config),
            true,
            Some(Connector::Rustls(Arc::new(tls))),
        )
        .await
        .map_err(io::Error::other)?;
        Ok(Socket(ws))
    }

    /// The next binary frame. Pings and text are skipped; a closed socket is an error.
    pub(super) async fn recv(&mut self) -> io::Result<Vec<u8>> {
        loop {
            match self.0.next().await {
                Some(Ok(Message::Binary(frame))) => return Ok(frame.to_vec()),
                Some(Ok(Message::Close(_))) | None => return Err(io::ErrorKind::ConnectionReset.into()),
                Some(Err(e)) => return Err(io::Error::other(e)),
                Some(Ok(_)) => {}
            }
        }
    }

    pub(super) async fn send(&mut self, frame: Vec<u8>) -> io::Result<()> {
        self.0.send(Message::Binary(frame.into())).await.map_err(io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use futures::{SinkExt, StreamExt};
    use tokio::net::TcpListener;
    use tokio_tungstenite::accept_async;
    use tokio_tungstenite::tungstenite::Message;

    use crate::SecretKey;
    use crate::ws::WsSignal;
    use crate::Signal;

    #[tokio::test]
    async fn refuses_plain_ws_to_a_remote_host() {
        let signal = WsSignal::new("ws://example.com/ws", &SecretKey::from_bytes([1; 32]));
        assert!(signal.recv().await.is_none());
    }

    #[tokio::test]
    async fn sends_no_login_for_a_zero_challenge() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/ws", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = accept_async(stream).await.unwrap();
            ws.send(Message::Binary(vec![0; 32].into())).await.unwrap();
            let next = tokio::time::timeout(Duration::from_millis(500), ws.next()).await;
            !matches!(next, Ok(Some(Ok(Message::Binary(_)))))
        });
        let _signal = WsSignal::new(&url, &SecretKey::from_bytes([1; 32]));
        assert!(server.await.unwrap());
    }
}
