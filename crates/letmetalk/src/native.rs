//! The native backend: webrtc-rs 0.21, with its UDP sockets bound to physical interfaces.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::BytesMut;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender, unbounded};
use futures::future::BoxFuture;
use futures::lock::Mutex as AsyncMutex;
use futures::StreamExt;
use n0_future::task::spawn;
use webrtc::data_channel::{DataChannel, DataChannelEvent};
use webrtc::runtime::{AsyncInterval, AsyncTcpListener, AsyncTcpStream, AsyncUdpSocket, JoinHandle, Runtime, default_runtime};
use webrtc::peer_connection::{
    PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler, RTCConfigurationBuilder,
    RTCIceCandidateInit, RTCIceServer, RTCIceTransportPolicy, RTCPeerConnectionIceEvent,
    RTCPeerConnectionState, RTCSessionDescription,
};
#[cfg(feature = "stats")]
use webrtc::peer_connection::{RTCStatsReport, RTCStatsReportEntry, StatsSelector};

use crate::IceServer;
use crate::backend::{CHANNELS, Event, Peer};
#[cfg(feature = "stats")]
use crate::backend::Path;

const SOCKET_BUFFER: usize = 4 << 20;

/// webrtc-rs binds its UDP sockets with the OS's default buffers, which drop packets under bulk load. This runtime
/// sizes each socket's buffers before webrtc-rs wraps it. Linux caps the request at `net.core.rmem_max`.
#[derive(Debug)]
struct Buffers(Arc<dyn Runtime>);

impl Runtime for Buffers {
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) -> Box<dyn JoinHandle> {
        self.0.spawn(future)
    }

    fn spawn_reactor(&self, n: usize, future: Pin<Box<dyn Future<Output = ()> + Send>>) -> Box<dyn JoinHandle> {
        self.0.spawn_reactor(n, future)
    }

    fn wrap_udp_socket(&self, sock: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let socket = socket2::SockRef::from(&sock);
        socket.set_recv_buffer_size(SOCKET_BUFFER)?;
        socket.set_send_buffer_size(SOCKET_BUFFER)?;
        self.0.wrap_udp_socket(sock)
    }

    fn wrap_tcp_listener(&self, listener: std::net::TcpListener) -> io::Result<Arc<dyn AsyncTcpListener>> {
        self.0.wrap_tcp_listener(listener)
    }

    fn connect_tcp<'a>(
        &'a self,
        addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<Arc<dyn AsyncTcpStream>>> + Send + 'a>> {
        self.0.connect_tcp(addr)
    }

    fn resolve_host<'a>(&'a self, host: &'a str) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'a>> {
        self.0.resolve_host(host)
    }

    fn now(&self) -> Instant {
        self.0.now()
    }

    fn sleep(&self, d: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        self.0.sleep(d)
    }

    fn interval(&self, period: Duration) -> Box<dyn AsyncInterval> {
        self.0.interval(period)
    }

    fn block_on(&self, future: Pin<Box<dyn Future<Output = ()> + '_>>) {
        self.0.block_on(future)
    }
}

/// Interfaces that are physical and up, with their addresses. Without any, loopback, so that peers on this
/// machine still connect.
fn bind_addrs() -> Vec<String> {
    let mut addrs: Vec<IpAddr> = netdev::get_interfaces()
        .into_iter()
        .filter(|i| i.is_up() && i.is_physical())
        .flat_map(|i| i.ip_addrs())
        .filter(|ip| !matches!(ip, IpAddr::V6(v6) if v6.segments()[0] & 0xffc0 == 0xfe80))
        .collect();
    if addrs.is_empty() {
        addrs.push(IpAddr::from([127, 0, 0, 1]));
    }
    addrs.into_iter().map(|ip| SocketAddr::new(ip, 0).to_string()).collect()
}

struct Shared {
    events: UnboundedSender<Event>,
    channels: Mutex<HashMap<u32, Arc<dyn DataChannel>>>,
}

impl Shared {
    fn register(self: &Arc<Self>, n: u32, dc: Arc<dyn DataChannel>) {
        self.channels.lock().unwrap().insert(n, dc.clone());
        let shared = self.clone();
        spawn(async move {
            while let Some(event) = dc.poll().await {
                let event = match event {
                    DataChannelEvent::OnOpen => Event::Ready(n),
                    DataChannelEvent::OnMessage(message) if message.is_string => Event::Failed,
                    DataChannelEvent::OnMessage(message) => Event::Message(n, message.data.to_vec()),
                    DataChannelEvent::OnClose => {
                        shared.channels.lock().unwrap().remove(&n);
                        let _ = shared.events.unbounded_send(Event::Closed);
                        return;
                    }
                    _ => continue,
                };
                if shared.events.unbounded_send(event).is_err() {
                    return;
                }
            }
        });
    }

    fn channel(&self, n: u32) -> io::Result<Arc<dyn DataChannel>> {
        self.channels
            .lock()
            .unwrap()
            .get(&n)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no such channel"))
    }
}

struct Handler(Arc<Shared>);

#[async_trait]
impl PeerConnectionEventHandler for Handler {
    async fn on_ice_candidate(&self, event: RTCPeerConnectionIceEvent) {
        if let Ok(init) = event.candidate.to_json() {
            let _ = self.0.events.unbounded_send(Event::Candidate(init.candidate));
        }
    }

    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        let event = match state {
            RTCPeerConnectionState::Connected => Event::Connected,
            RTCPeerConnectionState::Disconnected => Event::Disconnected,
            RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed => Event::Failed,
            _ => return,
        };
        let _ = self.0.events.unbounded_send(event);
    }

    async fn on_data_channel(&self, dc: Arc<dyn DataChannel>) {
        let Ok(n) = dc.label().await.unwrap_or_default().parse::<u32>() else {
            let _ = self.0.events.unbounded_send(Event::Failed);
            return;
        };
        self.0.register(n, dc);
        let _ = self.0.events.unbounded_send(Event::Opened(n));
    }
}

pub(crate) struct Native {
    pc: Arc<dyn PeerConnection>,
    shared: Arc<Shared>,
    events: AsyncMutex<UnboundedReceiver<Event>>,
}

fn other(e: webrtc::error::Error) -> io::Error {
    io::Error::other(e)
}

pub(crate) fn peer(ice: &[IceServer], relay_only: bool) -> BoxFuture<'static, io::Result<Arc<dyn Peer>>> {
    let native = native(ice, relay_only);
    Box::pin(async move { Ok(Arc::new(native.await?) as Arc<dyn Peer>) })
}

fn native(ice: &[IceServer], relay_only: bool) -> impl Future<Output = io::Result<Native>> + Send + 'static {
    let servers: Vec<RTCIceServer> = ice
        .iter()
        .map(|s| RTCIceServer { urls: s.urls.clone(), username: s.username.clone(), credential: s.credential.clone() })
        .collect();
    let policy = if relay_only { RTCIceTransportPolicy::Relay } else { RTCIceTransportPolicy::All };
    let config = RTCConfigurationBuilder::new().with_ice_servers(servers).with_ice_transport_policy(policy).build();
    async move {
        let (events, rx) = unbounded();
        let shared = Arc::new(Shared { events, channels: Mutex::new(HashMap::new()) });
        let pc = PeerConnectionBuilder::new()
            .with_configuration(config)
            .with_handler(Arc::new(Handler(shared.clone())))
            .with_runtime(Arc::new(Buffers(default_runtime().expect("webrtc-rs has a tokio runtime"))))
            .with_udp_addrs(bind_addrs())
            .build()
            .await
            .map_err(other)?;
        Ok(Native { pc: Arc::new(pc), shared, events: AsyncMutex::new(rx) })
    }
}

impl Peer for Native {
    /// The channels are in-band, created by the dialer before the offer. Negotiated channels would let the first
    /// message race the peer's channel opening, and webrtc-rs drops it.
    fn offer(&self) -> BoxFuture<'_, io::Result<String>> {
        Box::pin(async move {
            for channel in 0..CHANNELS {
                let dc = self.pc.create_data_channel(&channel.to_string(), None).await.map_err(other)?;
                self.shared.register(channel, dc);
            }
            let offer = self.pc.create_offer(None).await.map_err(other)?;
            self.pc.set_local_description(offer.clone()).await.map_err(other)?;
            Ok(offer.sdp)
        })
    }

    fn answer(&self, offer: &str) -> BoxFuture<'_, io::Result<String>> {
        let offer = offer.to_string();
        Box::pin(async move {
            let desc = RTCSessionDescription::offer(offer).map_err(other)?;
            self.pc.set_remote_description(desc).await.map_err(other)?;
            let answer = self.pc.create_answer(None).await.map_err(other)?;
            self.pc.set_local_description(answer.clone()).await.map_err(other)?;
            Ok(answer.sdp)
        })
    }

    fn accept(&self, answer: &str) -> BoxFuture<'_, io::Result<()>> {
        let answer = answer.to_string();
        Box::pin(async move {
            let desc = RTCSessionDescription::answer(answer).map_err(other)?;
            self.pc.set_remote_description(desc).await.map_err(other)
        })
    }

    fn candidate(&self, candidate: String) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(async move {
            let init = RTCIceCandidateInit {
                candidate,
                sdp_mid: Some("0".into()),
                sdp_mline_index: Some(0),
                ..Default::default()
            };
            self.pc.add_ice_candidate(init).await.map_err(other)
        })
    }

    fn send(&self, channel: u32, data: Vec<u8>) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(async move {
            let dc = self.shared.channel(channel)?;
            dc.send(BytesMut::from(data.as_slice())).await.map_err(other)
        })
    }

    fn next(&self) -> BoxFuture<'_, Option<Event>> {
        Box::pin(async { self.events.lock().await.next().await })
    }

    fn kick(&self) -> BoxFuture<'_, ()> {
        Box::pin(async {
            let config = self.pc.get_configuration().await;
            let _ = self.pc.set_configuration(config).await;
        })
    }

    fn close(&self) -> BoxFuture<'_, ()> {
        Box::pin(async {
            let _ = self.pc.close().await;
        })
    }

    #[cfg(feature = "stats")]
    fn path(&self) -> BoxFuture<'_, Option<Path>> {
        Box::pin(async {
            let report = self.pc.get_stats(Instant::now(), StatsSelector::None).await;
            let transport = report.iter().find_map(|e| match e {
                RTCStatsReportEntry::Transport(t) => Some(t),
                _ => None,
            })?;
            let RTCStatsReportEntry::IceCandidatePair(pair) = report.get(&transport.selected_candidate_pair_id)? else {
                return None;
            };
            Some(Path {
                local: candidate_type(&report, &pair.local_candidate_id)?,
                // webrtc-rs keeps no entry for a remote candidate learnt from a check, which is peer-reflexive.
                remote: candidate_type(&report, &pair.remote_candidate_id).unwrap_or_else(|| "prflx".into()),
                rtt: Duration::from_secs_f64(pair.current_round_trip_time),
            })
        })
    }
}

/// A pair names its candidates without the `RTCLocalIceCandidate_` and `RTCRemoteIceCandidate_` prefixes that their
/// own stats ids carry.
#[cfg(feature = "stats")]
fn candidate_type(report: &RTCStatsReport, id: &str) -> Option<String> {
    report.iter().find_map(|e| match e {
        RTCStatsReportEntry::LocalCandidate(c) | RTCStatsReportEntry::RemoteCandidate(c) if c.stats.id.ends_with(id) => {
            Some(c.candidate_type.to_string())
        }
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn connect(a: &dyn Peer, b: &dyn Peer) {
        let offer = a.offer().await.unwrap();
        let answer = b.answer(&offer).await.unwrap();
        a.accept(&answer).await.unwrap();
        let (mut a_up, mut b_up) = (false, false);
        while !(a_up && b_up) {
            tokio::select! {
                Some(event) = a.next() => match event {
                    Event::Candidate(c) => b.candidate(c).await.unwrap(),
                    Event::Connected => a_up = true,
                    _ => {}
                },
                Some(event) = b.next() => match event {
                    Event::Candidate(c) => a.candidate(c).await.unwrap(),
                    Event::Connected => b_up = true,
                    _ => {}
                },
            }
        }
    }

    async fn until(p: &dyn Peer, want: impl Fn(&Event) -> bool) -> Event {
        loop {
            let event = p.next().await.unwrap();
            if want(&event) {
                return event;
            }
        }
    }

    #[tokio::test]
    async fn udp_sockets_get_the_buffers_the_host_allows() {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let probe = sock.try_clone().unwrap();
        Buffers(default_runtime().unwrap()).wrap_udp_socket(sock).unwrap();
        let direct = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let direct = socket2::SockRef::from(&direct);
        direct.set_recv_buffer_size(SOCKET_BUFFER).unwrap();
        assert_eq!(
            socket2::SockRef::from(&probe).recv_buffer_size().unwrap(),
            direct.recv_buffer_size().unwrap()
        );
    }

    #[tokio::test]
    async fn a_text_message_fails_the_link() {
        let a = native(&[], false).await.unwrap();
        let b = native(&[], false).await.unwrap();
        connect(&a, &b).await;
        until(&a, |e| matches!(e, Event::Ready(1))).await;
        until(&b, |e| matches!(e, Event::Opened(1))).await;
        a.shared.channel(1).unwrap().send_text("text").await.unwrap();
        let event = until(&b, |e| matches!(e, Event::Failed | Event::Message(..))).await;
        assert!(matches!(event, Event::Failed));
    }

    #[tokio::test]
    async fn two_peers_carry_a_message_on_a_channel() {
        let a = peer(&[], false).await.unwrap();
        let b = peer(&[], false).await.unwrap();
        connect(a.as_ref(), b.as_ref()).await;
        until(a.as_ref(), |e| matches!(e, Event::Ready(1))).await;
        until(b.as_ref(), |e| matches!(e, Event::Opened(1))).await;
        a.send(1, b"hello".to_vec()).await.unwrap();
        let Event::Message(1, data) = until(b.as_ref(), |e| matches!(e, Event::Message(1, _))).await else {
            unreachable!()
        };
        assert_eq!(data, b"hello");
    }
}
