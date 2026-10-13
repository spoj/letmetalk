//! The native backend: webrtc-rs 0.21, with its UDP sockets bound to physical interfaces.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::BytesMut;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender, unbounded};
use futures::future::BoxFuture;
use futures::lock::Mutex as AsyncMutex;
use futures::StreamExt;
use n0_future::task::spawn;
use webrtc::data_channel::{DataChannel, DataChannelEvent, RTCDataChannelInit};
use webrtc::peer_connection::{
    PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler, RTCConfigurationBuilder,
    RTCIceCandidateInit, RTCIceServer, RTCIceTransportPolicy, RTCPeerConnectionIceEvent,
    RTCPeerConnectionState, RTCSessionDescription,
};

use crate::IceServer;
use crate::backend::{Event, Peer};

const CONTROL_LABEL: &str = "letmetalk/1";
const SEND_BUFFER: usize = 1 << 20;

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
                    DataChannelEvent::OnMessage(message) => Event::Message(n, message.data.to_vec()),
                    DataChannelEvent::OnClose => {
                        shared.channels.lock().unwrap().remove(&n);
                        let _ = shared.events.unbounded_send(Event::Closed(n));
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
            let _ = dc.close().await;
            return;
        };
        let _ = self.0.events.unbounded_send(Event::Opened(n));
        self.0.register(n, dc);
    }
}

pub(crate) struct Native {
    pc: Arc<dyn PeerConnection>,
    shared: Arc<Shared>,
    events: AsyncMutex<UnboundedReceiver<Event>>,
}

impl Native {
    async fn control(&self) -> io::Result<()> {
        let init = RTCDataChannelInit { negotiated: Some(0), ..Default::default() };
        let dc = self.pc.create_data_channel(CONTROL_LABEL, Some(init)).await.map_err(io::Error::other)?;
        self.shared.register(0, dc);
        Ok(())
    }
}

fn other(e: webrtc::error::Error) -> io::Error {
    io::Error::other(e)
}

pub(crate) fn peer(ice: &[IceServer], relay_only: bool) -> BoxFuture<'static, io::Result<Box<dyn Peer>>> {
    let servers: Vec<RTCIceServer> = ice
        .iter()
        .map(|s| RTCIceServer { urls: s.urls.clone(), username: s.username.clone(), credential: s.credential.clone() })
        .collect();
    let policy = if relay_only { RTCIceTransportPolicy::Relay } else { RTCIceTransportPolicy::All };
    let config = RTCConfigurationBuilder::new().with_ice_servers(servers).with_ice_transport_policy(policy).build();
    Box::pin(async move {
        let (events, rx) = unbounded();
        let shared = Arc::new(Shared { events, channels: Mutex::new(HashMap::new()) });
        let pc = PeerConnectionBuilder::new()
            .with_configuration(config)
            .with_handler(Arc::new(Handler(shared.clone())))
            .with_udp_addrs(bind_addrs())
            .with_data_channel_send_buffer_limit(SEND_BUFFER)
            .build()
            .await
            .map_err(other)?;
        Ok(Box::new(Native { pc: Arc::new(pc), shared, events: AsyncMutex::new(rx) }) as Box<dyn Peer>)
    })
}

impl Peer for Native {
    fn offer(&self) -> BoxFuture<'_, io::Result<String>> {
        Box::pin(async move {
            self.control().await?;
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
            self.control().await?;
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

    fn open(&self, channel: u32) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(async move {
            let dc = self.pc.create_data_channel(&channel.to_string(), None).await.map_err(other)?;
            self.shared.register(channel, dc);
            Ok(())
        })
    }

    fn send(&self, channel: u32, data: Vec<u8>) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(async move {
            let dc = self.shared.channel(channel)?;
            dc.send(BytesMut::from(data.as_slice())).await.map_err(other)
        })
    }

    fn close_channel(&self, channel: u32) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if let Ok(dc) = self.shared.channel(channel) {
                let _ = dc.close().await;
            }
        })
    }

    fn next(&self) -> BoxFuture<'_, Option<Event>> {
        Box::pin(async { self.events.lock().await.next().await })
    }

    fn close(&self) -> BoxFuture<'_, ()> {
        Box::pin(async {
            let _ = self.pc.close().await;
        })
    }
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
    async fn two_peers_carry_a_message_on_a_channel() {
        let a = peer(&[], false).await.unwrap();
        let b = peer(&[], false).await.unwrap();
        connect(a.as_ref(), b.as_ref()).await;
        a.open(5).await.unwrap();
        until(a.as_ref(), |e| matches!(e, Event::Ready(5))).await;
        until(b.as_ref(), |e| matches!(e, Event::Opened(5))).await;
        a.send(5, b"hello".to_vec()).await.unwrap();
        let Event::Message(5, data) = until(b.as_ref(), |e| matches!(e, Event::Message(5, _))).await else {
            unreachable!()
        };
        assert_eq!(data, b"hello");
    }
}
