//! The browser backend: the browser's own RTCPeerConnection and RTCDataChannels, through web-sys.
//!
//! JS objects are not `Send`, so they stay inside `SendWrapper`, which is sound on wasm's one thread. Nothing holding
//! a JS value lives across an await: each await takes a promise that a helper has already made.

use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::rc::Rc;
use std::sync::Arc;

use futures::StreamExt;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender, unbounded};
use futures::future::BoxFuture;
use futures::lock::Mutex as AsyncMutex;
use js_sys::{Array, ArrayBuffer, Promise, Uint8Array};
use send_wrapper::SendWrapper;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::{Closure, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    MessageEvent, RtcConfiguration, RtcDataChannel, RtcDataChannelEvent, RtcDataChannelType,
    RtcIceCandidateInit, RtcIceServer, RtcIceTransportPolicy, RtcPeerConnection, RtcPeerConnectionIceEvent,
    RtcPeerConnectionState, RtcSdpType, RtcSessionDescription, RtcSessionDescriptionInit,
};

use crate::IceServer;
use crate::backend::{Event, Peer};

const CONTROL: u32 = 0;

pub(crate) fn js(e: JsValue) -> io::Error {
    io::Error::other(format!("{e:?}"))
}

/// Awaits a promise. The promise is consumed here, and the future is `Send` because it only holds a `SendWrapper`.
fn settle(promise: Promise) -> impl Future<Output = io::Result<JsValue>> + Send {
    let future = SendWrapper::new(JsFuture::from(promise));
    async move { future.await.map_err(js) }
}

fn sdp_of(description: JsValue) -> String {
    description.unchecked_into::<RtcSessionDescription>().sdp()
}

fn description(kind: RtcSdpType, sdp: &str) -> RtcSessionDescriptionInit {
    let init = RtcSessionDescriptionInit::new(kind);
    init.set_sdp(sdp);
    init
}

type Lanes = Rc<RefCell<HashMap<u32, Lane>>>;

/// A data channel and its handlers. Dropping it detaches the handlers first, so no callback can reach a freed closure.
struct Lane {
    dc: RtcDataChannel,
    _open: Closure<dyn FnMut(JsValue)>,
    _message: Closure<dyn FnMut(MessageEvent)>,
    _closed: Closure<dyn FnMut(JsValue)>,
}

impl Drop for Lane {
    fn drop(&mut self) {
        self.dc.set_onopen(None);
        self.dc.set_onmessage(None);
        self.dc.set_onclose(None);
    }
}

/// Wires a channel's events into the peer's queue. Its numbers are letmetalk's, from the label. Only binary messages
/// are letmetalk's; a text message fails the link.
fn attach(events: &UnboundedSender<Event>, lanes: &Lanes, n: u32, dc: RtcDataChannel) {
    dc.set_binary_type(RtcDataChannelType::Arraybuffer);
    let tx = events.clone();
    let open = Closure::<dyn FnMut(JsValue)>::new(move |_: JsValue| {
        let _ = tx.unbounded_send(Event::Ready(n));
    });
    let tx = events.clone();
    let message = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
        let event = match event.data().dyn_into::<ArrayBuffer>() {
            Ok(buffer) => Event::Message(n, Uint8Array::new(&buffer).to_vec()),
            Err(_) => Event::Failed,
        };
        let _ = tx.unbounded_send(event);
    });
    let tx = events.clone();
    let closed = Closure::<dyn FnMut(JsValue)>::new(move |_: JsValue| {
        let _ = tx.unbounded_send(Event::Closed(n));
    });
    dc.set_onopen(Some(open.as_ref().unchecked_ref()));
    dc.set_onmessage(Some(message.as_ref().unchecked_ref()));
    dc.set_onclose(Some(closed.as_ref().unchecked_ref()));
    let lane = Lane { dc, _open: open, _message: message, _closed: closed };
    lanes.borrow_mut().insert(n, lane);
}

struct Inner {
    pc: RtcPeerConnection,
    events: UnboundedSender<Event>,
    lanes: Lanes,
    _candidate: Closure<dyn FnMut(RtcPeerConnectionIceEvent)>,
    _state: Closure<dyn FnMut(JsValue)>,
    _channel: Closure<dyn FnMut(RtcDataChannelEvent)>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.pc.set_onicecandidate(None);
        self.pc.set_onconnectionstatechange(None);
        self.pc.set_ondatachannel(None);
        self.pc.close();
    }
}

impl Inner {
    /// Creates channel `n` in band. The offer carries it, since it is created before the offer.
    fn create(&self, n: u32) {
        let dc = self.pc.create_data_channel(&n.to_string());
        attach(&self.events, &self.lanes, n, dc);
    }

    fn set_local(&self, kind: RtcSdpType, sdp: &str) -> Promise {
        self.pc.set_local_description(&description(kind, sdp))
    }

    fn set_remote(&self, kind: RtcSdpType, sdp: &str) -> Promise {
        self.pc.set_remote_description(&description(kind, sdp))
    }

    fn add_candidate(&self, candidate: &str) -> Promise {
        let init = RtcIceCandidateInit::new(candidate);
        init.set_sdp_mid(Some("0"));
        init.set_sdp_m_line_index(Some(0));
        self.pc.add_ice_candidate_with_opt_rtc_ice_candidate_init(Some(&init))
    }

    fn write(&self, n: u32, data: &[u8]) -> io::Result<()> {
        let lanes = self.lanes.borrow();
        let lane = lanes.get(&n).ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no such channel"))?;
        lane.dc.send_with_u8_array(data).map_err(js)
    }

    /// Closes channel `n` and drops its handlers. Its close event does not reach the queue. `close` flushes what
    /// was sent.
    fn close_lane(&self, n: u32) {
        if let Some(lane) = self.lanes.borrow_mut().remove(&n) {
            lane.dc.close();
        }
    }
}

pub(crate) struct Web {
    inner: SendWrapper<Inner>,
    events: AsyncMutex<UnboundedReceiver<Event>>,
}

impl Web {
    fn new(config: &RtcConfiguration) -> Result<Web, JsValue> {
        let pc = RtcPeerConnection::new_with_configuration(config)?;
        let (events, rx) = unbounded();
        let lanes: Lanes = Rc::default();

        let tx = events.clone();
        let candidate = Closure::<dyn FnMut(RtcPeerConnectionIceEvent)>::new(move |event: RtcPeerConnectionIceEvent| {
            if let Some(candidate) = event.candidate() {
                let _ = tx.unbounded_send(Event::Candidate(candidate.candidate()));
            }
        });
        let tx = events.clone();
        let peer = pc.clone();
        let state = Closure::<dyn FnMut(JsValue)>::new(move |_: JsValue| {
            let event = match peer.connection_state() {
                RtcPeerConnectionState::Connected => Event::Connected,
                RtcPeerConnectionState::Disconnected => Event::Disconnected,
                RtcPeerConnectionState::Failed => Event::Failed,
                _ => return,
            };
            let _ = tx.unbounded_send(event);
        });
        let (tx, channels) = (events.clone(), lanes.clone());
        let channel = Closure::<dyn FnMut(RtcDataChannelEvent)>::new(move |event: RtcDataChannelEvent| {
            let dc = event.channel();
            let Ok(n) = dc.label().parse::<u32>() else {
                dc.close();
                return;
            };
            attach(&tx, &channels, n, dc);
            let _ = tx.unbounded_send(Event::Opened(n));
        });
        pc.set_onicecandidate(Some(candidate.as_ref().unchecked_ref()));
        pc.set_onconnectionstatechange(Some(state.as_ref().unchecked_ref()));
        pc.set_ondatachannel(Some(channel.as_ref().unchecked_ref()));
        let inner = Inner { pc, events, lanes, _candidate: candidate, _state: state, _channel: channel };
        Ok(Web { inner: SendWrapper::new(inner), events: AsyncMutex::new(rx) })
    }
}

fn configuration(ice: &[IceServer], relay_only: bool) -> RtcConfiguration {
    let servers = Array::new();
    for server in ice {
        let entry = RtcIceServer::new();
        let urls: Array = server.urls.iter().map(|url| JsValue::from_str(url)).collect();
        entry.set_urls(&urls);
        entry.set_username(&server.username);
        entry.set_credential(&server.credential);
        servers.push(&entry);
    }
    let config = RtcConfiguration::new();
    config.set_ice_servers(&servers);
    if relay_only {
        config.set_ice_transport_policy(RtcIceTransportPolicy::Relay);
    }
    config
}

pub(crate) fn peer(ice: &[IceServer], relay_only: bool) -> BoxFuture<'static, io::Result<Arc<dyn Peer>>> {
    let peer = Web::new(&configuration(ice, relay_only))
        .map(|web| Arc::new(web) as Arc<dyn Peer>)
        .map_err(js);
    Box::pin(std::future::ready(peer))
}

impl Peer for Web {
    fn offer(&self) -> BoxFuture<'_, io::Result<String>> {
        Box::pin(async move {
            self.inner.create(CONTROL);
            let sdp = sdp_of(settle(self.inner.pc.create_offer()).await?);
            settle(self.inner.set_local(RtcSdpType::Offer, &sdp)).await?;
            Ok(sdp)
        })
    }

    fn answer(&self, offer: &str) -> BoxFuture<'_, io::Result<String>> {
        let offer = offer.to_string();
        Box::pin(async move {
            settle(self.inner.set_remote(RtcSdpType::Offer, &offer)).await?;
            let sdp = sdp_of(settle(self.inner.pc.create_answer()).await?);
            settle(self.inner.set_local(RtcSdpType::Answer, &sdp)).await?;
            Ok(sdp)
        })
    }

    fn accept(&self, answer: &str) -> BoxFuture<'_, io::Result<()>> {
        let answer = answer.to_string();
        Box::pin(async move { settle(self.inner.set_remote(RtcSdpType::Answer, &answer)).await.map(drop) })
    }

    fn candidate(&self, candidate: String) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(async move { settle(self.inner.add_candidate(&candidate)).await.map(drop) })
    }

    fn open(&self, channel: u32) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(async move {
            self.inner.create(channel);
            Ok(())
        })
    }

    fn send(&self, channel: u32, data: Vec<u8>) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(async move {
            self.inner.write(channel, &data)
        })
    }

    fn close_channel(&self, channel: u32) -> BoxFuture<'_, ()> {
        Box::pin(async move { self.inner.close_lane(channel) })
    }

    fn next(&self) -> BoxFuture<'_, Option<Event>> {
        Box::pin(async {
            let event = self.events.lock().await.next().await?;
            if let Event::Closed(n) = event {
                self.inner.lanes.borrow_mut().remove(&n);
            }
            Some(event)
        })
    }

    /// Browsers fire no event when a peer connection is closed, so `Failed` is synthesized: it wakes a run loop that
    /// is parked in `next`, after a send or close from another task. The channels go now, since none will report.
    fn close(&self) -> BoxFuture<'_, ()> {
        Box::pin(async {
            let _ = self.inner.events.unbounded_send(Event::Failed);
            self.inner.lanes.borrow_mut().clear();
            self.inner.pc.close();
        })
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod tests {
    use futures::FutureExt;
    use n0_future::time::timeout;
    use std::time::Duration;
    use wasm_bindgen_test::*;

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    async fn next_matching(peer: &Web, want: impl Fn(&Event) -> bool) -> Event {
        loop {
            let event = peer.next().await.unwrap();
            if want(&event) {
                return event;
            }
        }
    }

    async fn connect(a: &Web, b: &Web) {
        let offer = a.offer().await.unwrap();
        let answer = b.answer(&offer).await.unwrap();
        a.accept(&answer).await.unwrap();
        let (mut a_up, mut b_up) = (false, false);
        while !(a_up && b_up) {
            futures::select! {
                event = a.next().fuse() => match event.unwrap() {
                    Event::Candidate(c) => b.candidate(c).await.unwrap(),
                    Event::Connected => a_up = true,
                    _ => {}
                },
                event = b.next().fuse() => match event.unwrap() {
                    Event::Candidate(c) => a.candidate(c).await.unwrap(),
                    Event::Connected => b_up = true,
                    _ => {}
                },
            }
        }
    }

    #[wasm_bindgen_test]
    async fn a_text_message_fails_the_link() {
        let a = Web::new(&configuration(&[], false)).unwrap();
        let b = Web::new(&configuration(&[], false)).unwrap();
        connect(&a, &b).await;
        a.open(5).await.unwrap();
        next_matching(&a, |e| matches!(e, Event::Ready(5))).await;
        a.inner.lanes.borrow()[&5].dc.send_with_str("text").unwrap();
        let next = next_matching(&b, |e| matches!(e, Event::Failed | Event::Message(..)));
        let event = timeout(Duration::from_secs(10), next).await.expect("an event within 10 s");
        assert!(matches!(event, Event::Failed));
    }
}
