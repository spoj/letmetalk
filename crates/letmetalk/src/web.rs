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
use std::time::Duration;

use futures::StreamExt;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender, unbounded};
use futures::channel::oneshot;
use futures::future::BoxFuture;
use futures::lock::Mutex as AsyncMutex;
use js_sys::{Array, Promise, Uint8Array};
use n0_future::time::sleep;
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
/// Sends wait while a channel holds this many bytes, and resume once it has drained to half.
const SEND_BUFFER: u32 = 1 << 20;

pub(crate) fn js(e: JsValue) -> io::Error {
    io::Error::other(format!("{e:?}"))
}

fn gone() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "no such channel")
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

type Room = Rc<RefCell<Option<oneshot::Sender<()>>>>;
type Lanes = Rc<RefCell<HashMap<u32, Lane>>>;

/// A data channel and its handlers. Dropping it detaches the handlers first, so no callback can reach a freed closure.
struct Lane {
    dc: RtcDataChannel,
    room: Room,
    _open: Closure<dyn FnMut(JsValue)>,
    _message: Closure<dyn FnMut(MessageEvent)>,
    _closed: Closure<dyn FnMut(JsValue)>,
    _low: Closure<dyn FnMut(JsValue)>,
}

impl Drop for Lane {
    fn drop(&mut self) {
        self.dc.set_onopen(None);
        self.dc.set_onmessage(None);
        self.dc.set_onclose(None);
        self.dc.set_onbufferedamountlow(None);
    }
}

/// Wires a channel's events into the peer's queue. Its numbers are letmetalk's, from the label.
fn attach(events: &UnboundedSender<Event>, lanes: &Lanes, n: u32, dc: RtcDataChannel) {
    dc.set_binary_type(RtcDataChannelType::Arraybuffer);
    dc.set_buffered_amount_low_threshold(SEND_BUFFER / 2);
    let room: Room = Rc::default();
    let tx = events.clone();
    let open = Closure::<dyn FnMut(JsValue)>::new(move |_: JsValue| {
        let _ = tx.unbounded_send(Event::Ready(n));
    });
    let tx = events.clone();
    let message = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
        let data = Uint8Array::new(&event.data()).to_vec();
        let _ = tx.unbounded_send(Event::Message(n, data));
    });
    let tx = events.clone();
    let closed = Closure::<dyn FnMut(JsValue)>::new(move |_: JsValue| {
        let _ = tx.unbounded_send(Event::Closed(n));
    });
    let waiting = room.clone();
    let low = Closure::<dyn FnMut(JsValue)>::new(move |_: JsValue| {
        if let Some(waiting) = waiting.borrow_mut().take() {
            let _ = waiting.send(());
        }
    });
    dc.set_onopen(Some(open.as_ref().unchecked_ref()));
    dc.set_onmessage(Some(message.as_ref().unchecked_ref()));
    dc.set_onclose(Some(closed.as_ref().unchecked_ref()));
    dc.set_onbufferedamountlow(Some(low.as_ref().unchecked_ref()));
    let lane = Lane { dc, room, _open: open, _message: message, _closed: closed, _low: low };
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

    /// `Some` with a receiver to wait on while the channel is full. Waiting ends at `bufferedamountlow`.
    fn full(&self, n: u32) -> io::Result<Option<oneshot::Receiver<()>>> {
        let lanes = self.lanes.borrow();
        let lane = lanes.get(&n).ok_or_else(gone)?;
        if lane.dc.buffered_amount() < SEND_BUFFER {
            return Ok(None);
        }
        let (tx, rx) = oneshot::channel();
        *lane.room.borrow_mut() = Some(tx);
        Ok(Some(rx))
    }

    fn write(&self, n: u32, data: &[u8]) -> io::Result<()> {
        let lanes = self.lanes.borrow();
        let lane = lanes.get(&n).ok_or_else(gone)?;
        lane.dc.send_with_u8_array(data).map_err(js)
    }

    fn buffered(&self, n: u32) -> u32 {
        self.lanes.borrow().get(&n).map_or(0, |lane| lane.dc.buffered_amount())
    }

    /// Closes channel `n` and drops its handlers. Its close event does not reach the queue.
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
                RtcPeerConnectionState::Failed | RtcPeerConnectionState::Closed => Event::Failed,
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
            while let Some(drained) = self.inner.full(channel)? {
                let _ = drained.await;
            }
            self.inner.write(channel, &data)
        })
    }

    /// Waits until the channel's send buffer is empty, then closes it.
    fn close_channel(&self, channel: u32) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            while self.inner.buffered(channel) > 0 {
                sleep(Duration::from_millis(1)).await;
            }
            self.inner.close_lane(channel);
        })
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

    fn close(&self) -> BoxFuture<'_, ()> {
        Box::pin(async {
            let _ = self.inner.events.unbounded_send(Event::Failed);
            self.inner.pc.close();
        })
    }
}
