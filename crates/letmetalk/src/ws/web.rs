//! The browser's WebSocket. Frames and the close arrive on a channel, so `recv` can be cancelled safely.

use std::io;

use futures::StreamExt;
use futures::channel::mpsc::{UnboundedReceiver, unbounded};
use js_sys::{ArrayBuffer, Uint8Array};
use send_wrapper::SendWrapper;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::{Closure, JsValue};
use web_sys::{BinaryType, MessageEvent, WebSocket};

use crate::web::js;

pub(super) struct Socket {
    ws: SendWrapper<WebSocket>,
    frames: UnboundedReceiver<io::Result<Vec<u8>>>,
    _message: SendWrapper<Closure<dyn FnMut(MessageEvent)>>,
    _closed: SendWrapper<Closure<dyn FnMut(JsValue)>>,
}

impl Socket {
    /// Starts connecting. A failed connection shows up as the first read failing.
    pub(super) async fn connect(url: &str) -> io::Result<Socket> {
        let ws = WebSocket::new(url).map_err(js)?;
        ws.set_binary_type(BinaryType::Arraybuffer);
        let (tx, frames) = unbounded();
        let closed_tx = tx.clone();
        let message = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            if let Ok(buffer) = event.data().dyn_into::<ArrayBuffer>() {
                let _ = tx.unbounded_send(Ok(Uint8Array::new(&buffer).to_vec()));
            }
        });
        let closed = Closure::<dyn FnMut(JsValue)>::new(move |_: JsValue| {
            let _ = closed_tx.unbounded_send(Err(io::ErrorKind::ConnectionReset.into()));
        });
        ws.set_onmessage(Some(message.as_ref().unchecked_ref()));
        ws.set_onclose(Some(closed.as_ref().unchecked_ref()));
        Ok(Socket {
            ws: SendWrapper::new(ws),
            frames,
            _message: SendWrapper::new(message),
            _closed: SendWrapper::new(closed),
        })
    }

    /// The next binary frame. Text is skipped; a closed socket is an error.
    pub(super) async fn recv(&mut self) -> io::Result<Vec<u8>> {
        self.frames.next().await.expect("the socket's handlers hold a sender")
    }

    pub(super) async fn send(&mut self, frame: Vec<u8>) -> io::Result<()> {
        self.ws.send_with_u8_array(&frame).map_err(js)
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        self.ws.set_onmessage(None);
        self.ws.set_onclose(None);
        let _ = self.ws.close();
    }
}
