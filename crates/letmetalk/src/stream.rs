use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::keys::PublicKey;
use crate::mux::{CHUNK, FIRST_CREDIT, Mux, data_frame, reset};

pub(crate) struct Io {
    pub(crate) number: u32,
    own: bool,
    state: Mutex<IoState>,
}

pub(crate) struct IoState {
    pub(crate) accepted: bool,
    pub(crate) inbox: VecDeque<u8>,
    pub(crate) read: u64,
    pub(crate) granted: u64,
    pub(crate) received: u64,
    pub(crate) credit: usize,
    pub(crate) outbox: VecDeque<Vec<u8>>,
    pub(crate) local_finished: bool,
    pub(crate) remote_finished: bool,
    pub(crate) failed: bool,
    pub(crate) discard: bool,
    pub(crate) read_waker: Option<Waker>,
    pub(crate) write_waker: Option<Waker>,
}

impl IoState {
    /// Credit granted and not yet read. It stays within `ACCEPTED_CREDIT`, so it fits a `usize`.
    pub(crate) fn outstanding(&self) -> usize {
        (self.granted - self.read) as usize
    }
}

impl Io {
    pub(crate) fn new(number: u32, own: bool) -> Io {
        Io {
            number,
            own,
            state: Mutex::new(IoState {
                accepted: own,
                inbox: VecDeque::new(),
                read: 0,
                granted: FIRST_CREDIT as u64,
                received: 0,
                credit: FIRST_CREDIT,
                outbox: VecDeque::new(),
                local_finished: false,
                remote_finished: false,
                failed: false,
                discard: false,
                read_waker: None,
                write_waker: None,
            }),
        }
    }

    pub(crate) fn own(&self) -> bool {
        self.own
    }

    pub(crate) fn state(&self) -> MutexGuard<'_, IoState> {
        self.state.lock().unwrap()
    }

    pub(crate) fn fail(&self) {
        let mut s = self.state();
        s.failed = true;
        s.inbox.clear();
        for waker in [s.read_waker.take(), s.write_waker.take()].into_iter().flatten() {
            waker.wake();
        }
    }
}

/// A reliable, ordered, two-way byte stream to a peer. Dropping it before `shutdown` resets it.
pub struct Stream {
    mux: Arc<Mux>,
    io: Arc<Io>,
    protocol: String,
}

impl Stream {
    pub(crate) fn new(mux: Arc<Mux>, io: Arc<Io>, protocol: String) -> Stream {
        Stream { mux, io, protocol }
    }

    pub fn remote_key(&self) -> PublicKey {
        self.mux.remote
    }

    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    pub(crate) fn accept(&self) {
        self.mux.accept(self.io.number);
    }
}

impl AsyncRead for Stream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut s = self.io.state();
        if s.failed {
            return Poll::Ready(Err(reset()));
        }
        if s.inbox.is_empty() {
            if s.remote_finished {
                return Poll::Ready(Ok(()));
            }
            s.read_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = {
            let (front, _) = s.inbox.as_slices();
            let n = front.len().min(buf.remaining());
            buf.put_slice(&front[..n]);
            n
        };
        s.inbox.drain(..n);
        s.read += n as u64;
        drop(s);
        self.mux.consumed();
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut s = self.io.state();
        if s.failed {
            return Poll::Ready(Err(reset()));
        }
        if s.local_finished {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "stream shut down")));
        }
        if s.credit == 0 {
            s.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = buf.len().min(s.credit).min(CHUNK);
        s.credit -= n;
        drop(s);
        self.mux.push(&self.io, data_frame(self.io.number, &buf[..n]));
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut s = self.io.state();
        if s.failed {
            return Poll::Ready(Err(reset()));
        }
        if !s.local_finished {
            s.local_finished = true;
            drop(s);
            self.mux.finish(&self.io);
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.mux.dropped(self.io.number);
    }
}
