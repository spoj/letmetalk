mod client;
#[cfg(not(target_arch = "wasm32"))]
mod native;
#[cfg(target_arch = "wasm32")]
mod web;
#[doc(hidden)]
pub mod wire;

pub use client::WsSignal;
