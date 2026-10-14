//! The browser entry. Each JSON line goes to `out`, a function of one string.

use wasm_bindgen::prelude::*;

use crate::letmetalk::{Dial, serve};

#[wasm_bindgen]
pub async fn run(role: String, url: String, key: String, peer: String, pair: String, out: js_sys::Function) -> Result<(), JsError> {
    let sink = |line: String| {
        out.call1(&JsValue::NULL, &JsValue::from_str(&line)).expect("the output function takes a string");
    };
    let result = async {
        let key = crate::secret_key(&key)?;
        match role.as_str() {
            "serve" => serve(&url, &key, &sink).await,
            "dial" => {
                let peer = peer.parse().map_err(std::io::Error::other)?;
                crate::dial_all(&Dial { url, key, peer }, &pair, &sink).await
            }
            _ => Err(std::io::Error::other("the role is serve or dial")),
        }
    };
    result.await.map_err(|e| JsError::new(&e.to_string()))
}
