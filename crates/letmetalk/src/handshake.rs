use std::collections::HashMap;
use std::io;

use blake2::{Blake2s256, Digest};
use ml_kem::{
    Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey, Kem, KeyExport, MlKem768,
    TryKeyInit,
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteArray;
use snow::{Builder, HandshakeState, StatelessTransportState};

use crate::keys::{PublicKey, SecretKey};

const PATTERN: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const VERSION: u8 = 1;
const HEADER: usize = 18;
const TAG: usize = 16;
const KEM_CT: usize = 1088;
const KEM_EK: usize = 1184;
const MAX_MSG: usize = 65535;
const MAX_AGE_MS: u64 = 10 * 60 * 1000;
const CANDIDATE_NONCE: u64 = ((1 << 24) - 1) << 40;
const INDEX_LIMIT: u64 = (1 << 40) - 1;

#[derive(Clone, Copy)]
enum Kind {
    Offer = 1,
    Answer = 2,
    Candidates = 3,
}

#[derive(Serialize, Deserialize)]
struct OfferPayload {
    key: ByteArray<32>,
    sent_ms: u64,
    ek: ByteArray<KEM_EK>,
    sdp: String,
}

fn frame(kind: Kind, session: &[u8; 16], body: &[u8]) -> Vec<u8> {
    let mut out = vec![VERSION, kind as u8];
    out.extend_from_slice(session);
    out.extend_from_slice(body);
    out
}

fn unframe(envelope: &[u8], kind: Kind) -> io::Result<([u8; 16], &[u8])> {
    if envelope.len() < HEADER || envelope[..2] != [VERSION, kind as u8] {
        return Err(io::Error::other("bad envelope"));
    }
    Ok((envelope[2..HEADER].try_into().unwrap(), &envelope[HEADER..]))
}

fn prologue(session: &[u8; 16]) -> Vec<u8> {
    [b"letmetalk/1".as_slice(), session].concat()
}

fn pq_psk(secret: &[u8], ct: &[u8]) -> [u8; 32] {
    let mut hash = Blake2s256::new();
    hash.update(b"letmetalk/1 pq");
    hash.update(secret);
    hash.update(ct);
    hash.finalize().into()
}

pub(crate) struct Dialer {
    state: HandshakeState,
    decaps: DecapsulationKey<MlKem768>,
}

impl Dialer {
    /// `claimed` is the key the offer says it comes from; only tests set it to anything else.
    pub(crate) fn dial(
        local: &SecretKey,
        peer: &PublicKey,
        claimed: [u8; 32],
        sent_ms: u64,
        sdp: String,
    ) -> io::Result<(Self, Vec<u8>)> {
        let mut session = [0; 16];
        getrandom::fill(&mut session).expect("OS randomness");
        let (decaps, encaps) = MlKem768::generate_keypair();
        let payload = OfferPayload {
            key: claimed.into(),
            sent_ms,
            ek: ByteArray::new(encaps.to_bytes().into()),
            sdp,
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&payload, &mut cbor).map_err(io::Error::other)?;

        let mut state = Builder::new(PATTERN.parse().map_err(io::Error::other)?)
            .local_private_key(&local.x25519_secret())
            .map_err(io::Error::other)?
            .remote_public_key(&peer.x25519())
            .map_err(io::Error::other)?
            .prologue(&prologue(&session))
            .map_err(io::Error::other)?
            .build_initiator()
            .map_err(io::Error::other)?;
        let mut msg = vec![0; MAX_MSG];
        let n = state.write_message(&cbor, &mut msg).map_err(io::Error::other)?;
        msg.truncate(n);
        Ok((Self { state, decaps }, frame(Kind::Offer, &session, &msg)))
    }

    pub(crate) fn finish(mut self, envelope: &[u8]) -> io::Result<(Transport, String)> {
        let (_, body) = unframe(envelope, Kind::Answer)?;
        if body.len() < KEM_CT {
            return Err(io::Error::other("short answer"));
        }
        let (ct, msg) = body.split_at(KEM_CT);
        let secret = self.decaps.decapsulate_slice(ct).map_err(io::Error::other)?;
        self.state.set_psk(2, &pq_psk(&secret, ct)).map_err(io::Error::other)?;
        let mut payload = vec![0; MAX_MSG];
        let n = self.state.read_message(msg, &mut payload).map_err(io::Error::other)?;
        let sdp = String::from_utf8(payload[..n].to_vec()).map_err(io::Error::other)?;
        let transport = self.state.into_stateless_transport_mode().map_err(io::Error::other)?;
        Ok((Transport(transport), sdp))
    }
}

/// Sessions whose offers opened, so that a replayed offer is refused.
#[derive(Default)]
pub(crate) struct Replay(HashMap<[u8; 16], u64>);

impl Replay {
    fn admit(&mut self, session: [u8; 16], sent_ms: u64, now_ms: u64) -> bool {
        self.0.retain(|_, sent| *sent + MAX_AGE_MS >= now_ms);
        if self.0.contains_key(&session) {
            return false;
        }
        self.0.insert(session, sent_ms);
        true
    }
}

pub(crate) struct Offer {
    state: HandshakeState,
    session: [u8; 16],
    ek: EncapsulationKey<MlKem768>,
    pub(crate) dialer: PublicKey,
    pub(crate) sdp: String,
}

impl Offer {
    pub(crate) fn receive(
        local: &SecretKey,
        replay: &mut Replay,
        envelope: &[u8],
        now_ms: u64,
    ) -> io::Result<Self> {
        let (session, body) = unframe(envelope, Kind::Offer)?;
        let mut state = Builder::new(PATTERN.parse().map_err(io::Error::other)?)
            .local_private_key(&local.x25519_secret())
            .map_err(io::Error::other)?
            .prologue(&prologue(&session))
            .map_err(io::Error::other)?
            .build_responder()
            .map_err(io::Error::other)?;
        let mut cbor = vec![0; MAX_MSG];
        let n = state.read_message(body, &mut cbor).map_err(io::Error::other)?;
        let payload: OfferPayload =
            ciborium::from_reader(&cbor[..n]).map_err(io::Error::other)?;
        let dialer = PublicKey::from_bytes(&payload.key.into_array())?;
        if state.get_remote_static() != Some(&dialer.x25519()[..]) {
            return Err(io::Error::other("key does not match the handshake"));
        }
        if now_ms.abs_diff(payload.sent_ms) > MAX_AGE_MS {
            return Err(io::Error::other("stale offer"));
        }
        let ek = EncapsulationKey::<MlKem768>::new_from_slice(&payload.ek.into_array())
            .map_err(io::Error::other)?;
        if !replay.admit(session, payload.sent_ms, now_ms) {
            return Err(io::Error::other("replayed offer"));
        }
        Ok(Self { state, session, ek, dialer, sdp: payload.sdp })
    }

    pub(crate) fn answer(mut self, sdp: &str) -> io::Result<(Vec<u8>, Transport)> {
        let (ct, secret) = self.ek.encapsulate();
        self.state.set_psk(2, &pq_psk(&secret, &ct)).map_err(io::Error::other)?;
        let mut msg = vec![0; MAX_MSG];
        let n = self.state.write_message(sdp.as_bytes(), &mut msg).map_err(io::Error::other)?;
        let body = [&ct[..], &msg[..n]].concat();
        let transport = self.state.into_stateless_transport_mode().map_err(io::Error::other)?;
        Ok((frame(Kind::Answer, &self.session, &body), Transport(transport)))
    }
}

pub(crate) struct Transport(StatelessTransportState);

impl Transport {
    pub(crate) fn seal(&self, nonce: u64, plain: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = vec![0; plain.len() + TAG];
        let n = self.0.write_message(nonce, plain, &mut out).map_err(io::Error::other)?;
        out.truncate(n);
        Ok(out)
    }

    pub(crate) fn open(&self, nonce: u64, cipher: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = vec![0; cipher.len()];
        let n = self.0.read_message(nonce, cipher, &mut out).map_err(io::Error::other)?;
        out.truncate(n);
        Ok(out)
    }

    pub(crate) fn seal_candidates(
        &self,
        session: &[u8; 16],
        index: u64,
        batch: &[u8],
    ) -> io::Result<Vec<u8>> {
        if index >= INDEX_LIMIT {
            return Err(io::Error::other("candidate index out of range"));
        }
        let mut body = index.to_be_bytes()[3..].to_vec();
        body.extend(self.seal(CANDIDATE_NONCE | index, batch)?);
        Ok(frame(Kind::Candidates, session, &body))
    }

    pub(crate) fn open_candidates(&self, envelope: &[u8]) -> io::Result<(u64, Vec<u8>)> {
        let (_, body) = unframe(envelope, Kind::Candidates)?;
        if body.len() < 5 {
            return Err(io::Error::other("short candidates"));
        }
        let mut bytes = [0; 8];
        bytes[3..].copy_from_slice(&body[..5]);
        let index = u64::from_be_bytes(bytes);
        if index >= INDEX_LIMIT {
            return Err(io::Error::other("candidate index out of range"));
        }
        Ok((index, self.open(CANDIDATE_NONCE | index, &body[5..])?))
    }
}
