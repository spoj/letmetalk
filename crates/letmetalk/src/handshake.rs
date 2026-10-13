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
        let n = state
            .write_message(&cbor, &mut msg)
            .map_err(io::Error::other)?;
        msg.truncate(n);
        Ok((Self { state, decaps }, frame(Kind::Offer, &session, &msg)))
    }

    pub(crate) fn finish(mut self, envelope: &[u8]) -> io::Result<(Transport, String)> {
        let (_, body) = unframe(envelope, Kind::Answer)?;
        if body.len() < KEM_CT {
            return Err(io::Error::other("short answer"));
        }
        let (ct, msg) = body.split_at(KEM_CT);
        let secret = self
            .decaps
            .decapsulate_slice(ct)
            .map_err(io::Error::other)?;
        self.state
            .set_psk(2, &pq_psk(&secret, ct))
            .map_err(io::Error::other)?;
        let mut payload = vec![0; MAX_MSG];
        let n = self
            .state
            .read_message(msg, &mut payload)
            .map_err(io::Error::other)?;
        let sdp = String::from_utf8(payload[..n].to_vec()).map_err(io::Error::other)?;
        let transport = self
            .state
            .into_stateless_transport_mode()
            .map_err(io::Error::other)?;
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
        let n = state
            .read_message(body, &mut cbor)
            .map_err(io::Error::other)?;
        let payload: OfferPayload = ciborium::from_reader(&cbor[..n]).map_err(io::Error::other)?;
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
        Ok(Self {
            state,
            session,
            ek,
            dialer,
            sdp: payload.sdp,
        })
    }

    pub(crate) fn answer(mut self, sdp: &str) -> io::Result<(Vec<u8>, Transport)> {
        let (ct, secret) = self.ek.encapsulate();
        self.state
            .set_psk(2, &pq_psk(&secret, &ct))
            .map_err(io::Error::other)?;
        let mut msg = vec![0; MAX_MSG];
        let n = self
            .state
            .write_message(sdp.as_bytes(), &mut msg)
            .map_err(io::Error::other)?;
        let body = [&ct[..], &msg[..n]].concat();
        let transport = self
            .state
            .into_stateless_transport_mode()
            .map_err(io::Error::other)?;
        Ok((
            frame(Kind::Answer, &self.session, &body),
            Transport(transport),
        ))
    }
}

pub(crate) struct Transport(StatelessTransportState);

impl Transport {
    pub(crate) fn seal(&self, nonce: u64, plain: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = vec![0; plain.len() + TAG];
        let n = self
            .0
            .write_message(nonce, plain, &mut out)
            .map_err(io::Error::other)?;
        out.truncate(n);
        Ok(out)
    }

    pub(crate) fn open(&self, nonce: u64, cipher: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = vec![0; cipher.len()];
        let n = self
            .0
            .read_message(nonce, cipher, &mut out)
            .map_err(io::Error::other)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::torsioned;

    const NOW: u64 = 1_800_000_000_000;
    const TEN_MIN: u64 = MAX_AGE_MS;

    fn dial(from: &SecretKey, to: &SecretKey, sent_ms: u64) -> (Dialer, Vec<u8>) {
        let claimed = from.public().to_bytes();
        Dialer::dial(from, &to.public(), claimed, sent_ms, "offer".into()).unwrap()
    }

    fn answered(from: &SecretKey, to: &SecretKey) -> (Dialer, Vec<u8>, Vec<u8>) {
        let (dialer, msg1) = dial(from, to, NOW);
        let (msg2, _) = Offer::receive(to, &mut Replay::default(), &msg1, NOW)
            .unwrap()
            .answer("answer")
            .unwrap();
        (dialer, msg1, msg2)
    }

    fn flipped(bytes: &[u8], at: usize) -> Vec<u8> {
        let mut out = bytes.to_vec();
        out[at] ^= 1;
        out
    }

    #[test]
    fn full_handshake() {
        let (alice, bob) = (SecretKey::generate(), SecretKey::generate());
        let (dialer, msg1) = dial(&alice, &bob, NOW);
        let offer = Offer::receive(&bob, &mut Replay::default(), &msg1, NOW).unwrap();
        assert_eq!(offer.dialer, alice.public());
        assert_eq!(offer.sdp, "offer");
        let (msg2, bob_t) = offer.answer("answer").unwrap();
        let (alice_t, sdp) = dialer.finish(&msg2).unwrap();
        assert_eq!(sdp, "answer");

        let sealed = alice_t.seal(7, b"hello").unwrap();
        assert_eq!(bob_t.open(7, &sealed).unwrap(), b"hello");
        assert!(bob_t.open(8, &sealed).is_err());
        let back = bob_t.seal(8, b"hi").unwrap();
        assert_eq!(alice_t.open(8, &back).unwrap(), b"hi");
    }

    #[test]
    fn tampered_message1_fails() {
        let (alice, bob) = (SecretKey::generate(), SecretKey::generate());
        let (_, msg1) = dial(&alice, &bob, NOW);
        for at in [HEADER + 5, msg1.len() - 1] {
            let bad = flipped(&msg1, at);
            assert!(Offer::receive(&bob, &mut Replay::default(), &bad, NOW).is_err());
        }
    }

    #[test]
    fn tampered_message2_fails() {
        let (alice, bob) = (SecretKey::generate(), SecretKey::generate());
        let (dialer, _, msg2) = answered(&alice, &bob);
        assert!(dialer.finish(&flipped(&msg2, msg2.len() - 1)).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (alice, bob) = (SecretKey::generate(), SecretKey::generate());
        for at in [HEADER, HEADER + KEM_CT - 1] {
            let (dialer, _, msg2) = answered(&alice, &bob);
            assert!(dialer.finish(&flipped(&msg2, at)).is_err());
        }
    }

    #[test]
    fn message1_for_wrong_key_fails() {
        let (alice, bob, carol) = (
            SecretKey::generate(),
            SecretKey::generate(),
            SecretKey::generate(),
        );
        let (_, msg1) = dial(&alice, &bob, NOW);
        assert!(Offer::receive(&carol, &mut Replay::default(), &msg1, NOW).is_err());
    }

    #[test]
    fn claimed_key_not_mapping_to_static_fails() {
        let (alice, bob, carol) = (
            SecretKey::generate(),
            SecretKey::generate(),
            SecretKey::generate(),
        );
        let (_, msg1) = Dialer::dial(
            &alice,
            &bob.public(),
            carol.public().to_bytes(),
            NOW,
            "x".into(),
        )
        .unwrap();
        assert!(Offer::receive(&bob, &mut Replay::default(), &msg1, NOW).is_err());
    }

    #[test]
    fn small_order_and_torsioned_claimed_keys_fail() {
        let (alice, bob) = (SecretKey::generate(), SecretKey::generate());
        let mut identity = [0; 32];
        identity[0] = 1;
        for claimed in [identity, [0; 32], torsioned()] {
            let (_, msg1) = Dialer::dial(&alice, &bob.public(), claimed, NOW, "x".into()).unwrap();
            assert!(Offer::receive(&bob, &mut Replay::default(), &msg1, NOW).is_err());
        }
    }

    #[test]
    fn replayed_offer_fails() {
        let (alice, bob) = (SecretKey::generate(), SecretKey::generate());
        let (_, msg1) = dial(&alice, &bob, NOW);
        let mut replay = Replay::default();
        assert!(Offer::receive(&bob, &mut replay, &msg1, NOW).is_ok());
        assert!(Offer::receive(&bob, &mut replay, &msg1, NOW).is_err());
    }

    #[test]
    fn stale_and_future_offers_fail() {
        let (alice, bob) = (SecretKey::generate(), SecretKey::generate());
        let mut replay = Replay::default();
        for (sent, ok) in [
            (NOW - TEN_MIN - 1, false),
            (NOW + TEN_MIN + 1, false),
            (NOW - TEN_MIN, true),
            (NOW + TEN_MIN, true),
        ] {
            let (_, msg1) = dial(&alice, &bob, sent);
            assert_eq!(Offer::receive(&bob, &mut replay, &msg1, NOW).is_ok(), ok);
        }
    }

    #[test]
    fn forged_offers_do_not_enter_replay_cache() {
        let (alice, bob, carol) = (
            SecretKey::generate(),
            SecretKey::generate(),
            SecretKey::generate(),
        );
        let (_, msg1) = dial(&alice, &bob, NOW);
        let (_, other) = dial(&carol, &bob, NOW);
        let mut replay = Replay::default();
        let with_stolen_id = [&msg1[..HEADER], &other[HEADER..]].concat();
        for forged in [flipped(&msg1, msg1.len() - 1), with_stolen_id] {
            assert!(Offer::receive(&bob, &mut replay, &forged, NOW).is_err());
        }
        assert!(Offer::receive(&bob, &mut replay, &msg1, NOW).is_ok());
    }

    #[test]
    fn candidates_replayed_and_out_of_order() {
        let (alice, bob) = (SecretKey::generate(), SecretKey::generate());
        let (dialer, msg1) = dial(&alice, &bob, NOW);
        let (msg2, bob_t) = Offer::receive(&bob, &mut Replay::default(), &msg1, NOW)
            .unwrap()
            .answer("answer")
            .unwrap();
        let (alice_t, _) = dialer.finish(&msg2).unwrap();

        let session = [3; 16];
        let first = alice_t.seal_candidates(&session, 0, b"zero").unwrap();
        let second = alice_t.seal_candidates(&session, 1, b"one").unwrap();
        assert_eq!(
            bob_t.open_candidates(&second).unwrap(),
            (1, b"one".to_vec())
        );
        assert_eq!(
            bob_t.open_candidates(&first).unwrap(),
            (0, b"zero".to_vec())
        );
        assert_eq!(
            bob_t.open_candidates(&first).unwrap(),
            (0, b"zero".to_vec())
        );

        let moved = [&first[..HEADER], &[0, 0, 0, 0, 1], &first[HEADER + 5..]].concat();
        assert!(bob_t.open_candidates(&moved).is_err());
    }

    #[test]
    fn candidate_index_limits() {
        let (alice, bob) = (SecretKey::generate(), SecretKey::generate());
        let (dialer, msg1) = dial(&alice, &bob, NOW);
        let (msg2, bob_t) = Offer::receive(&bob, &mut Replay::default(), &msg1, NOW)
            .unwrap()
            .answer("answer")
            .unwrap();
        let (alice_t, _) = dialer.finish(&msg2).unwrap();

        let session = [3; 16];
        for index in [INDEX_LIMIT, 1 << 40] {
            assert!(alice_t.seal_candidates(&session, index, b"x").is_err());
        }
        let last = alice_t
            .seal_candidates(&session, INDEX_LIMIT - 1, b"x")
            .unwrap();
        assert_eq!(
            bob_t.open_candidates(&last).unwrap(),
            (INDEX_LIMIT - 1, b"x".to_vec())
        );

        let max_index = [&last[..HEADER], &[0xff; 5], &last[HEADER + 5..]].concat();
        assert!(bob_t.open_candidates(&max_index).is_err());
    }
}
