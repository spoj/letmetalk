use std::collections::{HashSet, VecDeque};
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
const CACHE_CAP: usize = 100_000;
const CANDIDATE_NONCE: u64 = ((1 << 24) - 1) << 40;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Kind {
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

/// The kind and session of an envelope, before it is opened.
pub(crate) fn route(envelope: &[u8]) -> Option<(Kind, [u8; 16])> {
    let kind = match envelope.get(1)? {
        1 => Kind::Offer,
        2 => Kind::Answer,
        3 => Kind::Candidates,
        _ => return None,
    };
    if envelope[0] != VERSION {
        return None;
    }
    Some((kind, envelope.get(2..HEADER)?.try_into().ok()?))
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
    pub(crate) fn dial(
        local: &SecretKey,
        peer: &PublicKey,
        sent_ms: u64,
        sdp: String,
    ) -> io::Result<(Self, Vec<u8>)> {
        let mut session = [0; 16];
        getrandom::fill(&mut session).expect("OS randomness");
        let (decaps, encaps) = MlKem768::generate_keypair();
        let payload = OfferPayload {
            key: local.public().to_bytes().into(),
            sent_ms,
            ek: ByteArray::new(encaps.to_bytes().into()),
            sdp,
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&payload, &mut cbor).expect("CBOR into a Vec");

        let mut state = Builder::new(PATTERN.parse().expect("pattern is valid"))
            .local_private_key(&local.x25519_secret())
            .expect("32-byte key")
            .remote_public_key(&peer.x25519())
            .expect("32-byte key")
            .prologue(&prologue(&session))
            .expect("prologue is set once")
            .build_initiator()
            .expect("keys are set");
        let mut msg = vec![0; MAX_MSG];
        let n = state
            .write_message(&cbor, &mut msg)
            .map_err(io::Error::other)?;
        msg.truncate(n);
        Ok((Self { state, decaps }, frame(Kind::Offer, &session, &msg)))
    }

    #[allow(clippy::result_large_err)]
    pub(crate) fn finish(
        mut self,
        envelope: &[u8],
    ) -> Result<(Transport, String), (Self, io::Error)> {
        match self.read(envelope) {
            Ok(sdp) => {
                let transport = self
                    .state
                    .into_stateless_transport_mode()
                    .expect("message 2 completes the handshake");
                Ok((Transport(transport), sdp))
            }
            Err(e) => Err((self, e)),
        }
    }

    fn read(&mut self, envelope: &[u8]) -> io::Result<String> {
        let (_, body) = unframe(envelope, Kind::Answer)?;
        if body.len() < KEM_CT {
            return Err(io::Error::other("short answer"));
        }
        let (ct, msg) = body.split_at(KEM_CT);
        let secret = self
            .decaps
            .decapsulate_slice(ct)
            .expect("ciphertext has the fixed ML-KEM length");
        self.state
            .set_psk(2, &pq_psk(&secret, ct))
            .expect("psk slot 2 exists in IKpsk2");
        let mut payload = vec![0; MAX_MSG];
        let n = self
            .state
            .read_message(msg, &mut payload)
            .map_err(io::Error::other)?;
        String::from_utf8(payload[..n].to_vec()).map_err(io::Error::other)
    }
}

/// Sessions of answered offers, so that a replayed offer is refused. Entries are inserted in time order.
#[derive(Default)]
pub(crate) struct Replay {
    order: VecDeque<(u64, [u8; 16])>,
    seen: HashSet<[u8; 16]>,
}

impl Replay {
    fn expire(&mut self, now_ms: u64) {
        while let Some(&(expires_ms, session)) = self.order.front() {
            if expires_ms >= now_ms {
                break;
            }
            self.order.pop_front();
            self.seen.remove(&session);
        }
    }
}

pub(crate) struct Offer {
    state: HandshakeState,
    session: [u8; 16],
    ek: EncapsulationKey<MlKem768>,
    pub(crate) dialer: PublicKey,
    pub(crate) sent_ms: u64,
    pub(crate) sdp: String,
}

impl Offer {
    pub(crate) fn receive(
        local: &SecretKey,
        replay: &Replay,
        envelope: &[u8],
        now_ms: u64,
    ) -> io::Result<Self> {
        let (session, body) = unframe(envelope, Kind::Offer)?;
        let mut state = Builder::new(PATTERN.parse().expect("pattern is valid"))
            .local_private_key(&local.x25519_secret())
            .expect("32-byte key")
            .prologue(&prologue(&session))
            .expect("prologue is set once")
            .build_responder()
            .expect("key is set");
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
        if replay.seen.contains(&session) {
            return Err(io::Error::other("replayed offer"));
        }
        Ok(Self {
            state,
            session,
            ek,
            dialer,
            sent_ms: payload.sent_ms,
            sdp: payload.sdp,
        })
    }

    pub(crate) fn answer(
        mut self,
        replay: &mut Replay,
        now_ms: u64,
        sdp: &str,
    ) -> io::Result<(Vec<u8>, Transport)> {
        replay.expire(now_ms);
        if replay.seen.contains(&self.session) {
            return Err(io::Error::other("replayed offer"));
        }
        if replay.order.len() >= CACHE_CAP {
            return Err(io::Error::other("replay cache full"));
        }
        let (ct, secret) = self.ek.encapsulate();
        self.state
            .set_psk(2, &pq_psk(&secret, &ct))
            .expect("psk slot 2 exists in IKpsk2");
        let mut msg = vec![0; MAX_MSG];
        let n = self
            .state
            .write_message(sdp.as_bytes(), &mut msg)
            .map_err(io::Error::other)?;
        let body = [&ct[..], &msg[..n]].concat();
        let transport = self
            .state
            .into_stateless_transport_mode()
            .expect("message 2 completes the handshake");
        replay.seen.insert(self.session);
        replay
            .order
            .push_back((now_ms + 2 * MAX_AGE_MS, self.session));
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
        Ok((index, self.open(CANDIDATE_NONCE | index, &body[5..])?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::torsioned;
    use ed25519_dalek::VerifyingKey;
    use snow::Error;
    use snow::params::{CipherChoice, DHChoice, HashChoice};
    use snow::resolvers::{CryptoResolver, DefaultResolver};
    use snow::types::{Cipher, Dh, Hash, Random};

    /// The private key of a message 1 forged with no secret, whose public key the resolver replaces.
    const FORGED_STATIC: [u8; 32] = [42; 32];

    /// Resolves a snow initiator whose static key is sent as `static_u` and whose ephemeral key is zero,
    /// with every DH output zero, so that message 1 carries no secret.
    struct NoSecret([u8; 32]);

    struct NoSecretDh {
        inner: Box<dyn Dh>,
        static_u: [u8; 32],
        forged: Option<[u8; 32]>,
    }

    impl Dh for NoSecretDh {
        fn name(&self) -> &'static str {
            self.inner.name()
        }
        fn pub_len(&self) -> usize {
            32
        }
        fn priv_len(&self) -> usize {
            32
        }
        fn set(&mut self, privkey: &[u8]) {
            self.inner.set(privkey);
            if privkey == FORGED_STATIC {
                self.forged = Some(self.static_u);
            }
        }
        fn generate(&mut self, rng: &mut dyn Random) -> Result<(), Error> {
            self.inner.generate(rng)?;
            self.forged = Some([0; 32]);
            Ok(())
        }
        fn pubkey(&self) -> &[u8] {
            match &self.forged {
                Some(u) => u,
                None => self.inner.pubkey(),
            }
        }
        fn privkey(&self) -> &[u8] {
            self.inner.privkey()
        }
        fn dh(&self, pubkey: &[u8], out: &mut [u8]) -> Result<(), Error> {
            if self.forged.is_some() {
                out.fill(0);
                Ok(())
            } else {
                self.inner.dh(pubkey, out)
            }
        }
    }

    impl CryptoResolver for NoSecret {
        fn resolve_rng(&self) -> Option<Box<dyn Random>> {
            DefaultResolver.resolve_rng()
        }
        fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
            Some(Box::new(NoSecretDh {
                inner: DefaultResolver.resolve_dh(choice)?,
                static_u: self.0,
                forged: None,
            }))
        }
        fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
            DefaultResolver.resolve_hash(choice)
        }
        fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
            DefaultResolver.resolve_cipher(choice)
        }
    }

    fn montgomery(ed: [u8; 32]) -> [u8; 32] {
        VerifyingKey::from_bytes(&ed)
            .unwrap()
            .to_montgomery()
            .to_bytes()
    }

    const NOW: u64 = 1_800_000_000_000;
    const TEN_MIN: u64 = MAX_AGE_MS;

    fn dial(from: &SecretKey, to: &SecretKey, sent_ms: u64) -> (Dialer, Vec<u8>) {
        Dialer::dial(from, &to.public(), sent_ms, "offer".into()).unwrap()
    }

    fn fresh_ek() -> ByteArray<KEM_EK> {
        ByteArray::new(MlKem768::generate_keypair().1.to_bytes().into())
    }

    /// Message 1 written by snow itself, so that a test chooses the payload and the DH keys.
    fn message1(
        local: [u8; 32],
        resolver: Box<dyn CryptoResolver + Send>,
        peer: &PublicKey,
        payload: &OfferPayload,
    ) -> Vec<u8> {
        let mut session = [0; 16];
        getrandom::fill(&mut session).unwrap();
        let mut cbor = Vec::new();
        ciborium::into_writer(payload, &mut cbor).unwrap();
        let mut state = Builder::with_resolver(PATTERN.parse().unwrap(), resolver)
            .local_private_key(&local)
            .unwrap()
            .remote_public_key(&peer.x25519())
            .unwrap()
            .prologue(&prologue(&session))
            .unwrap()
            .build_initiator()
            .unwrap();
        let mut msg = vec![0; MAX_MSG];
        let n = state.write_message(&cbor, &mut msg).unwrap();
        msg.truncate(n);
        frame(Kind::Offer, &session, &msg)
    }

    fn answered(from: &SecretKey, to: &SecretKey) -> (Dialer, Vec<u8>, Vec<u8>) {
        let (dialer, msg1) = dial(from, to, NOW);
        let (msg2, _) = Offer::receive(to, &Replay::default(), &msg1, NOW)
            .unwrap()
            .answer(&mut Replay::default(), NOW, "answer")
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
        let offer = Offer::receive(&bob, &Replay::default(), &msg1, NOW).unwrap();
        assert_eq!(offer.dialer, alice.public());
        assert_eq!(offer.sdp, "offer");
        let (msg2, bob_t) = offer.answer(&mut Replay::default(), NOW, "answer").unwrap();
        let (alice_t, sdp) = dialer.finish(&msg2).map_err(|(_, e)| e).unwrap();
        assert_eq!(sdp, "answer");

        let sealed = alice_t.seal(7, b"hello").unwrap();
        assert_eq!(bob_t.open(7, &sealed).unwrap(), b"hello");
        assert!(bob_t.open(8, &sealed).is_err());
        let back = bob_t.seal(8, b"hi").unwrap();
        assert_eq!(alice_t.open(8, &back).unwrap(), b"hi");
    }

    #[test]
    fn garbled_answer_then_real_answer_succeeds() {
        let (alice, bob) = (SecretKey::generate(), SecretKey::generate());
        let (dialer, msg1) = dial(&alice, &bob, NOW);
        let (msg2, _) = Offer::receive(&bob, &Replay::default(), &msg1, NOW)
            .unwrap()
            .answer(&mut Replay::default(), NOW, "answer")
            .unwrap();
        let Err((dialer, _)) = dialer.finish(&flipped(&msg2, msg2.len() - 1)) else {
            panic!("garbled answer accepted");
        };
        let (_, sdp) = dialer.finish(&msg2).map_err(|(_, e)| e).unwrap();
        assert_eq!(sdp, "answer");
    }

    #[test]
    fn answer_under_other_kem_key_fails() {
        let (alice, bob) = (SecretKey::generate(), SecretKey::generate());
        let (mut dialer, msg1) = dial(&alice, &bob, NOW);
        let (msg2, _) = Offer::receive(&bob, &Replay::default(), &msg1, NOW)
            .unwrap()
            .answer(&mut Replay::default(), NOW, "answer")
            .unwrap();
        dialer.decaps = MlKem768::generate_keypair().0;
        assert!(dialer.finish(&msg2).is_err());
    }

    #[test]
    fn tampered_message1_fails() {
        let (alice, bob) = (SecretKey::generate(), SecretKey::generate());
        let (_, msg1) = dial(&alice, &bob, NOW);
        for at in [HEADER + 5, msg1.len() - 1] {
            let bad = flipped(&msg1, at);
            assert!(Offer::receive(&bob, &Replay::default(), &bad, NOW).is_err());
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
        assert!(Offer::receive(&carol, &Replay::default(), &msg1, NOW).is_err());
    }

    #[test]
    fn claimed_key_not_mapping_to_static_fails() {
        let (alice, bob, carol) = (
            SecretKey::generate(),
            SecretKey::generate(),
            SecretKey::generate(),
        );
        let payload = OfferPayload {
            key: carol.public().to_bytes().into(),
            sent_ms: NOW,
            ek: fresh_ek(),
            sdp: "x".into(),
        };
        let msg1 = message1(
            alice.x25519_secret(),
            Box::new(DefaultResolver),
            &bob.public(),
            &payload,
        );
        assert!(Offer::receive(&bob, &Replay::default(), &msg1, NOW).is_err());
    }

    #[test]
    fn negated_key_dials_as_negated_key() {
        let (alice, bob) = (SecretKey::generate(), SecretKey::generate());
        let mut negated = alice.public().to_bytes();
        negated[31] ^= 0x80;
        let payload = OfferPayload {
            key: negated.into(),
            sent_ms: NOW,
            ek: fresh_ek(),
            sdp: "x".into(),
        };
        let msg1 = message1(
            alice.x25519_secret(),
            Box::new(DefaultResolver),
            &bob.public(),
            &payload,
        );
        let offer = Offer::receive(&bob, &Replay::default(), &msg1, NOW).unwrap();
        assert_eq!(offer.dialer.to_bytes(), negated);
        assert_ne!(offer.dialer, alice.public());
        assert_eq!(offer.dialer.x25519(), alice.public().x25519());
    }

    #[test]
    fn message1_without_secret_fails() {
        let bob = SecretKey::generate();
        let mut identity = [0; 32];
        identity[0] = 1;
        for claimed in [identity, [0; 32], torsioned()] {
            let payload = OfferPayload {
                key: claimed.into(),
                sent_ms: NOW,
                ek: fresh_ek(),
                sdp: "x".into(),
            };
            let resolver = NoSecret(montgomery(claimed));
            let msg1 = message1(FORGED_STATIC, Box::new(resolver), &bob.public(), &payload);
            assert!(Offer::receive(&bob, &Replay::default(), &msg1, NOW).is_err());
        }
    }

    #[test]
    fn replayed_offer_fails() {
        let (alice, bob) = (SecretKey::generate(), SecretKey::generate());
        let (_, msg1) = dial(&alice, &bob, NOW);
        let mut replay = Replay::default();
        let first = Offer::receive(&bob, &replay, &msg1, NOW).unwrap();
        let second = Offer::receive(&bob, &replay, &msg1, NOW).unwrap();
        first.answer(&mut replay, NOW, "a").unwrap();
        assert!(Offer::receive(&bob, &replay, &msg1, NOW).is_err());
        assert!(second.answer(&mut replay, NOW, "b").is_err());
    }

    #[test]
    fn stale_and_future_offers_fail() {
        let (alice, bob) = (SecretKey::generate(), SecretKey::generate());
        let replay = Replay::default();
        for (sent, ok) in [
            (NOW - TEN_MIN - 1, false),
            (NOW + TEN_MIN + 1, false),
            (NOW - TEN_MIN, true),
            (NOW + TEN_MIN, true),
        ] {
            let (_, msg1) = dial(&alice, &bob, sent);
            assert_eq!(Offer::receive(&bob, &replay, &msg1, NOW).is_ok(), ok);
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
        let replay = Replay::default();
        let with_stolen_id = [&msg1[..HEADER], &other[HEADER..]].concat();
        for forged in [flipped(&msg1, msg1.len() - 1), with_stolen_id] {
            assert!(Offer::receive(&bob, &replay, &forged, NOW).is_err());
        }
        assert!(Offer::receive(&bob, &replay, &msg1, NOW).is_ok());
        assert!(replay.seen.is_empty());
    }

    #[test]
    fn refused_offers_leave_cache_empty() {
        let (alice, bob, carol) = (
            SecretKey::generate(),
            SecretKey::generate(),
            SecretKey::generate(),
        );
        let replay = Replay::default();
        let payload = |key: [u8; 32], ek| OfferPayload {
            key: key.into(),
            sent_ms: NOW,
            ek,
            sdp: "x".into(),
        };
        let honest = |payload: &OfferPayload| {
            message1(
                alice.x25519_secret(),
                Box::new(DefaultResolver),
                &bob.public(),
                payload,
            )
        };
        let refused = [
            dial(&alice, &bob, NOW - TEN_MIN - 1).1,
            dial(&alice, &bob, NOW + TEN_MIN + 1).1,
            honest(&payload(carol.public().to_bytes(), fresh_ek())),
            honest(&payload(
                alice.public().to_bytes(),
                ByteArray::new([0xff; KEM_EK]),
            )),
        ];
        for msg1 in &refused {
            assert!(Offer::receive(&bob, &replay, msg1, NOW).is_err());
            assert!(replay.seen.is_empty());
        }
        let (_, ok) = dial(&alice, &bob, NOW);
        assert!(Offer::receive(&bob, &replay, &ok, NOW).is_ok());
        assert!(replay.seen.is_empty());
    }

    #[test]
    fn failed_answer_leaves_cache_empty() {
        let (alice, bob) = (SecretKey::generate(), SecretKey::generate());
        let (_, msg1) = dial(&alice, &bob, NOW);
        let mut replay = Replay::default();
        let offer = Offer::receive(&bob, &replay, &msg1, NOW).unwrap();
        assert!(
            offer
                .answer(&mut replay, NOW, &"x".repeat(MAX_MSG))
                .is_err()
        );
        assert!(replay.seen.is_empty());
    }

    #[test]
    fn full_cache_refuses_to_answer() {
        let (alice, bob) = (SecretKey::generate(), SecretKey::generate());
        let (_, msg1) = dial(&alice, &bob, NOW);
        let offer = Offer::receive(&bob, &Replay::default(), &msg1, NOW).unwrap();
        let mut replay = Replay::default();
        for i in 0..CACHE_CAP as u128 {
            let session = i.to_be_bytes();
            replay.order.push_back((NOW + 2 * TEN_MIN, session));
            replay.seen.insert(session);
        }
        assert!(offer.answer(&mut replay, NOW, "answer").is_err());
        assert_eq!(replay.order.len(), CACHE_CAP);
    }

    #[test]
    fn cache_expires_after_two_max_ages() {
        let (alice, bob, carol) = (
            SecretKey::generate(),
            SecretKey::generate(),
            SecretKey::generate(),
        );
        let mut replay = Replay::default();
        let (_, first) = dial(&alice, &bob, NOW + TEN_MIN);
        let id: [u8; 16] = first[2..HEADER].try_into().unwrap();
        Offer::receive(&bob, &replay, &first, NOW)
            .unwrap()
            .answer(&mut replay, NOW, "a")
            .unwrap();

        let last = NOW + 2 * TEN_MIN;
        assert!(Offer::receive(&bob, &replay, &first, last).is_err());
        let (_, second) = dial(&carol, &bob, last);
        Offer::receive(&bob, &replay, &second, last)
            .unwrap()
            .answer(&mut replay, last, "b")
            .unwrap();
        assert!(replay.seen.contains(&id));

        let (_, third) = dial(&alice, &bob, last + 1);
        Offer::receive(&bob, &replay, &third, last + 1)
            .unwrap()
            .answer(&mut replay, last + 1, "c")
            .unwrap();
        assert!(!replay.seen.contains(&id));
        assert_eq!(replay.seen.len(), 2);
    }

    #[test]
    fn candidates_replayed_and_out_of_order() {
        let (alice, bob) = (SecretKey::generate(), SecretKey::generate());
        let (dialer, msg1) = dial(&alice, &bob, NOW);
        let (msg2, bob_t) = Offer::receive(&bob, &Replay::default(), &msg1, NOW)
            .unwrap()
            .answer(&mut Replay::default(), NOW, "answer")
            .unwrap();
        let (alice_t, _) = dialer.finish(&msg2).map_err(|(_, e)| e).unwrap();

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
        let (msg2, bob_t) = Offer::receive(&bob, &Replay::default(), &msg1, NOW)
            .unwrap()
            .answer(&mut Replay::default(), NOW, "answer")
            .unwrap();
        let (alice_t, _) = dialer.finish(&msg2).map_err(|(_, e)| e).unwrap();

        let session = [3; 16];
        let last = alice_t
            .seal_candidates(&session, (1 << 40) - 2, b"x")
            .unwrap();
        assert_eq!(
            bob_t.open_candidates(&last).unwrap(),
            ((1 << 40) - 2, b"x".to_vec())
        );

        let max_index = [&last[..HEADER], &[0xff; 5], &last[HEADER + 5..]].concat();
        assert!(bob_t.open_candidates(&max_index).is_err());
    }
}
