//! Frames and login of the forwarder. No I/O: the client and the server both use it.

use std::io;

use blake2::digest::Mac;
use blake2::{Blake2s256, Blake2sMac256, Digest};
use x25519_dalek::{PublicKey as Montgomery, StaticSecret};

use crate::IceServer;
use crate::keys::{PublicKey, SecretKey};

pub const MAX_ENVELOPE: usize = 8 * 1024;
/// A client-to-server frame: id, recipient and envelope.
pub const MAX_UP: usize = 4 + 32 + MAX_ENVELOPE;
/// A server-to-client frame: an envelope, or the ICE servers.
pub const MAX_DOWN: usize = 16 * 1024;
const LABEL: &[u8] = b"letmetalk-signal/1";

pub enum Down {
    Deliver(Vec<u8>),
    Passed(u32),
    Offline(u32),
    Limited(u32),
    Ice(Vec<IceServer>),
    Replaced,
    Alive,
}

impl Down {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Deliver(envelope) => [&[0][..], envelope].concat(),
            Self::Passed(id) => tagged(1, *id),
            Self::Offline(id) => tagged(2, *id),
            Self::Limited(id) => tagged(3, *id),
            Self::Ice(ice) => {
                let mut out = vec![4];
                ciborium::into_writer(ice, &mut out).expect("CBOR into a Vec");
                out
            }
            Self::Replaced => vec![5],
            Self::Alive => vec![6],
        }
    }

    pub fn decode(frame: &[u8]) -> io::Result<Self> {
        let (&tag, body) = frame
            .split_first()
            .ok_or_else(|| io::Error::other("empty frame"))?;
        match (tag, body) {
            (0, envelope) => Ok(Self::Deliver(envelope.to_vec())),
            (1..=3, id) => {
                let id = u32::from_be_bytes(id.try_into().map_err(io::Error::other)?);
                Ok(match tag {
                    1 => Self::Passed(id),
                    2 => Self::Offline(id),
                    _ => Self::Limited(id),
                })
            }
            (4, cbor) => Ok(Self::Ice(
                ciborium::from_reader(cbor).map_err(io::Error::other)?,
            )),
            (5, []) => Ok(Self::Replaced),
            (6, []) => Ok(Self::Alive),
            _ => Err(io::Error::other("unknown frame")),
        }
    }
}

fn tagged(tag: u8, id: u32) -> Vec<u8> {
    [&[tag][..], &id.to_be_bytes()].concat()
}

pub struct Up {
    pub id: u32,
    pub to: PublicKey,
    pub envelope: Vec<u8>,
}

impl Up {
    pub fn encode(&self) -> Vec<u8> {
        [
            &self.id.to_be_bytes()[..],
            &self.to.to_bytes(),
            &self.envelope,
        ]
        .concat()
    }

    pub fn decode(frame: &[u8]) -> io::Result<Self> {
        if frame.len() < 36 {
            return Err(io::Error::other("short frame"));
        }
        Ok(Self {
            id: u32::from_be_bytes(frame[..4].try_into().expect("4 bytes")),
            to: PublicKey::from_bytes(frame[4..36].try_into().expect("32 bytes"))?,
            envelope: frame[36..].to_vec(),
        })
    }
}

/// The server's fresh X25519 key for one login.
pub struct Challenge {
    secret: StaticSecret,
    public: [u8; 32],
}

impl Challenge {
    pub fn fresh() -> Self {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).expect("OS randomness");
        let secret = StaticSecret::from(bytes);
        let public = Montgomery::from(&secret).to_bytes();
        Self { secret, public }
    }

    pub fn public(&self) -> [u8; 32] {
        self.public
    }
}

fn shared(secret: &StaticSecret, public: &[u8; 32]) -> io::Result<[u8; 32]> {
    let dh = secret.diffie_hellman(&Montgomery::from(*public));
    if !dh.was_contributory() {
        return Err(io::Error::other("all-zero Diffie-Hellman"));
    }
    Ok(dh.to_bytes())
}

/// The MAC state over the claimed Ed25519 key and the lowercased host, keyed by a labelled hash of the shared secret.
fn mac(dh: &[u8; 32], claimed: &[u8; 32], host: &str) -> Blake2sMac256 {
    let key: [u8; 32] = Blake2s256::new()
        .chain_update(b"letmetalk-signal/1 key")
        .chain_update(dh)
        .finalize()
        .into();
    let mut mac = Blake2sMac256::new_from_slice(&key).expect("32-byte key");
    mac.update(LABEL);
    mac.update(claimed);
    mac.update(host.to_ascii_lowercase().as_bytes());
    mac
}

/// What the forwarder keys sessions and routes by. A and its negation share it.
pub fn session_key(key: &PublicKey) -> [u8; 32] {
    key.x25519()
}

/// The client's login: its Ed25519 key, then the MAC. It answers a challenge for `host`.
pub fn answer(key: &SecretKey, host: &str, challenge: &[u8]) -> io::Result<[u8; 64]> {
    let challenge: [u8; 32] = challenge
        .try_into()
        .map_err(|_| io::Error::other("bad challenge"))?;
    let secret = StaticSecret::from(key.x25519_secret());
    let dh = shared(&secret, &challenge)?;
    let mut out = [0; 64];
    out[..32].copy_from_slice(&key.public().to_bytes());
    out[32..].copy_from_slice(
        &mac(&dh, &key.public().to_bytes(), host)
            .finalize()
            .into_bytes(),
    );
    Ok(out)
}

/// The server's check of a login made against `challenge` for `host`.
pub fn verify(challenge: &Challenge, host: &str, login: &[u8]) -> io::Result<PublicKey> {
    if login.len() != 64 {
        return Err(io::Error::other("bad login"));
    }
    let key = PublicKey::from_bytes(login[..32].try_into().expect("32 bytes"))?;
    let dh = shared(&challenge.secret, &key.x25519())?;
    mac(&dh, &key.to_bytes(), host)
        .verify_slice(&login[32..])
        .map_err(io::Error::other)?;
    Ok(key)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    const HOST: &str = "signal.example";

    fn login(key: &SecretKey, host: &str, challenge: &Challenge) -> Vec<u8> {
        answer(key, host, &challenge.public()).unwrap().to_vec()
    }

    #[test]
    fn login_round_trip() {
        let key = SecretKey::from_bytes([3; 32]);
        let challenge = Challenge::fresh();
        let verified = verify(&challenge, HOST, &login(&key, HOST, &challenge)).unwrap();
        assert_eq!(verified, key.public());
    }

    #[test]
    fn refuses_wrong_host() {
        let key = SecretKey::from_bytes([3; 32]);
        let challenge = Challenge::fresh();
        let login = login(&key, "other.example", &challenge);
        assert!(verify(&challenge, HOST, &login).is_err());
    }

    #[test]
    fn refuses_bad_mac() {
        let key = SecretKey::from_bytes([3; 32]);
        let challenge = Challenge::fresh();
        let mut login = login(&key, HOST, &challenge);
        login[63] ^= 1;
        assert!(verify(&challenge, HOST, &login).is_err());
    }

    #[test]
    fn login_is_case_insensitive_in_the_host() {
        let key = SecretKey::from_bytes([3; 32]);
        let challenge = Challenge::fresh();
        let login = login(&key, "Signal.Example", &challenge);
        assert!(verify(&challenge, HOST, &login).is_ok());
    }

    #[test]
    fn refuses_the_negation_of_the_signed_key() {
        let key = SecretKey::from_bytes([3; 32]);
        let challenge = Challenge::fresh();
        let mut login = login(&key, HOST, &challenge);
        let mut negated = key.public().to_bytes();
        negated[31] ^= 0x80;
        login[..32].copy_from_slice(&negated);
        assert!(verify(&challenge, HOST, &login).is_err());
    }

    #[test]
    fn refuses_all_zero_dh() {
        let key = SecretKey::from_bytes([3; 32]);
        assert!(answer(&key, HOST, &[0; 32]).is_err());
    }

    #[test]
    fn frames_round_trip() {
        let key = SecretKey::from_bytes([4; 32]).public();
        let up = Up {
            id: 7,
            to: key,
            envelope: vec![1, 2, 3],
        };
        let back = Up::decode(&up.encode()).unwrap();
        assert_eq!((back.id, back.to, back.envelope), (7, key, vec![1, 2, 3]));
        for down in [
            Down::Deliver(vec![9]),
            Down::Passed(1),
            Down::Offline(2),
            Down::Limited(3),
            Down::Replaced,
            Down::Alive,
        ] {
            assert_eq!(
                Down::decode(&down.encode()).unwrap().encode(),
                down.encode()
            );
        }
        assert!(Down::decode(&[9]).is_err());
        assert!(Down::decode(&[1, 0]).is_err());
    }
}
