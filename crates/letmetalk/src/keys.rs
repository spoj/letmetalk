use std::fmt;
use std::io;
use std::str::FromStr;

use ed25519_dalek::{SigningKey, VerifyingKey};

#[derive(Clone)]
pub struct SecretKey(SigningKey);

impl SecretKey {
    pub fn generate() -> Self {
        let mut seed = [0; 32];
        getrandom::fill(&mut seed).expect("OS randomness");
        Self::from_bytes(seed)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(SigningKey::from_bytes(&bytes))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PublicKey(VerifyingKey);

impl PublicKey {
    /// Refuses keys of small order and keys with a torsion part, which snow would accept.
    pub(crate) fn from_bytes(bytes: &[u8; 32]) -> io::Result<Self> {
        let key = VerifyingKey::from_bytes(bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if key.is_weak() || !key.to_edwards().is_torsion_free() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "weak or torsioned key",
            ));
        }
        Ok(Self(key))
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0.to_bytes()))
    }
}

impl FromStr for PublicKey {
    type Err = io::Error;

    fn from_str(s: &str) -> io::Result<Self> {
        let mut bytes = [0; 32];
        hex::decode_to_slice(s, &mut bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        Self::from_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let key = SecretKey::from_bytes([7; 32]).public();
        assert_eq!(key.to_string().parse::<PublicKey>().unwrap(), key);
    }

    #[test]
    fn refuses_small_order() {
        let identity = [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        let order_four = [0; 32];
        assert!(PublicKey::from_bytes(&identity).is_err());
        assert!(PublicKey::from_bytes(&order_four).is_err());
    }

    #[test]
    fn refuses_torsioned() {
        let torsioned = (2..=255u8)
            .map(|y| {
                let mut bytes = [0; 32];
                bytes[0] = y;
                bytes
            })
            .find(|bytes| {
                VerifyingKey::from_bytes(bytes)
                    .is_ok_and(|k| !k.is_weak() && !k.to_edwards().is_torsion_free())
            })
            .unwrap();
        assert!(PublicKey::from_bytes(&torsioned).is_err());
    }
}
