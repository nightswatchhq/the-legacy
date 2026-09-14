//! BLAKE3 content addressing.
//!
//! RFC-0001 §8.2: every content hash in The Legacy - per file, per manifest, per pact root - is
//! BLAKE3. The reason is bulk verification rather than fashion. A mirror bootstrapping the corpus
//! re-hashes hundreds of gigabytes before it trusts a byte of it, and that is exactly the workload
//! where SHA-256's throughput hurts. keccak256 stays where it belongs, inside trie work.

use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize, Serializer};
use std::fmt;

use crate::error::Error;

pub const HASH_LEN: usize = 32;

/// A 32-byte content hash. Serialises as lowercase hex with no `0x` prefix, which is the manifest
/// convention (RFC-0001 §8.1).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Hash32([u8; HASH_LEN]);

impl Hash32 {
    /// The all-zero hash. Used as `prev_relic_manifest_hash` on the genesis relic, and as the
    /// placeholder `pact_root` while a manifest is being hashed (§8.4).
    pub const ZERO: Hash32 = Hash32([0u8; HASH_LEN]);

    pub const fn new(bytes: [u8; HASH_LEN]) -> Self {
        Hash32(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; HASH_LEN]
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, Error> {
        // `0x` is tolerated on input because humans paste it, but never written on output: the
        // manifest is canonicalised, and two spellings of the same hash would be two documents.
        let s = s.strip_prefix("0x").unwrap_or(s);
        let raw = hex::decode(s).map_err(|e| Error::Hex(e.to_string()))?;
        let bytes: [u8; HASH_LEN] = raw
            .try_into()
            .map_err(|v: Vec<u8>| Error::Hex(format!("expected 32 bytes, got {}", v.len())))?;
        Ok(Hash32(bytes))
    }
}

/// Hash a byte slice.
pub fn blake3(bytes: &[u8]) -> Hash32 {
    Hash32(*::blake3::hash(bytes).as_bytes())
}

/// Hash the concatenation of two hashes, which is the pact chain's step function (§8.4).
pub fn blake3_pair(a: Hash32, b: Hash32) -> Hash32 {
    let mut h = ::blake3::Hasher::new();
    h.update(a.as_bytes());
    h.update(b.as_bytes());
    Hash32(*h.finalize().as_bytes())
}

impl fmt::Display for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash32({})", hex::encode(self.0))
    }
}

impl Serialize for Hash32 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Hash32 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = Hash32;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("64 lowercase hex characters")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Hash32, E> {
                Hash32::from_hex(v).map_err(E::custom)
            }
        }
        d.deserialize_str(V)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_and_rejects_short_input() {
        let h = blake3(b"the legacy");
        assert_eq!(Hash32::from_hex(&h.to_hex()).unwrap(), h);
        assert!(Hash32::from_hex("dead").is_err());
    }

    #[test]
    fn zero_is_zero_and_serialises_bare() {
        assert!(Hash32::ZERO.is_zero());
        assert_eq!(
            serde_json::to_string(&Hash32::ZERO).unwrap(),
            format!("\"{}\"", "0".repeat(64))
        );
    }

    #[test]
    fn accepts_an_0x_prefix_but_never_writes_one() {
        let h =
            Hash32::from_hex("0x00000000000000000000000000000000000000000000000000000000000000ff")
                .unwrap();
        assert!(h.to_hex().starts_with("00"));
        assert_eq!(h.as_bytes()[31], 0xff);
    }

    #[test]
    fn pair_is_order_dependent() {
        let a = blake3(b"a");
        let b = blake3(b"b");
        assert_ne!(blake3_pair(a, b), blake3_pair(b, a));
    }
}
