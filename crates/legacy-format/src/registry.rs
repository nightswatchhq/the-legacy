//! The per-chain registry document (RFC-0001 §8.5).
//!
//! This is the entry point a new mirror fetches first: it names every relic, its manifest, and the
//! head pact root, plus the mirrors that will serve them. Everything below it is content-addressed,
//! so the registry is a convenience rather than an authority - a mirror that fetched a doctored
//! registry still cannot be fed doctored relics without the pact chain noticing.

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::hash::Hash32;
use crate::manifest::Manifest;
use crate::relic::BlockRange;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Https,
    S3,
    Torrent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mirror {
    pub name: String,
    pub base_url: String,
    pub transport: Transport,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelicEntry {
    pub index: u64,
    pub block_range: BlockRange,
    pub manifest_url: String,
    pub pact_root: Hash32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registry {
    pub chain_id: u64,
    pub spec_version: u32,
    pub head_pact_root: Hash32,
    pub head_block: u64,
    pub relics: Vec<RelicEntry>,
    pub mirrors: Vec<Mirror>,
}

impl Registry {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(crate::jcs::to_canonical_bytes(self)?)
    }

    /// Check the registry against the manifests it claims to describe.
    ///
    /// A registry can only ever be stale or wrong, never authoritative, so this exists to catch the
    /// stale case early rather than after a mirror has downloaded a few hundred gigabytes.
    pub fn check_against(&self, manifests: &[Manifest]) -> Result<(), Error> {
        if self.relics.len() != manifests.len() {
            return Err(Error::Manifest(format!(
                "registry lists {} relics, {} manifests given",
                self.relics.len(),
                manifests.len()
            )));
        }
        for (entry, m) in self.relics.iter().zip(manifests) {
            if entry.index != m.relic_index() {
                return Err(Error::Manifest(format!(
                    "registry entry {} points at relic {}",
                    entry.index,
                    m.relic_index()
                )));
            }
            if entry.pact_root != m.pact_root {
                return Err(Error::Manifest(format!(
                    "registry pact_root for relic {} is {}, the manifest says {}",
                    entry.index, entry.pact_root, m.pact_root
                )));
            }
            if entry.block_range != m.block_range {
                return Err(Error::Manifest(format!(
                    "registry block_range for relic {} is {}, the manifest says {}",
                    entry.index, entry.block_range, m.block_range
                )));
            }
        }
        match manifests.last() {
            Some(last) => {
                if self.head_pact_root != last.pact_root {
                    return Err(Error::Manifest(format!(
                        "head_pact_root is {}, the last manifest's is {}",
                        self.head_pact_root, last.pact_root
                    )));
                }
                if self.head_block != last.block_range.end {
                    return Err(Error::Manifest(format!(
                        "head_block is {}, the last relic ends at {}",
                        self.head_block, last.block_range.end
                    )));
                }
            }
            None => {
                if !self.head_pact_root.is_zero() {
                    return Err(Error::Manifest(
                        "a registry with no relics still claims a head pact root".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Build a registry from a sealed chain. Mirrors are supplied by the operator; the rest is
    /// derived, so the two cannot drift.
    pub fn from_chain(
        chain_id: u64,
        spec_version: u32,
        manifests: &[Manifest],
        base_url: &str,
        mirrors: Vec<Mirror>,
    ) -> Self {
        let relics = manifests
            .iter()
            .map(|m| RelicEntry {
                index: m.relic_index(),
                block_range: m.block_range,
                manifest_url: format!(
                    "{}/{}/manifest.json",
                    base_url.trim_end_matches('/'),
                    crate::relic::relic_prefix(spec_version, chain_id, m.relic_index())
                ),
                pact_root: m.pact_root,
            })
            .collect();

        Registry {
            chain_id,
            spec_version,
            head_pact_root: manifests
                .last()
                .map(|m| m.pact_root)
                .unwrap_or(Hash32::ZERO),
            head_block: manifests.last().map(|m| m.block_range.end).unwrap_or(0),
            relics,
            mirrors,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::sample_manifest;
    use crate::pact;

    fn sealed(n: u64) -> Vec<Manifest> {
        let mut ms: Vec<Manifest> = (0..n).map(sample_manifest).collect();
        pact::seal_chain(None, &mut ms).unwrap();
        ms
    }

    fn registry_for(ms: &[Manifest]) -> Registry {
        Registry::from_chain(1, 1, ms, "https://legacy.example", vec![])
    }

    #[test]
    fn a_registry_built_from_a_chain_agrees_with_it() {
        let ms = sealed(4);
        registry_for(&ms).check_against(&ms).unwrap();
    }

    #[test]
    fn a_stale_head_is_caught() {
        let ms = sealed(4);
        let mut r = registry_for(&ms);
        r.head_block -= 1;
        assert!(r.check_against(&ms).is_err());
    }

    #[test]
    fn a_swapped_pact_root_is_caught() {
        let ms = sealed(4);
        let mut r = registry_for(&ms);
        r.relics[2].pact_root = Hash32::ZERO;
        assert!(r.check_against(&ms).is_err());
    }

    #[test]
    fn urls_follow_the_object_layout() {
        let ms = sealed(2452);
        let r = registry_for(&ms);
        assert_eq!(
            r.relics[2451].manifest_url,
            "https://legacy.example/legacy/v1/1/relics/002451/manifest.json"
        );
    }

    #[test]
    fn an_empty_registry_may_not_claim_a_head() {
        let mut r = registry_for(&[]);
        assert!(r.check_against(&[]).is_ok());
        r.head_pact_root = crate::hash::blake3(b"wishful thinking");
        assert!(r.check_against(&[]).is_err());
    }
}
