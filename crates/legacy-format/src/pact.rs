//! The pact: a per-chain hash chain over relic manifests (RFC-0001 §8.4).
//!
//! ```text
//! pact_root_0 = manifest_hash_0
//! pact_root_n = BLAKE3( pact_root_{n-1} || manifest_hash_n )
//! ```
//!
//! One 32-byte number per chain per height. If two mirrors agree on it, every relic and every file
//! byte underneath agrees; if they do not, a binary search over the per-relic roots finds the first
//! relic that differs in O(log n) requests rather than by downloading the corpus twice and staring
//! at it.

use crate::error::Error;
use crate::hash::{blake3_pair, Hash32};
use crate::manifest::Manifest;

/// Seal a run of manifests into a chain, filling in `prev_relic_manifest_hash` and `pact_root` on
/// each. Returns the head pact root.
///
/// `prev` is the last already-sealed manifest, or `None` when this run begins at the genesis
/// relic. Passing `None` for a run that does *not* begin at relic 0 is refused rather than
/// silently producing a chain anchored in the wrong place, which would verify perfectly against
/// itself and against nothing else.
pub fn seal_chain(prev: Option<&Manifest>, manifests: &mut [Manifest]) -> Result<Hash32, Error> {
    let mut carried: Option<Manifest> = prev.cloned();
    let mut head = prev.map(|p| p.pact_root).unwrap_or(Hash32::ZERO);

    for m in manifests.iter_mut() {
        head = extend(carried.as_ref(), m)?;
        carried = Some(m.clone());
    }

    Ok(head)
}

/// Extend an existing chain by one relic. This is the steady-state call: a Shadow seals one relic
/// at a time as finality moves, and never rewrites what came before.
pub fn extend(prev: Option<&Manifest>, next: &mut Manifest) -> Result<Hash32, Error> {
    next.validate()?;

    match prev {
        None => {
            let index = next.relic_index();
            if index != 0 {
                return Err(Error::Pact {
                    index,
                    reason: "no predecessor given, but this is not the genesis relic".into(),
                });
            }
            next.prev_relic_manifest_hash = Hash32::ZERO;
            let h = next.manifest_hash()?;
            next.pact_root = h;
        }
        Some(prev) => {
            check_link(prev, next)?;
            next.prev_relic_manifest_hash = prev.manifest_hash()?;
            let h = next.manifest_hash()?;
            next.pact_root = blake3_pair(prev.pact_root, h);
        }
    }
    Ok(next.pact_root)
}

/// Recompute the chain and check it against what the manifests claim.
///
/// This is the half of cleaning that needs no block data at all: a mirror can run it on the
/// manifests alone, before spending a single byte of transfer on Parquet.
pub fn verify_chain(prev: Option<&Manifest>, manifests: &[Manifest]) -> Result<Hash32, Error> {
    check_contiguous(manifests)?;
    if let (Some(prev), Some(first)) = (prev, manifests.first()) {
        check_link(prev, first)?;
    }

    let mut prev_manifest_hash = match prev {
        Some(p) => p.manifest_hash()?,
        None => Hash32::ZERO,
    };
    let mut prev_pact_root = prev.map(|p| p.pact_root).unwrap_or(Hash32::ZERO);
    let anchored_at_genesis = prev.is_none();

    for (i, m) in manifests.iter().enumerate() {
        let index = m.relic_index();
        m.validate()?;

        if i == 0 && anchored_at_genesis && index != 0 {
            return Err(Error::Pact {
                index,
                reason: "verified without a predecessor, but this is not the genesis relic".into(),
            });
        }

        if m.prev_relic_manifest_hash != prev_manifest_hash {
            return Err(Error::Pact {
                index,
                reason: format!(
                    "prev_relic_manifest_hash is {} but the previous manifest hashes to {prev_manifest_hash}",
                    m.prev_relic_manifest_hash
                ),
            });
        }

        let manifest_hash = m.manifest_hash()?;
        let expected = if i == 0 && anchored_at_genesis {
            manifest_hash
        } else {
            blake3_pair(prev_pact_root, manifest_hash)
        };

        if m.pact_root != expected {
            return Err(Error::Pact {
                index,
                reason: format!("pact_root is {} but recomputes to {expected}", m.pact_root),
            });
        }

        prev_manifest_hash = manifest_hash;
        prev_pact_root = m.pact_root;
    }

    Ok(prev_pact_root)
}

/// The head root of a sealed chain, without recomputing it.
pub fn head_root(manifests: &[Manifest]) -> Option<Hash32> {
    manifests.last().map(|m| m.pact_root)
}

/// Find the first relic at which two mirrors disagree.
///
/// `agrees(i)` answers "do our pact roots match at relic `i`". Because the pact root at `i`
/// commits to everything at or below `i`, the answer is monotone: true for a prefix, false
/// thereafter. That is what makes the search a binary one, and it is also the assumption to
/// remember - fed a non-monotone oracle this returns a boundary, just not a meaningful one.
///
/// Returns `None` when the two agree everywhere.
pub fn first_divergence(len: usize, agrees: impl Fn(usize) -> bool) -> Option<usize> {
    if len == 0 {
        return None;
    }
    if agrees(len - 1) {
        return None;
    }

    let (mut lo, mut hi) = (0usize, len - 1); // hi always disagrees
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if agrees(mid) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    Some(lo)
}

/// `first_divergence` over two in-memory root lists, for the case where you already hold both.
pub fn first_divergence_between(ours: &[Hash32], theirs: &[Hash32]) -> Option<usize> {
    let len = ours.len().min(theirs.len());
    match first_divergence(len, |i| ours[i] == theirs[i]) {
        Some(i) => Some(i),
        // Equal as far as the shorter list goes: the first difference is where one simply stops.
        None if ours.len() != theirs.len() => Some(len),
        None => None,
    }
}

fn check_contiguous(manifests: &[Manifest]) -> Result<(), Error> {
    for pair in manifests.windows(2) {
        check_link(&pair[0], &pair[1])?;
    }
    Ok(())
}

fn check_link(prev: &Manifest, next: &Manifest) -> Result<(), Error> {
    let index = next.relic_index();

    if next.chain_id != prev.chain_id {
        return Err(Error::Pact {
            index,
            reason: format!(
                "chain_id {} follows chain_id {}; one pact per chain",
                next.chain_id, prev.chain_id
            ),
        });
    }
    if index != prev.relic_index() + 1 {
        return Err(Error::Pact {
            index,
            reason: format!(
                "follows relic {}; the pact admits no gaps",
                prev.relic_index()
            ),
        });
    }
    // The header-chain link itself. Cheap here, and it means a mirror holding only manifests can
    // already tell that relic N+1 claims to continue relic N.
    if next.boundary.parent_hash_of_start != prev.boundary.end_block_hash {
        return Err(Error::Pact {
            index,
            reason: format!(
                "parent_hash_of_start is {} but relic {} ends at {}",
                next.boundary.parent_hash_of_start,
                prev.relic_index(),
                prev.boundary.end_block_hash
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::sample_manifest;

    fn chain(n: u64) -> Vec<Manifest> {
        (0..n).map(sample_manifest).collect()
    }

    #[test]
    fn a_sealed_chain_verifies() {
        let mut ms = chain(6);
        let head = seal_chain(None, &mut ms).unwrap();
        assert_eq!(verify_chain(None, &ms).unwrap(), head);
        assert_eq!(head_root(&ms), Some(head));
    }

    #[test]
    fn sealing_is_deterministic() {
        let mut a = chain(5);
        let mut b = chain(5);
        assert_eq!(
            seal_chain(None, &mut a).unwrap(),
            seal_chain(None, &mut b).unwrap()
        );
        assert_eq!(a, b);
    }

    #[test]
    fn a_continuation_run_verifies_against_its_predecessor() {
        // Relics 0..3 sealed yesterday, 3..6 sealed today. The head must come out the same as if
        // the whole run had been sealed in one go, or a mirror that backfilled in two sittings
        // would disagree with one that did it in a single pass.
        let mut in_one_go = chain(6);
        let head = seal_chain(None, &mut in_one_go).unwrap();

        let mut first_half = chain(3);
        seal_chain(None, &mut first_half).unwrap();
        let mut second_half: Vec<Manifest> = (3..6).map(sample_manifest).collect();
        let resumed = seal_chain(first_half.last(), &mut second_half).unwrap();

        assert_eq!(resumed, head);
        assert_eq!(second_half, in_one_go[3..]);
        assert_eq!(verify_chain(first_half.last(), &second_half).unwrap(), head);
    }

    #[test]
    fn a_run_that_does_not_start_at_genesis_needs_a_predecessor() {
        let mut orphan: Vec<Manifest> = (3..6).map(sample_manifest).collect();
        assert!(seal_chain(None, &mut orphan).is_err());

        let mut sealed = chain(6);
        seal_chain(None, &mut sealed).unwrap();
        assert!(verify_chain(None, &sealed[3..]).is_err());
    }

    #[test]
    fn extending_one_at_a_time_matches_sealing_the_lot() {
        let mut all_at_once = chain(5);
        let head = seal_chain(None, &mut all_at_once).unwrap();

        let mut incremental: Vec<Manifest> = Vec::new();
        for index in 0..5u64 {
            let mut next = sample_manifest(index);
            let prev = incremental.last().cloned();
            extend(prev.as_ref(), &mut next).unwrap();
            incremental.push(next);
        }

        assert_eq!(incremental, all_at_once);
        assert_eq!(head_root(&incremental), Some(head));
    }

    #[test]
    fn one_changed_byte_anywhere_moves_the_head_root() {
        let mut honest = chain(6);
        let head = seal_chain(None, &mut honest).unwrap();

        let mut tampered = chain(6);
        tampered[2].files[1].blake3 = crate::hash::blake3(b"not the file you asked for");
        let other_head = seal_chain(None, &mut tampered).unwrap();

        assert_ne!(head, other_head);
    }

    #[test]
    fn a_tampered_relic_fails_verification_at_its_own_index() {
        let mut ms = chain(4);
        seal_chain(None, &mut ms).unwrap();
        ms[2].files[0].row_count += 1; // sealed, then edited: exactly the malicious-mirror case

        match verify_chain(None, &ms) {
            Err(Error::Pact { index, .. }) => assert_eq!(index, 2),
            other => panic!("expected a pact failure at relic 2, got {other:?}"),
        }
    }

    #[test]
    fn a_gap_is_refused() {
        let mut ms = vec![sample_manifest(0), sample_manifest(2)];
        assert!(seal_chain(None, &mut ms).is_err());
    }

    #[test]
    fn a_broken_header_link_is_refused() {
        let mut ms = chain(3);
        ms[2].boundary.parent_hash_of_start = crate::hash::blake3(b"some other chain");
        assert!(seal_chain(None, &mut ms).is_err());
    }

    #[test]
    fn divergence_is_found_at_the_first_differing_relic() {
        let mut ours = chain(64);
        seal_chain(None, &mut ours).unwrap();

        let mut theirs = chain(64);
        theirs[37].files[0].byte_size += 1;
        seal_chain(None, &mut theirs).unwrap();

        let our_roots: Vec<Hash32> = ours.iter().map(|m| m.pact_root).collect();
        let their_roots: Vec<Hash32> = theirs.iter().map(|m| m.pact_root).collect();

        assert_eq!(first_divergence_between(&our_roots, &their_roots), Some(37));
    }

    #[test]
    fn divergence_search_is_logarithmic_in_the_number_of_relics() {
        use std::cell::Cell;
        let len = 1 << 16;
        let probes = Cell::new(0usize);
        let found = first_divergence(len, |i| {
            probes.set(probes.get() + 1);
            i < 40_000
        });
        assert_eq!(found, Some(40_000));
        // log2(65536) = 16, plus the one probe that establishes the head disagrees.
        assert!(probes.get() <= 17, "{} probes", probes.get());
    }

    #[test]
    fn identical_chains_diverge_nowhere() {
        let mut ours = chain(8);
        seal_chain(None, &mut ours).unwrap();
        let roots: Vec<Hash32> = ours.iter().map(|m| m.pact_root).collect();
        assert_eq!(first_divergence_between(&roots, &roots), None);
    }

    #[test]
    fn a_shorter_mirror_diverges_where_it_stops() {
        let mut ours = chain(8);
        seal_chain(None, &mut ours).unwrap();
        let roots: Vec<Hash32> = ours.iter().map(|m| m.pact_root).collect();
        assert_eq!(first_divergence_between(&roots, &roots[..5]), Some(5));
    }
}
