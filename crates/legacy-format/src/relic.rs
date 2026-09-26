//! Relic geometry.
//!
//! RFC-0001 §5: a relic covers 8192 blocks, both pre- and post-merge, on every chain. 8192 is
//! era1's epoch size (the SSZ accumulator is a `List[HeaderRecord, 8192]`, so an era1 file cannot
//! hold more). A full aligned era1 file maps to one pre-merge relic; partial files need more input
//! before a relic can be sealed. A full epoch's accumulator root carries into its manifest as a
//! verifiable boundary artefact. It is also a power of two, so
//! block-to-relic is a shift rather than a division, and the pre- and post-merge tooling is the
//! same tooling.
//!
//! The constant is written into every manifest as `blocks_per_relic` rather than being implied, so
//! a future silo can change it without invalidating anything already sealed.

use serde::{Deserialize, Serialize};

/// Blocks per relic.
pub const BLOCKS_PER_RELIC: u64 = 8192;

/// `BLOCKS_PER_RELIC == 1 << RELIC_SHIFT`, which is the whole point of choosing it.
pub const RELIC_SHIFT: u32 = 13;

const _: () = assert!(BLOCKS_PER_RELIC == 1 << RELIC_SHIFT);

/// Width of the zero-padded relic directory name in the object-storage layout (§9.1). Six digits
/// reaches relic 999,999, which is block 8,191,999,999 - comfortably past any chain's lifetime at
/// current rates, and short enough to read.
pub const RELIC_DIR_WIDTH: usize = 6;

/// An inclusive block range. Inclusive because that is how the manifest writes it and how block
/// ranges are discussed everywhere else in Ethereum, and a half-open range in the document with an
/// inclusive one in conversation is a bug waiting for a quiet afternoon.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockRange {
    pub start: u64,
    pub end: u64,
}

impl BlockRange {
    pub const fn new(start: u64, end: u64) -> Self {
        BlockRange { start, end }
    }

    pub const fn len(&self) -> u64 {
        self.end - self.start + 1
    }

    pub const fn is_empty(&self) -> bool {
        false // an inclusive range always holds at least `start`
    }

    pub const fn contains(&self, block: u64) -> bool {
        block >= self.start && block <= self.end
    }
}

impl std::fmt::Display for BlockRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}..={}", self.start, self.end)
    }
}

/// Which relic holds a block.
pub const fn relic_index(block: u64) -> u64 {
    block >> RELIC_SHIFT
}

/// The block range a relic covers.
pub const fn relic_range(index: u64) -> BlockRange {
    let start = index << RELIC_SHIFT;
    BlockRange::new(start, start + BLOCKS_PER_RELIC - 1)
}

/// Every relic touched by an inclusive block range, which is the first step of any `eth_getLogs`
/// plan (§13.5 step 1).
pub fn relics_for_range(from: u64, to: u64) -> std::ops::RangeInclusive<u64> {
    relic_index(from.min(to))..=relic_index(to.max(from))
}

/// The zero-padded directory name for a relic, e.g. `002451`.
pub fn relic_dir_name(index: u64) -> String {
    format!("{index:0RELIC_DIR_WIDTH$}")
}

/// The object-storage prefix for a relic (§9.1), without a trailing slash.
pub fn relic_prefix(spec_version: u32, chain_id: u64, index: u64) -> String {
    format!(
        "legacy/v{spec_version}/{chain_id}/relics/{}",
        relic_dir_name(index)
    )
}

/// The registry key for a chain (§8.5).
pub fn registry_key(spec_version: u32, chain_id: u64) -> String {
    format!("legacy/v{spec_version}/{chain_id}/registry.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundaries_land_where_the_shift_says_they_do() {
        assert_eq!(relic_index(0), 0);
        assert_eq!(relic_index(8191), 0);
        assert_eq!(relic_index(8192), 1);
        assert_eq!(relic_range(0), BlockRange::new(0, 8191));
        assert_eq!(relic_range(1), BlockRange::new(8192, 16383));
    }

    #[test]
    fn the_rfc_worked_example_agrees() {
        // RFC-0001 §8.6 sets relic 2451 at blocks 20078592..=20086783. If this ever fails, either
        // the geometry moved or the example did, and both are worth knowing about.
        assert_eq!(relic_range(2451), BlockRange::new(20_078_592, 20_086_783));
        assert_eq!(relic_index(20_078_592), 2451);
        assert_eq!(relic_index(20_086_783), 2451);
        assert_eq!(relic_index(20_086_784), 2452);
        assert_eq!(relic_dir_name(2451), "002451");
    }

    #[test]
    fn every_relic_is_exactly_a_relic_long() {
        for index in [0u64, 1, 2451, 999_999] {
            assert_eq!(relic_range(index).len(), BLOCKS_PER_RELIC);
        }
    }

    #[test]
    fn a_range_spanning_a_boundary_selects_both_relics() {
        assert_eq!(
            relics_for_range(8_190, 8_200).collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert_eq!(relics_for_range(0, 0).collect::<Vec<_>>(), vec![0]);
        // Reversed arguments are tolerated rather than producing an empty plan, because an empty
        // plan looks exactly like "no results" and that is the most expensive kind of wrong.
        assert_eq!(
            relics_for_range(8_200, 8_190).collect::<Vec<_>>(),
            vec![0, 1]
        );
    }

    #[test]
    fn object_paths_match_the_layout_in_the_rfc() {
        assert_eq!(relic_prefix(1, 1, 2451), "legacy/v1/1/relics/002451");
        assert_eq!(registry_key(1, 1), "legacy/v1/1/registry.json");
    }
}
